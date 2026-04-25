const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

const RATE_LIMIT_PER_INSTALL = 100;
const RATE_LIMIT_PER_IP = 200;
const CACHE_TTL_SECONDS = 3600;
const VECTOR_SIMILARITY_THRESHOLD = 0.30;
const VECTOR_PARTIAL_THRESHOLD = 0.60;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/health') {
        return jsonResponse({ status: 'healthy', service: 'scamwarning-api', version: '1.0.0' });
      }

      if (url.pathname === '/assess' && request.method === 'POST') {
        return await handleAssess(request, env);
      }

      if (url.pathname === '/correct' && request.method === 'POST') {
        return await handleCorrect(request, env);
      }

      return jsonResponse({ error: 'Not found' }, 404);
    } catch (err) {
      return jsonResponse({ error: 'Internal error' }, 500);
    }
  }
};

async function handleAssess(request, env) {
  const body = await request.json();
  const { install_id, domain, page_title, meta_description, content_hash, signals, request_id, body_text } = body;

  if (!install_id || !domain) {
    return jsonResponse({ error: 'Missing required fields: install_id, domain' }, 400);
  }

  // Rate limiting
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimited = await checkRateLimit(env, install_id, ip);
  if (rateLimited) {
    return jsonResponse({ error: 'Rate limit exceeded. Try again tomorrow.' }, 429);
  }

  // If this is a content escalation (second call with body_text)
  if (request_id && body_text) {
    return await handleContentEscalation(env, domain, body_text, request_id);
  }

  // Step 1: Check KV cache
  if (env.CACHE) {
    const cached = await env.CACHE.get(`assess:${domain}`, { type: 'json' });
    if (cached) {
      return jsonResponse({ ...cached, cached: true, source: 'cache' });
    }
  }

  // Step 2: Search VectorMind by domain metadata
  const vectorResult = await searchVectorMind(env, domain, page_title, meta_description);

  if (vectorResult && vectorResult.distance < VECTOR_SIMILARITY_THRESHOLD) {
    const result = {
      risk_score: vectorResult.risk_score,
      risk_level: vectorResult.risk_level,
      flags: vectorResult.flags ? vectorResult.flags.split(',').map(f => f.trim()).filter(Boolean) : [],
      summary: vectorResult.summary || 'Previously assessed domain.',
      source: 'vector_match',
      cached: false
    };

    if (env.CACHE) {
      await env.CACHE.put(`assess:${domain}`, JSON.stringify(result), { expirationTtl: CACHE_TTL_SECONDS });
    }
    return jsonResponse(result);
  }

  // Step 3: Check if signals indicate risk
  const totalScore = signals ? (signals.total_signal_score || 0) : 0;

  if (totalScore <= 0) {
    const safeResult = {
      risk_score: 0,
      risk_level: 'safe',
      flags: [],
      summary: 'No suspicious patterns detected.',
      source: 'signal_clean',
      cached: false
    };

    if (env.CACHE) {
      await env.CACHE.put(`assess:${domain}`, JSON.stringify(safeResult), { expirationTtl: CACHE_TTL_SECONDS });
    }
    return jsonResponse(safeResult);
  }

  // Step 4: If we have a partial vector match, use it as context for Claude
  if (vectorResult && vectorResult.distance < VECTOR_PARTIAL_THRESHOLD) {
    const contextResult = await assessWithClaude(env, domain, page_title, meta_description, null, signals, vectorResult);
    await storeAssessment(env, domain, page_title, contextResult);
    return jsonResponse(contextResult);
  }

  // Step 5: Need full content for novel assessment — request escalation
  const escalationId = crypto.randomUUID();
  return jsonResponse({ needs_content: true, request_id: escalationId });
}

async function handleContentEscalation(env, domain, bodyText, requestId) {
  const result = await assessWithClaude(env, domain, '', '', bodyText, null, null);
  await storeAssessment(env, domain, '', result);
  return jsonResponse(result);
}

async function handleCorrect(request, env) {
  const body = await request.json();
  const { install_id, domain, original_score, corrected_level, note } = body;

  if (!install_id || !domain || !corrected_level) {
    return jsonResponse({ error: 'Missing required fields' }, 400);
  }

  const correctedScore = corrected_level === 'safe' ? 0 : corrected_level === 'moderate' ? 35 : 75;

  try {
    await fetch(`${env.VECTORMIND_URL}/api/v1/vectors/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        collection: 'scamwarning',
        documents: [`User correction for ${domain}: ${corrected_level}. ${note || ''}`],
        ids: [`correction_${domain}_${Date.now()}`],
        metadatas: [{
          domain: domain,
          risk_score: String(correctedScore),
          risk_level: corrected_level,
          flags: '',
          summary: note || `User corrected assessment to ${corrected_level}`,
          source: 'user_correction',
          assessed_at: new Date().toISOString(),
          original_score: String(original_score || 0),
          correction_weight: '1.5'
        }]
      })
    });

    // Invalidate cache
    if (env.CACHE) {
      await env.CACHE.delete(`assess:${domain}`);
    }

    return jsonResponse({ success: true });
  } catch {
    return jsonResponse({ error: 'Failed to store correction' }, 500);
  }
}

// --- VectorMind ---

async function searchVectorMind(env, domain, title, meta) {
  const query = `${domain} ${title} ${meta}`.trim();
  if (!query) return null;

  try {
    const response = await fetch(`${env.VECTORMIND_URL}/api/v1/vectors/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: query.substring(0, 500),
        collection: 'scamwarning',
        limit: 3
      })
    });

    if (!response.ok) return null;

    const data = await response.json();
    const results = data?.data?.results;
    if (!results || !results.ids || !results.ids[0] || results.ids[0].length === 0) return null;

    const topDistance = results.distances[0][0];
    const topMeta = results.metadatas[0][0] || {};

    // Prefer user corrections (weighted higher)
    let bestIdx = 0;
    for (let i = 0; i < Math.min(3, results.ids[0].length); i++) {
      const meta = results.metadatas[0][i] || {};
      if (meta.source === 'user_correction' && results.distances[0][i] < VECTOR_PARTIAL_THRESHOLD) {
        bestIdx = i;
        break;
      }
    }

    const best = results.metadatas[0][bestIdx] || topMeta;
    return {
      distance: results.distances[0][bestIdx] || topDistance,
      risk_score: parseInt(best.risk_score || '0', 10),
      risk_level: best.risk_level || 'safe',
      flags: best.flags || '',
      summary: best.summary || '',
      source: best.source || 'vector'
    };
  } catch {
    return null;
  }
}

async function storeAssessment(env, domain, title, assessment) {
  try {
    await fetch(`${env.VECTORMIND_URL}/api/v1/vectors/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        collection: 'scamwarning',
        documents: [`${domain} ${title} ${assessment.summary}`],
        ids: [`assess_${domain}_${Date.now()}`],
        metadatas: [{
          domain: domain,
          risk_score: String(assessment.risk_score || 0),
          risk_level: assessment.risk_level || 'safe',
          flags: (assessment.flags || []).join(', '),
          summary: (assessment.summary || '').substring(0, 500),
          source: 'claude',
          assessed_at: new Date().toISOString(),
          page_title: (title || '').substring(0, 200),
          user_corrections: '0',
          correction_direction: ''
        }]
      })
    });

    if (env.CACHE) {
      await env.CACHE.put(`assess:${domain}`, JSON.stringify(assessment), { expirationTtl: CACHE_TTL_SECONDS });
    }
  } catch {}
}

// --- Claude API ---

async function assessWithClaude(env, domain, title, meta, bodyText, signals, vectorContext) {
  const systemPrompt = `You are a cybersecurity analyst specializing in online scam detection.
Analyze the provided webpage information and return ONLY valid JSON with this structure:

{
  "risk_score": <0-100>,
  "risk_level": "safe" | "moderate" | "threat",
  "flags": ["<specific red flag, max 8 words each, max 5 flags>"],
  "summary": "<plain English explanation, 1-2 sentences, non-technical>"
}

Scoring guide:
- 0-20: Safe — legitimate site, no red flags
- 21-50: Moderate — some suspicious patterns, user should be aware
- 51-100: Threat — strong scam/fraud indicators

Be conservative. Only flag genuine threats. False positives erode user trust faster than false negatives. When uncertain, score moderate (25-40), not threat.

NEVER flag a site as threat based solely on:
- Aggressive but legal marketing
- Poor web design
- Being a small or unknown business
- Having ads (even annoying ones)
- Selling legal products at high markups`;

  let userContent = `Domain: ${domain}\n`;
  if (title) userContent += `Page Title: ${title}\n`;
  if (meta) userContent += `Meta Description: ${meta}\n`;

  if (signals) {
    userContent += `\nLocal threat signals detected:\n`;
    for (const [key, val] of Object.entries(signals)) {
      if (val && val > 0) userContent += `  ${key}: ${val}\n`;
    }
  }

  if (bodyText) {
    userContent += `\nPage content (first 2000 chars):\n${bodyText.substring(0, 2000)}\n`;
  }

  if (vectorContext) {
    userContent += `\nSimilar previously-assessed site scored ${vectorContext.risk_score}/100 (${vectorContext.risk_level}) with flags: ${vectorContext.flags}\n`;
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 300,
        system: systemPrompt,
        messages: [{ role: 'user', content: userContent }]
      })
    });

    if (!response.ok) {
      throw new Error(`Anthropic API returned ${response.status}`);
    }

    const data = await response.json();
    const text = data.content?.[0]?.text || '';

    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in response');

    const parsed = JSON.parse(jsonMatch[0]);
    return {
      risk_score: Math.min(100, Math.max(0, parsed.risk_score || 0)),
      risk_level: ['safe', 'moderate', 'threat'].includes(parsed.risk_level) ? parsed.risk_level : 'moderate',
      flags: (parsed.flags || []).slice(0, 5),
      summary: (parsed.summary || 'Assessment completed.').substring(0, 300),
      source: 'claude',
      cached: false
    };
  } catch {
    // Fallback: use signals-based scoring if Claude fails
    if (signals) {
      return buildSignalFallback(signals, domain);
    }
    return {
      risk_score: 25,
      risk_level: 'moderate',
      flags: ['Unable to complete full assessment'],
      summary: 'Assessment service temporarily unavailable. Local analysis detected some patterns.',
      source: 'fallback',
      cached: false
    };
  }
}

function buildSignalFallback(signals, domain) {
  const flags = [];
  const score = Math.min(100, Math.round((signals.total_signal_score || 0) * 3));

  if (signals.phishing_count > 0) flags.push('Phishing language detected');
  if (signals.financial_fraud_count > 0) flags.push('Financial fraud indicators');
  if (signals.tech_support_count > 0) flags.push('Tech support scam patterns');
  if (signals.urgency_count > 0) flags.push('Urgency manipulation');
  if (signals.too_good_count > 0) flags.push('Too-good-to-be-true claims');

  let level = 'safe';
  if (score > 50) level = 'threat';
  else if (score > 20) level = 'moderate';

  return {
    risk_score: score,
    risk_level: level,
    flags: flags.slice(0, 5),
    summary: level === 'threat'
      ? `Multiple scam indicators detected on ${domain}.`
      : `Some suspicious patterns found on ${domain}. Exercise caution.`,
    source: 'signal_fallback',
    cached: false
  };
}

// --- Rate Limiting ---

async function checkRateLimit(env, installId, ip) {
  if (!env.RATE_LIMITS) return false;

  const today = new Date().toISOString().split('T')[0];
  const installKey = `rl:${installId}:${today}`;
  const ipKey = `rl:ip:${ip}:${today}`;

  const [installCount, ipCount] = await Promise.all([
    env.RATE_LIMITS.get(installKey).then(v => parseInt(v || '0', 10)),
    env.RATE_LIMITS.get(ipKey).then(v => parseInt(v || '0', 10))
  ]);

  if (installCount >= RATE_LIMIT_PER_INSTALL || ipCount >= RATE_LIMIT_PER_IP) {
    return true;
  }

  await Promise.all([
    env.RATE_LIMITS.put(installKey, String(installCount + 1), { expirationTtl: 86400 }),
    env.RATE_LIMITS.put(ipKey, String(ipCount + 1), { expirationTtl: 86400 })
  ]);

  return false;
}

// --- Helpers ---

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS
    }
  });
}
