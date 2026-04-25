(() => {
  if (window.__scamwarningScanned) return;
  window.__scamwarningScanned = true;

  const domain = location.hostname;
  if (!domain || domain === 'localhost' || domain.endsWith('.local')) return;

  const SKIP_DOMAINS = new Set([
    'chrome.google.com', 'chromewebstore.google.com',
    'chrome-extension', 'about:blank', 'newtab'
  ]);
  if (SKIP_DOMAINS.has(domain)) return;

  function getMetaDescription() {
    const el = document.querySelector('meta[name="description"]');
    return el ? el.getAttribute('content') || '' : '';
  }

  function countForms() {
    return document.querySelectorAll('form').length;
  }

  function countPasswordFields() {
    return document.querySelectorAll('input[type="password"]').length;
  }

  function getExternalLinkDomains() {
    const domains = new Set();
    document.querySelectorAll('a[href]').forEach(a => {
      try {
        const url = new URL(a.href, location.origin);
        if (url.hostname && url.hostname !== domain) {
          domains.add(url.hostname);
        }
      } catch {}
    });
    return domains.size;
  }

  function getBodyText() {
    const text = document.body ? document.body.innerText || '' : '';
    return text.substring(0, 2000);
  }

  async function computeContentHash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function runLocalPatterns(text) {
    const results = {};
    let totalScore = 0;

    for (const [category, patterns] of Object.entries(SCAM_PATTERNS)) {
      let matchCount = 0;
      for (const pattern of patterns) {
        pattern.lastIndex = 0;
        const matches = text.match(pattern);
        if (matches) matchCount += matches.length;
      }
      results[category + '_count'] = matchCount;

      const weight = SIGNAL_WEIGHTS[category] || 1.0;
      totalScore += Math.min(matchCount, 5) * weight;
    }

    results.total_signal_score = Math.round(totalScore * 100) / 100;
    return results;
  }

  async function analyze() {
    const bodyText = getBodyText();
    const contentHash = await computeContentHash(bodyText);
    const pageTitle = document.title || '';
    const metaDescription = getMetaDescription();

    const fullText = [pageTitle, metaDescription, bodyText].join(' ');
    const patternResults = runLocalPatterns(fullText);

    const signals = {
      page_title: pageTitle.substring(0, 200),
      meta_description: metaDescription.substring(0, 500),
      domain: domain,
      url_path: location.pathname,
      is_https: location.protocol === 'https:',
      form_count: countForms(),
      password_field_count: countPasswordFields(),
      external_link_count: getExternalLinkDomains(),
      content_hash: contentHash,
      ...patternResults
    };

    chrome.runtime.sendMessage(
      { type: 'PAGE_SIGNALS', signals: signals },
      (response) => {
        if (response && response.needsContent) {
          chrome.runtime.sendMessage({
            type: 'PAGE_CONTENT',
            requestId: response.requestId,
            content: {
              body_text: bodyText,
              domain: domain
            }
          });
        }
      }
    );
  }

  analyze().catch(() => {});
})();
