# ScamWarning by MCPCIO

AI-powered scam detection for every page you visit. Free. Private. Open source.

## What It Does

ScamWarning analyzes web pages for scam indicators, phishing attempts, and fraudulent content. It shows a clear risk assessment in your browser toolbar:

- **Green** — Safe, no threats detected
- **Yellow** — Moderate, some suspicious patterns found
- **Red** — Threat, significant scam/fraud indicators detected

## How It Works

1. **Local analysis first.** ScamWarning runs pattern matching on page content entirely within your browser. No data leaves your device for the majority of pages.

2. **API lookup when needed.** If local patterns detect suspicious signals, the domain and extracted signals are sent to our assessment API. Full page content is only sent when no cached assessment exists for novel threats.

3. **AI assessment.** Novel threats are analyzed by Claude (Anthropic's AI) and the result is stored anonymously in our threat database, improving future assessments for all users.

4. **Results cached locally.** Assessment results are cached for 1 hour — revisits use the cache with zero network calls.

## Privacy

ScamWarning is built by [MCPCIO](https://mcpcio.com), a privacy-first AI platform.

- **No browsing history collected**
- **No personal information stored**
- **No tracking or analytics**
- **No ads, no premium tier, no upsells**
- Anonymous install ID for rate limiting only (not linked to any identity)
- Full source code available in this repository

Read the [full privacy policy](https://scamwarning.ai/privacy.html).

## Two Protection Modes

- **Click to Scan** (default) — Click the toolbar icon to scan the current page. No data is sent until you click.
- **Always-On** — Automatically scans every page. Requires granting additional browser permission (you'll be prompted).

## What ScamWarning Detects

- Phishing and credential harvesting
- Financial fraud and investment scams
- Tech support scams
- Fake government/brand impersonation
- Urgency manipulation tactics
- Misleading advertisements
- Suspicious e-commerce sites
- Data harvesting attempts
- Malware distribution sites

## Install

Install from the [Chrome Web Store](https://chrome.google.com/webstore).

Or load unpacked for development:
1. Clone this repository
2. Open `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the `scamwarning/` directory

## Architecture

```
Chrome Extension                    Cloudflare Worker                  MCPCIO Backend
─────────────────                   ─────────────────                  ──────────────
content-script.js                   api.scamwarning.ai          VectorMind
  → local regex patterns              → rate limiting                    → threat database
  → DOM signal extraction              → VectorMind search               → semantic search
  → sends signals to SW               → Claude API (novel only)          → assessment storage

service-worker.js                                                     Claude API (Anthropic)
  → checks local cache                                                  → novel threat assessment
  → calls Worker API
  → updates toolbar icon
```

## License

MIT License. See [LICENSE](LICENSE).

## Built By

[MCPCIO](https://mcpcio.com) — MCP Chief Intelligence Orchestrator. Privacy-first AI platform.
