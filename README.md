# PhishGuard — AI-Powered Phishing Detection & Cyber Threat Intelligence Platform

PhishGuard is an enterprise-grade defensive Security Operations Center (SOC) platform for detecting, analyzing, classifying, and reporting phishing URLs, malicious emails, and suspicious domain infrastructure.

## Core Capabilities
- **Module A — Advanced URL Threat Analyzer**: Detects IP-hosted URLs, excessive subdomains, brand impersonation & Levenshtein typosquatting, Punycode/IDN homographs, userinfo (`@`) obfuscation, URL shorteners, non-standard ports, open-redirect query parameters, and percent-encoding obfuscation.
- **Module B — AI Email Phishing Analyzer**: Analyzes urgency coercion, credential harvesting, financial/BEC fraud, risky attachment pretexts, sender/reply-to mismatches, embedded URLs, TF-IDF NLP classification, and strictly evidence-based SPF/DKIM/DMARC header parsing.
- **Module C — Zero-Leakage Machine Learning Pipeline**: Trains L2-Regularized Logistic Regression, a 25-tree Random Forest, and an Email TF-IDF + Logistic Regression classifier on a documented benchmark corpus with stratified 80/20 splits and held-out test metrics.
- **Module D — Domain, DNS & TLS Intelligence**: Timeout-bounded `A`, `AAAA`, `MX`, `NS`, and `TXT` DNS lookups, TLS certificate inspection (validity, expiry, issuer, self-signed, SHA-256 fingerprint), and RDAP domain age checks protected by SSRF & DNS-rebinding guards.
- **Module E — Consent-Gated Threat Intelligence**: Server-side integrations for Google Safe Browsing v4, VirusTotal v3, and abuse.ch URLhaus—never transmitting indicators without explicit user consent and never fabricating unavailable results.
- **Module F — Transparent Risk Scoring & PDF Reporting**: Documented dynamic-weight fusion (`0–29` Low, `30–59` Medium, `60–79` High, `80–100` Critical), interactive 4-category forensic evidence separation, optional server-side Gemini AI explanation, and downloadable PDF investigation reports.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. (Optional) Retrain ML models from ml/datasets/
node ml/training/train_models.mjs

# 3. Start full-stack dev server on port 3000
npm run dev
```

Default evaluation credentials (also selectable on the Login screen):
- **Email**: `analyst@phishguard.sec`
- **Password**: `PhishGuard!SOC2026`

## Environment Variables
Copy `.env.example` to `.env` and configure optional server-side keys:
- `JWT_SECRET`: Secret used to sign analyst session tokens.
- `GEMINI_API_KEY`: Enables Gemini (`gemini-4-hydrogen`) explainable threat narratives.
- `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY`: Optional external threat intelligence feeds.

## Verification & Testing

```bash
npm run lint     # TypeScript type-check
npm test         # Vitest unit + API integration suite
npm run build    # Production Vite bundle
```

## Documentation
- [Architecture Overview](docs/architecture.md)
- [API Documentation](docs/api_documentation.md)
- [Security Controls](docs/security.md)
- [Testing Guide](docs/testing.md)
- [Dataset Attribution & Limitations](ml/datasets/DATASET_ATTRIBUTION.md)

## Known Limitations
- ML confidence scores reflect statistical similarity to the curated benchmark corpus and do not guarantee safety against compromised legitimate domains or novel zero-day lures.
- External threat intelligence feeds and Gemini AI explainability report `Unavailable` unless valid API keys are configured in server environment variables.
