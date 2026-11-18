# PhishGuard Architecture Documentation

## 1. System Topology
PhishGuard is structured as a full-stack defensive SOC platform:

```
[ React 19 + TypeScript + Vite SPA ]
        │  HTTPS / JSON + Bearer JWT
        ▼
[ Express REST API (server.ts / server/app.ts) ]
   ├── Auth & RBAC Middleware (bcryptjs + JWT HS256)
   ├── Rate Limiter (Sliding Window per IP)
   ├── Zod Schema & Payload Size Validation (256KB max)
   ├── SSRF & DNS-Rebinding Guard (server/security/ssrf.ts)
   │
   ├── Module A: URL Threat Analyzer (server/detectors/urlAnalyzer.ts)
   ├── Module B: Email Phishing Analyzer (server/detectors/emailAnalyzer.ts)
   ├── Module C: ML Inference Engine (server/ml/inference.ts -> ml/models/phishguard_models.json)
   ├── Module D: Domain, DNS & TLS Inspector (server/intelligence/domainIntel.ts)
   ├── Module E: Consent-Gated Threat Intel (server/intelligence/threatIntel.ts)
   ├── Module F: Transparent Risk Scorer (server/detectors/riskScorer.ts)
   └── Optional Gemini Explainable AI (server/ai/explainer.ts)
        │
        ▼
[ SQLite Persistence (WAL Mode, Parameterized Queries) ]
```

## 2. Non-Execution & SSRF Philosophy
- Submitted URLs are **never** fetched, rendered, or clicked by the server.
- Only DNS lookups (`dns.promises`), TLS certificate handshakes on public IPs (`tls.connect` with SSRF verification before and after DNS resolution), and public RDAP registry queries (`https://rdap.org`) are permitted.
- External Threat Intelligence APIs (Google Safe Browsing, VirusTotal, URLhaus) are only queried when `externalConsentGranted === true` and server environment keys are present.
