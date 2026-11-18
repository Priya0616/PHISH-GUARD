# PhishGuard REST API Documentation

Machine-readable OpenAPI 3.0 specification is served live at `GET /api/docs/openapi.json`.

## Authentication Endpoints
- `POST /api/auth/login` — Body: `{ email, password }`. Returns `{ token, user }`.
- `POST /api/auth/register` — Body: `{ email, password, fullName }`. Creates analyst account and returns JWT.
- `GET /api/auth/me` — Requires `Authorization: Bearer <token>`. Returns authenticated analyst profile.

## Scanning & Intelligence Endpoints (JWT Required)
- `GET /api/dashboard` — Aggregated KPIs, risk distribution, threat categories, 7-day trends, and recent scans from SQLite.
- `POST /api/scans/url` — Body: `{ url, externalConsentGranted?: boolean }`. Runs heuristics, ML ensemble, DNS/TLS/RDAP, consent-gated threat intel, and risk scoring.
- `POST /api/scans/email` — Body: `{ subject, body, sender, replyTo?, headers? }`. Evaluates social engineering, reply-to mismatch, embedded URLs, SPF/DKIM/DMARC header evidence, and TF-IDF NLP classification.
- `POST /api/scans/domain` — Body: `{ domain }`. Resolves A/AAAA/MX/NS/TXT DNS records, TLS certificate metadata, and RDAP registration age.
- `POST /api/threat-intel/lookup` — Body: `{ url, consentGranted: true }`. Queries Google Safe Browsing, VirusTotal, and URLhaus. Rejects with HTTP 400 if consent is false.
- `GET /api/scans?search=&riskLevel=&scanType=&limit=&offset=` — Paginated & filtered scan history.
- `GET /api/scans/:id` / `DELETE /api/scans/:id` — Retrieve or delete an investigation record.
- `DELETE /api/scans/demo` — Remove initial sample baseline scans.
- `GET /api/ml/insights` — Returns held-out test metrics, confusion matrices, feature importances, and TF-IDF weights.
- `GET /api/system/config` — Returns server capability flags (no secrets) and recent security audit logs.
