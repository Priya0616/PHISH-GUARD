export function AboutPage() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-3">
        <h2 className="font-display text-xl font-bold text-slate-900">
          PhishGuard — AI-Powered Phishing Detection &amp; Cyber Threat Intelligence
        </h2>
        <p className="text-sm text-slate-600 leading-relaxed">
          PhishGuard is an enterprise-grade defensive security operations platform built to analyze suspicious URLs, phishing emails, domain infrastructure, and TLS certificates with transparent, explainable risk scoring.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2.5">
          <h3 className="font-display text-base font-semibold text-slate-900">
            Transparent Risk Scoring Formula
          </h3>
          <p className="text-xs text-slate-600 leading-relaxed">
            PhishGuard combines four non-overlapping signal groups and dynamically re-normalizes weights when external feeds or network telemetry are unavailable so missing information is never falsely treated as malicious:
          </p>
          <ul className="text-xs font-mono text-slate-800 space-y-1 pt-1">
            <li>35% — Rule-Based Structural &amp; Lexical Heuristics</li>
            <li>25% — Supervised ML Ensemble (LogReg + Random Forest / TF-IDF)</li>
            <li>20% — Live DNS, TLS Certificate &amp; RDAP Domain Age</li>
            <li>20% — Consent-Gated External Threat Intelligence Feeds</li>
          </ul>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2.5">
          <h3 className="font-display text-base font-semibold text-slate-900">
            Defensive Architecture &amp; Safeguards
          </h3>
          <ul className="text-xs text-slate-700 space-y-1.5 leading-relaxed">
            <li>Never visits, renders, or executes submitted suspicious URLs or attachments.</li>
            <li>Strict SSRF &amp; DNS-rebinding guards block loopback, RFC1918, and cloud metadata IPs.</li>
            <li>SPF/DKIM/DMARC verdicts are reported strictly from supplied header evidence.</li>
            <li>External threat feeds require explicit per-scan analyst consent.</li>
            <li>Parameterized SQLite queries, bcrypt password hashing, JWT auth, and rate limiting.</li>
          </ul>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
        <h3 className="font-display text-base font-semibold text-slate-900">
          API Documentation &amp; Known Limitations
        </h3>
        <p className="text-xs text-slate-600 leading-relaxed">
          Machine learning models evaluate lexical, structural, and n-gram similarity to our benchmark corpus and do not guarantee immunity against compromised legitimate websites or zero-day BEC campaigns. View the machine-readable OpenAPI 3.0 specification at{' '}
          <a
            href="/api/docs/openapi.json"
            target="_blank"
            rel="noreferrer"
            className="font-mono text-cyan-700 hover:text-cyan-800 underline"
          >
            /api/docs/openapi.json
          </a>
          .
        </p>
      </div>
    </div>
  );
}
