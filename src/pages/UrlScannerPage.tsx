import { useState, type FormEvent } from 'react';
import { ArrowUpRight, FileDown, Link2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { ScanRecord } from '../types/phishguard';
import { downloadScanPdfReport } from '../utils/pdfReport';

const SAMPLE_URLS = [
  { label: 'Legitimate (Python Docs)', url: 'https://docs.python.org/3/library/ssl.html' },
  { label: 'Subdomain Spoof (Microsoft)', url: 'http://login.microsoftonline.com.verify-account-session-841.com/oauth2/token' },
  { label: 'IP-Literal Phish', url: 'http://198.51.100.42:8080/paypal/login.php?redirect=http%3A%2F%2Fevil.ru' },
  { label: 'IDN Homograph (Punycode)', url: 'https://xn--pypal-4ve.com/signin/confirm-identity' },
  { label: 'SSRF Internal Guard Test', url: 'http://127.0.0.1:3000/api/health' },
];

export function UrlScannerPage({ onOpenInvestigation }: { onOpenInvestigation: (id: string) => void }) {
  const [urlInput, setUrlInput] = useState('');
  const [externalConsent, setExternalConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanRecord | null>(null);

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const scan = await api.scanUrl(urlInput, externalConsent);
      setResult(scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'URL scan failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-5">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-slate-900">
            Advanced URL Threat Analyzer
          </h2>
          <p className="text-sm text-slate-600">
            Static lexical inspection, ML ensemble scoring (Logistic Regression + Random Forest), live DNS/TLS/RDAP telemetry, and SSRF-protected parsing. Links are never opened or executed.
          </p>
        </div>

        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Link2 className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                required
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com/login or suspicious URL"
                className="w-full pl-10 pr-4 py-2.5 text-sm font-mono rounded-lg bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-cyan-600 focus:bg-white"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 text-sm font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0"
            >
              {loading ? 'Analyzing Indicator...' : 'Analyze URL'}
            </button>
          </div>

          <label className="flex items-start gap-2.5 text-xs text-slate-600 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={externalConsent}
              onChange={(e) => setExternalConsent(e.target.checked)}
              className="mt-0.5 rounded border-slate-300 text-cyan-600 focus:ring-cyan-600"
            />
            <span>
              Consent to also check configured external Threat Intelligence feeds when available. Leave unchecked for private or internal indicators.
            </span>
          </label>
        </form>

        <div className="pt-3 border-t border-slate-200 space-y-2">
          <div className="text-xs text-slate-500">Load Benchmark Test Vector</div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_URLS.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => {
                  setUrlInput(item.url);
                  setError(null);
                }}
                className="px-3 py-1.5 text-xs rounded-lg bg-slate-50 border border-slate-200 text-slate-700 hover:text-cyan-700 hover:border-cyan-300 transition-colors"
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
          {error}
        </div>
      )}

      {result && (
        <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-6">
          <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-slate-200">
            <div className="space-y-1.5 min-w-0">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span className="font-mono text-cyan-700 font-semibold">{result.id}</span>
                <span aria-hidden="true">·</span>
                <span>{result.threatCategory}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono">{result.engineVersion}</span>
              </div>
              <div className="font-mono text-sm text-slate-900 break-all">{result.indicator}</div>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <RiskBadge level={result.riskLevel} score={result.riskScore} />
              <button
                type="button"
                onClick={() => downloadScanPdfReport(result)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50"
              >
                <FileDown className="w-3.5 h-3.5" />
                <span>PDF</span>
              </button>
              <button
                type="button"
                onClick={() => onOpenInvestigation(result.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-50 border border-cyan-200 text-cyan-800 hover:bg-cyan-100"
              >
                <span>Full Investigation</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">Overall Risk Score</div>
              <div className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
                {result.riskScore} / 100
              </div>
            </div>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">Heuristic Score</div>
              <div className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
                {result.riskBreakdown.componentScores.heuristicsScore} / 100
              </div>
            </div>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">ML Ensemble</div>
              <div className="mt-1 font-display text-2xl font-bold text-cyan-700 tabular-nums">
                {result.riskBreakdown.componentScores.mlScore}%
              </div>
            </div>
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200">
              <div className="text-xs text-slate-500">Agreement Confidence</div>
              <div className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
                {result.riskBreakdown.confidence}%
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-slate-900">Key Findings &amp; Explanations</h3>
            <div className="space-y-2">
              {result.evidence.slice(0, 6).map((ev) => (
                <div
                  key={ev.id}
                  className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex items-start gap-3"
                >
                  {ev.severity === 'high' || ev.severity === 'critical' ? (
                    <ShieldAlert className="w-4 h-4 text-rose-600 mt-0.5 shrink-0" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-cyan-700 mt-0.5 shrink-0" />
                  )}
                  <div className="space-y-0.5 text-xs">
                    <div className="font-semibold text-slate-900">
                      {ev.title}{' '}
                      <span className="font-normal text-slate-500">· {ev.source} ({ev.category})</span>
                    </div>
                    <div className="text-slate-600">{ev.detail}</div>
                  </div>
                </div>
              ))}
            </div>
            <p className="text-xs text-slate-500">{result.riskBreakdown.confidenceLimitations}</p>
          </div>
        </div>
      )}
    </div>
  );
}
