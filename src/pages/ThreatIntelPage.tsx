import { useEffect, useState, type FormEvent } from 'react';
import { Radar, ShieldAlert, ShieldCheck } from 'lucide-react';
import { StatusIndicator } from '../components/RiskBadge';
import { api } from '../services/api';
import type { SystemConfigStatus, ThreatIntelProviderResult } from '../types/phishguard';

export function ThreatIntelPage() {
  const [config, setConfig] = useState<SystemConfigStatus | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ThreatIntelProviderResult[] | null>(null);

  useEffect(() => {
    api.getSystemConfig().then((res) => setConfig(res.config)).catch(() => {});
  }, []);

  const handleLookup = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.lookupThreatIntel(urlInput, consent);
      setResults(res.results);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'External threat intelligence lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="text-xs text-slate-500">Google Safe Browsing v4</div>
          <StatusIndicator
            ok={Boolean(config?.googleSafeBrowsingConfigured)}
            label={config?.googleSafeBrowsingConfigured ? 'Active' : 'Optional Feed (Offline)'}
          />
          <p className="text-xs text-slate-500">Checks Social Engineering &amp; Malware threat lists when enabled.</p>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="text-xs text-slate-500">VirusTotal v3 URL Intel</div>
          <StatusIndicator
            ok={Boolean(config?.virusTotalConfigured)}
            label={config?.virusTotalConfigured ? 'Active' : 'Optional Feed (Offline)'}
          />
          <p className="text-xs text-slate-500">Queries multi-vendor URL reputation telemetry with rate-limit protection.</p>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="text-xs text-slate-500">abuse.ch URLhaus</div>
          <StatusIndicator
            ok={Boolean(config?.urlhausConfigured)}
            label={config?.urlhausConfigured ? 'Active' : 'Optional Feed (Offline)'}
          />
          <p className="text-xs text-slate-500">Checks known malware distribution URLs against URLhaus feed.</p>
        </div>
      </div>

      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-4">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-slate-900">
            Consent-Gated Threat Intelligence Lookup
          </h2>
          <p className="text-sm text-slate-600">
            PhishGuard handles all local ML, heuristic, and DNS/SSL checks automatically without external keys. If external threat intelligence feeds are enabled in your deployment, this tool lets you query them with explicit analyst consent.
          </p>
        </div>

        <form onSubmit={handleLookup} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Radar className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                required
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://suspicious-domain.example/login"
                className="w-full pl-10 pr-4 py-2.5 text-sm font-mono rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !consent}
              className="px-6 py-2.5 text-sm font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
            >
              {loading ? 'Querying Feeds...' : 'Query External Feeds'}
            </button>
          </div>

          <label className="flex items-start gap-2.5 text-xs text-slate-600 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              className="mt-0.5 rounded border-slate-300 text-cyan-600"
            />
            <span>
              I confirm this indicator does not contain confidential internal tokens/PII and consent to querying configured external threat intelligence services.
            </span>
          </label>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
          {error}
        </div>
      )}

      {results && (
        <div className="space-y-3">
          {results.map((item) => (
            <div
              key={item.provider}
              className="p-5 rounded-xl bg-white border border-slate-200 flex flex-wrap items-start justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {item.status === 'malicious' ? (
                    <ShieldAlert className="w-4 h-4 text-rose-600" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-cyan-700" />
                  )}
                  <span className="font-semibold text-sm text-slate-900">{item.provider}</span>
                  <span className="text-xs font-mono text-slate-500">({item.status})</span>
                </div>
                <div className="text-xs text-slate-600">{item.verdictSummary}</div>
              </div>
              <div className="text-xs font-mono text-slate-500">
                {item.latencyMs !== null ? `${item.latencyMs}ms · ` : ''}
                {new Date(item.checkedAt).toLocaleTimeString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
