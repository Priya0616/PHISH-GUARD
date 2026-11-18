import { useState, type FormEvent } from 'react';
import { Globe, Lock, Server } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { ScanRecord } from '../types/phishguard';

export function DomainIntelPage({ onOpenInvestigation }: { onOpenInvestigation: (id: string) => void }) {
  const [domainInput, setDomainInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanRecord | null>(null);

  const handleLookup = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const scan = await api.scanDomain(domainInput);
      setResult(scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Domain intelligence lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  const intel = result?.domainIntel;

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-4">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-slate-900">
            Domain, DNS &amp; TLS Certificate Intelligence
          </h2>
          <p className="text-sm text-slate-600">
            Executes timeout-bounded DNS resolution (A, AAAA, MX, NS, TXT), TLS handshake certificate inspection, and RDAP registration lookups with SSRF and DNS-rebinding defenses.
          </p>
        </div>

        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              required
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="github.com or suspicious-domain.xyz"
              className="w-full pl-10 pr-4 py-2.5 text-sm font-mono rounded-lg bg-slate-50 border border-slate-300 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-cyan-600 focus:bg-white"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2.5 text-sm font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0"
          >
            {loading ? 'Querying DNS & TLS...' : 'Inspect Domain'}
          </button>
        </form>

        <div className="flex flex-wrap gap-2">
          {['github.com', 'cloudflare.com', 'nonexistent-phish-test-99182.invalid', '127.0.0.1'].map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => setDomainInput(d)}
              className="px-3 py-1.5 text-xs font-mono rounded-lg bg-slate-50 border border-slate-200 text-slate-700 hover:text-cyan-700 hover:border-cyan-300"
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
          {error}
        </div>
      )}

      {result && intel && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-white border border-slate-200 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs font-mono text-slate-500">
                {result.id} · Registrable: {intel.registrableDomain} · Retrieved {new Date(intel.retrievedAt).toLocaleString()}
              </div>
              <div className="font-mono text-base font-semibold text-slate-900">{intel.domain}</div>
            </div>
            <div className="flex items-center gap-3">
              <RiskBadge level={result.riskLevel} score={result.riskScore} />
              <button
                type="button"
                onClick={() => onOpenInvestigation(result.id)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-50 border border-cyan-200 text-cyan-800 hover:bg-cyan-100"
              >
                Open Investigation
              </button>
            </div>
          </div>

          {intel.ssrfBlocked && (
            <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-800">
              {intel.ssrfReason}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* DNS Records */}
            <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Server className="w-4 h-4 text-cyan-700" />
                <span>DNS Records</span>
              </div>
              {!intel.dnsAvailable ? (
                <div className="text-xs text-amber-700">{intel.dnsError ?? 'DNS resolution unavailable.'}</div>
              ) : (
                <div className="space-y-2.5 text-xs font-mono">
                  <div>
                    <div className="text-slate-500">A (IPv4)</div>
                    <div className="text-slate-900">{intel.dnsRecords.a.join(', ') || 'None'}</div>
                  </div>
                  <div>
                    <div className="text-slate-500">AAAA (IPv6)</div>
                    <div className="text-slate-900 break-all">{intel.dnsRecords.aaaa.join(', ') || 'None'}</div>
                  </div>
                  <div>
                    <div className="text-slate-500">MX (Mail Exchangers)</div>
                    <div className="text-slate-900">
                      {intel.dnsRecords.mx.map((m) => `${m.exchange} (${m.priority})`).join(', ') || 'None'}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500">NS (Nameservers)</div>
                    <div className="text-slate-900">{intel.dnsRecords.ns.join(', ') || 'None'}</div>
                  </div>
                </div>
              )}
            </div>

            {/* TLS Certificate */}
            <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Lock className="w-4 h-4 text-emerald-700" />
                <span>SSL / TLS Certificate</span>
              </div>
              {!intel.ssl.available ? (
                <div className="text-xs text-slate-500">{intel.ssl.error ?? 'TLS certificate unavailable.'}</div>
              ) : (
                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500">Chain Valid: </span>
                    <span className={intel.ssl.valid ? 'text-emerald-700 font-semibold' : 'text-rose-700 font-semibold'}>
                      {String(intel.ssl.valid)}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Subject: </span>
                    <span className="text-slate-900 break-all">{intel.ssl.subject ?? 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Issuer: </span>
                    <span className="text-slate-900 break-all">{intel.ssl.issuer ?? 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Valid To: </span>
                    <span className="text-slate-900">
                      {intel.ssl.validTo?.slice(0, 10) ?? 'N/A'} ({intel.ssl.daysRemaining ?? '?'}d left)
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">SHA-256: </span>
                    <span className="text-slate-600 break-all text-[10px]">{intel.ssl.fingerprintSha256 ?? 'N/A'}</span>
                  </div>
                </div>
              )}
            </div>

            {/* RDAP Registration */}
            <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Globe className="w-4 h-4 text-violet-700" />
                <span>RDAP / WHOIS Metadata</span>
              </div>
              {!intel.rdap.available ? (
                <div className="text-xs text-slate-500">{intel.rdap.error ?? 'RDAP metadata unavailable.'}</div>
              ) : (
                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500">Registrar: </span>
                    <span className="text-slate-900">{intel.rdap.registrar ?? 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Domain Age: </span>
                    <span className="text-slate-900">{intel.rdap.domainAgeDays ?? '?'} days</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Registered: </span>
                    <span className="text-slate-900">{intel.rdap.createdAt?.slice(0, 10) ?? 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Expires: </span>
                    <span className="text-slate-900">{intel.rdap.expiresAt?.slice(0, 10) ?? 'N/A'}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
