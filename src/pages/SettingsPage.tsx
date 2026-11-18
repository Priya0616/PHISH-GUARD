import { useEffect, useState } from 'react';
import { StatusIndicator } from '../components/RiskBadge';
import { api } from '../services/api';
import type { AuditLogEntry, SystemConfigStatus } from '../types/phishguard';

export function SettingsPage() {
  const [config, setConfig] = useState<SystemConfigStatus | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getSystemConfig()
      .then((res) => {
        setConfig(res.config);
        setAuditLogs(res.auditLogs);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load configuration.'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="h-64 rounded-xl bg-white border border-slate-200 animate-pulse" />;
  }

  if (error || !config) {
    return (
      <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
        {error ?? 'System configuration unavailable.'}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-4">
        <div>
          <h2 className="font-display text-lg font-semibold text-slate-900">
            Built-In Security Engines &amp; Platform Status
          </h2>
          <p className="text-sm text-slate-600">
            All core PhishGuard analyzers, ML classifiers, DNS/TLS inspectors, and defensive safeguards operate out-of-the-box with zero external setup required.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-900">Built-In ML &amp; Heuristic Engines</div>
              <div className="text-slate-500">URL LogReg + Random Forest + Email TF-IDF</div>
            </div>
            <StatusIndicator ok={true} label="Active" />
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-900">DNS, TLS &amp; RDAP Domain Inspector</div>
              <div className="text-slate-500">Live A/AAAA/MX/NS &amp; Certificate Validation</div>
            </div>
            <StatusIndicator ok={true} label="Active" />
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-900">Gemini AI Narrative Module</div>
              <div className="text-slate-500">Optional cloud enhancement (local synthesis active)</div>
            </div>
            <StatusIndicator
              ok={config.geminiConfigured}
              label={config.geminiConfigured ? 'Active' : 'Local Synthesis Active'}
            />
          </div>

          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
            <div>
              <div className="font-semibold text-slate-900">External Threat Intel Feeds</div>
              <div className="text-slate-500">Safe Browsing, VirusTotal, URLhaus</div>
            </div>
            <StatusIndicator
              ok={config.googleSafeBrowsingConfigured || config.virusTotalConfigured || config.urlhausConfigured}
              label={
                config.googleSafeBrowsingConfigured || config.virusTotalConfigured || config.urlhausConfigured
                  ? 'Configured'
                  : 'Optional (Local Mode)'
              }
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-2">
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-slate-500">SSRF &amp; DNS Rebinding Guard</div>
            <div className="mt-1 font-semibold text-emerald-700">
              {config.ssrfProtectionEnabled ? 'Active (RFC1918 / Loopback / Metadata Blocked)' : 'Disabled'}
            </div>
          </div>
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-slate-500">API Rate Limiter</div>
            <div className="mt-1 font-mono font-semibold text-slate-900">
              {config.rateLimitMaxPerMinute} requests / minute / IP
            </div>
          </div>
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-slate-500">Database Persistence</div>
            <div className="mt-1 font-semibold text-slate-900">{config.databaseEngine}</div>
          </div>
        </div>
      </div>

      <div className="rounded-xl bg-white border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200">
          <h3 className="font-display text-base font-semibold text-slate-900">
            Security &amp; Scan Audit Trail
          </h3>
          <p className="text-xs text-slate-500">Recent authentication, scan, and SSRF block events</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-[11px] text-slate-500 bg-slate-50">
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Analyst</th>
                <th className="py-2.5 px-4">Target</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50">
                  <td className="py-2.5 px-4 font-mono text-cyan-700 whitespace-nowrap">{log.action}</td>
                  <td className="py-2.5 px-4 text-slate-700 whitespace-nowrap">{log.userEmail ?? 'anonymous'}</td>
                  <td className="py-2.5 px-4 font-mono text-slate-800 max-w-xs truncate">{log.target}</td>
                  <td className="py-2.5 px-4 font-mono whitespace-nowrap">
                    <span
                      className={
                        log.status === 'blocked'
                          ? 'text-amber-700 font-semibold'
                          : log.status === 'error'
                          ? 'text-rose-700 font-semibold'
                          : 'text-emerald-700 font-semibold'
                      }
                    >
                      {log.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono text-slate-500 whitespace-nowrap">
                    {new Date(log.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
