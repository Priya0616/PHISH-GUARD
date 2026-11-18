import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  FileDown,
  HelpCircle,
  ShieldAlert,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { EvidenceCategory, ScanRecord } from '../types/phishguard';
import { downloadScanPdfReport } from '../utils/pdfReport';

const EVIDENCE_TABS: Array<{ id: EvidenceCategory; label: string }> = [
  { id: 'confirmed', label: 'Confirmed Findings' },
  { id: 'suspicious', label: 'Suspicious Indicators' },
  { id: 'unavailable', label: 'Unavailable Checks' },
  { id: 'model', label: 'Model Predictions' },
];

export function InvestigationPage({
  scanId,
  onSelectScan,
}: {
  scanId: string | null;
  onSelectScan: (id: string) => void;
}) {
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [recentList, setRecentList] = useState<ScanRecord[]>([]);
  const [activeTab, setActiveTab] = useState<EvidenceCategory>('confirmed');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    const load = async () => {
      try {
        const list = await api.listScans({ limit: 15, offset: 0 });
        setRecentList(list.items);
        const targetId = scanId ?? list.items[0]?.id ?? null;
        if (!targetId) {
          setScan(null);
        } else {
          const detail = await api.getScan(targetId);
          setScan(detail);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load investigation record.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [scanId]);

  if (loading) {
    return <div className="h-72 rounded-xl bg-white border border-slate-200 animate-pulse" />;
  }

  if (error) {
    return (
      <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
        {error}
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-10 rounded-xl bg-white border border-slate-200 text-center text-sm text-slate-500">
        No scans available to investigate. Submit a URL, Email, or Domain scan first.
      </div>
    );
  }

  const counts: Record<EvidenceCategory, number> = {
    confirmed: scan.evidence.filter((e) => e.category === 'confirmed').length,
    suspicious: scan.evidence.filter((e) => e.category === 'suspicious').length,
    unavailable: scan.evidence.filter((e) => e.category === 'unavailable').length,
    model: scan.evidence.filter((e) => e.category === 'model').length,
  };

  const filteredEvidence = scan.evidence.filter((e) => e.category === activeTab);
  const highRiskEvidence = scan.evidence.filter(
    (e) => e.severity === 'high' || e.severity === 'critical' || e.severity === 'medium'
  );

  return (
    <div className="space-y-6">
      {/* Selector & Header */}
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <label htmlFor="scan-switcher" className="text-xs text-slate-500 whitespace-nowrap">
              Active Investigation:
            </label>
            <select
              id="scan-switcher"
              value={scan.id}
              onChange={(e) => onSelectScan(e.target.value)}
              className="px-3 py-1.5 text-xs font-mono rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600"
            >
              {recentList.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id} · {item.scanType.toUpperCase()} · {item.riskScore}/100
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-3">
            <RiskBadge level={scan.riskLevel} score={scan.riskScore} />
            <button
              type="button"
              onClick={() => downloadScanPdfReport(scan)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 whitespace-nowrap"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span>Export PDF Report</span>
            </button>
          </div>
        </div>

        <div className="space-y-2 pt-3 border-t border-slate-200">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="font-mono text-cyan-700 font-semibold">{scan.id}</span>
            <span aria-hidden="true">·</span>
            <span>{new Date(scan.createdAt).toLocaleString()}</span>
            <span aria-hidden="true">·</span>
            <span>{scan.threatCategory}</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono">{scan.engineVersion}</span>
          </div>
          <div className="font-mono text-sm text-slate-900 break-all">{scan.indicator}</div>
          <div className="text-[11px] font-mono text-slate-400 break-all">
            SHA-256: {scan.indicatorSha256}
          </div>
        </div>

        {/* Component Score Breakdown */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-xs text-slate-500">Heuristics ({Math.round(scan.riskBreakdown.componentWeights.heuristicsWeight * 100)}%)</div>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 tabular-nums">
              {scan.riskBreakdown.componentScores.heuristicsScore}/100
            </div>
          </div>
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-xs text-slate-500">ML Models ({Math.round(scan.riskBreakdown.componentWeights.mlWeight * 100)}%)</div>
            <div className="mt-1 font-mono text-xl font-bold text-cyan-700 tabular-nums">
              {scan.riskBreakdown.componentScores.mlScore}/100
            </div>
          </div>
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-xs text-slate-500">Domain/SSL ({Math.round(scan.riskBreakdown.componentWeights.domainSslWeight * 100)}%)</div>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 tabular-nums">
              {scan.riskBreakdown.componentScores.domainSslScore}/100
            </div>
          </div>
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
            <div className="text-xs text-slate-500">External Intel ({Math.round(scan.riskBreakdown.componentWeights.externalIntelWeight * 100)}%)</div>
            <div className="mt-1 font-mono text-xl font-bold text-slate-900 tabular-nums">
              {scan.riskBreakdown.componentScores.externalIntelScore !== null
                ? `${scan.riskBreakdown.componentScores.externalIntelScore}/100`
                : 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Evidence Panel (4 Explicit Categories) */}
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 className="font-display text-base font-semibold text-slate-900">
            Interactive Forensic Evidence Panel
          </h2>
          <div className="flex flex-wrap gap-1 p-1 rounded-lg bg-slate-100 border border-slate-200">
            {EVIDENCE_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'bg-white text-cyan-800 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {tab.label} ({counts[tab.id]})
              </button>
            ))}
          </div>
        </div>

        {filteredEvidence.length === 0 ? (
          <div className="p-6 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-500 text-center">
            No items recorded in the "{EVIDENCE_TABS.find((t) => t.id === activeTab)?.label}" category for this scan.
          </div>
        ) : (
          <div className="space-y-2.5">
            {filteredEvidence.map((ev) => {
              const Icon =
                ev.category === 'confirmed'
                  ? ev.severity === 'info'
                    ? CheckCircle2
                    : ShieldAlert
                  : ev.category === 'suspicious'
                  ? AlertTriangle
                  : ev.category === 'model'
                  ? BrainCircuit
                  : HelpCircle;
              const iconColor =
                ev.severity === 'critical' || ev.severity === 'high'
                  ? 'text-rose-600'
                  : ev.severity === 'medium'
                  ? 'text-amber-600'
                  : ev.category === 'unavailable'
                  ? 'text-slate-400'
                  : 'text-cyan-700';

              return (
                <div
                  key={ev.id}
                  className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-start gap-3"
                >
                  <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${iconColor}`} />
                  <div className="space-y-1 text-xs">
                    <div className="font-semibold text-slate-900">
                      {ev.title}{' '}
                      <span className="font-normal text-slate-500">· {ev.source}</span>
                    </div>
                    <div className="text-slate-600">{ev.detail}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Technical Sub-Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <h3 className="font-display text-base font-semibold text-slate-900">
            Explainable Threat Assessment &amp; Analyst Response
          </h3>
          {scan.riskBreakdown.aiAssessment.available && scan.riskBreakdown.aiAssessment.summary ? (
            <div className="p-3.5 rounded-lg bg-cyan-50 border border-cyan-200 space-y-2 text-xs">
              <div className="text-cyan-800 font-semibold">
                AI Threat Summary ({scan.riskBreakdown.aiAssessment.model})
              </div>
              <p className="text-slate-800 leading-relaxed">{scan.riskBreakdown.aiAssessment.summary}</p>
              {scan.riskBreakdown.aiAssessment.reasoningSteps.length > 0 && (
                <ul className="list-disc pl-4 space-y-1 text-slate-600">
                  {scan.riskBreakdown.aiAssessment.reasoningSteps.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 text-xs">
              <div className="font-semibold text-slate-800">Local Deterministic Threat Synthesis</div>
              <p className="text-slate-600 leading-relaxed">
                This indicator scored <strong className="text-slate-900">{scan.riskScore}/100 ({scan.riskLevel})</strong> under{' '}
                <strong className="text-slate-900">{scan.threatCategory}</strong> based on {highRiskEvidence.length} elevated signal(s) and ML ensemble telemetry.
              </p>
            </div>
          )}

          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-700">Recommended SOC Actions</div>
            <ul className="space-y-1.5 text-xs text-slate-700">
              {scan.riskBreakdown.recommendations.map((rec, idx) => (
                <li key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  {rec}
                </li>
              ))}
            </ul>
          </div>

          <p className="text-xs text-slate-500">{scan.riskBreakdown.confidenceLimitations}</p>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          {scan.urlFeatures ? (
            <>
              <h3 className="font-display text-base font-semibold text-slate-900">
                Extracted URL Feature Matrix
              </h3>
              <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">URL Length</span>
                  <span className="text-slate-900 font-semibold">{scan.urlFeatures.urlLength}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Entropy</span>
                  <span className="text-slate-900 font-semibold">{scan.urlFeatures.shannonEntropy}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Subdomains</span>
                  <span className="text-slate-900 font-semibold">{scan.urlFeatures.subdomainDepth}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">IP Host</span>
                  <span className="text-slate-900 font-semibold">{String(scan.urlFeatures.isIpHost)}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Non-HTTPS</span>
                  <span className="text-slate-900 font-semibold">{String(scan.urlFeatures.isNonHttps)}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Punycode/IDN</span>
                  <span className="text-slate-900 font-semibold">{String(scan.urlFeatures.hasPunycodeOrUnicode)}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Shortener</span>
                  <span className="text-slate-900 font-semibold">{String(scan.urlFeatures.isShortener)}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
                  <span className="text-slate-500">Brand Spoof</span>
                  <span className="text-slate-900 font-semibold">{scan.urlFeatures.brandImpersonationTarget ?? 'None'}</span>
                </div>
              </div>
            </>
          ) : scan.emailAnalysis ? (
            <>
              <h3 className="font-display text-base font-semibold text-slate-900">
                Email Header &amp; Social Engineering Details
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="text-slate-500">Sender: <span className="text-slate-900">{scan.emailAnalysis.sender}</span></div>
                  <div className="text-slate-500">Reply-To: <span className="text-slate-900">{scan.emailAnalysis.replyTo}</span></div>
                  <div className="text-slate-500">Mismatch: <span className="text-slate-900">{String(scan.emailAnalysis.senderReplyToMismatch)}</span></div>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <div className="text-slate-700">SPF: {scan.emailAnalysis.authHeaders.spf} · DKIM: {scan.emailAnalysis.authHeaders.dkim} · DMARC: {scan.emailAnalysis.authHeaders.dmarc}</div>
                  <div className="text-slate-500 font-sans mt-1">{scan.emailAnalysis.authHeaders.note}</div>
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
