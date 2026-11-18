import { useEffect, useState } from 'react';
import { FileDown, FileText } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { ScanRecord } from '../types/phishguard';
import { downloadScanPdfReport } from '../utils/pdfReport';

export function ReportsPage({ onSelectScan }: { onSelectScan: (id: string) => void }) {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listScans({ limit: 30, offset: 0 })
      .then((res) => setScans(res.items))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load reports.'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="h-64 rounded-xl bg-white border border-slate-200 animate-pulse" />;
  }

  if (error) {
    return (
      <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">{error}</div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-1">
        <h2 className="font-display text-lg font-semibold text-slate-900">
          Cybersecurity Investigation PDF Reports
        </h2>
        <p className="text-sm text-slate-600">
          Generate formal, audit-ready PDF threat investigation reports containing scan identifiers, SHA-256 digests, risk decomposition, ML results, DNS/TLS intelligence, and mitigation playbooks.
        </p>
      </div>

      {scans.length === 0 ? (
        <div className="p-10 rounded-xl bg-white border border-slate-200 text-center text-sm text-slate-500">
          No scan records available to export. Run a scan first.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="p-5 rounded-xl bg-white border border-slate-200 flex flex-col justify-between gap-4"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs font-mono text-cyan-700 font-semibold">
                    <FileText className="w-4 h-4" />
                    <span>{scan.id}</span>
                  </div>
                  <RiskBadge level={scan.riskLevel} score={scan.riskScore} />
                </div>
                <div className="font-mono text-xs text-slate-800 break-all line-clamp-2">
                  {scan.indicator}
                </div>
                <div className="text-xs text-slate-500">
                  {scan.threatCategory} · {new Date(scan.createdAt).toLocaleString()}
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => onSelectScan(scan.id)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50"
                >
                  Inspect
                </button>
                <button
                  type="button"
                  onClick={() => downloadScanPdfReport(scan)}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700"
                >
                  <FileDown className="w-3.5 h-3.5" />
                  <span>Download PDF</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
