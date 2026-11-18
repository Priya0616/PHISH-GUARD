import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Search, Trash2 } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { ScanRecord } from '../types/phishguard';

const RISK_FILTERS = ['ALL', 'Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'];
const TYPE_FILTERS = ['ALL', 'url', 'email', 'domain'];

export function ScanHistoryPage({ onSelectScan }: { onSelectScan: (id: string) => void }) {
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [page, setPage] = useState(0);
  const pageSize = 10;

  const [items, setItems] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listScans({
        search,
        riskLevel: riskFilter,
        scanType: typeFilter,
        limit: pageSize,
        offset: page * pageSize,
      });
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, [search, riskFilter, typeFilter, page]);

  const handleDelete = async (id: string) => {
    try {
      await api.deleteScan(id);
      loadScans();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete scan.');
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-5">
      <div className="p-4 rounded-xl bg-white border border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search indicator, Scan ID, or threat category..."
            className="w-full pl-10 pr-4 py-2 text-xs rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-100 border border-slate-200">
            {TYPE_FILTERS.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => {
                  setTypeFilter(t);
                  setPage(0);
                }}
                className={`px-2.5 py-1 text-xs font-medium rounded-md uppercase transition-colors ${
                  typeFilter === t ? 'bg-white text-cyan-800 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setPage(0);
            }}
            aria-label="Filter by risk level"
            className="px-3 py-1.5 text-xs rounded-lg bg-white border border-slate-300 text-slate-800 focus:outline-none focus:border-cyan-600"
          >
            {RISK_FILTERS.map((rf) => (
              <option key={rf} value={rf}>
                {rf === 'ALL' ? 'All Risk Levels' : rf}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800">{error}</div>
      )}

      <div className="rounded-xl bg-white border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-sm text-slate-500">Loading persisted scan records...</div>
        ) : items.length === 0 ? (
          <div className="p-10 text-center text-sm text-slate-500">
            No matching scan records found. Adjust filters or submit a new indicator scan.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] font-medium text-slate-500 bg-slate-50">
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Indicator</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {items.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono text-cyan-700 whitespace-nowrap">
                      {scan.id}
                      {scan.isDemo && <span className="ml-2 text-[10px] text-slate-400 font-sans">Sample</span>}
                    </td>
                    <td className="py-3 px-4 uppercase font-mono text-slate-600 whitespace-nowrap">{scan.scanType}</td>
                    <td className="py-3 px-4 font-mono text-slate-900 max-w-xs truncate">{scan.indicator}</td>
                    <td className="py-3 px-4 text-slate-700 whitespace-nowrap">{scan.threatCategory}</td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <RiskBadge level={scan.riskLevel} score={scan.riskScore} />
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-500 whitespace-nowrap">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDelete(scan.id);
                        }}
                        aria-label={`Delete scan ${scan.id}`}
                        className="p-1.5 text-slate-400 hover:text-rose-600 rounded-md"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="px-4 py-3 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
          <span className="tabular-nums">
            Showing {items.length} of {total} scans
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 bg-white text-slate-700 disabled:opacity-40"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Previous</span>
            </button>
            <span className="font-mono tabular-nums text-slate-700">
              {page + 1} / {totalPages}
            </span>
            <button
              type="button"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 bg-white text-slate-700 disabled:opacity-40"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
