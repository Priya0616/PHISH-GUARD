import { useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  AlertOctagon,
  ArrowRight,
  Link2,
  Mail,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import type { NavPage } from '../components/Sidebar';
import { api } from '../services/api';
import type { DashboardStats, SystemConfigStatus } from '../types/phishguard';

const RISK_COLORS: Record<string, string> = {
  'Low Risk': '#16A34A',
  'Medium Risk': '#D97706',
  'High Risk': '#EA580C',
  'Critical Risk': '#DC2626',
};

export function DashboardPage({
  onSelectScan,
  onNavigate,
}: {
  onSelectScan: (scanId: string) => void;
  onNavigate: (page: NavPage) => void;
}) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [config, setConfig] = useState<SystemConfigStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [clearingDemo, setClearingDemo] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dash, sys] = await Promise.all([api.getDashboard(), api.getSystemConfig()]);
      setStats(dash);
      setConfig(sys.config);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load SOC dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleClearDemo = async () => {
    setClearingDemo(true);
    try {
      await api.clearDemoScans();
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear sample baseline records.');
    } finally {
      setClearingDemo(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-28 rounded-xl bg-white border border-slate-200 animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-72 rounded-xl bg-white border border-slate-200 animate-pulse" />
          <div className="h-72 rounded-xl bg-white border border-slate-200 animate-pulse" />
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="p-6 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800 flex items-center justify-between gap-4">
        <span>{error ?? 'Dashboard telemetry unavailable.'}</span>
        <button
          type="button"
          onClick={loadData}
          className="px-4 py-2 rounded-lg bg-white border border-slate-300 text-xs font-medium text-slate-900 hover:bg-slate-50"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {stats.demoCount > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 rounded-xl bg-white border border-cyan-200 text-xs text-slate-700">
          <span>
            Dashboard metrics reflect {stats.totalScans} persisted SQLite records, including{' '}
            <strong className="text-cyan-700 font-semibold">{stats.demoCount} clearly labeled sample baseline scans</strong>{' '}
            for initial evaluation.
          </span>
          <button
            type="button"
            onClick={handleClearDemo}
            disabled={clearingDemo}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-700 hover:text-rose-700 hover:border-rose-300 transition-colors whitespace-nowrap"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>{clearingDemo ? 'Clearing...' : 'Clear Sample Baselines'}</span>
          </button>
        </div>
      )}

      {/* 5 Core SOC KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Total URLs Analyzed</span>
            <Link2 className="w-4 h-4 text-cyan-600" />
          </div>
          <div className="font-display text-2xl font-bold text-slate-900 tabular-nums">
            {stats.totalUrlsAnalyzed}
          </div>
          <div className="text-xs text-slate-500">Across {stats.totalScans} total stored scans</div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Phishing URLs Detected</span>
            <ShieldAlert className="w-4 h-4 text-orange-600" />
          </div>
          <div className="font-display text-2xl font-bold text-orange-700 tabular-nums">
            {stats.phishingUrlsDetected}
          </div>
          <div className="text-xs text-slate-500">Score 60+ High or Critical Risk</div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Suspicious Emails</span>
            <Mail className="w-4 h-4 text-violet-600" />
          </div>
          <div className="font-display text-2xl font-bold text-violet-700 tabular-nums">
            {stats.suspiciousEmailsIdentified}
          </div>
          <div className="text-xs text-slate-500">NLP + Header + BEC signals</div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Critical Threats</span>
            <AlertOctagon className="w-4 h-4 text-rose-600" />
          </div>
          <div className="font-display text-2xl font-bold text-rose-700 tabular-nums">
            {stats.criticalThreats}
          </div>
          <div className="text-xs text-slate-500">Immediate containment tier (80–100)</div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Threat Detection Rate</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="font-display text-2xl font-bold text-cyan-700 tabular-nums">
            {stats.threatDetectionRate}%
          </div>
          <div className="text-xs text-slate-500">High/Critical share of stored scans</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                7-Day Threat Detection Trends
              </h2>
              <p className="text-xs text-slate-500">
                Daily High/Critical threats vs. benign/low-risk scans stored in SQLite
              </p>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.weeklyTrends} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="threatGradLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EA580C" stopOpacity={0.22} />
                    <stop offset="95%" stopColor="#EA580C" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="benignGradLight" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0891B2" stopOpacity={0.22} />
                    <stop offset="95%" stopColor="#0891B2" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} />
                <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #CBD5E1',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#0F172A',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="High/Critical Threats"
                  stroke="#EA580C"
                  fill="url(#threatGradLight)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="benign"
                  name="Low/Medium Scans"
                  stroke="#0891B2"
                  fill="url(#benignGradLight)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Risk Severity Breakdown
            </h2>
            <p className="text-xs text-slate-500">Distribution across PhishGuard risk tiers</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.riskBreakdown} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis dataKey="level" stroke="#64748B" fontSize={10} tickFormatter={(v) => String(v).replace(' Risk', '')} />
                <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #CBD5E1',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#0F172A',
                  }}
                />
                <Bar dataKey="count" name="Scans" radius={[6, 6, 0, 0]}>
                  {stats.riskBreakdown.map((entry) => (
                    <Cell key={entry.level} fill={RISK_COLORS[entry.level] ?? '#0891B2'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Threat Distribution & Detection Engine Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Threat Category Distribution
              </h2>
              <p className="text-xs text-slate-500">Primary attack vector classifications across persisted scans</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('scan-history')}
              className="inline-flex items-center gap-1 text-xs font-medium text-cyan-700 hover:text-cyan-800 whitespace-nowrap"
            >
              <span>View All History</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
          {stats.threatCategories.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-500">
              No scan data stored yet. Run a URL or Email scan to populate category telemetry.
            </div>
          ) : (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.threatCategories}
                  layout="vertical"
                  margin={{ top: 4, right: 16, left: 20, bottom: 4 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                  <XAxis type="number" stroke="#64748B" fontSize={11} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    width={175}
                    stroke="#475569"
                    fontSize={11}
                    tickFormatter={(v) => (String(v).length > 26 ? `${String(v).slice(0, 26)}…` : String(v))}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #CBD5E1',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#0F172A',
                    }}
                  />
                  <Bar dataKey="count" name="Incidents" fill="#7C3AED" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Detection Engine Status
            </h2>
            <p className="text-xs text-slate-500">Built-in detection &amp; network intelligence modules</p>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between py-2 border-b border-slate-100">
              <span className="text-slate-700">URL &amp; Email ML Ensemble</span>
              <span className="text-emerald-700 font-medium">Ready (v1.2.0)</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-100">
              <span className="text-slate-700">DNS / TLS / RDAP Inspector</span>
              <span className="text-emerald-700 font-medium">Active + SSRF Guard</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-100">
              <span className="text-slate-700">Local Explainable Assessment</span>
              <span className="text-emerald-700 font-medium">Active</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-100">
              <span className="text-slate-700">Gemini AI Narrative</span>
              <span className={config?.geminiConfigured ? 'text-emerald-700 font-medium' : 'text-slate-500'}>
                {config?.geminiConfigured ? 'Active' : 'Optional (Local Active)'}
              </span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-slate-100">
              <span className="text-slate-700">Google Safe Browsing</span>
              <span className={config?.googleSafeBrowsingConfigured ? 'text-emerald-700 font-medium' : 'text-slate-500'}>
                {config?.googleSafeBrowsingConfigured ? 'Configured' : 'Optional Feed'}
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-slate-700">VirusTotal / URLhaus</span>
              <span className={config?.virusTotalConfigured || config?.urlhausConfigured ? 'text-emerald-700 font-medium' : 'text-slate-500'}>
                {config?.virusTotalConfigured || config?.urlhausConfigured ? 'Configured' : 'Optional Feed'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Security Scans Table */}
      <div className="rounded-xl bg-white border border-slate-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">Recent Security Scans</h2>
            <p className="text-xs text-slate-500">Select any scan row to launch the full Threat Investigation view</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onNavigate('url-scanner')}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              Scan URL
            </button>
            <button
              type="button"
              onClick={() => onNavigate('email-analyzer')}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              Analyze Email
            </button>
          </div>
        </div>

        {stats.recentScans.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm text-slate-500">No security scans recorded yet.</p>
            <button
              type="button"
              onClick={() => onNavigate('url-scanner')}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700"
            >
              Run First URL Scan
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] font-medium text-slate-500 bg-slate-50">
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Indicator</th>
                  <th className="py-3 px-4">Threat Category</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {stats.recentScans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono text-cyan-700 whitespace-nowrap">
                      {scan.id}
                      {scan.isDemo && (
                        <span className="ml-2 text-[10px] text-slate-400 font-sans">Sample</span>
                      )}
                    </td>
                    <td className="py-3 px-4 uppercase font-mono text-slate-600 whitespace-nowrap">
                      {scan.scanType}
                    </td>
                    <td className="py-3 px-4 text-slate-800 max-w-xs truncate font-mono">
                      {scan.indicator}
                    </td>
                    <td className="py-3 px-4 text-slate-700 whitespace-nowrap">
                      {scan.threatCategory}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <RiskBadge level={scan.riskLevel} score={scan.riskScore} />
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-slate-500 whitespace-nowrap">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
