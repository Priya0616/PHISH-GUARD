import { AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { RiskLevel } from '../types/phishguard';

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  const styles: Record<RiskLevel, string> = {
    'Low Risk': 'text-emerald-800 bg-emerald-50 border-emerald-200',
    'Medium Risk': 'text-amber-800 bg-amber-50 border-amber-200',
    'High Risk': 'text-orange-800 bg-orange-50 border-orange-200',
    'Critical Risk': 'text-rose-800 bg-rose-50 border-rose-200',
  };

  const Icon =
    level === 'Low Risk'
      ? ShieldCheck
      : level === 'Medium Risk'
      ? AlertTriangle
      : ShieldAlert;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border whitespace-nowrap shrink-0 tabular-nums ${styles[level]}`}
    >
      <Icon className="w-3.5 h-3.5 shrink-0" />
      <span>{level}</span>
      {score !== undefined && <span className="font-mono opacity-90">({score})</span>}
    </span>
  );
}

export function StatusIndicator({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-medium whitespace-nowrap shrink-0 ${
        ok ? 'text-emerald-700' : 'text-slate-500'
      }`}
    >
      {ok ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> : <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />}
      <span>{label}</span>
    </span>
  );
}
