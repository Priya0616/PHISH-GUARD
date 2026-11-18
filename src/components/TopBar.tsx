import { Menu, Plus } from 'lucide-react';
import type { NavPage } from './Sidebar';

const PAGE_LABELS: Record<NavPage, string> = {
  dashboard: 'Security Overview',
  'url-scanner': 'URL Threat Scanner',
  'email-analyzer': 'Email Phishing Analyzer',
  'domain-intel': 'Domain Intelligence',
  'threat-intel': 'Threat Intelligence',
  'ml-insights': 'Machine Learning Insights',
  'scan-history': 'Scan History',
  investigation: 'Threat Investigation',
  reports: 'Security Reports',
  settings: 'Security & Engine Status',
  about: 'About PhishGuard',
};

export function TopBar({
  activePage,
  onOpenMobileMenu,
  onQuickScan,
}: {
  activePage: NavPage;
  onOpenMobileMenu: () => void;
  onQuickScan: () => void;
}) {
  return (
    <header className="h-16 px-4 sm:px-6 lg:px-8 border-b border-slate-200 bg-white/95 backdrop-blur-sm sticky top-0 z-30 flex items-center justify-between gap-4">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 text-slate-600 hover:text-slate-900 rounded-lg border border-slate-200 bg-slate-50"
        >
          <Menu className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2 text-sm min-w-0">
          <span className="text-slate-400 hidden sm:inline whitespace-nowrap">PhishGuard SOC</span>
          <span className="text-slate-300 hidden sm:inline" aria-hidden="true">
            /
          </span>
          <h1 className="font-display font-semibold text-slate-900 truncate">
            {PAGE_LABELS[activePage]}
          </h1>
        </div>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <button
          type="button"
          onClick={onQuickScan}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 transition-colors whitespace-nowrap shrink-0"
        >
          <Plus className="w-4 h-4 shrink-0" />
          <span>New URL Scan</span>
        </button>
      </div>
    </header>
  );
}
