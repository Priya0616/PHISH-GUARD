import {
  Activity,
  BrainCircuit,
  FileText,
  Globe,
  History,
  Info,
  Link2,
  LogOut,
  Mail,
  Radar,
  SearchCode,
  Settings,
  Shield,
  X,
} from 'lucide-react';
import type { UserProfile } from '../types/phishguard';

export type NavPage =
  | 'dashboard'
  | 'url-scanner'
  | 'email-analyzer'
  | 'domain-intel'
  | 'threat-intel'
  | 'ml-insights'
  | 'scan-history'
  | 'investigation'
  | 'reports'
  | 'settings'
  | 'about';

interface SidebarProps {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  user: UserProfile;
  onLogout: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

const NAV_GROUPS: Array<{
  title: string;
  items: Array<{ id: NavPage; label: string; icon: typeof Shield }>;
}> = [
  {
    title: 'Operations',
    items: [
      { id: 'dashboard', label: 'Security Overview', icon: Activity },
      { id: 'url-scanner', label: 'URL Threat Scanner', icon: Link2 },
      { id: 'email-analyzer', label: 'Email Phishing Analyzer', icon: Mail },
      { id: 'domain-intel', label: 'Domain Intelligence', icon: Globe },
      { id: 'threat-intel', label: 'Threat Intelligence', icon: Radar },
    ],
  },
  {
    title: 'Analytics & Investigation',
    items: [
      { id: 'ml-insights', label: 'Machine Learning Insights', icon: BrainCircuit },
      { id: 'scan-history', label: 'Scan History', icon: History },
      { id: 'investigation', label: 'Threat Investigation', icon: SearchCode },
      { id: 'reports', label: 'Security Reports', icon: FileText },
    ],
  },
  {
    title: 'Platform',
    items: [
      { id: 'settings', label: 'Security & Engine Status', icon: Settings },
      { id: 'about', label: 'About PhishGuard', icon: Info },
    ],
  },
];

export function Sidebar({
  activePage,
  onNavigate,
  user,
  onLogout,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const navContent = (
    <div className="flex flex-col h-full bg-white border-r border-slate-200 w-64 shrink-0">
      <div className="flex items-center justify-between px-5 h-16 border-b border-slate-200">
        <button
          type="button"
          onClick={() => {
            onNavigate('dashboard');
            onCloseMobile();
          }}
          className="flex items-center gap-2.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-600 rounded-md"
        >
          <div className="w-8 h-8 rounded-lg bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-700 shrink-0">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap">
            PhishGuard
          </span>
        </button>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation menu"
          className="lg:hidden p-1.5 text-slate-500 hover:text-slate-900 rounded-md"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {NAV_GROUPS.map((group) => (
          <div key={group.title}>
            <div className="px-3 mb-2 text-xs font-medium text-slate-400">{group.title}</div>
            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      onNavigate(item.id);
                      onCloseMobile();
                    }}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${
                      active
                        ? 'bg-cyan-50 text-cyan-800 border border-cyan-200'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-transparent'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-cyan-700' : 'text-slate-500'}`} />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="p-3 border-t border-slate-200">
        <div className="flex items-center gap-3 px-2.5 py-2 rounded-lg bg-slate-50 border border-slate-200">
          <img
            src="/src/assets/images/avatar_soc_analyst_1794998550509.jpg"
            alt={user.fullName}
            referrerPolicy="no-referrer"
            className="w-9 h-9 rounded-lg object-cover border border-slate-200 shrink-0"
          />
          <div className="min-w-0 flex-1">
            <div className="text-xs font-semibold text-slate-900 truncate">{user.fullName}</div>
            <div className="text-[11px] text-slate-500 truncate">{user.email}</div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            title="Sign out"
            aria-label="Sign out"
            className="p-1.5 text-slate-500 hover:text-rose-600 rounded-md transition-colors shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:flex h-screen sticky top-0">{navContent}</aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-slate-900/40" onClick={onCloseMobile} />
          <div className="relative z-10 h-full">{navContent}</div>
        </div>
      )}
    </>
  );
}
