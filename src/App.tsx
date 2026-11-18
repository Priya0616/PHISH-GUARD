import { useEffect, useState } from 'react';
import { Sidebar, type NavPage } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { AboutPage } from './pages/AboutPage';
import { DashboardPage } from './pages/DashboardPage';
import { DomainIntelPage } from './pages/DomainIntelPage';
import { EmailAnalyzerPage } from './pages/EmailAnalyzerPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { LoginPage } from './pages/LoginPage';
import { MlInsightsPage } from './pages/MlInsightsPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { SettingsPage } from './pages/SettingsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { UrlScannerPage } from './pages/UrlScannerPage';
import { api, getStoredToken, setStoredToken } from './services/api';
import type { UserProfile } from './types/phishguard';

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [activePage, setActivePage] = useState<NavPage>('dashboard');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setCheckingAuth(false);
      return;
    }
    api
      .me()
      .then((res) => setUser(res.user))
      .catch(() => {
        setStoredToken(null);
        setUser(null);
      })
      .finally(() => setCheckingAuth(false));
  }, []);

  const handleOpenInvestigation = (scanId: string) => {
    setSelectedScanId(scanId);
    setActivePage('investigation');
  };

  const handleLogout = () => {
    setStoredToken(null);
    setUser(null);
    setActivePage('dashboard');
  };

  if (checkingAuth) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center text-sm text-slate-600">
        Verifying SOC analyst session...
      </div>
    );
  }

  if (!user) {
    return <LoginPage onSuccess={(u) => setUser(u)} />;
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        user={user}
        onLogout={handleLogout}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          activePage={activePage}
          onOpenMobileMenu={() => setMobileOpen(true)}
          onQuickScan={() => setActivePage('url-scanner')}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1440px] w-full mx-auto">
          {activePage === 'dashboard' && (
            <DashboardPage
              onSelectScan={handleOpenInvestigation}
              onNavigate={setActivePage}
            />
          )}
          {activePage === 'url-scanner' && (
            <UrlScannerPage onOpenInvestigation={handleOpenInvestigation} />
          )}
          {activePage === 'email-analyzer' && (
            <EmailAnalyzerPage onOpenInvestigation={handleOpenInvestigation} />
          )}
          {activePage === 'domain-intel' && (
            <DomainIntelPage onOpenInvestigation={handleOpenInvestigation} />
          )}
          {activePage === 'threat-intel' && <ThreatIntelPage />}
          {activePage === 'ml-insights' && <MlInsightsPage />}
          {activePage === 'scan-history' && (
            <ScanHistoryPage onSelectScan={handleOpenInvestigation} />
          )}
          {activePage === 'investigation' && (
            <InvestigationPage
              scanId={selectedScanId}
              onSelectScan={setSelectedScanId}
            />
          )}
          {activePage === 'reports' && (
            <ReportsPage onSelectScan={handleOpenInvestigation} />
          )}
          {activePage === 'settings' && <SettingsPage />}
          {activePage === 'about' && <AboutPage />}
        </main>
      </div>
    </div>
  );
}
