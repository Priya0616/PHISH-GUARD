import type {
  AuditLogEntry,
  DashboardStats,
  MlInsightsPayload,
  ScanRecord,
  SystemConfigStatus,
  ThreatIntelProviderResult,
  UserProfile,
} from '../types/phishguard';

const TOKEN_STORAGE_KEY = 'phishguard_jwt_token';

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
  else localStorage.removeItem(TOKEN_STORAGE_KEY);
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!res.ok) {
    const errMsg =
      data && typeof data === 'object' && 'error' in data && typeof (data as { error: unknown }).error === 'string'
        ? (data as { error: string }).error
        : `Request failed with HTTP ${res.status}`;
    throw new Error(errMsg);
  }

  return data as T;
}

export const api = {
  login(username: string, password: string) {
    return apiRequest<{ token: string; user: UserProfile }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },
  register(email: string, password: string, fullName: string, username?: string) {
    return apiRequest<{ token: string; user: UserProfile }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, fullName, username }),
    });
  },
  me() {
    return apiRequest<{ user: UserProfile }>('/api/auth/me');
  },
  getDashboard() {
    return apiRequest<DashboardStats>('/api/dashboard');
  },
  scanUrl(url: string, externalConsentGranted: boolean) {
    return apiRequest<ScanRecord>('/api/scans/url', {
      method: 'POST',
      body: JSON.stringify({ url, externalConsentGranted }),
    });
  },
  scanEmail(payload: {
    subject: string;
    body: string;
    sender: string;
    replyTo?: string;
    headers?: string;
  }) {
    return apiRequest<ScanRecord>('/api/scans/email', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },
  scanDomain(domain: string) {
    return apiRequest<ScanRecord>('/api/scans/domain', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
  },
  lookupThreatIntel(url: string, consentGranted: boolean) {
    return apiRequest<{ url: string; results: ThreatIntelProviderResult[] }>('/api/threat-intel/lookup', {
      method: 'POST',
      body: JSON.stringify({ url, consentGranted }),
    });
  },
  listScans(params: { search?: string; riskLevel?: string; scanType?: string; limit?: number; offset?: number }) {
    const qs = new URLSearchParams();
    if (params.search) qs.set('search', params.search);
    if (params.riskLevel) qs.set('riskLevel', params.riskLevel);
    if (params.scanType) qs.set('scanType', params.scanType);
    if (params.limit !== undefined) qs.set('limit', String(params.limit));
    if (params.offset !== undefined) qs.set('offset', String(params.offset));
    return apiRequest<{ items: ScanRecord[]; total: number }>(`/api/scans?${qs.toString()}`);
  },
  getScan(id: string) {
    return apiRequest<ScanRecord>(`/api/scans/${encodeURIComponent(id)}`);
  },
  deleteScan(id: string) {
    return apiRequest<{ deleted: boolean; id: string }>(`/api/scans/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },
  clearDemoScans() {
    return apiRequest<{ deletedCount: number }>('/api/scans/demo', { method: 'DELETE' });
  },
  getMlInsights() {
    return apiRequest<MlInsightsPayload>('/api/ml/insights');
  },
  getSystemConfig() {
    return apiRequest<{ config: SystemConfigStatus; auditLogs: AuditLogEntry[] }>('/api/system/config');
  },
};
