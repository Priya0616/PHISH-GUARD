import type { ThreatIntelProviderResult } from '../../src/types/phishguard.ts';

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs = 4000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryGoogleSafeBrowsing(targetUrl: string): Promise<ThreatIntelProviderResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  const checkedAt = new Date().toISOString();
  if (!apiKey) {
    return {
      provider: 'Google Safe Browsing',
      configured: false,
      consented: true,
      status: 'unavailable',
      verdictSummary: 'Unavailable: GOOGLE_SAFE_BROWSING_API_KEY is not configured in server environment.',
      details: null,
      checkedAt,
      latencyMs: null,
    };
  }

  const start = Date.now();
  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'phishguard-soc', clientVersion: '1.2.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: targetUrl }],
          },
        }),
      }
    );
    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        provider: 'Google Safe Browsing',
        configured: true,
        consented: true,
        status: 'rate_limited',
        verdictSummary: 'Rate limited by Google Safe Browsing API (HTTP 429).',
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    if (!res.ok) {
      return {
        provider: 'Google Safe Browsing',
        configured: true,
        consented: true,
        status: 'error',
        verdictSummary: `Safe Browsing API error (HTTP ${res.status}).`,
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    const data = (await res.json()) as { matches?: Array<{ threatType?: string; platformType?: string }> };
    const matches = data.matches ?? [];
    if (matches.length > 0) {
      return {
        provider: 'Google Safe Browsing',
        configured: true,
        consented: true,
        status: 'malicious',
        verdictSummary: `Flagged by Google Safe Browsing (${matches.map((m) => m.threatType).join(', ')}).`,
        details: { matches },
        checkedAt,
        latencyMs,
      };
    }

    return {
      provider: 'Google Safe Browsing',
      configured: true,
      consented: true,
      status: 'clean',
      verdictSummary: 'No matches found in Google Safe Browsing lists.',
      details: { matches: [] },
      checkedAt,
      latencyMs,
    };
  } catch (err) {
    return {
      provider: 'Google Safe Browsing',
      configured: true,
      consented: true,
      status: 'error',
      verdictSummary: err instanceof Error ? `Safe Browsing request failed: ${err.message}` : 'Safe Browsing request failed.',
      details: null,
      checkedAt,
      latencyMs: Date.now() - start,
    };
  }
}

async function queryVirusTotal(targetUrl: string): Promise<ThreatIntelProviderResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  const checkedAt = new Date().toISOString();
  if (!apiKey) {
    return {
      provider: 'VirusTotal',
      configured: false,
      consented: true,
      status: 'unavailable',
      verdictSummary: 'Unavailable: VIRUSTOTAL_API_KEY is not configured in server environment.',
      details: null,
      checkedAt,
      latencyMs: null,
    };
  }

  const start = Date.now();
  try {
    const urlId = Buffer.from(targetUrl).toString('base64url');
    const res = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: { 'x-apikey': apiKey },
    });
    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        provider: 'VirusTotal',
        configured: true,
        consented: true,
        status: 'rate_limited',
        verdictSummary: 'VirusTotal API quota/rate limit reached (HTTP 429).',
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    if (res.status === 404) {
      return {
        provider: 'VirusTotal',
        configured: true,
        consented: true,
        status: 'unavailable',
        verdictSummary: 'URL not yet indexed in VirusTotal database (no active scan submitted).',
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    if (!res.ok) {
      return {
        provider: 'VirusTotal',
        configured: true,
        consented: true,
        status: 'error',
        verdictSummary: `VirusTotal API error (HTTP ${res.status}).`,
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    const payload = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number>; reputation?: number } };
    };
    const stats = payload.data?.attributes?.last_analysis_stats ?? {};
    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;

    return {
      provider: 'VirusTotal',
      configured: true,
      consented: true,
      status: malicious >= 2 ? 'malicious' : malicious === 1 || suspicious >= 2 ? 'suspicious' : 'clean',
      verdictSummary: `VirusTotal vendors: ${malicious} malicious, ${suspicious} suspicious, ${stats.harmless ?? 0} harmless.`,
      details: { stats, reputation: payload.data?.attributes?.reputation ?? null },
      checkedAt,
      latencyMs,
    };
  } catch (err) {
    return {
      provider: 'VirusTotal',
      configured: true,
      consented: true,
      status: 'error',
      verdictSummary: err instanceof Error ? `VirusTotal request failed: ${err.message}` : 'VirusTotal request failed.',
      details: null,
      checkedAt,
      latencyMs: Date.now() - start,
    };
  }
}

async function queryUrlhaus(targetUrl: string): Promise<ThreatIntelProviderResult> {
  const checkedAt = new Date().toISOString();
  const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
  const start = Date.now();
  try {
    const form = new URLSearchParams({ url: targetUrl });
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (authKey) headers['Auth-Key'] = authKey;

    const res = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers,
      body: form.toString(),
    });
    const latencyMs = Date.now() - start;

    if (res.status === 429) {
      return {
        provider: 'URLhaus',
        configured: Boolean(authKey),
        consented: true,
        status: 'rate_limited',
        verdictSummary: 'URLhaus API rate limited (HTTP 429).',
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    if (res.status === 401 || res.status === 403) {
      return {
        provider: 'URLhaus',
        configured: Boolean(authKey),
        consented: true,
        status: 'unavailable',
        verdictSummary: 'URLhaus lookup requires a valid URLHAUS_AUTH_KEY in server environment.',
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    if (!res.ok) {
      return {
        provider: 'URLhaus',
        configured: Boolean(authKey),
        consented: true,
        status: 'error',
        verdictSummary: `URLhaus returned HTTP ${res.status}.`,
        details: null,
        checkedAt,
        latencyMs,
      };
    }

    const data = (await res.json()) as { query_status?: string; threat?: string; url_status?: string; tags?: string[] };
    if (data.query_status === 'ok') {
      return {
        provider: 'URLhaus',
        configured: true,
        consented: true,
        status: 'malicious',
        verdictSummary: `Listed in abuse.ch URLhaus (${data.threat ?? 'malware'}, status: ${data.url_status ?? 'unknown'}).`,
        details: { threat: data.threat, urlStatus: data.url_status, tags: data.tags ?? [] },
        checkedAt,
        latencyMs,
      };
    }

    return {
      provider: 'URLhaus',
      configured: true,
      consented: true,
      status: 'clean',
      verdictSummary: 'Not listed in abuse.ch URLhaus malware feed.',
      details: { queryStatus: data.query_status ?? 'no_results' },
      checkedAt,
      latencyMs,
    };
  } catch (err) {
    return {
      provider: 'URLhaus',
      configured: Boolean(authKey),
      consented: true,
      status: 'error',
      verdictSummary: err instanceof Error ? `URLhaus lookup failed: ${err.message}` : 'URLhaus lookup failed.',
      details: null,
      checkedAt,
      latencyMs: Date.now() - start,
    };
  }
}

export async function queryExternalThreatIntel(
  targetUrl: string,
  consentGranted: boolean
): Promise<ThreatIntelProviderResult[]> {
  const checkedAt = new Date().toISOString();
  const gsbConfigured = Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim());
  const vtConfigured = Boolean(process.env.VIRUSTOTAL_API_KEY?.trim());
  const uhConfigured = Boolean(process.env.URLHAUS_AUTH_KEY?.trim());

  if (!consentGranted) {
    return [
      {
        provider: 'Google Safe Browsing',
        configured: gsbConfigured,
        consented: false,
        status: 'skipped_no_consent',
        verdictSummary: 'Skipped: User consent not granted to transmit indicator to external services.',
        details: null,
        checkedAt,
        latencyMs: null,
      },
      {
        provider: 'VirusTotal',
        configured: vtConfigured,
        consented: false,
        status: 'skipped_no_consent',
        verdictSummary: 'Skipped: User consent not granted to transmit indicator to external services.',
        details: null,
        checkedAt,
        latencyMs: null,
      },
      {
        provider: 'URLhaus',
        configured: uhConfigured,
        consented: false,
        status: 'skipped_no_consent',
        verdictSummary: 'Skipped: User consent not granted to transmit indicator to external services.',
        details: null,
        checkedAt,
        latencyMs: null,
      },
    ];
  }

  return Promise.all([
    queryGoogleSafeBrowsing(targetUrl),
    queryVirusTotal(targetUrl),
    queryUrlhaus(targetUrl),
  ]);
}
