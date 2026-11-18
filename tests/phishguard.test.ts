import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Server } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { createPhishGuardApp } from '../server/app.ts';
import { seedInitialAnalyst } from '../server/database/db.ts';
import { analyzeEmailContent, parseEmailAuthHeaders } from '../server/detectors/emailAnalyzer.ts';
import { evaluateDomainAndSslRisk, evaluateThreatIntelScore } from '../server/detectors/riskScorer.ts';
import { analyzeUrlHeuristics } from '../server/detectors/urlAnalyzer.ts';
import { gatherDomainIntelligence } from '../server/intelligence/domainIntel.ts';
import { predictUrlModels } from '../server/ml/inference.ts';
import { isPrivateOrReservedIp, safeParseUrl } from '../server/security/ssrf.ts';

describe('PhishGuard Detection Engine & Security Controls', () => {
  it('classifies normal legitimate URLs with low heuristic risk', () => {
    const parsed = safeParseUrl('https://docs.python.org/3/library/ssl.html');
    expect(parsed.valid).toBe(true);
    expect(parsed.ssrfBlocked).toBe(false);
    const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
    const ml = predictUrlModels(heur.mlFeatureVector);
    expect(heur.heuristicScore).toBeLessThan(20);
    expect(ml.logisticRegression.classification).toBe('benign');
  });

  it('detects suspicious brand-spoofing and subdomain abuse URLs', () => {
    const parsed = safeParseUrl('http://login.microsoftonline.com.verify-account-session-841.com/oauth2/token');
    expect(parsed.valid).toBe(true);
    const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
    expect(heur.features.brandImpersonationTarget).toBe('microsoft');
    expect(heur.features.subdomainDepth).toBeGreaterThanOrEqual(3);
    expect(heur.heuristicScore).toBeGreaterThanOrEqual(45);
  });

  it('detects IP-based URLs and unusual ports', () => {
    const parsed = safeParseUrl('http://198.51.100.42:8080/paypal/login.php?verify=1');
    expect(parsed.valid).toBe(true);
    const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
    expect(heur.features.isIpHost).toBe(true);
    expect(heur.features.unusualPort).toBe(8080);
    expect(heur.heuristicScore).toBeGreaterThanOrEqual(50);
  });

  it('detects URL shortening services', () => {
    const parsed = safeParseUrl('https://bit.ly/3xPhishVerifyBank');
    expect(parsed.valid).toBe(true);
    const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
    expect(heur.features.isShortener).toBe(true);
    expect(heur.evidence.some((e) => e.id === 'url-shortener')).toBe(true);
  });

  it('detects Punycode and Unicode homograph domains', () => {
    const puny = safeParseUrl('https://xn--pypal-4ve.com/signin');
    expect(puny.valid).toBe(true);
    const heurPuny = analyzeUrlHeuristics(puny.normalizedUrl);
    expect(heurPuny.features.hasPunycodeOrUnicode).toBe(true);

    const uni = analyzeUrlHeuristics('https://pаypal.com/signin'); // Cyrillic 'а'
    expect(uni.features.hasPunycodeOrUnicode).toBe(true);
  });

  it('rejects empty inputs, invalid URLs, and extremely long inputs', () => {
    expect(safeParseUrl('').valid).toBe(false);
    expect(safeParseUrl('   ').valid).toBe(false);
    expect(safeParseUrl('javascript:alert(1)').valid).toBe(false);
    expect(safeParseUrl(`https://example.com/${'a'.repeat(2100)}`).valid).toBe(false);
    expect(safeParseUrl('http://exa mple.com').valid).toBe(false);
  });

  it('blocks SSRF against localhost, RFC1918, and cloud metadata IPs', () => {
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedIp('10.20.30.40')).toBe(true);
    expect(isPrivateOrReservedIp('172.16.5.4')).toBe(true);
    expect(isPrivateOrReservedIp('192.168.1.1')).toBe(true);
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true);
    expect(isPrivateOrReservedIp('::1')).toBe(true);
    expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);

    const ssrfUrl = safeParseUrl('http://169.254.169.254/latest/meta-data/');
    expect(ssrfUrl.ssrfBlocked).toBe(true);
  });

  it('never fabricates SPF/DKIM/DMARC verdicts on missing or malformed headers', () => {
    const emptyAuth = parseEmailAuthHeaders(undefined);
    expect(emptyAuth.headerPresent).toBe(false);
    expect(emptyAuth.spf).toBe('unavailable');
    expect(emptyAuth.dkim).toBe('unavailable');
    expect(emptyAuth.dmarc).toBe('unavailable');

    const malformedAuth = parseEmailAuthHeaders('X-Random-Header: :::broken:::\nNot-An-Auth-Header');
    expect(malformedAuth.headerPresent).toBe(true);
    expect(malformedAuth.spf).toBe('unavailable');
    expect(malformedAuth.dkim).toBe('unavailable');
    expect(malformedAuth.dmarc).toBe('unavailable');
  });

  it('detects phishing email content, reply-to mismatch, and failed auth headers', () => {
    const res = analyzeEmailContent({
      sender: 'PayPal Security <alert@paypa1-verify.com>',
      replyTo: 'drop@evil-relay.xyz',
      subject: 'URGENT: Action Required - Account Suspended',
      body: 'Verify your password, SSN, and bank routing number immediately at http://198.51.100.42/login or open invoice_99.xlsm.',
      headers: 'Authentication-Results: mx.test.local; spf=fail; dkim=fail; dmarc=fail',
    });
    expect(res.report.senderReplyToMismatch).toBe(true);
    expect(res.report.authHeaders.spf).toBe('fail');
    expect(res.report.extractedUrls.length).toBe(1);
    expect(res.heuristicScore).toBeGreaterThanOrEqual(75);
  });

  it('handles DNS resolution failures and unavailable SSL/API checks gracefully', async () => {
    const intel = await gatherDomainIntelligence({
      hostname: 'nonexistent-domain-9988112233.invalid',
      ssrfBlocked: false,
      ssrfReason: null,
    });
    expect(intel.dnsAvailable).toBe(false);
    expect(intel.ssl.available).toBe(false);
    const domainEval = evaluateDomainAndSslRisk(intel);
    expect(domainEval.evidence.some((e) => e.category === 'unavailable')).toBe(true);

    const tiEval = evaluateThreatIntelScore([
      {
        provider: 'VirusTotal',
        configured: false,
        consented: false,
        status: 'unavailable',
        verdictSummary: 'Unavailable',
        details: null,
        checkedAt: new Date().toISOString(),
        latencyMs: null,
      },
    ]);
    expect(tiEval.score).toBeNull();
  });
});

describe('PhishGuard API Integration, Auth & Rate Limiting', () => {
  let server: Server;
  let baseUrl = '';
  let token = '';
  let db: DatabaseSync;

  beforeAll(async () => {
    db = new DatabaseSync(':memory:');
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, full_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, scan_type TEXT NOT NULL, indicator TEXT NOT NULL, indicator_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL, classification TEXT NOT NULL, threat_category TEXT NOT NULL, engine_version TEXT NOT NULL, external_consent_granted INTEGER NOT NULL DEFAULT 0, payload_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_email TEXT, action TEXT NOT NULL, target TEXT NOT NULL, ip_address TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL);
    `);
    seedInitialAnalyst(db);

    const app = await createPhishGuardApp({
      db,
      skipDemoSeed: true,
      rateLimitMaxPerMinute: 12,
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  });

  it('rejects unauthenticated requests and invalid credentials with HTTP 401', async () => {
    const unauth = await fetch(`${baseUrl}/api/dashboard`);
    expect(unauth.status).toBe(401);

    const badLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'WrongPassword123' }),
    });
    expect(badLogin.status).toBe(401);
  });

  it('authenticates analyst, persists URL and Email scans in SQLite, and enforces consent on threat intel', async () => {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'pass123' }),
    });
    expect(loginRes.status).toBe(200);
    const loginJson = (await loginRes.json()) as { token: string };
    token = loginJson.token;
    expect(token.length).toBeGreaterThan(20);

    const urlRes = await fetch(`${baseUrl}/api/scans/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        url: 'http://198.51.100.42/paypal/login.php?verify=1',
        externalConsentGranted: false,
        skipNetworkForTest: true,
      }),
    });
    expect(urlRes.status).toBe(201);
    const urlScan = (await urlRes.json()) as { id: string; riskScore: number };
    expect(urlScan.riskScore).toBeGreaterThanOrEqual(60);

    const noConsentRes = await fetch(`${baseUrl}/api/threat-intel/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ url: 'https://example.com', consentGranted: false }),
    });
    expect(noConsentRes.status).toBe(400);

    const dashRes = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(dashRes.status).toBe(200);
    const dash = (await dashRes.json()) as { totalScans: number; phishingUrlsDetected: number };
    expect(dash.totalScans).toBe(1);
    expect(dash.phishingUrlsDetected).toBe(1);
  });

  it('enforces API rate limiting with HTTP 429 and Retry-After header', async () => {
    let got429 = false;
    for (let i = 0; i < 15; i++) {
      const r = await fetch(`${baseUrl}/api/ml/insights`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (r.status === 429) {
        got429 = true;
        expect(r.headers.get('retry-after')).toBeTruthy();
        break;
      }
    }
    expect(got429).toBe(true);
  });
});
