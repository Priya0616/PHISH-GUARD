import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import type { DatabaseSync } from 'node:sqlite';
import { z } from 'zod';
import type { SystemConfigStatus, UserProfile } from '../src/types/phishguard.ts';
import {
  deleteScanById,
  getDb,
  getScanById,
  listAuditLogs,
  listScans,
  recordAuditLog,
  seedInitialAnalyst,
} from './database/db.ts';
import { queryExternalThreatIntel } from './intelligence/threatIntel.ts';
import { getMlInsights } from './ml/inference.ts';
import { createRateLimiter } from './security/rateLimit.ts';
import { safeParseUrl } from './security/ssrf.ts';
import {
  computeDashboardStats,
  ENGINE_VERSION,
  runDomainIntelScan,
  runEmailThreatScan,
  runUrlThreatScan,
  seedBaselineDemoScansIfEmpty,
} from './services/scanService.ts';

interface AuthRequest extends Request {
  user?: UserProfile;
}

function resolveJwtSecret(db: DatabaseSync): string {
  const configured = process.env.JWT_SECRET?.trim();
  if (configured && !configured.startsWith('CHANGE_ME')) {
    return configured;
  }
  db.exec('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);');
  const existing = db.prepare('SELECT value FROM app_settings WHERE key = ?').get('jwt_secret') as
    | { value: string }
    | undefined;
  if (existing?.value) return existing.value;
  const generated = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run('jwt_secret', generated);
  return generated;
}

function getClientIp(req: Request): string {
  return (
    (typeof req.headers['x-forwarded-for'] === 'string'
      ? req.headers['x-forwarded-for'].split(',')[0]?.trim()
      : undefined) ||
    req.ip ||
    '127.0.0.1'
  );
}

export async function createPhishGuardApp(options: {
  db?: DatabaseSync;
  skipDemoSeed?: boolean;
  rateLimitMaxPerMinute?: number;
} = {}) {
  const app = express();
  const db = options.db ?? getDb();
  const jwtSecret = resolveJwtSecret(db);
  const demoUser = seedInitialAnalyst(db);
  if (!options.skipDemoSeed) {
    await seedBaselineDemoScansIfEmpty(db, demoUser.id);
  }

  const maxPerMin = options.rateLimitMaxPerMinute ?? 60;

  // Defensive security headers & strict body size limit
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use(express.json({ limit: '256kb' }));

  // Handle malformed JSON payloads cleanly
  app.use((err: Error, _req: Request, res: Response, next: NextFunction) => {
    if (err instanceof SyntaxError && 'body' in err) {
      res.status(400).json({ error: 'Malformed JSON request payload.' });
      return;
    }
    next(err);
  });

  const apiRateLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: maxPerMin,
    keyPrefix: 'api',
  });

  const authRateLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: Math.min(maxPerMin, 25),
    keyPrefix: 'auth',
  });

  function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Authentication required. Provide a valid Bearer token.' });
      return;
    }
    const token = authHeader.slice(7).trim();
    try {
      const decoded = jwt.verify(token, jwtSecret) as unknown;
      if (!decoded || typeof decoded !== 'object' || !('sub' in decoded) || typeof decoded.sub !== 'number') {
        res.status(401).json({ error: 'Invalid authentication token payload.' });
        return;
      }
      const userRow = db
        .prepare('SELECT id, email, full_name, role, created_at FROM users WHERE id = ?')
        .get(decoded.sub) as
        | { id: number; email: string; full_name: string; role: 'analyst' | 'senior_analyst' | 'admin'; created_at: string }
        | undefined;

      if (!userRow) {
        res.status(401).json({ error: 'User session no longer exists.' });
        return;
      }

      req.user = {
        id: userRow.id,
        email: userRow.email,
        fullName: userRow.full_name,
        role: userRow.role,
        createdAt: userRow.created_at,
      };
      next();
    } catch {
      res.status(401).json({ error: 'Invalid or expired authentication token.' });
    }
  }

  // Health & OpenAPI documentation endpoints
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'PhishGuard API',
      engineVersion: ENGINE_VERSION,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/docs/openapi.json', (_req, res) => {
    res.json({
      openapi: '3.0.3',
      info: {
        title: 'PhishGuard Cyber Threat Intelligence API',
        version: '1.2.0',
        description: 'Defensive phishing detection, ML classification, domain/TLS intelligence, and risk scoring REST API.',
      },
      paths: {
        '/api/auth/login': { post: { summary: 'Authenticate SOC analyst and issue JWT' } },
        '/api/auth/register': { post: { summary: 'Register new analyst account' } },
        '/api/dashboard': { get: { summary: 'Retrieve live SQLite-backed SOC KPIs and trends' } },
        '/api/scans/url': { post: { summary: 'Analyze URL using heuristics, ML ensemble, DNS/TLS, and consent-gated intel' } },
        '/api/scans/email': { post: { summary: 'Analyze email content, headers, SPF/DKIM/DMARC, and NLP classification' } },
        '/api/scans/domain': { post: { summary: 'Run Domain, DNS, SSL/TLS, and RDAP intelligence check' } },
        '/api/scans': { get: { summary: 'List paginated and filtered scan history' } },
        '/api/scans/{id}': { get: { summary: 'Retrieve detailed investigation record' }, delete: { summary: 'Delete scan record' } },
        '/api/ml/insights': { get: { summary: 'Retrieve ML training dataset metrics, confusion matrices, and feature importances' } },
      },
    });
  });

  // Auth routes
  const loginSchema = z.object({
    username: z.string().min(1).max(160).optional(),
    email: z.string().min(1).max(160).optional(),
    password: z.string().min(4).max(128),
  });

  const registerSchema = z.object({
    username: z.string().min(2).max(60).optional(),
    email: z.string().email().max(160),
    password: z.string().min(6).max(128),
    fullName: z.string().min(2).max(100),
  });

  app.post('/api/auth/login', authRateLimiter, (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    const identifier = (parsed.success ? parsed.data.username ?? parsed.data.email ?? '' : '').toLowerCase().trim();
    if (!parsed.success || !identifier) {
      res.status(400).json({ error: 'Valid username and password are required.' });
      return;
    }

    const row = db
      .prepare('SELECT id, email, password_hash, full_name, role, created_at FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?')
      .get(identifier, identifier) as
      | {
          id: number;
          email: string;
          password_hash: string;
          full_name: string;
          role: 'analyst' | 'senior_analyst' | 'admin';
          created_at: string;
        }
      | undefined;

    if (!row || !bcrypt.compareSync(parsed.data.password, row.password_hash)) {
      recordAuditLog(db, {
        userId: row?.id ?? null,
        userEmail: identifier,
        action: 'AUTH_LOGIN_FAILED',
        target: identifier,
        ipAddress: getClientIp(req),
        status: 'blocked',
      });
      res.status(401).json({ error: 'Invalid username or password.' });
      return;
    }

    const user: UserProfile = {
      id: row.id,
      email: row.email,
      fullName: row.full_name,
      role: row.role,
      createdAt: row.created_at,
    };

    const token = jwt.sign({ sub: user.id, email: user.email, role: user.role }, jwtSecret, {
      expiresIn: '12h',
    });

    recordAuditLog(db, {
      userId: user.id,
      userEmail: user.email,
      action: 'AUTH_LOGIN',
      target: user.email,
      ipAddress: getClientIp(req),
      status: 'success',
    });

    res.json({ token, user });
  });

  app.post('/api/auth/register', authRateLimiter, (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Provide a valid email, full name, and password (6+ characters).' });
      return;
    }

    const email = parsed.data.email.toLowerCase().trim();
    const username = (parsed.data.username ?? email.split('@')[0]).toLowerCase().trim();
    const existing = db
      .prepare('SELECT id FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?')
      .get(email, username);
    if (existing) {
      res.status(409).json({ error: 'An account with this username or email already exists.' });
      return;
    }

    const hash = bcrypt.hashSync(parsed.data.password, 10);
    const now = new Date().toISOString();
    const info = db
      .prepare('INSERT INTO users (username, email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(username, email, hash, parsed.data.fullName.trim(), 'analyst', now);

    const user: UserProfile = {
      id: Number(info.lastInsertRowid),
      email,
      fullName: parsed.data.fullName.trim(),
      role: 'analyst',
      createdAt: now,
    };

    const token = jwt.sign({ sub: user.id, email: user.email, role: user.role }, jwtSecret, {
      expiresIn: '12h',
    });

    recordAuditLog(db, {
      userId: user.id,
      userEmail: user.email,
      action: 'AUTH_REGISTER',
      target: user.email,
      ipAddress: getClientIp(req),
      status: 'success',
    });

    res.status(201).json({ token, user });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthRequest, res) => {
    res.json({ user: req.user });
  });

  // Protected SOC API routes
  app.get('/api/dashboard', apiRateLimiter, requireAuth, (_req, res) => {
    const stats = computeDashboardStats(db);
    res.json(stats);
  });

  const urlScanSchema = z.object({
    url: z.string().min(1, 'URL cannot be empty.').max(2048, 'URL exceeds 2048 character limit.'),
    externalConsentGranted: z.boolean().optional().default(false),
    skipNetworkForTest: z.boolean().optional().default(false),
  });

  app.post('/api/scans/url', apiRateLimiter, requireAuth, async (req: AuthRequest, res) => {
    const parsed = urlScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid URL scan payload.' });
      return;
    }

    try {
      const scan = await runUrlThreatScan({
        db,
        userId: req.user!.id,
        rawUrl: parsed.data.url,
        externalConsentGranted: parsed.data.externalConsentGranted,
        skipNetworkForTest: parsed.data.skipNetworkForTest,
      });

      recordAuditLog(db, {
        userId: req.user!.id,
        userEmail: req.user!.email,
        action: 'SCAN_URL',
        target: scan.indicator,
        ipAddress: getClientIp(req),
        status: scan.domainIntel?.ssrfBlocked ? 'blocked' : 'success',
      });

      res.status(201).json(scan);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'URL scan failed.';
      res.status(400).json({ error: msg });
    }
  });

  const emailScanSchema = z.object({
    subject: z.string().min(1, 'Email subject is required.').max(500),
    body: z.string().min(1, 'Email body is required.').max(25000, 'Email body exceeds 25KB limit.'),
    sender: z.string().min(3, 'Sender address is required.').max(256),
    replyTo: z.string().max(256).optional(),
    headers: z.string().max(30000).optional(),
    skipNetworkForTest: z.boolean().optional().default(false),
  });

  app.post('/api/scans/email', apiRateLimiter, requireAuth, async (req: AuthRequest, res) => {
    const parsed = emailScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid email scan payload.' });
      return;
    }

    try {
      const scan = await runEmailThreatScan({
        db,
        userId: req.user!.id,
        ...parsed.data,
      });

      recordAuditLog(db, {
        userId: req.user!.id,
        userEmail: req.user!.email,
        action: 'SCAN_EMAIL',
        target: scan.indicator,
        ipAddress: getClientIp(req),
        status: 'success',
      });

      res.status(201).json(scan);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Email analysis failed.';
      res.status(400).json({ error: msg });
    }
  });

  const domainScanSchema = z.object({
    domain: z.string().min(1, 'Domain is required.').max(512),
  });

  app.post('/api/scans/domain', apiRateLimiter, requireAuth, async (req: AuthRequest, res) => {
    const parsed = domainScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.issues[0]?.message ?? 'Invalid domain payload.' });
      return;
    }

    try {
      const scan = await runDomainIntelScan({
        db,
        userId: req.user!.id,
        rawDomain: parsed.data.domain,
      });

      recordAuditLog(db, {
        userId: req.user!.id,
        userEmail: req.user!.email,
        action: 'SCAN_DOMAIN',
        target: scan.indicator,
        ipAddress: getClientIp(req),
        status: scan.domainIntel?.ssrfBlocked ? 'blocked' : 'success',
      });

      res.status(201).json(scan);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Domain scan failed.' });
    }
  });

  const threatIntelSchema = z.object({
    url: z.string().min(1).max(2048),
    consentGranted: z.boolean(),
  });

  app.post('/api/threat-intel/lookup', apiRateLimiter, requireAuth, async (req: AuthRequest, res) => {
    const parsed = threatIntelSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Valid URL and explicit consentGranted boolean are required.' });
      return;
    }

    const safeUrl = safeParseUrl(parsed.data.url);
    if (!safeUrl.valid) {
      res.status(400).json({ error: safeUrl.error ?? 'Invalid URL.' });
      return;
    }
    if (safeUrl.ssrfBlocked) {
      res.status(403).json({ error: safeUrl.ssrfReason ?? 'Internal/private targets cannot be queried.' });
      return;
    }
    if (!parsed.data.consentGranted) {
      res.status(400).json({
        error: 'Explicit user consent is required before submitting indicators to external threat intelligence services.',
      });
      return;
    }

    const results = await queryExternalThreatIntel(safeUrl.normalizedUrl, true);
    recordAuditLog(db, {
      userId: req.user!.id,
      userEmail: req.user!.email,
      action: 'EXTERNAL_THREAT_INTEL_LOOKUP',
      target: safeUrl.normalizedUrl,
      ipAddress: getClientIp(req),
      status: 'success',
    });
    res.json({ url: safeUrl.normalizedUrl, results });
  });

  app.get('/api/scans', apiRateLimiter, requireAuth, (req, res) => {
    const search = typeof req.query.search === 'string' ? req.query.search : '';
    const riskLevel = typeof req.query.riskLevel === 'string' ? req.query.riskLevel : 'ALL';
    const scanType = typeof req.query.scanType === 'string' ? req.query.scanType : 'ALL';
    const limit = typeof req.query.limit === 'string' ? Number(req.query.limit) : 15;
    const offset = typeof req.query.offset === 'string' ? Number(req.query.offset) : 0;

    const result = listScans(db, {
      search,
      riskLevel,
      scanType,
      limit: Number.isNaN(limit) ? 15 : limit,
      offset: Number.isNaN(offset) ? 0 : offset,
    });
    res.json(result);
  });

  app.delete('/api/scans/demo', apiRateLimiter, requireAuth, (req: AuthRequest, res) => {
    const result = db.prepare('DELETE FROM scans WHERE is_demo = 1').run();
    recordAuditLog(db, {
      userId: req.user!.id,
      userEmail: req.user!.email,
      action: 'CLEAR_SAMPLE_SCANS',
      target: `${result.changes} demo records`,
      ipAddress: getClientIp(req),
      status: 'success',
    });
    res.json({ deletedCount: Number(result.changes) });
  });

  app.get('/api/scans/:id', apiRateLimiter, requireAuth, (req, res) => {
    const id = String(req.params.id);
    const scan = getScanById(db, id);
    if (!scan) {
      res.status(404).json({ error: 'Scan record not found.' });
      return;
    }
    res.json(scan);
  });

  app.delete('/api/scans/:id', apiRateLimiter, requireAuth, (req: AuthRequest, res) => {
    const id = String(req.params.id);
    const deleted = deleteScanById(db, id);
    if (!deleted) {
      res.status(404).json({ error: 'Scan record not found.' });
      return;
    }
    recordAuditLog(db, {
      userId: req.user!.id,
      userEmail: req.user!.email,
      action: 'DELETE_SCAN',
      target: id,
      ipAddress: getClientIp(req),
      status: 'success',
    });
    res.json({ deleted: true, id });
  });

  app.get('/api/ml/insights', apiRateLimiter, requireAuth, (_req, res) => {
    res.json(getMlInsights());
  });

  app.get('/api/system/config', apiRateLimiter, requireAuth, (_req, res) => {
    const geminiKey = process.env.GEMINI_API_KEY?.trim();
    const config: SystemConfigStatus = {
      engineVersion: ENGINE_VERSION,
      geminiConfigured: Boolean(geminiKey && geminiKey !== 'MY_GEMINI_API_KEY'),
      googleSafeBrowsingConfigured: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim()),
      virusTotalConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY?.trim()),
      urlhausConfigured: Boolean(process.env.URLHAUS_AUTH_KEY?.trim()),
      rateLimitMaxPerMinute: maxPerMin,
      ssrfProtectionEnabled: true,
      databaseEngine: 'SQLite (WAL Mode, Parameterized Statements)',
    };
    const auditLogs = listAuditLogs(db, 30);
    res.json({ config, auditLogs });
  });

  return app;
}
