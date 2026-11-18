import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';
import type { AuditLogEntry, ScanRecord, UserProfile } from '../../src/types/phishguard.ts';

let dbInstance: DatabaseSync | null = null;

export function getDb(customPath?: string): DatabaseSync {
  if (dbInstance && !customPath) return dbInstance;

  const dbPath =
    customPath ??
    process.env.PHISHGUARD_DB_PATH ??
    path.join(process.cwd(), 'data', 'phishguard.db');

  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      scan_type TEXT NOT NULL,
      indicator TEXT NOT NULL,
      indicator_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_demo INTEGER NOT NULL DEFAULT 0,
      risk_score INTEGER NOT NULL,
      risk_level TEXT NOT NULL,
      classification TEXT NOT NULL,
      threat_category TEXT NOT NULL,
      engine_version TEXT NOT NULL,
      external_consent_granted INTEGER NOT NULL DEFAULT 0,
      payload_json TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
    CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      user_email TEXT,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Ensure username column exists if migrating an older SQLite file
  const userCols = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
  if (!userCols.some((c) => c.name === 'username')) {
    db.exec('ALTER TABLE users ADD COLUMN username TEXT;');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);');
  }

  if (!customPath) {
    dbInstance = db;
  }
  return db;
}

export function closeDbForTests(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

export function seedInitialAnalyst(db: DatabaseSync): UserProfile {
  const existingAdmin = db
    .prepare('SELECT id, email, full_name, role, created_at FROM users WHERE username = ? OR email = ?')
    .get('admin', 'admin@phishguard.sec') as
    | { id: number; email: string; full_name: string; role: 'analyst' | 'senior_analyst' | 'admin'; created_at: string }
    | undefined;

  if (existingAdmin) {
    return {
      id: existingAdmin.id,
      email: existingAdmin.email,
      fullName: existingAdmin.full_name,
      role: existingAdmin.role,
      createdAt: existingAdmin.created_at,
    };
  }

  const hash = bcrypt.hashSync('pass123', 10);
  const now = new Date().toISOString();
  const info = db
    .prepare('INSERT INTO users (username, email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run('admin', 'admin@phishguard.sec', hash, 'SOC Administrator', 'admin', now);

  return {
    id: Number(info.lastInsertRowid),
    email: 'admin@phishguard.sec',
    fullName: 'SOC Administrator',
    role: 'admin',
    createdAt: now,
  };
}

export function insertScan(db: DatabaseSync, scan: ScanRecord): void {
  db.prepare(`
    INSERT INTO scans (
      id, user_id, scan_type, indicator, indicator_sha256, created_at, is_demo,
      risk_score, risk_level, classification, threat_category, engine_version,
      external_consent_granted, payload_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    scan.id,
    scan.userId,
    scan.scanType,
    scan.indicator,
    scan.indicatorSha256,
    scan.createdAt,
    scan.isDemo ? 1 : 0,
    scan.riskScore,
    scan.riskLevel,
    scan.classification,
    scan.threatCategory,
    scan.engineVersion,
    scan.externalConsentGranted ? 1 : 0,
    JSON.stringify(scan)
  );
}

export function getScanById(db: DatabaseSync, id: string): ScanRecord | null {
  const row = db.prepare('SELECT payload_json FROM scans WHERE id = ?').get(id) as
    | { payload_json: string }
    | undefined;
  if (!row) return null;
  return JSON.parse(row.payload_json) as ScanRecord;
}

export function listScans(
  db: DatabaseSync,
  opts: {
    search?: string;
    riskLevel?: string;
    scanType?: string;
    limit?: number;
    offset?: number;
  } = {}
): { items: ScanRecord[]; total: number } {
  const clauses: string[] = [];
  const params: Array<string | number> = [];

  if (opts.search && opts.search.trim()) {
    clauses.push('(indicator LIKE ? OR threat_category LIKE ? OR id LIKE ?)');
    const q = `%${opts.search.trim()}%`;
    params.push(q, q, q);
  }
  if (opts.riskLevel && opts.riskLevel !== 'ALL') {
    clauses.push('risk_level = ?');
    params.push(opts.riskLevel);
  }
  if (opts.scanType && opts.scanType !== 'ALL') {
    clauses.push('scan_type = ?');
    params.push(opts.scanType);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const countRow = db
    .prepare(`SELECT COUNT(*) AS cnt FROM scans ${whereSql}`)
    .get(...params) as { cnt: number };

  const limit = Math.min(100, Math.max(1, opts.limit ?? 20));
  const offset = Math.max(0, opts.offset ?? 0);

  const rows = db
    .prepare(`SELECT payload_json FROM scans ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...params, limit, offset) as Array<{ payload_json: string }>;

  return {
    items: rows.map((r) => JSON.parse(r.payload_json) as ScanRecord),
    total: countRow.cnt,
  };
}

export function deleteScanById(db: DatabaseSync, id: string): boolean {
  const result = db.prepare('DELETE FROM scans WHERE id = ?').run(id);
  return Number(result.changes) > 0;
}

export function recordAuditLog(
  db: DatabaseSync,
  entry: Omit<AuditLogEntry, 'id' | 'createdAt'>
): void {
  db.prepare(
    'INSERT INTO audit_logs (user_id, user_email, action, target, ip_address, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(
    entry.userId,
    entry.userEmail,
    entry.action,
    entry.target.slice(0, 240),
    entry.ipAddress,
    entry.status,
    new Date().toISOString()
  );
}

export function listAuditLogs(db: DatabaseSync, limit = 50): AuditLogEntry[] {
  const rows = db
    .prepare(
      'SELECT id, user_id, user_email, action, target, ip_address, status, created_at FROM audit_logs ORDER BY id DESC LIMIT ?'
    )
    .all(limit) as Array<{
    id: number;
    user_id: number | null;
    user_email: string | null;
    action: string;
    target: string;
    ip_address: string;
    status: 'success' | 'blocked' | 'error';
    created_at: string;
  }>;

  return rows.map((r) => ({
    id: r.id,
    userId: r.user_id,
    userEmail: r.user_email,
    action: r.action,
    target: r.target,
    ipAddress: r.ip_address,
    status: r.status,
    createdAt: r.created_at,
  }));
}
