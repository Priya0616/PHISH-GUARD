import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import type {
  DnsRecordSet,
  DomainIntelligenceReport,
  RdapDomainInfo,
  SslCertificateInfo,
} from '../../src/types/phishguard.ts';
import { isPrivateOrReservedIp } from '../security/ssrf.ts';

const TWO_PART_PUBLIC_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx', 'co.in', 'workers.dev',
]);

export function extractRegistrableDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(clean)) return clean;
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (TWO_PART_PUBLIC_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return lastTwo;
}

async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function resolveDnsRecords(hostname: string): Promise<{
  available: boolean;
  error: string | null;
  records: DnsRecordSet;
}> {
  const empty: DnsRecordSet = { a: [], aaaa: [], mx: [], ns: [], txt: [] };
  if (net.isIP(hostname.replace(/^\[|\]$/g, ''))) {
    return { available: false, error: 'Host is an IP literal; DNS domain records do not apply.', records: empty };
  }

  try {
    const [aRes, aaaaRes, mxRes, nsRes, txtRes] = await withTimeout(
      Promise.allSettled([
        dns.resolve4(hostname),
        dns.resolve6(hostname),
        dns.resolveMx(hostname),
        dns.resolveNs(hostname),
        dns.resolveTxt(hostname),
      ]),
      3500,
      'DNS resolution'
    );

    const a = aRes.status === 'fulfilled' ? aRes.value : [];
    const aaaa = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
    const mx =
      mxRes.status === 'fulfilled'
        ? mxRes.value.map((m) => ({ exchange: m.exchange, priority: m.priority }))
        : [];
    const ns = nsRes.status === 'fulfilled' ? nsRes.value : [];
    const txt = txtRes.status === 'fulfilled' ? txtRes.value.map((chunks) => chunks.join('')) : [];

    const anyResolved = a.length > 0 || aaaa.length > 0 || mx.length > 0 || ns.length > 0 || txt.length > 0;
    if (!anyResolved) {
      const firstErr = [aRes, aaaaRes, nsRes].find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined;
      return {
        available: false,
        error: firstErr?.reason instanceof Error ? firstErr.reason.message : 'No DNS records found (NXDOMAIN or SERVFAIL).',
        records: empty,
      };
    }

    return {
      available: true,
      error: null,
      records: { a, aaaa, mx, ns, txt: txt.slice(0, 6) },
    };
  } catch (err) {
    return {
      available: false,
      error: err instanceof Error ? err.message : 'DNS resolution failed',
      records: empty,
    };
  }
}

async function inspectSslCertificate(hostname: string, resolvedIps: string[], port = 443): Promise<SslCertificateInfo> {
  const emptySsl: SslCertificateInfo = {
    available: false,
    valid: null,
    subject: null,
    issuer: null,
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    selfSigned: null,
    expired: null,
    fingerprintSha256: null,
    subjectAltNames: [],
    error: null,
  };

  // DNS rebinding guard: verify all resolved IPs are public before opening TLS socket
  for (const ip of resolvedIps) {
    if (isPrivateOrReservedIp(ip)) {
      return {
        ...emptySsl,
        error: `TLS inspection aborted: hostname resolved to private/reserved IP (${ip}).`,
      };
    }
  }

  return new Promise<SslCertificateInfo>((resolve) => {
    let settled = false;
    const finish = (res: SslCertificateInfo) => {
      if (!settled) {
        settled = true;
        resolve(res);
      }
    };

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: net.isIP(hostname.replace(/^\[|\]$/g, '')) ? undefined : hostname,
        rejectUnauthorized: false, // Read certificate metadata safely without trusting chain blindly
        timeout: 3500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            finish({ ...emptySsl, error: 'Peer presented no TLS certificate.' });
            return;
          }

          const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
          const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
          const nowMs = Date.now();
          const expMs = validTo ? Date.parse(validTo) : NaN;
          const startMs = validFrom ? Date.parse(validFrom) : NaN;
          const daysRemaining = Number.isNaN(expMs) ? null : Math.floor((expMs - nowMs) / 86400000);
          const expired = Number.isNaN(expMs) ? null : expMs < nowMs || (!Number.isNaN(startMs) && startMs > nowMs);

          const subjectStr = cert.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(', ') : null;
          const issuerStr = cert.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(', ') : null;
          const selfSigned = Boolean(subjectStr && issuerStr && subjectStr === issuerStr);
          const sanList = typeof cert.subjectaltname === 'string'
            ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, '')).slice(0, 10)
            : [];

          const valid = socket.authorized && expired === false && !selfSigned;

          socket.destroy();
          finish({
            available: true,
            valid,
            subject: subjectStr,
            issuer: issuerStr,
            validFrom,
            validTo,
            daysRemaining,
            selfSigned,
            expired,
            fingerprintSha256: cert.fingerprint256 ?? null,
            subjectAltNames: sanList,
            error: socket.authorized ? null : String(socket.authorizationError ?? 'Certificate chain untrusted'),
          });
        } catch (err) {
          socket.destroy();
          finish({
            ...emptySsl,
            error: err instanceof Error ? err.message : 'Failed to parse TLS certificate',
          });
        }
      }
    );

    socket.setTimeout(3500, () => {
      socket.destroy();
      finish({ ...emptySsl, error: 'TLS handshake timed out after 3500ms.' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      finish({ ...emptySsl, error: err.message || 'TLS connection failed.' });
    });
  });
}

async function fetchRdapInfo(registrableDomain: string): Promise<RdapDomainInfo> {
  const emptyRdap: RdapDomainInfo = {
    available: false,
    registrar: null,
    createdAt: null,
    updatedAt: null,
    expiresAt: null,
    domainAgeDays: null,
    status: [],
    error: null,
  };

  if (net.isIP(registrableDomain.replace(/^\[|\]$/g, ''))) {
    return { ...emptyRdap, error: 'RDAP domain registration lookup skipped for IP literal.' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`, {
      signal: controller.signal,
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        ...emptyRdap,
        error: `RDAP registry returned HTTP ${res.status} (unavailable or unsupported TLD).`,
      };
    }

    const data = (await res.json()) as {
      status?: string[];
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: [string, Array<[string, Record<string, unknown>, string, string]>] }>;
    };

    const events = Array.isArray(data.events) ? data.events : [];
    const createdRaw = events.find((e) => e.eventAction === 'registration')?.eventDate ?? null;
    const updatedRaw = events.find((e) => e.eventAction === 'last changed')?.eventDate ?? null;
    const expiresRaw = events.find((e) => e.eventAction === 'expiration')?.eventDate ?? null;

    let domainAgeDays: number | null = null;
    if (createdRaw) {
      const createdMs = Date.parse(createdRaw);
      if (!Number.isNaN(createdMs)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - createdMs) / 86400000));
      }
    }

    let registrar: string | null = null;
    if (Array.isArray(data.entities)) {
      const regEntity = data.entities.find((ent) => ent.roles?.includes('registrar'));
      const fnField = regEntity?.vcardArray?.[1]?.find((item) => item[0] === 'fn');
      if (fnField && typeof fnField[3] === 'string') {
        registrar = fnField[3];
      }
    }

    return {
      available: true,
      registrar,
      createdAt: createdRaw,
      updatedAt: updatedRaw,
      expiresAt: expiresRaw,
      domainAgeDays,
      status: Array.isArray(data.status) ? data.status.slice(0, 6) : [],
      error: null,
    };
  } catch (err) {
    return {
      ...emptyRdap,
      error: err instanceof Error ? err.message : 'RDAP lookup unavailable',
    };
  }
}

export async function gatherDomainIntelligence(options: {
  hostname: string;
  ssrfBlocked: boolean;
  ssrfReason: string | null;
  port?: number | null;
}): Promise<DomainIntelligenceReport> {
  const retrievedAt = new Date().toISOString();
  const domain = options.hostname.toLowerCase();
  const registrableDomain = extractRegistrableDomain(domain);

  if (options.ssrfBlocked) {
    return {
      domain,
      registrableDomain,
      retrievedAt,
      ssrfBlocked: true,
      ssrfReason: options.ssrfReason,
      dnsAvailable: false,
      dnsError: 'Blocked by SSRF defense.',
      dnsRecords: { a: [], aaaa: [], mx: [], ns: [], txt: [] },
      ssl: {
        available: false,
        valid: null,
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        selfSigned: null,
        expired: null,
        fingerprintSha256: null,
        subjectAltNames: [],
        error: 'Blocked by SSRF defense.',
      },
      rdap: {
        available: false,
        registrar: null,
        createdAt: null,
        updatedAt: null,
        expiresAt: null,
        domainAgeDays: null,
        status: [],
        error: 'Blocked by SSRF defense.',
      },
    };
  }

  const dnsResult = await resolveDnsRecords(domain);
  const resolvedIps = [...dnsResult.records.a, ...dnsResult.records.aaaa];

  // Re-verify resolved IPs against private/reserved ranges (DNS rebinding mitigation)
  const rebindingIp = resolvedIps.find((ip) => isPrivateOrReservedIp(ip));
  if (rebindingIp) {
    return {
      domain,
      registrableDomain,
      retrievedAt,
      ssrfBlocked: true,
      ssrfReason: `DNS rebinding protection triggered: "${domain}" resolved to private/reserved IP ${rebindingIp}.`,
      dnsAvailable: dnsResult.available,
      dnsError: dnsResult.error,
      dnsRecords: dnsResult.records,
      ssl: {
        available: false,
        valid: null,
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        selfSigned: null,
        expired: null,
        fingerprintSha256: null,
        subjectAltNames: [],
        error: `Aborted TLS probe due to private IP resolution (${rebindingIp}).`,
      },
      rdap: {
        available: false,
        registrar: null,
        createdAt: null,
        updatedAt: null,
        expiresAt: null,
        domainAgeDays: null,
        status: [],
        error: 'Skipped due to private IP resolution.',
      },
    };
  }

  const [sslInfo, rdapInfo] = await Promise.all([
    inspectSslCertificate(domain, resolvedIps, options.port && options.port !== 80 ? options.port : 443),
    fetchRdapInfo(registrableDomain),
  ]);

  return {
    domain,
    registrableDomain,
    retrievedAt,
    ssrfBlocked: false,
    ssrfReason: null,
    dnsAvailable: dnsResult.available,
    dnsError: dnsResult.error,
    dnsRecords: dnsResult.records,
    ssl: sslInfo,
    rdap: rdapInfo,
  };
}
