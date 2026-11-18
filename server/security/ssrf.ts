import crypto from 'node:crypto';
import net from 'node:net';

/**
 * Checks whether an IPv4 or IPv6 address belongs to a private, loopback,
 * link-local, multicast, or cloud metadata range (SSRF & DNS rebinding defense).
 */
export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().replace(/^\[|\]$/g, '').split('%')[0];
  const version = net.isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8 current network
    if (a === 10) return true; // 10.0.0.0/8 RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local & AWS/GCP metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
    if (a >= 224) return true; // multicast & reserved
    return false;
  }

  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIp(lower.slice(7));
    }
    if (lower.startsWith('fe80:') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
      return true; // link-local fe80::/10
    }
    if (lower.startsWith('fc') || lower.startsWith('fd')) {
      return true; // unique local fc00::/7
    }
    if (lower.startsWith('ff')) {
      return true; // multicast ff00::/8
    }
    return false;
  }

  return false;
}

export interface SafeParsedUrl {
  valid: boolean;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  port: number | null;
  ssrfBlocked: boolean;
  ssrfReason: string | null;
  error: string | null;
}

export function safeParseUrl(rawInput: string): SafeParsedUrl {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      valid: false,
      normalizedUrl: '',
      protocol: '',
      hostname: '',
      port: null,
      ssrfBlocked: false,
      ssrfReason: null,
      error: 'URL input cannot be empty.',
    };
  }

  if (trimmed.length > 2048) {
    return {
      valid: false,
      normalizedUrl: trimmed.slice(0, 2048),
      protocol: '',
      hostname: '',
      port: null,
      ssrfBlocked: false,
      ssrfReason: null,
      error: 'URL exceeds maximum permitted length of 2048 characters.',
    };
  }

  // Reject dangerous non-web schemes immediately
  const lower = trimmed.toLowerCase();
  if (/^(javascript|data|vbscript|file|ftp|gopher):/.test(lower)) {
    return {
      valid: false,
      normalizedUrl: trimmed,
      protocol: lower.split(':')[0] + ':',
      hostname: '',
      port: null,
      ssrfBlocked: true,
      ssrfReason: 'Non-HTTP(S) scheme rejected by defensive parser.',
      error: 'Only http:// and https:// URLs are supported for threat scanning.',
    };
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      normalizedUrl: trimmed,
      protocol: '',
      hostname: '',
      port: null,
      ssrfBlocked: false,
      ssrfReason: null,
      error: 'Malformed URL syntax. Provide a valid domain or HTTP/HTTPS URL.',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname.length > 253) {
    return {
      valid: false,
      normalizedUrl: candidate,
      protocol: parsed.protocol,
      hostname,
      port: null,
      ssrfBlocked: false,
      ssrfReason: null,
      error: 'URL does not contain a valid hostname.',
    };
  }

  const blockedHostnames = new Set([
    'localhost',
    'localhost.localdomain',
    'metadata.google.internal',
    'metadata',
    'internal',
  ]);

  let ssrfBlocked = false;
  let ssrfReason: string | null = null;

  if (blockedHostnames.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    ssrfBlocked = true;
    ssrfReason = `Internal or metadata hostname "${hostname}" is blocked from backend network probes (SSRF defense).`;
  } else if (net.isIP(hostname.replace(/^\[|\]$/g, '')) && isPrivateOrReservedIp(hostname)) {
    ssrfBlocked = true;
    ssrfReason = `Private/loopback/reserved IP "${hostname}" is blocked from backend network probes (SSRF defense).`;
  }

  const portNum = parsed.port ? Number(parsed.port) : null;

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    protocol: parsed.protocol,
    hostname,
    port: portNum && !Number.isNaN(portNum) ? portNum : null,
    ssrfBlocked,
    ssrfReason,
    error: null,
  };
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}
