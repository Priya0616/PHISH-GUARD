import net from 'node:net';
import type { EvidenceItem, UrlFeatureSummary } from '../../src/types/phishguard.ts';

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy',
  'ow.ly', 'shorturl.at', 'rebrand.ly', 'v.gd', 'goo.gl', 'buff.ly', 't.ly',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'click', 'buzz', 'info', 'ru', 'site', 'gq', 'work',
]);

const PROTECTED_BRANDS = [
  'paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'google', 'facebook',
  'linkedin', 'chase', 'wellsfargo', 'bankofamerica', 'okta', 'dhl', 'fedex',
  'stripe', 'github', 'dropbox', 'slack', 'zoom', 'citibank', 'barclays', 'hsbc',
  'americanexpress', 'capitalone', 'instagram', 'whatsapp', 'discord', 'steam',
  'coinbase', 'metamask', 'binance', 'docusign', 'adobe',
];

const URL_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'auth',
  'banking', 'wallet', 'seed', 'unlock', 'suspend', 'billing', 'password', 'token',
  'invoice', 'payroll', 'refund', 'claim', 'credential', 'otp', 'pin', 'ssn', 'mfa',
];

const SUSPICIOUS_QUERY_KEYS = new Set([
  'redirect', 'redirect_uri', 'next', 'url', 'target', 'return', 'return_to',
  'continue', 'dest', 'destination', 'token', 'session', 'auth', 'verify', 'cmd',
]);

function shannonEntropy(str: string): number {
  if (!str) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  let ent = 0;
  for (const key of Object.keys(freq)) {
    const p = freq[key] / str.length;
    ent -= p * Math.log2(p);
  }
  return Number(ent.toFixed(3));
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function hasMixedScriptsOrUnicode(host: string): boolean {
  if (host.includes('xn--')) return true;
  return /[^\x00-\x7F]/.test(host);
}

export interface UrlHeuristicAnalysisResult {
  features: UrlFeatureSummary;
  mlFeatureVector: number[];
  heuristicScore: number; // 0-100
  threatCategory: string;
  evidence: EvidenceItem[];
}

export function analyzeUrlHeuristics(normalizedUrl: string): UrlHeuristicAnalysisResult {
  const parsed = new URL(normalizedUrl);
  const host = parsed.hostname.toLowerCase();
  const bareIpHost = host.replace(/^\[|\]$/g, '');
  const isIpHost = net.isIP(bareIpHost) !== 0;
  const labels = host.split('.').filter(Boolean);
  const tld = labels.length > 0 ? labels[labels.length - 1] : '';
  const subdomainDepth = isIpHost ? 0 : Math.max(0, labels.length - 2);
  const dotCount = (host.match(/\./g) ?? []).length;
  const digits = (normalizedUrl.match(/\d/g) ?? []).length;
  const specials = (normalizedUrl.match(/[-_@?=&#%~+]/g) ?? []).length;
  const digitRatio = Number((digits / Math.max(1, normalizedUrl.length)).toFixed(4));
  const specialCharRatio = Number((specials / Math.max(1, normalizedUrl.length)).toFixed(4));
  const entropy = shannonEntropy(normalizedUrl);
  const isNonHttps = parsed.protocol !== 'https:';
  const isShortener = URL_SHORTENERS.has(host);
  const hasSuspiciousTld = !isIpHost && SUSPICIOUS_TLDS.has(tld);
  const hasAtSymbol = Boolean(parsed.username || parsed.password || normalizedUrl.includes('@'));
  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const hasDoubleSlashPath =
    parsed.pathname.includes('//') ||
    pathAndQuery.includes('http%3a') ||
    pathAndQuery.includes('https%3a') ||
    pathAndQuery.includes('http://') ||
    pathAndQuery.includes('https://');
  const hasPunycodeOrUnicode = hasMixedScriptsOrUnicode(host);

  const portNum = parsed.port ? Number(parsed.port) : null;
  const unusualPort = portNum && portNum !== 80 && portNum !== 443 ? portNum : null;

  const lowerFull = normalizedUrl.toLowerCase();
  const suspiciousKeywords = URL_KEYWORDS.filter((kw) => lowerFull.includes(kw));

  const suspiciousQueryParams: string[] = [];
  for (const [k, v] of parsed.searchParams.entries()) {
    const lk = k.toLowerCase();
    const lv = v.toLowerCase();
    if (SUSPICIOUS_QUERY_KEYS.has(lk) || lv.startsWith('http://') || lv.startsWith('https://')) {
      suspiciousQueryParams.push(`${k}=${v.slice(0, 48)}`);
    }
  }

  const encodedSegmentCount = (normalizedUrl.match(/%[0-9a-fA-F]{2}/g) ?? []).length;

  // Brand impersonation & typosquatting detection
  let brandImpersonationTarget: string | null = null;
  let typosquattingDistance: number | null = null;
  let brandScore = 0;

  const normalizedHostForTypo = host
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/rn/g, 'm');

  const hostTokens = normalizedHostForTypo.split(/[.-]/).filter(Boolean);
  const registrable = labels.length >= 2 ? labels[labels.length - 2] : host;

  for (const brand of PROTECTED_BRANDS) {
    const isOfficial =
      host === `${brand}.com` ||
      host.endsWith(`.${brand}.com`) ||
      host === `${brand}.org` ||
      host.endsWith(`.${brand}.org`) ||
      (brand === 'microsoft' && (host.endsWith('.microsoftonline.com') || host.endsWith('.azure.com'))) ||
      (brand === 'amazon' && host.endsWith('.amazonaws.com'));

    if (isOfficial) continue;

    if (host.includes(brand) || normalizedHostForTypo.includes(brand)) {
      brandImpersonationTarget = brand;
      typosquattingDistance = host.includes(brand) ? 0 : 1;
      brandScore = 1.0;
      break;
    }

    for (const tok of hostTokens) {
      if (tok.length >= 4 && Math.abs(tok.length - brand.length) <= 2) {
        const dist = levenshtein(tok, brand);
        if (dist > 0 && dist <= 2) {
          brandImpersonationTarget = brand;
          typosquattingDistance = dist;
          brandScore = dist === 1 ? 0.9 : 0.65;
          break;
        }
      }
    }
    if (brandImpersonationTarget) break;

    if (registrable.includes(brand.slice(0, 5)) && levenshtein(registrable, brand) <= 3) {
      brandImpersonationTarget = brand;
      typosquattingDistance = levenshtein(registrable, brand);
      brandScore = 0.7;
      break;
    }
  }

  // Build non-overlapping heuristic evidence & score (avoids double-counting correlated length/subdomain signals)
  const evidence: EvidenceItem[] = [];
  let score = 0;

  if (isIpHost) {
    score += 32;
    evidence.push({
      id: 'url-ip-host',
      category: 'confirmed',
      source: 'URL Structural Analyzer',
      title: 'Direct IP Address Used as Hostname',
      detail: `URL targets raw IP literal (${bareIpHost}) instead of a registered domain name, a common evasion technique for credential harvesting kits.`,
      severity: 'high',
      weightContribution: 32,
    });
  }

  if (hasAtSymbol) {
    score += 28;
    evidence.push({
      id: 'url-at-userinfo',
      category: 'confirmed',
      source: 'URL Structural Analyzer',
      title: 'Userinfo (@) Host Obfuscation Detected',
      detail: 'URL contains "@" authority syntax, which browsers resolve to the domain after "@" while visually misleading users with the prefix.',
      severity: 'critical',
      weightContribution: 28,
    });
  }

  if (hasPunycodeOrUnicode) {
    score += 24;
    evidence.push({
      id: 'url-idn-homograph',
      category: 'suspicious',
      source: 'IDN / Homograph Inspector',
      title: 'Punycode / Non-ASCII Domain Characters',
      detail: `Hostname "${host}" uses Punycode (xn--) or non-ASCII characters, which may indicate an IDN homograph attack spoofing a trusted brand.`,
      severity: 'high',
      weightContribution: 24,
    });
  }

  if (brandImpersonationTarget) {
    const pts = typosquattingDistance === 0 ? 28 : 24;
    score += pts;
    evidence.push({
      id: 'url-brand-impersonation',
      category: 'suspicious',
      source: 'Brand & Typosquatting Engine',
      title: `Potential Brand Impersonation (${brandImpersonationTarget})`,
      detail:
        typosquattingDistance === 0
          ? `Non-canonical hostname "${host}" embeds protected brand keyword "${brandImpersonationTarget}".`
          : `Hostname token closely resembles "${brandImpersonationTarget}" (normalized edit distance: ${typosquattingDistance}).`,
      severity: 'high',
      weightContribution: pts,
    });
  }

  if (subdomainDepth >= 3) {
    const pts = subdomainDepth >= 4 ? 18 : 12;
    score += pts;
    evidence.push({
      id: 'url-excessive-subdomains',
      category: 'suspicious',
      source: 'URL Structural Analyzer',
      title: `Excessive Subdomain Depth (${subdomainDepth} levels)`,
      detail: `Hostname "${host}" chains ${subdomainDepth} subdomain labels, often used to push deceptive brand names to the left of the true registrable domain.`,
      severity: 'medium',
      weightContribution: pts,
    });
  }

  if (isShortener) {
    score += 18;
    evidence.push({
      id: 'url-shortener',
      category: 'suspicious',
      source: 'URL Structural Analyzer',
      title: `URL Shortening Service Detected (${host})`,
      detail: 'Shortened links conceal the final destination host from the recipient prior to click. PhishGuard never automatically follows redirects.',
      severity: 'medium',
      weightContribution: 18,
    });
  }

  if (hasDoubleSlashPath || suspiciousQueryParams.length > 0) {
    const pts = hasDoubleSlashPath ? 18 : 12;
    score += pts;
    evidence.push({
      id: 'url-redirect-param',
      category: 'suspicious',
      source: 'URL Query & Path Inspector',
      title: hasDoubleSlashPath ? 'Embedded Redirect / Double-Slash Path' : 'Sensitive or Redirect Query Parameters',
      detail: hasDoubleSlashPath
        ? 'Path or query contains an embedded secondary URL or "//" redirect pattern.'
        : `Detected sensitive/redirect query parameters: ${suspiciousQueryParams.slice(0, 3).join(', ')}.`,
      severity: 'medium',
      weightContribution: pts,
    });
  }

  if (unusualPort) {
    score += 14;
    evidence.push({
      id: 'url-unusual-port',
      category: 'confirmed',
      source: 'URL Structural Analyzer',
      title: `Non-Standard Web Port (${unusualPort})`,
      detail: `Service specifies port ${unusualPort} instead of standard 80/443, atypical for legitimate enterprise authentication portals.`,
      severity: 'medium',
      weightContribution: 14,
    });
  }

  if (hasSuspiciousTld) {
    score += 10;
    evidence.push({
      id: 'url-suspicious-tld',
      category: 'suspicious',
      source: 'Domain Pattern Analyzer',
      title: `High-Abuse Top-Level Domain (.${tld})`,
      detail: `TLD ".${tld}" exhibits elevated abuse prevalence in phishing feeds; evaluated alongside host structure rather than in isolation.`,
      severity: 'low',
      weightContribution: 10,
    });
  }

  if (isNonHttps) {
    score += 10;
    evidence.push({
      id: 'url-non-https',
      category: 'confirmed',
      source: 'Transport Security Check',
      title: 'Plaintext HTTP Scheme (No TLS)',
      detail: 'URL uses unencrypted http:// transport rather than https://, exposing submitted credentials or session data to interception.',
      severity: 'medium',
      weightContribution: 10,
    });
  }

  if (encodedSegmentCount >= 6) {
    score += 14;
    evidence.push({
      id: 'url-encoding-obfuscation',
      category: 'suspicious',
      source: 'URL Lexical Inspector',
      title: `Heavy Percent-Encoding Obfuscation (${encodedSegmentCount} sequences)`,
      detail: 'Excessive hex percent-encoding in hostname/path may be attempting to evade static keyword blocklists.',
      severity: 'medium',
      weightContribution: 14,
    });
  }

  if (normalizedUrl.length >= 90) {
    score += 10;
    evidence.push({
      id: 'url-excessive-length',
      category: 'suspicious',
      source: 'URL Lexical Inspector',
      title: `Long URL Structure (${normalizedUrl.length} chars)`,
      detail: 'Extended URL path/query length can obscure the root domain in mobile browsers and email clients.',
      severity: 'low',
      weightContribution: 10,
    });
  }

  if (suspiciousKeywords.length >= 2) {
    const pts = Math.min(18, suspiciousKeywords.length * 5);
    score += pts;
    evidence.push({
      id: 'url-credential-keywords',
      category: 'suspicious',
      source: 'Lexical Keyword Scanner',
      title: `Phishing-Lure Tokens in URL (${suspiciousKeywords.slice(0, 5).join(', ')})`,
      detail: `Found ${suspiciousKeywords.length} credential/account-action tokens inside the URL string.`,
      severity: 'medium',
      weightContribution: pts,
    });
  }

  if (evidence.length === 0) {
    evidence.push({
      id: 'url-clean-structure',
      category: 'confirmed',
      source: 'URL Structural Analyzer',
      title: 'Standard HTTPS Structure With No Lexical Evasion Indicators',
      detail: `Hostname "${host}" uses standard HTTPS, clean ASCII characters, and zero suspicious obfuscation markers.`,
      severity: 'info',
      weightContribution: 0,
    });
  }

  // Categorize primary threat vector
  let threatCategory = 'Benign / Standard Web Resource';
  if (hasAtSymbol) threatCategory = 'Credential URL Obfuscation';
  else if (isIpHost) threatCategory = 'IP-Hosted Phishing Infrastructure';
  else if (hasPunycodeOrUnicode) threatCategory = 'IDN Homograph Spoofing';
  else if (brandImpersonationTarget) threatCategory = 'Brand Impersonation / Typosquatting';
  else if (isShortener) threatCategory = 'Obfuscated Redirect / URL Shortener';
  else if (hasDoubleSlashPath || suspiciousQueryParams.length > 0) threatCategory = 'Open Redirect / Parameter Abuse';
  else if (suspiciousKeywords.length >= 2 || score >= 30) threatCategory = 'Suspicious Credential Harvesting URL';

  const mlFeatureVector = [
    normalizedUrl.length,
    host.length,
    dotCount,
    subdomainDepth,
    digitRatio,
    specialCharRatio,
    entropy,
    isIpHost ? 1 : 0,
    isNonHttps ? 1 : 0,
    isShortener ? 1 : 0,
    hasSuspiciousTld ? 1 : 0,
    hasAtSymbol ? 1 : 0,
    hasDoubleSlashPath ? 1 : 0,
    hasPunycodeOrUnicode ? 1 : 0,
    suspiciousKeywords.length,
    brandScore,
  ];

  return {
    features: {
      urlLength: normalizedUrl.length,
      hostnameLength: host.length,
      dotCount,
      subdomainDepth,
      digitRatio,
      specialCharRatio,
      shannonEntropy: entropy,
      isIpHost,
      isNonHttps,
      isShortener,
      hasSuspiciousTld,
      hasAtSymbol,
      hasDoubleSlashPath,
      hasPunycodeOrUnicode,
      unusualPort,
      suspiciousKeywords,
      suspiciousQueryParams,
      brandImpersonationTarget,
      typosquattingDistance,
      encodedSegmentCount,
    },
    mlFeatureVector,
    heuristicScore: Math.min(100, score),
    threatCategory,
    evidence,
  };
}
