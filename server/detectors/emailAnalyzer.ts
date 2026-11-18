import type {
  EmailAnalysisReport,
  EmailAuthHeaderResult,
  EvidenceItem,
} from '../../src/types/phishguard.ts';
import { predictEmailModel, predictUrlModels } from '../ml/inference.ts';
import { safeParseUrl } from '../security/ssrf.ts';
import { analyzeUrlHeuristics } from './urlAnalyzer.ts';
import { classifyRiskLevel } from './riskScorer.ts';

const URGENCY_PATTERNS = [
  'immediately', 'urgent', 'action required', 'within 24 hours', 'within 12 hours',
  'final warning', 'final notice', 'suspended', 'permanently closed', 'permanently deleted',
  'expires today', 'expires in', 'account locked', 'deactivated', 'limited', 'breach',
];

const CREDENTIAL_PATTERNS = [
  'password', 'verify your identity', 'sign in', 'log in', 're-enter', 'confirm your account',
  '2fa', 'mfa', 'otp', 'recovery phrase', 'seed phrase', 'ssn', 'social security',
  'pin', 'cvv', 'security questions', 'passcode', 'enable macros', 'enable content',
];

const FINANCIAL_PATTERNS = [
  'wire transfer', 'invoice', 'ach', 'gift card', 'bank account', 'routing number',
  'direct deposit', 'customs fee', 'redelivery fee', 'tax refund', 'rebate',
  'credit card', 'debit card', 'payment declined', 'unpaid', 'payout', 'e-transfer',
];

const ATTACHMENT_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jse', '.iso', '.img',
  '.xlsm', '.docm', '.pptm', '.html', '.htm', '.zip', '.rar', '.7z',
];

const PROTECTED_BRANDS = [
  'microsoft', 'paypal', 'apple', 'amazon', 'google', 'chase', 'bank of america',
  'wells fargo', 'dhl', 'fedex', 'usps', 'irs', 'hmrc', 'okta', 'docusign',
  'netflix', 'coinbase', 'metamask', 'binance', 'github', 'slack', 'zoom',
];

function extractEmailDomain(addr: string): string | null {
  const match = addr.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase() : null;
}

export function parseEmailAuthHeaders(rawHeaders: string | undefined): EmailAuthHeaderResult {
  if (!rawHeaders || !rawHeaders.trim()) {
    return {
      headerPresent: false,
      spf: 'unavailable',
      dkim: 'unavailable',
      dmarc: 'unavailable',
      rawAuthenticationResults: null,
      note: 'No raw RFC-5322 email headers provided; SPF, DKIM, and DMARC status cannot be verified and are marked unavailable.',
    };
  }

  const normalized = rawHeaders.replace(/\r?\n[ \t]+/g, ' ');
  const authMatch = normalized.match(/^Authentication-Results:\s*(.+)$/im);
  const spfHeaderMatch = normalized.match(/^Received-SPF:\s*(\w+)/im);
  const dkimSigPresent = /^DKIM-Signature:/im.test(normalized);

  const authLine = authMatch ? authMatch[1].trim() : null;

  const parseResult = (regex: RegExp): 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unavailable' => {
    if (!authLine) return 'unavailable';
    const m = authLine.match(regex);
    if (!m) return 'unavailable';
    const val = m[1].toLowerCase();
    if (val === 'pass' || val === 'fail' || val === 'softfail' || val === 'neutral' || val === 'none') {
      return val;
    }
    return 'unavailable';
  };

  let spf = parseResult(/\bspf=(pass|fail|softfail|neutral|none)\b/i);
  if (spf === 'unavailable' && spfHeaderMatch) {
    const val = spfHeaderMatch[1].toLowerCase();
    if (val === 'pass' || val === 'fail' || val === 'softfail' || val === 'neutral' || val === 'none') {
      spf = val;
    }
  }

  const dkimRaw = parseResult(/\bdkim=(pass|fail|none)\b/i);
  const dkim: EmailAuthHeaderResult['dkim'] =
    dkimRaw === 'pass' || dkimRaw === 'fail' || dkimRaw === 'none' ? dkimRaw : 'unavailable';

  const dmarcRaw = parseResult(/\bdmarc=(pass|fail|none)\b/i);
  const dmarc: EmailAuthHeaderResult['dmarc'] =
    dmarcRaw === 'pass' || dmarcRaw === 'fail' || dmarcRaw === 'none' ? dmarcRaw : 'unavailable';

  const hasAnyEvidence = spf !== 'unavailable' || dkim !== 'unavailable' || dmarc !== 'unavailable';

  return {
    headerPresent: true,
    spf,
    dkim,
    dmarc,
    rawAuthenticationResults: authLine ? authLine.slice(0, 400) : null,
    note: hasAnyEvidence
      ? 'Parsed directly from supplied Authentication-Results / Received-SPF headers.'
      : dkimSigPresent
      ? 'DKIM-Signature header is present, but no Authentication-Results verdict header was supplied to verify cryptographic signature status.'
      : 'Headers supplied, but no Authentication-Results or Received-SPF evidence found; authentication status remains unavailable.',
  };
}

export function analyzeEmailContent(input: {
  subject: string;
  body: string;
  sender: string;
  replyTo?: string;
  headers?: string;
}): {
  report: EmailAnalysisReport;
  heuristicScore: number;
  threatCategory: string;
  evidence: EvidenceItem[];
} {
  const combinedLower = `${input.subject}\n${input.body}`.toLowerCase();
  const senderDomain = extractEmailDomain(input.sender);
  const replyToText = (input.replyTo ?? '').trim();
  const replyToDomain = replyToText ? extractEmailDomain(replyToText) : null;
  const senderReplyToMismatch = Boolean(senderDomain && replyToDomain && senderDomain !== replyToDomain);

  // Display name brand impersonation check (e.g., "PayPal Support <attacker@gmail.com>")
  let displayNameImpersonation: string | null = null;
  const senderLower = input.sender.toLowerCase();
  for (const brand of PROTECTED_BRANDS) {
    const compactBrand = brand.replace(/\s+/g, '');
    if (senderLower.includes(brand) && senderDomain && !senderDomain.includes(compactBrand)) {
      displayNameImpersonation = brand;
      break;
    }
  }

  const urgencySignals = URGENCY_PATTERNS.filter((p) => combinedLower.includes(p));
  const credentialSignals = CREDENTIAL_PATTERNS.filter((p) => combinedLower.includes(p));
  const financialSignals = FINANCIAL_PATTERNS.filter((p) => combinedLower.includes(p));

  const suspiciousAttachmentMentions: string[] = [];
  for (const ext of ATTACHMENT_EXTENSIONS) {
    const regex = new RegExp(`[a-z0-9_.-]+\\${ext}\\b`, 'gi');
    const matches = combinedLower.match(regex);
    if (matches) {
      for (const m of matches) suspiciousAttachmentMentions.push(m);
    }
  }

  const socialEngineeringTactics: string[] = [];
  if (urgencySignals.length > 0) socialEngineeringTactics.push('Artificial Urgency / Fear Coercion');
  if (credentialSignals.length > 0) socialEngineeringTactics.push('Credential / Token Harvesting Lure');
  if (financialSignals.length > 0) socialEngineeringTactics.push('Financial / Wire / Payment Fraud Lure');
  if (combinedLower.includes('confidential') || combinedLower.includes('do not call')) {
    socialEngineeringTactics.push('Secrecy / Out-of-Band Bypass (BEC)');
  }
  if (suspiciousAttachmentMentions.length > 0) {
    socialEngineeringTactics.push('Risky Attachment / Macro Execution Pretext');
  }

  // Extract embedded URLs and analyze each safely (never fetch/open)
  const rawUrls = Array.from(new Set(input.body.match(/https?:\/\/[^\s<>"')]+/gi) ?? [])).slice(0, 8);
  const extractedUrls = rawUrls.map((raw) => {
    const parsed = safeParseUrl(raw);
    if (!parsed.valid) {
      return {
        url: raw,
        riskScore: 45,
        riskLevel: classifyRiskLevel(45),
        classification: 'Malformed Embedded URL',
      };
    }
    const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
    const ml = predictUrlModels(heur.mlFeatureVector);
    const combined = Math.min(
      100,
      Math.round(heur.heuristicScore * 0.6 + ml.ensembleProbability * 100 * 0.4)
    );
    return {
      url: parsed.normalizedUrl,
      riskScore: combined,
      riskLevel: classifyRiskLevel(combined),
      classification: combined >= 60 ? 'High-Risk Embedded Link' : combined >= 30 ? 'Suspicious Link' : 'Low-Risk Link',
    };
  });

  const authHeaders = parseEmailAuthHeaders(input.headers);
  const nlpModelPrediction = predictEmailModel(input.subject, input.body);

  // Build evidence items & score
  const evidence: EvidenceItem[] = [];
  let score = 0;

  if (senderReplyToMismatch) {
    score += 24;
    evidence.push({
      id: 'email-reply-to-mismatch',
      category: 'confirmed',
      source: 'Email Header Analyzer',
      title: 'Sender and Reply-To Domain Mismatch',
      detail: `From domain (${senderDomain}) differs from Reply-To domain (${replyToDomain}), a classic BEC and phishing redirection signal.`,
      severity: 'high',
      weightContribution: 24,
    });
  }

  if (displayNameImpersonation) {
    score += 26;
    evidence.push({
      id: 'email-brand-impersonation',
      category: 'suspicious',
      source: 'Sender Identity Analyzer',
      title: `Sender Display Name Impersonates "${displayNameImpersonation}"`,
      detail: `Sender claims affiliation with "${displayNameImpersonation}" while originating from domain "${senderDomain ?? 'unknown'}".`,
      severity: 'high',
      weightContribution: 26,
    });
  }

  if (authHeaders.spf === 'fail' || authHeaders.dkim === 'fail' || authHeaders.dmarc === 'fail') {
    score += 28;
    evidence.push({
      id: 'email-auth-fail',
      category: 'confirmed',
      source: 'Email Authentication Parser',
      title: 'Email Authentication Failure (SPF/DKIM/DMARC)',
      detail: `Header evidence indicates failure: SPF=${authHeaders.spf}, DKIM=${authHeaders.dkim}, DMARC=${authHeaders.dmarc}.`,
      severity: 'critical',
      weightContribution: 28,
    });
  } else if (!authHeaders.headerPresent || (authHeaders.spf === 'unavailable' && authHeaders.dkim === 'unavailable' && authHeaders.dmarc === 'unavailable')) {
    evidence.push({
      id: 'email-auth-unavailable',
      category: 'unavailable',
      source: 'Email Authentication Parser',
      title: 'SPF / DKIM / DMARC Evidence Unavailable',
      detail: authHeaders.note,
      severity: 'info',
      weightContribution: 0,
    });
  } else {
    evidence.push({
      id: 'email-auth-verified',
      category: 'confirmed',
      source: 'Email Authentication Parser',
      title: 'Email Authentication Header Evidence Present',
      detail: `Parsed headers: SPF=${authHeaders.spf}, DKIM=${authHeaders.dkim}, DMARC=${authHeaders.dmarc}.`,
      severity: 'info',
      weightContribution: 0,
    });
  }

  if (urgencySignals.length > 0) {
    const pts = Math.min(18, urgencySignals.length * 6);
    score += pts;
    evidence.push({
      id: 'email-urgency',
      category: 'suspicious',
      source: 'Social Engineering NLP',
      title: `Urgency & Coercion Phrases (${urgencySignals.slice(0, 4).join(', ')})`,
      detail: 'Message pressures the recipient with imminent deadlines or account termination.',
      severity: 'medium',
      weightContribution: pts,
    });
  }

  if (credentialSignals.length > 0) {
    const pts = Math.min(24, credentialSignals.length * 7);
    score += pts;
    evidence.push({
      id: 'email-credential-harvest',
      category: 'suspicious',
      source: 'Social Engineering NLP',
      title: `Credential / Sensitive Secret Request (${credentialSignals.slice(0, 4).join(', ')})`,
      detail: 'Email solicits login credentials, OTP/MFA codes, seed phrases, or identity numbers.',
      severity: 'high',
      weightContribution: pts,
    });
  }

  if (financialSignals.length > 0) {
    const pts = Math.min(22, financialSignals.length * 7);
    score += pts;
    evidence.push({
      id: 'email-financial-fraud',
      category: 'suspicious',
      source: 'Financial Fraud Detector',
      title: `Financial / Payment Lure (${financialSignals.slice(0, 4).join(', ')})`,
      detail: 'Contains wire transfer, invoice, banking update, or gift card purchase cues.',
      severity: 'high',
      weightContribution: pts,
    });
  }

  if (suspiciousAttachmentMentions.length > 0) {
    score += 22;
    evidence.push({
      id: 'email-attachment-lure',
      category: 'suspicious',
      source: 'Payload Pretext Scanner',
      title: `High-Risk Attachment Reference (${suspiciousAttachmentMentions.slice(0, 3).join(', ')})`,
      detail: 'Email references executable, macro-enabled, archive, or HTML credential-form files.',
      severity: 'high',
      weightContribution: 22,
    });
  }

  const maxUrlScore = extractedUrls.reduce((max, u) => Math.max(max, u.riskScore), 0);
  if (maxUrlScore >= 55) {
    const pts = Math.round(maxUrlScore * 0.35);
    score += pts;
    evidence.push({
      id: 'email-malicious-link',
      category: 'confirmed',
      source: 'Embedded URL Scanner',
      title: `High-Risk Embedded URL Detected (Max Score ${maxUrlScore}/100)`,
      detail: `Embedded URL "${extractedUrls.find((u) => u.riskScore === maxUrlScore)?.url ?? ''}" triggered structural/ML phishing indicators.`,
      severity: 'high',
      weightContribution: pts,
    });
  }

  evidence.push({
    id: 'email-ml-prediction',
    category: 'model',
    source: nlpModelPrediction.modelName,
    title: `NLP Classifier: ${nlpModelPrediction.classification.toUpperCase()} (${Math.round(nlpModelPrediction.phishingProbability * 100)}%)`,
    detail: `Top weighted tokens: ${nlpModelPrediction.topMatchedTokens.slice(0, 5).map((t) => t.term).join(', ') || 'none'}.`,
    severity: nlpModelPrediction.phishingProbability >= 0.65 ? 'high' : 'info',
  });

  let threatCategory = 'Benign Enterprise Correspondence';
  if (financialSignals.length > 0 && (senderReplyToMismatch || combinedLower.includes('wire') || combinedLower.includes('gift card'))) {
    threatCategory = 'Business Email Compromise (BEC) / Financial Fraud';
  } else if (suspiciousAttachmentMentions.length > 0) {
    threatCategory = 'Malicious Attachment / Payload Lure';
  } else if (credentialSignals.length > 0 || maxUrlScore >= 60) {
    threatCategory = 'Credential Harvesting Phishing Email';
  } else if (score >= 30) {
    threatCategory = 'Suspicious Social Engineering Email';
  }

  return {
    report: {
      sender: input.sender,
      replyTo: replyToText || input.sender,
      subject: input.subject,
      senderReplyToMismatch,
      senderDomain,
      replyToDomain,
      displayNameImpersonation,
      authHeaders,
      extractedUrls,
      urgencySignals,
      credentialSignals,
      financialSignals,
      suspiciousAttachmentMentions,
      socialEngineeringTactics,
      nlpModelPrediction,
    },
    heuristicScore: Math.min(100, score),
    threatCategory,
    evidence,
  };
}
