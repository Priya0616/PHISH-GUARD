import type {
  DomainIntelligenceReport,
  EvidenceItem,
  RiskBreakdown,
  RiskLevel,
  ThreatIntelProviderResult,
} from '../../src/types/phishguard.ts';
import type { AiThreatAssessment } from '../ai/explainer.ts';

export function classifyRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'Critical Risk';
  if (score >= 60) return 'High Risk';
  if (score >= 30) return 'Medium Risk';
  return 'Low Risk';
}

export function evaluateDomainAndSslRisk(domainIntel: DomainIntelligenceReport): {
  score: number;
  evidence: EvidenceItem[];
} {
  const evidence: EvidenceItem[] = [];
  let score = 0;

  if (domainIntel.ssrfBlocked) {
    evidence.push({
      id: 'domain-ssrf-blocked',
      category: 'confirmed',
      source: 'SSRF Defense Guard',
      title: 'Internal / Reserved Target Blocked from Network Probes',
      detail: domainIntel.ssrfReason ?? 'Backend DNS/TLS lookups were blocked to protect internal infrastructure.',
      severity: 'high',
      weightContribution: 0,
    });
    return { score: 25, evidence };
  }

  // DNS findings (never interpret missing IPv6/TXT as a failure)
  if (!domainIntel.dnsAvailable) {
    score += 22;
    evidence.push({
      id: 'dns-resolution-failed',
      category: 'suspicious',
      source: 'DNS Resolver',
      title: 'Domain DNS Resolution Failed (NXDOMAIN / Unresolvable)',
      detail: domainIntel.dnsError ?? 'No active A, AAAA, MX, or NS records could be resolved.',
      severity: 'medium',
      weightContribution: 22,
    });
  } else {
    evidence.push({
      id: 'dns-resolved-ok',
      category: 'confirmed',
      source: 'DNS Resolver',
      title: `DNS Active (${domainIntel.dnsRecords.a.length} A, ${domainIntel.dnsRecords.mx.length} MX, ${domainIntel.dnsRecords.ns.length} NS)`,
      detail: `Resolved A records: ${domainIntel.dnsRecords.a.slice(0, 3).join(', ') || 'none'}. Nameservers: ${domainIntel.dnsRecords.ns.slice(0, 2).join(', ') || 'none'}.`,
      severity: 'info',
      weightContribution: 0,
    });
  }

  // SSL/TLS findings
  if (!domainIntel.ssl.available) {
    evidence.push({
      id: 'ssl-unavailable',
      category: 'unavailable',
      source: 'TLS Certificate Inspector',
      title: 'TLS Certificate Inspection Unavailable',
      detail: domainIntel.ssl.error ?? 'Could not complete TLS handshake on port 443.',
      severity: 'info',
      weightContribution: 0,
    });
  } else if (domainIntel.ssl.expired) {
    score += 35;
    evidence.push({
      id: 'ssl-expired',
      category: 'confirmed',
      source: 'TLS Certificate Inspector',
      title: 'Expired TLS/SSL Certificate',
      detail: `Certificate expired on ${domainIntel.ssl.validTo ?? 'unknown date'}.`,
      severity: 'high',
      weightContribution: 35,
    });
  } else if (domainIntel.ssl.selfSigned) {
    score += 30;
    evidence.push({
      id: 'ssl-self-signed',
      category: 'confirmed',
      source: 'TLS Certificate Inspector',
      title: 'Self-Signed TLS Certificate Detected',
      detail: `Certificate subject matches issuer (${domainIntel.ssl.issuer ?? 'unknown'}); not issued by a trusted public CA.`,
      severity: 'high',
      weightContribution: 30,
    });
  } else if (domainIntel.ssl.valid === false) {
    score += 22;
    evidence.push({
      id: 'ssl-untrusted',
      category: 'suspicious',
      source: 'TLS Certificate Inspector',
      title: 'Untrusted TLS Certificate Chain',
      detail: domainIntel.ssl.error ?? 'TLS certificate chain failed validation against system root CAs.',
      severity: 'medium',
      weightContribution: 22,
    });
  } else {
    evidence.push({
      id: 'ssl-valid',
      category: 'confirmed',
      source: 'TLS Certificate Inspector',
      title: 'Valid Public TLS Certificate',
      detail: `Issued by ${domainIntel.ssl.issuer ?? 'CA'}; expires in ${domainIntel.ssl.daysRemaining ?? '?'} days.`,
      severity: 'info',
      weightContribution: 0,
    });
  }

  // RDAP / WHOIS domain age findings (missing RDAP is never treated as malicious)
  if (!domainIntel.rdap.available) {
    evidence.push({
      id: 'rdap-unavailable',
      category: 'unavailable',
      source: 'RDAP Registry Lookup',
      title: 'WHOIS / RDAP Registration Metadata Unavailable',
      detail: domainIntel.rdap.error ?? 'Registry did not return RDAP registration dates.',
      severity: 'info',
      weightContribution: 0,
    });
  } else if (domainIntel.rdap.domainAgeDays !== null) {
    if (domainIntel.rdap.domainAgeDays < 30) {
      score += 32;
      evidence.push({
        id: 'rdap-newly-registered',
        category: 'confirmed',
        source: 'RDAP Registry Lookup',
        title: `Newly Registered Domain (${domainIntel.rdap.domainAgeDays} days old)`,
        detail: `Domain registered on ${domainIntel.rdap.createdAt?.slice(0, 10) ?? 'unknown'} via ${domainIntel.rdap.registrar ?? 'unknown registrar'}. Very young domains carry elevated phishing risk.`,
        severity: 'high',
        weightContribution: 32,
      });
    } else if (domainIntel.rdap.domainAgeDays < 90) {
      score += 14;
      evidence.push({
        id: 'rdap-young-domain',
        category: 'suspicious',
        source: 'RDAP Registry Lookup',
        title: `Recently Registered Domain (${domainIntel.rdap.domainAgeDays} days old)`,
        detail: `Registered on ${domainIntel.rdap.createdAt?.slice(0, 10) ?? 'unknown'}.`,
        severity: 'low',
        weightContribution: 14,
      });
    } else {
      evidence.push({
        id: 'rdap-established',
        category: 'confirmed',
        source: 'RDAP Registry Lookup',
        title: `Established Domain (${domainIntel.rdap.domainAgeDays} days old)`,
        detail: `Registered ${domainIntel.rdap.createdAt?.slice(0, 10) ?? 'unknown'} via ${domainIntel.rdap.registrar ?? 'registrar'}.`,
        severity: 'info',
        weightContribution: 0,
      });
    }
  }

  return { score: Math.min(100, score), evidence };
}

export function evaluateThreatIntelScore(results: ThreatIntelProviderResult[]): {
  score: number | null;
  evidence: EvidenceItem[];
} {
  const evidence: EvidenceItem[] = [];
  const activeResults = results.filter(
    (r) => r.status === 'clean' || r.status === 'malicious' || r.status === 'suspicious'
  );

  for (const r of results) {
    if (r.status === 'malicious') {
      evidence.push({
        id: `ti-${r.provider.toLowerCase().replace(/\s+/g, '-')}-malicious`,
        category: 'confirmed',
        source: r.provider,
        title: `${r.provider}: Malicious Indicator Match`,
        detail: r.verdictSummary,
        severity: 'critical',
      });
    } else if (r.status === 'suspicious') {
      evidence.push({
        id: `ti-${r.provider.toLowerCase().replace(/\s+/g, '-')}-suspicious`,
        category: 'suspicious',
        source: r.provider,
        title: `${r.provider}: Suspicious Reputation`,
        detail: r.verdictSummary,
        severity: 'medium',
      });
    } else if (r.status === 'clean') {
      evidence.push({
        id: `ti-${r.provider.toLowerCase().replace(/\s+/g, '-')}-clean`,
        category: 'confirmed',
        source: r.provider,
        title: `${r.provider}: Clean / No Listing`,
        detail: r.verdictSummary,
        severity: 'info',
      });
    } else {
      evidence.push({
        id: `ti-${r.provider.toLowerCase().replace(/\s+/g, '-')}-unavail`,
        category: 'unavailable',
        source: r.provider,
        title: `${r.provider}: ${r.status === 'skipped_no_consent' ? 'Skipped (Consent Not Granted)' : 'Unavailable'}`,
        detail: r.verdictSummary,
        severity: 'info',
      });
    }
  }

  if (activeResults.length === 0) {
    return { score: null, evidence };
  }

  if (activeResults.some((r) => r.status === 'malicious')) {
    return { score: 95, evidence };
  }
  if (activeResults.some((r) => r.status === 'suspicious')) {
    return { score: 65, evidence };
  }
  return { score: 0, evidence };
}

export function computeTransparentRiskBreakdown(params: {
  heuristicsScore: number;
  mlEnsembleProbability: number;
  domainSslScore: number | null;
  externalIntelScore: number | null;
  threatCategory: string;
  aiAssessment: AiThreatAssessment;
  scanType: 'url' | 'email' | 'domain';
}): RiskBreakdown {
  const mlScore = Math.round(params.mlEnsembleProbability * 100);

  // Base weights: Heuristics 35%, ML 25%, Domain/SSL 20%, External Intel 20%
  // Dynamically re-normalize if Domain/SSL or External Intel is null so missing checks NEVER penalize score!
  const rawWeights = {
    heuristics: 0.35,
    ml: 0.25,
    domainSsl: params.domainSslScore !== null ? 0.20 : 0,
    externalIntel: params.externalIntelScore !== null ? 0.20 : 0,
  };

  const totalWeight =
    rawWeights.heuristics + rawWeights.ml + rawWeights.domainSsl + rawWeights.externalIntel;

  const wH = rawWeights.heuristics / totalWeight;
  const wM = rawWeights.ml / totalWeight;
  const wD = rawWeights.domainSsl / totalWeight;
  const wE = rawWeights.externalIntel / totalWeight;

  let weightedScore =
    params.heuristicsScore * wH +
    mlScore * wM +
    (params.domainSslScore ?? 0) * wD +
    (params.externalIntelScore ?? 0) * wE;

  // Guardrail: Confirmed external malicious intelligence or extreme heuristic flags elevate floor
  if (params.externalIntelScore !== null && params.externalIntelScore >= 90) {
    weightedScore = Math.max(weightedScore, 85);
  }
  if (params.heuristicsScore >= 75 && mlScore >= 70) {
    weightedScore = Math.max(weightedScore, 75);
  }

  const overallScore = Math.min(100, Math.max(0, Math.round(weightedScore)));
  const riskLevel = classifyRiskLevel(overallScore);

  const classification =
    overallScore >= 60
      ? 'Phishing / Malicious'
      : overallScore >= 30
      ? 'Suspicious — Analyst Review Recommended'
      : 'Likely Benign';

  const agreementDelta = Math.abs(params.heuristicsScore - mlScore);
  const confidence = Math.min(96, Math.max(35, Math.round(90 - agreementDelta * 0.45)));

  const recommendations: string[] = [];
  if (overallScore >= 80) {
    recommendations.push('Block indicator immediately at secure web gateway (SWG) and email perimeter.');
    recommendations.push('Quarantine matching messages and check SIEM/proxy logs for users who interacted with the indicator.');
    recommendations.push('Reset credentials and revoke active OAuth/SSO sessions for any exposed accounts.');
  } else if (overallScore >= 60) {
    recommendations.push('Do not click or submit credentials; escalate indicator to Tier-2 SOC analyst review.');
    recommendations.push('Verify target domain ownership out-of-band before permitting user access.');
    recommendations.push('Cross-check indicator against internal mail gateway and endpoint telemetry.');
  } else if (overallScore >= 30) {
    recommendations.push('Treat with caution; confirm sender or destination authenticity through an independent channel.');
    recommendations.push('Submit indicator with explicit user consent to external threat feeds if suspicious context persists.');
  } else {
    recommendations.push('No high-risk phishing indicators observed in static lexical, ML, or available DNS/TLS checks.');
    recommendations.push('Continue standard endpoint protection and user awareness hygiene; automated scores do not guarantee absolute safety.');
  }

  return {
    overallScore,
    riskLevel,
    classification,
    threatCategory: overallScore < 30 ? 'Benign / Low Risk Indicator' : params.threatCategory,
    confidence,
    confidenceLimitations:
      params.externalIntelScore === null
        ? 'External threat intelligence feeds were unavailable or skipped (consent required); score reflects local heuristics, ML ensemble, and available network telemetry only.'
        : 'Confidence reflects agreement across lexical heuristics, ML ensemble, DNS/TLS signals, and external feeds; never treat automated confidence as a 100% safety guarantee.',
    componentWeights: {
      heuristicsWeight: Number(wH.toFixed(3)),
      mlWeight: Number(wM.toFixed(3)),
      domainSslWeight: Number(wD.toFixed(3)),
      externalIntelWeight: Number(wE.toFixed(3)),
    },
    componentScores: {
      heuristicsScore: params.heuristicsScore,
      mlScore,
      domainSslScore: params.domainSslScore ?? 0,
      externalIntelScore: params.externalIntelScore,
    },
    aiAssessment: params.aiAssessment,
    recommendations,
  };
}
