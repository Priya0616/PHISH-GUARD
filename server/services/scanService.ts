import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  DashboardStats,
  EvidenceItem,
  RiskLevel,
  ScanRecord,
} from '../../src/types/phishguard.ts';
import { generateAiThreatExplanation } from '../ai/explainer.ts';
import { insertScan, listScans } from '../database/db.ts';
import { analyzeEmailContent } from '../detectors/emailAnalyzer.ts';
import {
  computeTransparentRiskBreakdown,
  evaluateDomainAndSslRisk,
  evaluateThreatIntelScore,
} from '../detectors/riskScorer.ts';
import { analyzeUrlHeuristics } from '../detectors/urlAnalyzer.ts';
import { gatherDomainIntelligence } from '../intelligence/domainIntel.ts';
import { queryExternalThreatIntel } from '../intelligence/threatIntel.ts';
import { predictUrlModels } from '../ml/inference.ts';
import { safeParseUrl, sha256Hex } from '../security/ssrf.ts';

export const ENGINE_VERSION = 'PhishGuard-Engine/1.2.0';

export async function runUrlThreatScan(params: {
  db: DatabaseSync;
  userId: number;
  rawUrl: string;
  externalConsentGranted: boolean;
  skipNetworkForTest?: boolean;
}): Promise<ScanRecord> {
  const parsed = safeParseUrl(params.rawUrl);
  if (!parsed.valid) {
    throw new Error(parsed.error ?? 'Invalid URL input.');
  }

  const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
  const ml = predictUrlModels(heur.mlFeatureVector);

  const mlEvidence: EvidenceItem[] = [
    {
      id: 'ml-logreg',
      category: 'model',
      source: ml.logisticRegression.modelName,
      title: `Logistic Regression: ${ml.logisticRegression.classification.toUpperCase()} (${Math.round(ml.logisticRegression.phishingProbability * 100)}%)`,
      detail: `Model confidence ${ml.logisticRegression.confidenceScore}%. ${ml.logisticRegression.limitationsNote}`,
      severity: ml.logisticRegression.phishingProbability >= 0.65 ? 'high' : 'info',
    },
    {
      id: 'ml-rf',
      category: 'model',
      source: ml.randomForest.modelName,
      title: `Random Forest: ${ml.randomForest.classification.toUpperCase()} (${Math.round(ml.randomForest.phishingProbability * 100)}%)`,
      detail: `Ensemble vote across 25 decision trees (confidence ${ml.randomForest.confidenceScore}%).`,
      severity: ml.randomForest.phishingProbability >= 0.65 ? 'high' : 'info',
    },
  ];

  const domainIntel = params.skipNetworkForTest
    ? {
        domain: parsed.hostname,
        registrableDomain: parsed.hostname,
        retrievedAt: new Date().toISOString(),
        ssrfBlocked: parsed.ssrfBlocked,
        ssrfReason: parsed.ssrfReason,
        dnsAvailable: false,
        dnsError: 'Network probes disabled in offline mode.',
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
          error: 'Network probes disabled in offline mode.',
        },
        rdap: {
          available: false,
          registrar: null,
          createdAt: null,
          updatedAt: null,
          expiresAt: null,
          domainAgeDays: null,
          status: [],
          error: 'Network probes disabled in offline mode.',
        },
      }
    : await gatherDomainIntelligence({
        hostname: parsed.hostname,
        ssrfBlocked: parsed.ssrfBlocked,
        ssrfReason: parsed.ssrfReason,
        port: parsed.port,
      });

  const domainEval = evaluateDomainAndSslRisk(domainIntel);

  const threatIntel = params.skipNetworkForTest
    ? await queryExternalThreatIntel(parsed.normalizedUrl, false)
    : await queryExternalThreatIntel(parsed.normalizedUrl, params.externalConsentGranted && !parsed.ssrfBlocked);

  const tiEval = evaluateThreatIntelScore(threatIntel);

  const preliminaryRisk = computeTransparentRiskBreakdown({
    heuristicsScore: heur.heuristicScore,
    mlEnsembleProbability: ml.ensembleProbability,
    domainSslScore: domainIntel.dnsAvailable || domainIntel.ssl.available || domainIntel.ssrfBlocked ? domainEval.score : null,
    externalIntelScore: tiEval.score,
    threatCategory: heur.threatCategory,
    aiAssessment: { available: false, model: null, summary: null, reasoningSteps: [], error: null },
    scanType: 'url',
  });

  const allEvidence = [...heur.evidence, ...domainEval.evidence, ...tiEval.evidence, ...mlEvidence];

  const aiAssessment = params.skipNetworkForTest
    ? {
        available: false,
        model: null,
        summary: null,
        reasoningSteps: [],
        error: 'Gemini AI skipped in offline mode.',
      }
    : await generateAiThreatExplanation({
        scanType: 'url',
        indicator: parsed.normalizedUrl,
        riskScore: preliminaryRisk.overallScore,
        riskLevel: preliminaryRisk.riskLevel,
        threatCategory: preliminaryRisk.threatCategory,
        findings: allEvidence.map((e) => `${e.title}: ${e.detail}`),
      });

  const riskBreakdown = { ...preliminaryRisk, aiAssessment };

  const scan: ScanRecord = {
    id: `SCN-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    userId: params.userId,
    scanType: 'url',
    indicator: parsed.normalizedUrl,
    indicatorSha256: sha256Hex(parsed.normalizedUrl),
    createdAt: new Date().toISOString(),
    isDemo: false,
    riskScore: riskBreakdown.overallScore,
    riskLevel: riskBreakdown.riskLevel,
    classification: riskBreakdown.classification,
    threatCategory: riskBreakdown.threatCategory,
    engineVersion: ENGINE_VERSION,
    externalConsentGranted: params.externalConsentGranted,
    evidence: allEvidence,
    riskBreakdown,
    urlFeatures: heur.features,
    mlPredictions: {
      logisticRegression: ml.logisticRegression,
      randomForest: ml.randomForest,
      ensembleProbability: ml.ensembleProbability,
    },
    domainIntel,
    threatIntel,
  };

  insertScan(params.db, scan);
  return scan;
}

export async function runEmailThreatScan(params: {
  db: DatabaseSync;
  userId: number;
  subject: string;
  body: string;
  sender: string;
  replyTo?: string;
  headers?: string;
  skipNetworkForTest?: boolean;
}): Promise<ScanRecord> {
  const emailEval = analyzeEmailContent({
    subject: params.subject,
    body: params.body,
    sender: params.sender,
    replyTo: params.replyTo,
    headers: params.headers,
  });

  const senderDomain = emailEval.report.senderDomain;
  let domainIntel;
  let domainEvalScore: number | null = null;
  let domainEvidence: EvidenceItem[] = [];

  if (senderDomain && !params.skipNetworkForTest) {
    const parsedSender = safeParseUrl(`https://${senderDomain}`);
    domainIntel = await gatherDomainIntelligence({
      hostname: senderDomain,
      ssrfBlocked: parsedSender.ssrfBlocked,
      ssrfReason: parsedSender.ssrfReason,
    });
    const dEval = evaluateDomainAndSslRisk(domainIntel);
    domainEvalScore = domainIntel.dnsAvailable || domainIntel.ssrfBlocked ? dEval.score : null;
    domainEvidence = dEval.evidence;
  }

  const preliminaryRisk = computeTransparentRiskBreakdown({
    heuristicsScore: emailEval.heuristicScore,
    mlEnsembleProbability: emailEval.report.nlpModelPrediction.phishingProbability,
    domainSslScore: domainEvalScore,
    externalIntelScore: null,
    threatCategory: emailEval.threatCategory,
    aiAssessment: { available: false, model: null, summary: null, reasoningSteps: [], error: null },
    scanType: 'email',
  });

  const allEvidence = [...emailEval.evidence, ...domainEvidence];
  const indicator = `${params.sender} | ${params.subject}`.slice(0, 260);

  const aiAssessment = params.skipNetworkForTest
    ? {
        available: false,
        model: null,
        summary: null,
        reasoningSteps: [],
        error: 'Gemini AI skipped in offline mode.',
      }
    : await generateAiThreatExplanation({
        scanType: 'email',
        indicator,
        riskScore: preliminaryRisk.overallScore,
        riskLevel: preliminaryRisk.riskLevel,
        threatCategory: preliminaryRisk.threatCategory,
        findings: allEvidence.map((e) => `${e.title}: ${e.detail}`),
      });

  const riskBreakdown = { ...preliminaryRisk, aiAssessment };

  const scan: ScanRecord = {
    id: `EML-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    userId: params.userId,
    scanType: 'email',
    indicator,
    indicatorSha256: sha256Hex(`${params.sender}\n${params.subject}\n${params.body}`),
    createdAt: new Date().toISOString(),
    isDemo: false,
    riskScore: riskBreakdown.overallScore,
    riskLevel: riskBreakdown.riskLevel,
    classification: riskBreakdown.classification,
    threatCategory: riskBreakdown.threatCategory,
    engineVersion: ENGINE_VERSION,
    externalConsentGranted: false,
    evidence: allEvidence,
    riskBreakdown,
    domainIntel,
    emailAnalysis: emailEval.report,
  };

  insertScan(params.db, scan);
  return scan;
}

export async function runDomainIntelScan(params: {
  db: DatabaseSync;
  userId: number;
  rawDomain: string;
}): Promise<ScanRecord> {
  const parsed = safeParseUrl(params.rawDomain);
  if (!parsed.valid) {
    throw new Error(parsed.error ?? 'Invalid domain input.');
  }

  const domainIntel = await gatherDomainIntelligence({
    hostname: parsed.hostname,
    ssrfBlocked: parsed.ssrfBlocked,
    ssrfReason: parsed.ssrfReason,
    port: parsed.port,
  });

  const domainEval = evaluateDomainAndSslRisk(domainIntel);
  const heur = analyzeUrlHeuristics(parsed.normalizedUrl);
  const ml = predictUrlModels(heur.mlFeatureVector);

  const riskBreakdown = computeTransparentRiskBreakdown({
    heuristicsScore: heur.heuristicScore,
    mlEnsembleProbability: ml.ensembleProbability,
    domainSslScore: domainEval.score,
    externalIntelScore: null,
    threatCategory: domainEval.score >= 30 ? 'Suspicious Domain Infrastructure' : 'Verified Domain Infrastructure',
    aiAssessment: {
      available: false,
      model: null,
      summary: null,
      reasoningSteps: [],
      error: null,
    },
    scanType: 'domain',
  });

  const scan: ScanRecord = {
    id: `DOM-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    userId: params.userId,
    scanType: 'domain',
    indicator: parsed.hostname,
    indicatorSha256: sha256Hex(parsed.hostname),
    createdAt: new Date().toISOString(),
    isDemo: false,
    riskScore: riskBreakdown.overallScore,
    riskLevel: riskBreakdown.riskLevel,
    classification: riskBreakdown.classification,
    threatCategory: riskBreakdown.threatCategory,
    engineVersion: ENGINE_VERSION,
    externalConsentGranted: false,
    evidence: [...domainEval.evidence, ...heur.evidence],
    riskBreakdown,
    domainIntel,
    mlPredictions: {
      logisticRegression: ml.logisticRegression,
      randomForest: ml.randomForest,
      ensembleProbability: ml.ensembleProbability,
    },
  };

  insertScan(params.db, scan);
  return scan;
}

export function computeDashboardStats(db: DatabaseSync): DashboardStats {
  const { items: allScans } = listScans(db, { limit: 500, offset: 0 });
  const totalScans = allScans.length;
  const urlScans = allScans.filter((s) => s.scanType === 'url');
  const emailScans = allScans.filter((s) => s.scanType === 'email');

  const phishingUrlsDetected = urlScans.filter((s) => s.riskScore >= 60).length;
  const suspiciousEmailsIdentified = emailScans.filter((s) => s.riskScore >= 30).length;
  const criticalThreats = allScans.filter((s) => s.riskLevel === 'Critical Risk').length;
  const detectedThreats = allScans.filter((s) => s.riskScore >= 60).length;
  const threatDetectionRate = totalScans > 0 ? Number(((detectedThreats / totalScans) * 100).toFixed(1)) : 0;
  const demoCount = allScans.filter((s) => s.isDemo).length;

  const levels: RiskLevel[] = ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'];
  const riskBreakdown = levels.map((level) => ({
    level,
    count: allScans.filter((s) => s.riskLevel === level).length,
  }));

  const catMap = new Map<string, number>();
  for (const s of allScans) {
    catMap.set(s.threatCategory, (catMap.get(s.threatCategory) ?? 0) + 1);
  }
  const threatCategories = Array.from(catMap.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  // 7-day trend anchored to actual stored scan timestamps
  const today = new Date();
  const weeklyTrends: Array<{ date: string; total: number; threats: number; benign: number }> = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const dayIso = d.toISOString().slice(0, 10);
    const label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const dayScans = allScans.filter((s) => s.createdAt.slice(0, 10) === dayIso);
    const threats = dayScans.filter((s) => s.riskScore >= 60).length;
    const benign = dayScans.filter((s) => s.riskScore < 60).length;
    weeklyTrends.push({ date: label, total: dayScans.length, threats, benign });
  }

  return {
    totalScans,
    totalUrlsAnalyzed: urlScans.length,
    phishingUrlsDetected,
    suspiciousEmailsIdentified,
    criticalThreats,
    threatDetectionRate,
    demoCount,
    riskBreakdown,
    threatCategories,
    weeklyTrends,
    recentScans: allScans.slice(0, 8),
  };
}

export async function seedBaselineDemoScansIfEmpty(db: DatabaseSync, userId: number): Promise<void> {
  const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM scans').get() as { cnt: number };
  if (countRow.cnt > 0) return;

  const sampleUrls = [
    { url: 'http://login.microsoftonline.com.verify-account-session-841.com/oauth2/token', daysAgo: 0 },
    { url: 'http://198.51.100.42/paypal/login.php?verify=1', daysAgo: 1 },
    { url: 'https://xn--pypal-4ve.com/signin/confirm-identity', daysAgo: 2 },
    { url: 'https://bit.ly/3xPhishVerifyBank', daysAgo: 3 },
    { url: 'https://docs.python.org/3/library/ssl.html', daysAgo: 4 },
    { url: 'https://github.com/torvalds/linux/blob/master/README', daysAgo: 5 },
  ];

  for (const item of sampleUrls) {
    const scan = await runUrlThreatScan({
      db,
      userId,
      rawUrl: item.url,
      externalConsentGranted: false,
      skipNetworkForTest: true,
    });
    const ts = new Date(Date.now() - item.daysAgo * 86400000).toISOString();
    scan.isDemo = true;
    scan.createdAt = ts;
    db.prepare('UPDATE scans SET is_demo = 1, created_at = ?, payload_json = ? WHERE id = ?').run(
      ts,
      JSON.stringify(scan),
      scan.id
    );
  }

  const emailScan = await runEmailThreatScan({
    db,
    userId,
    subject: 'URGENT: Unpaid Invoice #88412 - Immediate Wire Transfer Required',
    sender: 'PayPal Billing Support <billing-alert@paypa1-security-verify.com>',
    replyTo: 'finance-remittance@evil-drop.xyz',
    body: 'Immediate action required! Your account will be permanently suspended within 24 hours. Verify your password and bank routing number at http://paypa1-security-verify.com/signin immediately.',
    skipNetworkForTest: true,
  });
  const emlTs = new Date(Date.now() - 1 * 86400000).toISOString();
  emailScan.isDemo = true;
  emailScan.createdAt = emlTs;
  db.prepare('UPDATE scans SET is_demo = 1, created_at = ?, payload_json = ? WHERE id = ?').run(
    emlTs,
    JSON.stringify(emailScan),
    emailScan.id
  );
}
