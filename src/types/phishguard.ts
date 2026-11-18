export type RiskLevel = 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical Risk';
export type ScanType = 'url' | 'email' | 'domain';
export type EvidenceCategory = 'confirmed' | 'suspicious' | 'unavailable' | 'model';

export interface UserProfile {
  id: number;
  email: string;
  fullName: string;
  role: 'analyst' | 'senior_analyst' | 'admin';
  createdAt: string;
}

export interface EvidenceItem {
  id: string;
  category: EvidenceCategory;
  source: string;
  title: string;
  detail: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  weightContribution?: number;
}

export interface UrlFeatureSummary {
  urlLength: number;
  hostnameLength: number;
  dotCount: number;
  subdomainDepth: number;
  digitRatio: number;
  specialCharRatio: number;
  shannonEntropy: number;
  isIpHost: boolean;
  isNonHttps: boolean;
  isShortener: boolean;
  hasSuspiciousTld: boolean;
  hasAtSymbol: boolean;
  hasDoubleSlashPath: boolean;
  hasPunycodeOrUnicode: boolean;
  unusualPort: number | null;
  suspiciousKeywords: string[];
  suspiciousQueryParams: string[];
  brandImpersonationTarget: string | null;
  typosquattingDistance: number | null;
  encodedSegmentCount: number;
}

export interface MlModelPrediction {
  modelName: string;
  modelVersion: string;
  classification: 'phishing' | 'benign';
  phishingProbability: number;
  confidenceScore: number;
  limitationsNote: string;
}

export interface DnsRecordSet {
  a: string[];
  aaaa: string[];
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  txt: string[];
}

export interface SslCertificateInfo {
  available: boolean;
  valid: boolean | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  selfSigned: boolean | null;
  expired: boolean | null;
  fingerprintSha256: string | null;
  subjectAltNames: string[];
  error: string | null;
}

export interface RdapDomainInfo {
  available: boolean;
  registrar: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  domainAgeDays: number | null;
  status: string[];
  error: string | null;
}

export interface DomainIntelligenceReport {
  domain: string;
  registrableDomain: string;
  retrievedAt: string;
  ssrfBlocked: boolean;
  ssrfReason: string | null;
  dnsAvailable: boolean;
  dnsError: string | null;
  dnsRecords: DnsRecordSet;
  ssl: SslCertificateInfo;
  rdap: RdapDomainInfo;
}

export interface ThreatIntelProviderResult {
  provider: 'Google Safe Browsing' | 'VirusTotal' | 'URLhaus';
  configured: boolean;
  consented: boolean;
  status: 'clean' | 'malicious' | 'suspicious' | 'unavailable' | 'skipped_no_consent' | 'rate_limited' | 'error';
  verdictSummary: string;
  details: Record<string, unknown> | null;
  checkedAt: string;
  latencyMs: number | null;
}

export interface EmailAuthHeaderResult {
  headerPresent: boolean;
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unavailable';
  dkim: 'pass' | 'fail' | 'none' | 'unavailable';
  dmarc: 'pass' | 'fail' | 'none' | 'unavailable';
  rawAuthenticationResults: string | null;
  note: string;
}

export interface EmailAnalysisReport {
  sender: string;
  replyTo: string;
  subject: string;
  senderReplyToMismatch: boolean;
  senderDomain: string | null;
  replyToDomain: string | null;
  displayNameImpersonation: string | null;
  authHeaders: EmailAuthHeaderResult;
  extractedUrls: Array<{
    url: string;
    riskScore: number;
    riskLevel: RiskLevel;
    classification: string;
  }>;
  urgencySignals: string[];
  credentialSignals: string[];
  financialSignals: string[];
  suspiciousAttachmentMentions: string[];
  socialEngineeringTactics: string[];
  nlpModelPrediction: MlModelPrediction & { topMatchedTokens: Array<{ term: string; weight: number }> };
}

export interface RiskBreakdown {
  overallScore: number;
  riskLevel: RiskLevel;
  classification: string;
  threatCategory: string;
  confidence: number;
  confidenceLimitations: string;
  componentWeights: {
    heuristicsWeight: number;
    mlWeight: number;
    domainSslWeight: number;
    externalIntelWeight: number;
  };
  componentScores: {
    heuristicsScore: number;
    mlScore: number;
    domainSslScore: number;
    externalIntelScore: number | null;
  };
  aiAssessment: {
    available: boolean;
    model: string | null;
    summary: string | null;
    reasoningSteps: string[];
    error: string | null;
  };
  recommendations: string[];
}

export interface ScanRecord {
  id: string;
  userId: number;
  scanType: ScanType;
  indicator: string;
  indicatorSha256: string;
  createdAt: string;
  isDemo: boolean;
  riskScore: number;
  riskLevel: RiskLevel;
  classification: string;
  threatCategory: string;
  engineVersion: string;
  externalConsentGranted: boolean;
  evidence: EvidenceItem[];
  riskBreakdown: RiskBreakdown;
  urlFeatures?: UrlFeatureSummary;
  mlPredictions?: {
    logisticRegression: MlModelPrediction;
    randomForest: MlModelPrediction;
    ensembleProbability: number;
  };
  domainIntel?: DomainIntelligenceReport;
  threatIntel?: ThreatIntelProviderResult[];
  emailAnalysis?: EmailAnalysisReport;
}

export interface DashboardStats {
  totalScans: number;
  totalUrlsAnalyzed: number;
  phishingUrlsDetected: number;
  suspiciousEmailsIdentified: number;
  criticalThreats: number;
  threatDetectionRate: number;
  demoCount: number;
  riskBreakdown: Array<{ level: RiskLevel; count: number }>;
  threatCategories: Array<{ category: string; count: number }>;
  weeklyTrends: Array<{ date: string; total: number; threats: number; benign: number }>;
  recentScans: ScanRecord[];
}

export interface MlInsightsPayload {
  version: string;
  trainedAt: string;
  dataset: {
    urlCorpusSamples: number;
    urlTrainSamples: number;
    urlTestSamples: number;
    emailCorpusSamples: number;
    emailTrainSamples: number;
    emailTestSamples: number;
    splitStrategy: string;
  };
  urlModels: {
    logisticRegression: {
      name: string;
      metrics: ModelEvalMetrics;
    };
    randomForest: {
      name: string;
      featureImportances: Array<{ feature: string; importance: number }>;
      metrics: ModelEvalMetrics;
    };
  };
  emailModel: {
    name: string;
    metrics: ModelEvalMetrics;
    topPhishingTokens: Array<{ term: string; weight: number }>;
    topBenignTokens: Array<{ term: string; weight: number }>;
  };
}

export interface ModelEvalMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  confusionMatrix: { tp: number; fp: number; tn: number; fn: number };
  testSamples: number;
}

export interface SystemConfigStatus {
  engineVersion: string;
  geminiConfigured: boolean;
  googleSafeBrowsingConfigured: boolean;
  virusTotalConfigured: boolean;
  urlhausConfigured: boolean;
  rateLimitMaxPerMinute: number;
  ssrfProtectionEnabled: boolean;
  databaseEngine: string;
}

export interface AuditLogEntry {
  id: number;
  userId: number | null;
  userEmail: string | null;
  action: string;
  target: string;
  ipAddress: string;
  status: 'success' | 'blocked' | 'error';
  createdAt: string;
}
