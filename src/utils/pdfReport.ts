import { jsPDF } from 'jspdf';
import type { ScanRecord } from '../types/phishguard';

export function downloadScanPdfReport(scan: ScanRecord): void {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 44;
  const maxWidth = pageWidth - margin * 2;
  let y = 48;

  const checkPageBreak = (needed = 60) => {
    if (y + needed > 780) {
      doc.addPage();
      y = 48;
    }
  };

  const addSectionTitle = (title: string) => {
    checkPageBreak(44);
    y += 10;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(15, 23, 42);
    doc.text(title, margin, y);
    y += 6;
    doc.setDrawColor(203, 213, 225);
    doc.line(margin, y, pageWidth - margin, y);
    y += 14;
  };

  const addWrappedLine = (label: string, value: string) => {
    checkPageBreak(28);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(51, 65, 85);
    doc.text(`${label}:`, margin, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(15, 23, 42);
    const lines = doc.splitTextToSize(value, maxWidth - 125) as string[];
    doc.text(lines, margin + 125, y);
    y += Math.max(15, lines.length * 12.5);
  };

  // Header Banner
  doc.setFillColor(8, 13, 26);
  doc.rect(0, 0, pageWidth, 88, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(6, 182, 212);
  doc.text('PHISHGUARD', margin, 38);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(226, 232, 240);
  doc.text('Threat Investigation & Security Analysis Report', margin, 56);
  doc.setFontSize(8.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`Generated: ${new Date().toISOString()}  |  Engine: ${scan.engineVersion}`, margin, 72);

  y = 114;

  addSectionTitle('1. Executive Summary & Indicator Metadata');
  addWrappedLine('Scan ID', scan.id);
  addWrappedLine('Scan Type', scan.scanType.toUpperCase());
  addWrappedLine('Submitted Indicator', scan.indicator);
  addWrappedLine('SHA-256 Digest', scan.indicatorSha256);
  addWrappedLine('Scan Timestamp', scan.createdAt);
  addWrappedLine('Risk Score', `${scan.riskScore} / 100 (${scan.riskLevel})`);
  addWrappedLine('Classification', scan.classification);
  addWrappedLine('Threat Category', scan.threatCategory);
  addWrappedLine('Dataset Origin', scan.isDemo ? 'Sample Baseline Record' : 'Live Analyst Submission');

  addSectionTitle('2. Risk Scoring Breakdown & Confidence Limitations');
  addWrappedLine(
    'Component Scores',
    `Heuristics: ${scan.riskBreakdown.componentScores.heuristicsScore}/100 | ML Ensemble: ${scan.riskBreakdown.componentScores.mlScore}/100 | Domain/SSL: ${scan.riskBreakdown.componentScores.domainSslScore}/100 | External Intel: ${
      scan.riskBreakdown.componentScores.externalIntelScore !== null
        ? `${scan.riskBreakdown.componentScores.externalIntelScore}/100`
        : 'Unavailable / Not Consented'
    }`
  );
  addWrappedLine('Agreement Confidence', `${scan.riskBreakdown.confidence}%`);
  addWrappedLine('Limitations', scan.riskBreakdown.confidenceLimitations);

  if (scan.riskBreakdown.aiAssessment.available && scan.riskBreakdown.aiAssessment.summary) {
    addWrappedLine('AI Threat Assessment', scan.riskBreakdown.aiAssessment.summary);
  }

  addSectionTitle('3. Detection Evidence & Technical Findings');
  for (const ev of scan.evidence.slice(0, 18)) {
    checkPageBreak(36);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`[${ev.category.toUpperCase()} / ${ev.severity.toUpperCase()}] ${ev.title}`, margin, y);
    y += 12;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(71, 85, 105);
    const detailLines = doc.splitTextToSize(`${ev.source}: ${ev.detail}`, maxWidth - 10) as string[];
    doc.text(detailLines, margin + 8, y);
    y += detailLines.length * 11.5 + 6;
  }

  if (scan.mlPredictions) {
    addSectionTitle('4. Machine Learning Model Results');
    addWrappedLine(
      'Logistic Regression',
      `${scan.mlPredictions.logisticRegression.classification.toUpperCase()} (p=${(
        scan.mlPredictions.logisticRegression.phishingProbability * 100
      ).toFixed(1)}%, confidence=${scan.mlPredictions.logisticRegression.confidenceScore}%)`
    );
    addWrappedLine(
      'Random Forest',
      `${scan.mlPredictions.randomForest.classification.toUpperCase()} (p=${(
        scan.mlPredictions.randomForest.phishingProbability * 100
      ).toFixed(1)}%, confidence=${scan.mlPredictions.randomForest.confidenceScore}%)`
    );
  }

  if (scan.domainIntel) {
    addSectionTitle('5. Domain, DNS & TLS Intelligence');
    addWrappedLine('Registrable Domain', scan.domainIntel.registrableDomain);
    addWrappedLine('Retrieved At', scan.domainIntel.retrievedAt);
    addWrappedLine(
      'DNS Records',
      scan.domainIntel.dnsAvailable
        ? `A: ${scan.domainIntel.dnsRecords.a.join(', ') || 'none'} | MX: ${
            scan.domainIntel.dnsRecords.mx.map((m) => m.exchange).join(', ') || 'none'
          } | NS: ${scan.domainIntel.dnsRecords.ns.join(', ') || 'none'}`
        : `Unavailable (${scan.domainIntel.dnsError ?? 'Resolution failed'})`
    );
    addWrappedLine(
      'TLS Certificate',
      scan.domainIntel.ssl.available
        ? `Valid=${String(scan.domainIntel.ssl.valid)} | Issuer=${scan.domainIntel.ssl.issuer ?? 'unknown'} | Expires=${
            scan.domainIntel.ssl.validTo ?? 'unknown'
          }`
        : `Unavailable (${scan.domainIntel.ssl.error ?? 'Handshake failed'})`
    );
    addWrappedLine(
      'RDAP / WHOIS',
      scan.domainIntel.rdap.available
        ? `Registrar=${scan.domainIntel.rdap.registrar ?? 'unknown'} | Age=${
            scan.domainIntel.rdap.domainAgeDays ?? '?'
          } days`
        : `Unavailable (${scan.domainIntel.rdap.error ?? 'Not available'})`
    );
  }

  addSectionTitle('6. Recommended Mitigation Steps');
  for (const rec of scan.riskBreakdown.recommendations) {
    checkPageBreak(24);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(15, 23, 42);
    const lines = doc.splitTextToSize(`• ${rec}`, maxWidth) as string[];
    doc.text(lines, margin, y);
    y += lines.length * 13 + 3;
  }

  doc.save(`PhishGuard_Report_${scan.id}.pdf`);
}
