import { useState, type FormEvent } from 'react';
import { ArrowUpRight, Mail, ShieldAlert, ShieldCheck } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../services/api';
import type { ScanRecord } from '../types/phishguard';

const EMAIL_PRESETS = [
  {
    label: 'Credential Harvest + Failed SPF/DMARC',
    sender: 'PayPal Resolution Center <security@paypa1-security-verify.com>',
    replyTo: 'harvest-drop@evil-phish.xyz',
    subject: 'Action Required: Verify your PayPal account immediately',
    body: 'We noticed unusual login activity on your PayPal account. Your account is temporarily limited and will be permanently closed within 24 hours unless you confirm your password, SSN, and card details at http://paypa1-security-verify.com/signin.',
    headers:
      'Authentication-Results: mx.phishguard.sec; spf=fail smtp.mailfrom=paypa1-security-verify.com; dkim=fail; dmarc=fail\nReceived-SPF: fail',
  },
  {
    label: 'CEO Wire Fraud (BEC)',
    sender: 'Chief Financial Officer <cfo-office@external-mail.top>',
    replyTo: 'urgent-wire@finance-relay.ru',
    subject: 'Unpaid Invoice #88412 - Immediate Wire Transfer Required',
    body: 'Are you at your desk? I am in a confidential board meeting and cannot take calls. Please process an urgent wire transfer of $48,500 via ACH immediately and enable macros in invoice_4491.xlsm.',
    headers: '',
  },
  {
    label: 'Benign Engineering Update',
    sender: 'Engineering Lead <lead@company-platform.org>',
    replyTo: 'lead@company-platform.org',
    subject: 'Weekly Engineering Standup Notes',
    body: 'Hi team, summary of sprint deliverables: completed unit test suite, updated PostgreSQL schema migration, and reviewed latency metrics. View documentation at https://docs.python.org/3/library/ssl.html.',
    headers:
      'Authentication-Results: mx.company-platform.org; spf=pass; dkim=pass; dmarc=pass',
  },
];

export function EmailAnalyzerPage({ onOpenInvestigation }: { onOpenInvestigation: (id: string) => void }) {
  const [sender, setSender] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [headers, setHeaders] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanRecord | null>(null);

  const handleAnalyze = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const scan = await api.scanEmail({ sender, replyTo, subject, body, headers });
      setResult(scan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Email analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-5">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-slate-900">
            AI Email Phishing Analyzer
          </h2>
          <p className="text-sm text-slate-600">
            Detects social engineering lures, sender/reply-to spoofing, embedded malicious links, TF-IDF NLP patterns, and verifies SPF/DKIM/DMARC strictly from supplied header evidence.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {EMAIL_PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => {
                setSender(preset.sender);
                setReplyTo(preset.replyTo);
                setSubject(preset.subject);
                setBody(preset.body);
                setHeaders(preset.headers);
                setError(null);
              }}
              className="px-3 py-1.5 text-xs rounded-lg bg-slate-50 border border-slate-200 text-slate-700 hover:text-cyan-700 hover:border-cyan-300 transition-colors"
            >
              Load: {preset.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-700">Sender (From) Address</label>
              <input
                type="text"
                required
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="Support <alert@example.com>"
                className="w-full px-3.5 py-2 text-sm rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-700">Reply-To Address (Optional)</label>
              <input
                type="text"
                value={replyTo}
                onChange={(e) => setReplyTo(e.target.value)}
                placeholder="reply@other-domain.com"
                className="w-full px-3.5 py-2 text-sm rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-700">Email Subject</label>
            <input
              type="text"
              required
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="URGENT: Account Verification Required"
              className="w-full px-3.5 py-2 text-sm rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-700">Email Body Content</label>
            <textarea
              required
              rows={5}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Paste suspicious email body text here..."
              className="w-full px-3.5 py-2 text-sm rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-cyan-600 focus:bg-white"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-700">
              Raw Email Headers (Optional — required to evaluate SPF / DKIM / DMARC)
            </label>
            <textarea
              rows={3}
              value={headers}
              onChange={(e) => setHeaders(e.target.value)}
              placeholder="Authentication-Results: mx.domain.com; spf=pass; dkim=pass; dmarc=pass"
              className="w-full px-3.5 py-2 text-xs font-mono rounded-lg bg-slate-50 border border-slate-300 text-slate-800 focus:outline-none focus:border-cyan-600 focus:bg-white"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold rounded-lg bg-cyan-600 text-white hover:bg-cyan-700 disabled:opacity-60 transition-colors"
          >
            <Mail className="w-4 h-4" />
            <span>{loading ? 'Running NLP & Header Inspection...' : 'Analyze Email'}</span>
          </button>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">
          {error}
        </div>
      )}

      {result && result.emailAnalysis && (
        <div className="p-6 rounded-xl bg-white border border-slate-200 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200">
            <div className="space-y-1">
              <div className="text-xs font-mono text-cyan-700 font-semibold">
                {result.id} · {result.threatCategory}
              </div>
              <div className="text-base font-semibold text-slate-900">{result.emailAnalysis.subject}</div>
            </div>
            <div className="flex items-center gap-3">
              <RiskBadge level={result.riskLevel} score={result.riskScore} />
              <button
                type="button"
                onClick={() => onOpenInvestigation(result.id)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-50 border border-cyan-200 text-cyan-800 hover:bg-cyan-100"
              >
                <span>Open Investigation</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="text-slate-500 font-medium">Authentication Evidence</div>
              <div className="font-mono space-y-1 text-slate-700">
                <div>SPF: <span className="text-slate-900 font-semibold">{result.emailAnalysis.authHeaders.spf}</span></div>
                <div>DKIM: <span className="text-slate-900 font-semibold">{result.emailAnalysis.authHeaders.dkim}</span></div>
                <div>DMARC: <span className="text-slate-900 font-semibold">{result.emailAnalysis.authHeaders.dmarc}</span></div>
              </div>
              <div className="text-slate-500">{result.emailAnalysis.authHeaders.note}</div>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="text-slate-500 font-medium">TF-IDF NLP Classification</div>
              <div className="font-display text-lg font-bold text-cyan-700">
                {result.emailAnalysis.nlpModelPrediction.classification.toUpperCase()} (
                {Math.round(result.emailAnalysis.nlpModelPrediction.phishingProbability * 100)}%)
              </div>
              <div className="text-slate-600">
                Top tokens:{' '}
                <span className="font-mono text-slate-900">
                  {result.emailAnalysis.nlpModelPrediction.topMatchedTokens
                    .slice(0, 4)
                    .map((t) => t.term)
                    .join(', ') || 'none'}
                </span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="text-slate-500 font-medium">Embedded URLs ({result.emailAnalysis.extractedUrls.length})</div>
              {result.emailAnalysis.extractedUrls.length === 0 ? (
                <div className="text-slate-500">No HTTP/HTTPS links extracted from body.</div>
              ) : (
                <div className="space-y-1.5">
                  {result.emailAnalysis.extractedUrls.map((u) => (
                    <div key={u.url} className="font-mono text-[11px] text-slate-800 truncate">
                      [{u.riskScore}/100] {u.url}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-2">
            {result.evidence.map((ev) => (
              <div key={ev.id} className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-start gap-3 text-xs">
                {ev.severity === 'high' || ev.severity === 'critical' ? (
                  <ShieldAlert className="w-4 h-4 text-rose-600 mt-0.5 shrink-0" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-cyan-700 mt-0.5 shrink-0" />
                )}
                <div>
                  <div className="font-semibold text-slate-900">{ev.title}</div>
                  <div className="text-slate-600">{ev.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
