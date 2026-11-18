import { useEffect, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../services/api';
import type { MlInsightsPayload, ModelEvalMetrics } from '../types/phishguard';

function MetricCard({ title, metrics }: { title: string; metrics: ModelEvalMetrics }) {
  const cm = metrics.confusionMatrix;
  return (
    <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
      <div>
        <h3 className="font-display text-base font-semibold text-slate-900">{title}</h3>
        <p className="text-xs text-slate-500">Held-out test split: {metrics.testSamples} samples</p>
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <div className="text-slate-500">Precision</div>
          <div className="mt-1 font-mono text-lg font-bold text-cyan-700 tabular-nums">
            {(metrics.precision * 100).toFixed(1)}%
          </div>
        </div>
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <div className="text-slate-500">Recall</div>
          <div className="mt-1 font-mono text-lg font-bold text-emerald-700 tabular-nums">
            {(metrics.recall * 100).toFixed(1)}%
          </div>
        </div>
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <div className="text-slate-500">F1-Score</div>
          <div className="mt-1 font-mono text-lg font-bold text-violet-700 tabular-nums">
            {(metrics.f1Score * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
          <span className="text-slate-500">False Positive Rate</span>
          <span className="font-mono text-slate-900 tabular-nums">{(metrics.falsePositiveRate * 100).toFixed(1)}%</span>
        </div>
        <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex justify-between">
          <span className="text-slate-500">False Negative Rate</span>
          <span className="font-mono text-slate-900 tabular-nums">{(metrics.falseNegativeRate * 100).toFixed(1)}%</span>
        </div>
      </div>

      <div className="space-y-1.5">
        <div className="text-xs text-slate-500">Confusion Matrix</div>
        <div className="grid grid-cols-2 gap-2 text-xs font-mono text-center">
          <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 font-semibold">
            TP: {cm.tp}
          </div>
          <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 font-semibold">
            FP: {cm.fp}
          </div>
          <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 font-semibold">
            FN: {cm.fn}
          </div>
          <div className="p-2.5 rounded-lg bg-cyan-50 border border-cyan-200 text-cyan-800 font-semibold">
            TN: {cm.tn}
          </div>
        </div>
      </div>
    </div>
  );
}

export function MlInsightsPage() {
  const [insights, setInsights] = useState<MlInsightsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getMlInsights()
      .then(setInsights)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load ML insights.'));
  }, []);

  if (error) {
    return (
      <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-sm text-rose-800">{error}</div>
    );
  }

  if (!insights) {
    return <div className="h-64 rounded-xl bg-white border border-slate-200 animate-pulse" />;
  }

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-xl bg-white border border-slate-200 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="font-display text-lg font-semibold text-slate-900">
            Machine Learning Detection Pipeline &amp; Model Evaluation
          </h2>
          <p className="text-xs text-slate-500">
            Artifact v{insights.version} · Trained {new Date(insights.trainedAt).toLocaleDateString()} ·{' '}
            {insights.dataset.splitStrategy}
          </p>
        </div>
        <div className="text-xs font-mono text-slate-700">
          URLs: {insights.dataset.urlTrainSamples} train / {insights.dataset.urlTestSamples} test · Emails:{' '}
          {insights.dataset.emailTrainSamples} train / {insights.dataset.emailTestSamples} test
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <MetricCard
          title={insights.urlModels.logisticRegression.name}
          metrics={insights.urlModels.logisticRegression.metrics}
        />
        <MetricCard
          title={insights.urlModels.randomForest.name}
          metrics={insights.urlModels.randomForest.metrics}
        />
        <MetricCard
          title={insights.emailModel.name}
          metrics={insights.emailModel.metrics}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div>
            <h3 className="font-display text-base font-semibold text-slate-900">
              Random Forest Feature Importances
            </h3>
            <p className="text-xs text-slate-500">Normalized Gini impurity reduction across 25 decision trees</p>
          </div>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={insights.urlModels.randomForest.featureImportances.slice(0, 10)}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 30, bottom: 4 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
                <XAxis type="number" stroke="#64748B" fontSize={11} />
                <YAxis type="category" dataKey="feature" width={160} stroke="#475569" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #CBD5E1',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#0F172A',
                  }}
                />
                <Bar dataKey="importance" name="Importance" fill="#0891B2" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-4">
          <div>
            <h3 className="font-display text-base font-semibold text-slate-900">
              Email TF-IDF Predictive Tokens &amp; Confidence Limitations
            </h3>
            <p className="text-xs text-slate-500">Highest-weight phishing n-grams learned from training split</p>
          </div>

          <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
            {insights.emailModel.topPhishingTokens.slice(0, 10).map((t) => (
              <div
                key={t.term}
                className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono"
              >
                <span className="text-slate-900">{t.term}</span>
                <span className="text-orange-700 font-semibold">+{t.weight.toFixed(3)}</span>
              </div>
            ))}
          </div>

          <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
            <div className="font-semibold">Model Confidence Limitations</div>
            <p className="text-amber-800">
              Probabilities reflect statistical similarity to lexical and n-gram patterns in the curated benchmark corpus. A low ML score does NOT guarantee safety if an attacker hosts phishing pages on compromised legitimate domains or uses novel zero-day lures.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
