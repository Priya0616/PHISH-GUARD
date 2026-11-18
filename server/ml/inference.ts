import fs from 'node:fs';
import path from 'node:path';
import type { MlInsightsPayload, MlModelPrediction, ModelEvalMetrics } from '../../src/types/phishguard.ts';

interface CartTreeNode {
  leaf: boolean;
  prob?: number;
  feature?: number;
  threshold?: number;
  left?: CartTreeNode;
  right?: CartTreeNode;
}

interface TrainedModelArtifact {
  version: string;
  trainedAt: string;
  dataset: MlInsightsPayload['dataset'];
  urlFeatureNames: string[];
  urlScaler: { mean: number[]; std: number[] };
  urlModels: {
    logisticRegression: {
      name: string;
      weights: number[];
      bias: number;
      metrics: ModelEvalMetrics;
    };
    randomForest: {
      name: string;
      trees: CartTreeNode[];
      featureImportances: Array<{ feature: string; importance: number }>;
      metrics: ModelEvalMetrics;
    };
  };
  emailModel: {
    name: string;
    vocabList: string[];
    idf: number[];
    weights: number[];
    bias: number;
    metrics: ModelEvalMetrics;
    topPhishingTokens: Array<{ term: string; weight: number }>;
    topBenignTokens: Array<{ term: string; weight: number }>;
  };
}

let cachedArtifact: TrainedModelArtifact | null = null;

function loadArtifact(): TrainedModelArtifact {
  if (cachedArtifact) return cachedArtifact;
  const modelPath = path.join(process.cwd(), 'ml/models/phishguard_models.json');
  const raw = fs.readFileSync(modelPath, 'utf8');
  cachedArtifact = JSON.parse(raw) as TrainedModelArtifact;
  return cachedArtifact;
}

function sigmoid(z: number): number {
  if (z > 35) return 1;
  if (z < -35) return 0;
  return 1 / (1 + Math.exp(-z));
}

function predictTree(node: CartTreeNode, x: number[]): number {
  if (node.leaf) return node.prob ?? 0.5;
  const featIdx = node.feature ?? 0;
  const thresh = node.threshold ?? 0;
  if (x[featIdx] <= thresh) {
    return node.left ? predictTree(node.left, x) : 0.5;
  }
  return node.right ? predictTree(node.right, x) : 0.5;
}

export function getMlInsights(): MlInsightsPayload {
  const art = loadArtifact();
  return {
    version: art.version,
    trainedAt: art.trainedAt,
    dataset: art.dataset,
    urlModels: {
      logisticRegression: {
        name: art.urlModels.logisticRegression.name,
        metrics: art.urlModels.logisticRegression.metrics,
      },
      randomForest: {
        name: art.urlModels.randomForest.name,
        featureImportances: art.urlModels.randomForest.featureImportances,
        metrics: art.urlModels.randomForest.metrics,
      },
    },
    emailModel: {
      name: art.emailModel.name,
      metrics: art.emailModel.metrics,
      topPhishingTokens: art.emailModel.topPhishingTokens,
      topBenignTokens: art.emailModel.topBenignTokens,
    },
  };
}

export function predictUrlModels(featureVector: number[]): {
  logisticRegression: MlModelPrediction;
  randomForest: MlModelPrediction;
  ensembleProbability: number;
  modelVersion: string;
} {
  const art = loadArtifact();

  // 1. Logistic Regression with training scaler
  const scaled = featureVector.map(
    (v, j) => (v - (art.urlScaler.mean[j] ?? 0)) / (art.urlScaler.std[j] || 1)
  );
  let z = art.urlModels.logisticRegression.bias;
  for (let j = 0; j < art.urlModels.logisticRegression.weights.length; j++) {
    z += art.urlModels.logisticRegression.weights[j] * (scaled[j] ?? 0);
  }
  const lrProb = sigmoid(z);
  const lrConf = Math.round(Math.abs(lrProb - 0.5) * 200);

  // 2. Random Forest (raw feature vector)
  const trees = art.urlModels.randomForest.trees;
  let rfSum = 0;
  for (const tree of trees) {
    rfSum += predictTree(tree, featureVector);
  }
  const rfProb = trees.length > 0 ? rfSum / trees.length : 0.5;
  const rfConf = Math.round(Math.abs(rfProb - 0.5) * 200);

  const ensembleProbability = Number(((lrProb + rfProb) / 2).toFixed(4));
  const limitationText =
    'Classifier probability measures lexical/structural similarity to the benchmark corpus; it is NOT a guarantee of safety against compromised legitimate domains or novel obfuscation.';

  return {
    modelVersion: art.version,
    ensembleProbability,
    logisticRegression: {
      modelName: art.urlModels.logisticRegression.name,
      modelVersion: art.version,
      classification: lrProb >= 0.5 ? 'phishing' : 'benign',
      phishingProbability: Number(lrProb.toFixed(4)),
      confidenceScore: Math.min(99, Math.max(5, lrConf)),
      limitationsNote: limitationText,
    },
    randomForest: {
      modelName: art.urlModels.randomForest.name,
      modelVersion: art.version,
      classification: rfProb >= 0.5 ? 'phishing' : 'benign',
      phishingProbability: Number(rfProb.toFixed(4)),
      confidenceScore: Math.min(99, Math.max(5, rfConf)),
      limitationsNote: limitationText,
    },
  };
}

export function predictEmailModel(subject: string, body: string): MlModelPrediction & {
  topMatchedTokens: Array<{ term: string; weight: number }>;
} {
  const art = loadArtifact();
  const em = art.emailModel;

  const clean = `${subject} ${body}`.toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
  const unigrams = clean.split(/\s+/).filter((w) => w.length >= 2);
  const tokens = [...unigrams];
  for (let i = 0; i < unigrams.length - 1; i++) {
    tokens.push(`${unigrams[i]}_${unigrams[i + 1]}`);
  }

  const vocabIndex = new Map<string, number>();
  em.vocabList.forEach((term, idx) => vocabIndex.set(term, idx));

  const tf = new Map<number, number>();
  for (const tok of tokens) {
    const idx = vocabIndex.get(tok);
    if (idx !== undefined) {
      tf.set(idx, (tf.get(idx) ?? 0) + 1);
    }
  }

  const vec = new Array<number>(em.vocabList.length).fill(0);
  let norm = 0;
  for (const [idx, count] of tf.entries()) {
    const val = (count / Math.max(1, tokens.length)) * (em.idf[idx] ?? 1);
    vec[idx] = val;
    norm += val * val;
  }
  norm = Math.sqrt(norm) || 1;

  let z = em.bias;
  const contributions: Array<{ term: string; weight: number }> = [];
  for (const [idx] of tf.entries()) {
    const normalizedTfIdf = vec[idx] / norm;
    const w = em.weights[idx] ?? 0;
    z += normalizedTfIdf * w;
    contributions.push({
      term: em.vocabList[idx] ?? '',
      weight: Number((normalizedTfIdf * w).toFixed(4)),
    });
  }

  const prob = sigmoid(z);
  const conf = Math.min(99, Math.max(5, Math.round(Math.abs(prob - 0.5) * 200)));

  return {
    modelName: em.name,
    modelVersion: art.version,
    classification: prob >= 0.5 ? 'phishing' : 'benign',
    phishingProbability: Number(prob.toFixed(4)),
    confidenceScore: conf,
    limitationsNote:
      'TF-IDF classification reflects vocabulary and bigram frequency patterns; short emails or image-only lures may receive lower statistical confidence.',
    topMatchedTokens: contributions
      .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
      .slice(0, 8),
  };
}
