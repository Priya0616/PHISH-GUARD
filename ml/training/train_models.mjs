/**
 * PhishGuard ML Training & Evaluation Pipeline (Node.js)
 * Trains and evaluates:
 *   1. URL Logistic Regression (L2-regularized)
 *   2. URL Random Forest (25 bagged CART decision trees)
 *   3. Email TF-IDF + Logistic Regression
 * Strictly prevents data leakage by splitting 80/20 stratified BEFORE scaling or TF-IDF fitting.
 */
import fs from 'node:fs';
import path from 'node:path';

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy',
  'ow.ly', 'shorturl.at', 'rebrand.ly', 'v.gd', 'goo.gl', 'buff.ly',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'click', 'buzz', 'info', 'ru', 'site',
]);

const PROTECTED_BRANDS = [
  'paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'google', 'facebook',
  'linkedin', 'chase', 'wellsfargo', 'bankofamerica', 'okta', 'dhl', 'fedex',
  'stripe', 'github', 'dropbox', 'slack', 'zoom', 'citibank', 'barclays', 'hsbc',
  'americanexpress', 'capitalone', 'instagram', 'whatsapp', 'discord', 'steam',
];

const URL_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'auth',
  'banking', 'wallet', 'seed', 'unlock', 'suspend', 'billing', 'password', 'token',
  'invoice', 'payroll', 'refund', 'claim', 'credential', 'otp', 'pin', 'ssn',
];

export const URL_FEATURE_NAMES = [
  'url_length',
  'hostname_length',
  'dot_count',
  'subdomain_depth',
  'digit_ratio',
  'special_char_ratio',
  'shannon_entropy',
  'is_ip_host',
  'is_non_https',
  'is_shortener',
  'has_suspicious_tld',
  'has_at_symbol',
  'has_double_slash_path',
  'has_punycode',
  'suspicious_keyword_count',
  'brand_impersonation_score',
];

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let ent = 0;
  const len = str.length;
  for (const k in freq) {
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
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

export function extractUrlFeatureVector(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return new Array(URL_FEATURE_NAMES.length).fill(0);
  }

  const full = rawUrl.trim();
  const host = parsed.hostname.toLowerCase();
  const labels = host.split('.').filter(Boolean);
  const tld = labels.length > 0 ? labels[labels.length - 1] : '';
  const digits = (full.match(/\d/g) || []).length;
  const specials = (full.match(/[-_@?=&#%~+]/g) || []).length;
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[');
  const subdomainDepth = isIp ? 0 : Math.max(0, labels.length - 2);
  const isNonHttps = parsed.protocol !== 'https:' ? 1 : 0;
  const isShortener = URL_SHORTENERS.has(host) ? 1 : 0;
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld) ? 1 : 0;
  const hasAt = parsed.username || parsed.password || full.includes('@') ? 1 : 0;
  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const hasDoubleSlash = parsed.pathname.includes('//') || pathAndQuery.includes('http%3a') || pathAndQuery.includes('https%3a') ? 1 : 0;
  const hasPunycode = host.includes('xn--') || /[^\x00-\x7F]/.test(host) ? 1 : 0;

  const lowerFull = full.toLowerCase();
  let kwCount = 0;
  for (const kw of URL_KEYWORDS) {
    if (lowerFull.includes(kw)) kwCount++;
  }

  // Brand impersonation / typosquatting in non-canonical host
  let brandScore = 0;
  const registrable = labels.length >= 2 ? labels[labels.length - 2] : host;
  const hostTokens = host.replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').split(/[.-]/);
  for (const brand of PROTECTED_BRANDS) {
    const isExactCanonical = host === `${brand}.com` || host.endsWith(`.${brand}.com`) || host === `${brand}.org`;
    if (isExactCanonical) continue;
    if (host.includes(brand)) {
      brandScore = Math.max(brandScore, 1.0);
    } else {
      for (const tok of hostTokens) {
        if (tok.length >= 4 && Math.abs(tok.length - brand.length) <= 2) {
          const dist = levenshtein(tok, brand);
          if (dist > 0 && dist <= 2) {
            brandScore = Math.max(brandScore, dist === 1 ? 0.9 : 0.65);
          }
        }
      }
      if (registrable.includes(brand.slice(0, 5)) && levenshtein(registrable, brand) <= 3) {
        brandScore = Math.max(brandScore, 0.7);
      }
    }
  }

  return [
    full.length,
    host.length,
    (host.match(/\./g) || []).length,
    subdomainDepth,
    digits / Math.max(1, full.length),
    specials / Math.max(1, full.length),
    shannonEntropy(full),
    isIp ? 1 : 0,
    isNonHttps,
    isShortener,
    hasSuspiciousTld,
    hasAt,
    hasDoubleSlash,
    hasPunycode,
    kwCount,
    brandScore,
  ];
}

function parseCsv(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  const lines = raw.split(/\r?\n/);
  const headers = lines[0].split(',');
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const cols = [];
    let cur = '';
    let inQuotes = false;
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === '"' && line[c + 1] === '"') {
        cur += '"';
        c++;
      } else if (ch === '"') {
        inQuotes = !inQuotes;
      } else if (ch === ',' && !inQuotes) {
        cols.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    cols.push(cur);
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h.trim()] = (cols[idx] ?? '').trim();
    });
    rows.push(obj);
  }
  return rows;
}

function createRng(seed = 42) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

function stratifiedSplit(items, labelFn, testRatio = 0.2, seed = 42) {
  const rng = createRng(seed);
  const pos = items.filter((x) => labelFn(x) === 1);
  const neg = items.filter((x) => labelFn(x) === 0);
  const shuffle = (arr) => {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  };
  const posS = shuffle(pos);
  const negS = shuffle(neg);
  const posTestN = Math.max(1, Math.round(posS.length * testRatio));
  const negTestN = Math.max(1, Math.round(negS.length * testRatio));
  const test = shuffle([...posS.slice(0, posTestN), ...negS.slice(0, negTestN)]);
  const train = shuffle([...posS.slice(posTestN), ...negS.slice(negTestN)]);
  return { train, test };
}

function sigmoid(z) {
  if (z > 35) return 1;
  if (z < -35) return 0;
  return 1 / (1 + Math.exp(-z));
}

function fitScaler(X) {
  const dims = X[0].length;
  const mean = new Array(dims).fill(0);
  const std = new Array(dims).fill(1);
  for (const row of X) {
    for (let j = 0; j < dims; j++) mean[j] += row[j];
  }
  for (let j = 0; j < dims; j++) mean[j] /= X.length;
  for (const row of X) {
    for (let j = 0; j < dims; j++) std[j] += (row[j] - mean[j]) ** 2;
  }
  for (let j = 0; j < dims; j++) {
    std[j] = Math.sqrt(std[j] / X.length) || 1;
  }
  return { mean, std };
}

function applyScaler(X, scaler) {
  return X.map((row) => row.map((v, j) => (v - scaler.mean[j]) / scaler.std[j]));
}

function trainLogisticRegression(X, y, { lr = 0.12, epochs = 450, l2 = 0.02 } = {}) {
  const dims = X[0].length;
  const weights = new Array(dims).fill(0);
  let bias = 0;
  const n = X.length;

  for (let ep = 0; ep < epochs; ep++) {
    const gradW = new Array(dims).fill(0);
    let gradB = 0;
    for (let i = 0; i < n; i++) {
      let z = bias;
      for (let j = 0; j < dims; j++) z += weights[j] * X[i][j];
      const pred = sigmoid(z);
      const err = pred - y[i];
      gradB += err;
      for (let j = 0; j < dims; j++) gradW[j] += err * X[i][j];
    }
    bias -= (lr / n) * gradB;
    for (let j = 0; j < dims; j++) {
      weights[j] -= lr * (gradW[j] / n + l2 * weights[j]);
    }
  }
  return { weights, bias };
}

function predictLogRegProba(model, x) {
  let z = model.bias;
  for (let j = 0; j < model.weights.length; j++) z += model.weights[j] * x[j];
  return sigmoid(z);
}

// CART Decision Tree + Random Forest
function giniImpurity(labels) {
  if (labels.length === 0) return 0;
  let ones = 0;
  for (const l of labels) if (l === 1) ones++;
  const p = ones / labels.length;
  return 1 - (p * p + (1 - p) * (1 - p));
}

function buildTree(X, y, depth, maxDepth, minSamples, maxFeatures, rng, importances) {
  const ones = y.reduce((a, b) => a + b, 0);
  const prob = y.length ? ones / y.length : 0.5;
  if (depth >= maxDepth || y.length < minSamples || ones === 0 || ones === y.length) {
    return { leaf: true, prob };
  }

  const dims = X[0].length;
  const indices = Array.from({ length: dims }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  const candidateFeatures = indices.slice(0, maxFeatures);

  const parentGini = giniImpurity(y);
  let bestGain = 0;
  let bestFeat = -1;
  let bestThresh = 0;

  for (const f of candidateFeatures) {
    const vals = Array.from(new Set(X.map((r) => r[f]))).sort((a, b) => a - b);
    if (vals.length < 2) continue;
    for (let i = 0; i < vals.length - 1; i++) {
      const thresh = (vals[i] + vals[i + 1]) / 2;
      const leftY = [];
      const rightY = [];
      for (let r = 0; r < X.length; r++) {
        if (X[r][f] <= thresh) leftY.push(y[r]);
        else rightY.push(y[r]);
      }
      if (leftY.length === 0 || rightY.length === 0) continue;
      const weightedGini = (leftY.length / y.length) * giniImpurity(leftY) + (rightY.length / y.length) * giniImpurity(rightY);
      const gain = parentGini - weightedGini;
      if (gain > bestGain) {
        bestGain = gain;
        bestFeat = f;
        bestThresh = thresh;
      }
    }
  }

  if (bestFeat === -1 || bestGain <= 1e-6) {
    return { leaf: true, prob };
  }

  importances[bestFeat] += bestGain * y.length;

  const leftX = [];
  const leftY = [];
  const rightX = [];
  const rightY = [];
  for (let r = 0; r < X.length; r++) {
    if (X[r][bestFeat] <= bestThresh) {
      leftX.push(X[r]);
      leftY.push(y[r]);
    } else {
      rightX.push(X[r]);
      rightY.push(y[r]);
    }
  }

  return {
    leaf: false,
    feature: bestFeat,
    threshold: bestThresh,
    left: buildTree(leftX, leftY, depth + 1, maxDepth, minSamples, maxFeatures, rng, importances),
    right: buildTree(rightX, rightY, depth + 1, maxDepth, minSamples, maxFeatures, rng, importances),
  };
}

function trainRandomForest(X, y, nTrees = 25, maxDepth = 6, minSamples = 3, seed = 42) {
  const rng = createRng(seed);
  const dims = X[0].length;
  const maxFeatures = Math.max(2, Math.round(Math.sqrt(dims)));
  const importances = new Array(dims).fill(0);
  const trees = [];

  for (let t = 0; t < nTrees; t++) {
    const bootX = [];
    const bootY = [];
    for (let i = 0; i < X.length; i++) {
      const idx = Math.floor(rng() * X.length);
      bootX.push(X[idx]);
      bootY.push(y[idx]);
    }
    trees.push(buildTree(bootX, bootY, 0, maxDepth, minSamples, maxFeatures, rng, importances));
  }

  const totalImp = importances.reduce((a, b) => a + b, 0) || 1;
  const normalizedImportances = importances.map((v) => Number((v / totalImp).toFixed(4)));
  return { trees, featureImportances: normalizedImportances };
}

function predictTree(node, x) {
  if (node.leaf) return node.prob;
  return x[node.feature] <= node.threshold ? predictTree(node.left, x) : predictTree(node.right, x);
}

function predictForestProba(trees, x) {
  let sum = 0;
  for (const t of trees) sum += predictTree(t, x);
  return sum / trees.length;
}

function computeMetrics(yTrue, yProbs, threshold = 0.5) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (let i = 0; i < yTrue.length; i++) {
    const pred = yProbs[i] >= threshold ? 1 : 0;
    const actual = yTrue[i];
    if (pred === 1 && actual === 1) tp++;
    else if (pred === 1 && actual === 0) fp++;
    else if (pred === 0 && actual === 0) tn++;
    else fn++;
  }
  const accuracy = (tp + tn) / Math.max(1, yTrue.length);
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp / Math.max(1, fp + tn);
  const fnr = fn / Math.max(1, fn + tp);
  return {
    accuracy: Number(accuracy.toFixed(4)),
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1Score: Number(f1.toFixed(4)),
    falsePositiveRate: Number(fpr.toFixed(4)),
    falseNegativeRate: Number(fnr.toFixed(4)),
    confusionMatrix: { tp, fp, tn, fn },
    testSamples: yTrue.length,
  };
}

// Email TF-IDF tokenization
export function tokenizeText(text) {
  const clean = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ');
  const unigrams = clean.split(/\s+/).filter((w) => w.length >= 2);
  const tokens = [...unigrams];
  for (let i = 0; i < unigrams.length - 1; i++) {
    tokens.push(`${unigrams[i]}_${unigrams[i + 1]}`);
  }
  return tokens;
}

function fitTfIdf(docs, maxVocab = 260, minDf = 2) {
  const df = {};
  const tokenized = docs.map((d) => tokenizeText(d));
  for (const toks of tokenized) {
    const uniq = new Set(toks);
    for (const t of uniq) df[t] = (df[t] || 0) + 1;
  }
  const N = docs.length;
  const vocabList = Object.entries(df)
    .filter(([, count]) => count >= minDf && count < N * 0.9)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxVocab)
    .map(([term]) => term);

  const vocabIndex = {};
  vocabList.forEach((t, i) => {
    vocabIndex[t] = i;
  });

  const idf = vocabList.map((t) => Math.log((N + 1) / ((df[t] || 0) + 1)) + 1);
  return { vocabList, vocabIndex, idf };
}

function transformTfIdf(docs, tfidf) {
  return docs.map((d) => {
    const toks = tokenizeText(d);
    const tf = {};
    for (const t of toks) {
      if (t in tfidf.vocabIndex) tf[t] = (tf[t] || 0) + 1;
    }
    const vec = new Array(tfidf.vocabList.length).fill(0);
    let norm = 0;
    for (const t in tf) {
      const idx = tfidf.vocabIndex[t];
      const val = (tf[t] / Math.max(1, toks.length)) * tfidf.idf[idx];
      vec[idx] = val;
      norm += val * val;
    }
    norm = Math.sqrt(norm) || 1;
    return vec.map((v) => v / norm);
  });
}

function runTraining() {
  const rootDir = process.cwd();
  const urlRows = parseCsv(path.join(rootDir, 'ml/datasets/phishing_urls_corpus.csv'));
  const emailRows = parseCsv(path.join(rootDir, 'ml/datasets/phishing_emails_corpus.csv'));

  // 1. URL Dataset Split (no leakage)
  const urlSplit = stratifiedSplit(urlRows, (r) => Number(r.label), 0.2, 42);
  const XUrlTrainRaw = urlSplit.train.map((r) => extractUrlFeatureVector(r.url));
  const yUrlTrain = urlSplit.train.map((r) => Number(r.label));
  const XUrlTestRaw = urlSplit.test.map((r) => extractUrlFeatureVector(r.url));
  const yUrlTest = urlSplit.test.map((r) => Number(r.label));

  const urlScaler = fitScaler(XUrlTrainRaw);
  const XUrlTrainScaled = applyScaler(XUrlTrainRaw, urlScaler);
  const XUrlTestScaled = applyScaler(XUrlTestRaw, urlScaler);

  const urlLogReg = trainLogisticRegression(XUrlTrainScaled, yUrlTrain, { lr: 0.15, epochs: 500, l2: 0.015 });
  const urlLogRegProbs = XUrlTestScaled.map((x) => predictLogRegProba(urlLogReg, x));
  const urlLogRegMetrics = computeMetrics(yUrlTest, urlLogRegProbs);

  const urlForest = trainRandomForest(XUrlTrainRaw, yUrlTrain, 25, 6, 3, 42);
  const urlForestProbs = XUrlTestRaw.map((x) => predictForestProba(urlForest.trees, x));
  const urlForestMetrics = computeMetrics(yUrlTest, urlForestProbs);

  // 2. Email Dataset Split (no leakage)
  const emailSplit = stratifiedSplit(emailRows, (r) => Number(r.label), 0.2, 42);
  const emailTrainDocs = emailSplit.train.map((r) => `${r.subject} ${r.body}`);
  const yEmailTrain = emailSplit.train.map((r) => Number(r.label));
  const emailTestDocs = emailSplit.test.map((r) => `${r.subject} ${r.body}`);
  const yEmailTest = emailSplit.test.map((r) => Number(r.label));

  const tfidf = fitTfIdf(emailTrainDocs, 260, 2);
  const XEmailTrain = transformTfIdf(emailTrainDocs, tfidf);
  const XEmailTest = transformTfIdf(emailTestDocs, tfidf);

  const emailLogReg = trainLogisticRegression(XEmailTrain, yEmailTrain, { lr: 0.8, epochs: 600, l2: 0.003 });
  const emailProbs = XEmailTest.map((x) => predictLogRegProba(emailLogReg, x));
  const emailMetrics = computeMetrics(yEmailTest, emailProbs);

  const topPositiveEmailTokens = tfidf.vocabList
    .map((term, idx) => ({ term, weight: Number(emailLogReg.weights[idx].toFixed(4)) }))
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 15);

  const topNegativeEmailTokens = tfidf.vocabList
    .map((term, idx) => ({ term, weight: Number(emailLogReg.weights[idx].toFixed(4)) }))
    .sort((a, b) => a.weight - b.weight)
    .slice(0, 10);

  const artifact = {
    version: '1.2.0',
    trainedAt: new Date().toISOString(),
    dataset: {
      urlCorpusSamples: urlRows.length,
      urlTrainSamples: urlSplit.train.length,
      urlTestSamples: urlSplit.test.length,
      emailCorpusSamples: emailRows.length,
      emailTrainSamples: emailSplit.train.length,
      emailTestSamples: emailSplit.test.length,
      splitStrategy: 'Stratified 80/20 (seed=42), zero test leakage',
    },
    urlFeatureNames: URL_FEATURE_NAMES,
    urlScaler,
    urlModels: {
      logisticRegression: {
        name: 'L2-Regularized Logistic Regression',
        weights: urlLogReg.weights.map((w) => Number(w.toFixed(6))),
        bias: Number(urlLogReg.bias.toFixed(6)),
        metrics: urlLogRegMetrics,
      },
      randomForest: {
        name: 'Random Forest (25 Bagged CART Trees)',
        trees: urlForest.trees,
        featureImportances: URL_FEATURE_NAMES.map((name, i) => ({
          feature: name,
          importance: urlForest.featureImportances[i],
        })).sort((a, b) => b.importance - a.importance),
        metrics: urlForestMetrics,
      },
    },
    emailModel: {
      name: 'TF-IDF (Unigram+Bigram) + L2 Logistic Regression',
      vocabList: tfidf.vocabList,
      idf: tfidf.idf.map((v) => Number(v.toFixed(6))),
      weights: emailLogReg.weights.map((w) => Number(w.toFixed(6))),
      bias: Number(emailLogReg.bias.toFixed(6)),
      metrics: emailMetrics,
      topPhishingTokens: topPositiveEmailTokens,
      topBenignTokens: topNegativeEmailTokens,
    },
  };

  const outPath = path.join(rootDir, 'ml/models/phishguard_models.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(artifact, null, 2));
  console.log('Trained PhishGuard ML models successfully:');
  console.log('URL Logistic Regression:', urlLogRegMetrics);
  console.log('URL Random Forest:', urlForestMetrics);
  console.log('Email TF-IDF + LogReg:', emailMetrics);
}

runTraining();
