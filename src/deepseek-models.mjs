/**
 * DeepSeek + Local Token-Ngram Embedding Adapter for ReCall's recoverFunctions()
 *
 * Implements the exact `models` client interface expected by
 * ReCall/components/pipeline/index.mjs without modifying upstream ReCall:
 *  - embed(inputs): fast deterministic 256-dim L2-normalized JS token & trigram
 *    hashed feature vectors (zero GPU / zero API cost) for Top-K neighbor ranking.
 *  - validate({source, bundle, minified}): calls official DeepSeek Chat API
 *    using ReCall's canonical validator-system-prompt.txt, expecting 'T' or 'F'.
 */

import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { RECALL_ROOT } from './identify.mjs';

const { hash, readJSON, writeJSON } = await import(
  path.join(RECALL_ROOT, 'src/shared/artifacts.mjs')
);

const EMBED_DIM = 256;

function fnv1a(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * Deterministic structural JS code vector (256-dim unit vector)
 * Focuses on JS keywords, operators, property names, and structural trigrams
 * so cosine similarity ranks semantically & structurally similar functions high.
 */
function embedCodeLocally(rawInput) {
  // Strip ReCall's instruction prefix if present
  const idx = rawInput.indexOf('\nQuery:');
  const code = idx !== -1 ? rawInput.slice(idx + 7) : rawInput;

  const vec = new Float64Array(EMBED_DIM);

  // 1. Token features (keywords, property accesses, operators, punctuation)
  const tokens = code.match(/[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+|===|!==|==|!=|<=|>=|&&|\|\||=>|\.\.\.|[{}()[\].,;:?+\-*/%&|^!~<>]/g) || [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    // Preserve JS keywords & property names after '.', normalize arbitrary short local ids
    const prev = i > 0 ? tokens[i - 1] : '';
    const norm =
      prev === '.' || t.length > 2 || !/^[A-Za-z_$]/.test(t) ? t : '$ID';
    const h = fnv1a('T:' + norm);
    const sign = (h & 1) === 0 ? 1 : -1;
    vec[(h >>> 1) % EMBED_DIM] += sign * (prev === '.' ? 2.0 : 1.0);

    // Token bigrams capture control-flow & call shape
    if (i > 0) {
      const prevNorm = tokens[i - 1].length > 2 || !/^[A-Za-z_$]/.test(tokens[i - 1]) ? tokens[i - 1] : '$ID';
      const hb = fnv1a('B:' + prevNorm + '|' + norm);
      vec[(hb >>> 1) % EMBED_DIM] += ((hb & 1) === 0 ? 1 : -1) * 1.2;
    }
  }

  // 2. Character trigrams on compact code (resilient to minification)
  const compact = code.replace(/\s+/g, ' ').slice(0, 4000);
  for (let i = 0; i + 3 <= compact.length; i++) {
    const tri = compact.slice(i, i + 3);
    const h = fnv1a('G:' + tri);
    vec[(h >>> 1) % EMBED_DIM] += ((h & 1) === 0 ? 1 : -1) * 0.35;
  }

  // L2 normalize (guarantee non-zero finite vector)
  let normSq = 0;
  for (let i = 0; i < EMBED_DIM; i++) normSq += vec[i] * vec[i];
  if (normSq === 0) {
    vec[0] = 1;
    normSq = 1;
  }
  const inv = 1 / Math.sqrt(normSq);
  const out = new Array(EMBED_DIM);
  for (let i = 0; i < EMBED_DIM; i++) out[i] = vec[i] * inv;
  return out;
}

export function createDeepSeekModelClient({
  apiKey = process.env.DEEPSEEK_API_KEY,
  model = process.env.DEEPSEEK_MODEL || 'deepseek-chat',
  endpoint = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com/v1/chat/completions',
  cacheDir = null,
  timeoutMs = 60000
} = {}) {
  if (!apiKey) {
    throw new Error('DEEPSEEK_API_KEY is required for DeepSeek-backed ReCall recovery.');
  }

  const systemPromptPath = path.join(RECALL_ROOT, 'src/analysis/validator-system-prompt.txt');
  const systemPrompt = fs.readFileSync(systemPromptPath, 'utf8');

  const config = {
    provider: 'deepseek-api',
    endpoint,
    embeddingModel: 'local-hashed-ngram-256',
    validationModel: model,
    temperature: 0,
    cacheDir
  };

  const digests = {
    'local-hashed-ngram-256': 'local-hashed-ngram-256-v1',
    [model]: `deepseek-api:${model}`
  };

  const memory = new Map();
  const stats = {
    requests: 0,
    cacheHits: 0,
    validationCacheHits: 0,
    embeddingCacheHits: 0,
    embeddingRequests: 0,
    validationRequests: 0,
    wallMs: 0,
    inputTokens: 0,
    outputTokens: 0
  };

  return {
    config,
    stats,
    get modelDigests() {
      return { ...digests };
    },
    async metadata() {
      return { ...digests };
    },
    async embed(inputs) {
      stats.embeddingRequests++;
      return inputs.map(embedCodeLocally);
    },
    async validate({ source, bundle, minified }) {
      const user = JSON.stringify({
        source_function: source.code,
        minified_source_function: minified,
        bundled_function: bundle.code
      });

      const cacheKey = hash({ provider: 'deepseek', model, systemPrompt, user });
      if (memory.has(cacheKey)) {
        stats.cacheHits++;
        stats.validationCacheHits++;
        return memory.get(cacheKey);
      }

      const cacheFile = cacheDir ? path.join(cacheDir, 'deepseek-chat', `${cacheKey}.json`) : null;
      if (cacheFile && fs.existsSync(cacheFile)) {
        const cached = readJSON(cacheFile);
        stats.cacheHits++;
        stats.validationCacheHits++;
        memory.set(cacheKey, cached);
        return cached;
      }

      const started = performance.now();
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`
        },
        signal: AbortSignal.timeout(timeoutMs),
        body: JSON.stringify({
          model,
          temperature: 0,
          max_tokens: 16,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: user }
          ]
        })
      });

      stats.wallMs += performance.now() - started;
      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        throw new Error(`DeepSeek validate HTTP ${res.status}: ${errText.slice(0, 200)}`);
      }

      const data = await res.json();
      stats.requests++;
      stats.validationRequests++;
      stats.inputTokens += data?.usage?.prompt_tokens || 0;
      stats.outputTokens += data?.usage?.completion_tokens || 0;

      const rawText = (data?.choices?.[0]?.message?.content || '').trim();
      // Extract clean 'T' or 'F' token
      const firstToken = rawText.replace(/[^TFtf]/g, '').toUpperCase().slice(0, 1);
      const verdict = firstToken === 'T' ? 'accept' : firstToken === 'F' ? 'reject' : 'invalid';

      const result = { verdict, validator: 'model', rawText };
      memory.set(cacheKey, result);
      if (cacheFile) {
        fs.mkdirSync(path.dirname(cacheFile), { recursive: true });
        writeJSON(cacheFile, result, { overwrite: true });
      }
      return result;
    }
  };
}
