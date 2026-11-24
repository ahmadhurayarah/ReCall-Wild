#!/usr/bin/env node
/**
 * RQ4 A/B Study — Condition 1: Baseline (WITHOUT ReCall)
 *
 * Runs a standardized defensive client-side security audit prompt
 * (adapted from cloudflare/security-audit-skill CLIENT-SIDE.md)
 * directly on raw, minified production JavaScript bundles using
 * the official DeepSeek API (OpenAI-compatible) or local Ollama.
 *
 * Usage:
 *   node experiments/rq4-ab-study/run-condition1-baseline.mjs \
 *     --url http://localhost:3000 \
 *     --max-chunks 20
 *
 *   node experiments/rq4-ab-study/run-condition1-baseline.mjs \
 *     --bundle output/captured-bundle/chunk_1_index-Gx3_I0g8.js \
 *     --max-chunks 20
 *
 * Dry-run (verifies chunking & prompt without calling API):
 *   node experiments/rq4-ab-study/run-condition1-baseline.mjs \
 *     --bundle output/captured-bundle/chunk_1_index-Gx3_I0g8.js \
 *     --dry-run
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { captureFromUrl } from '../../src/capture.mjs';
import { SYSTEM_PROMPT, renderWarningsMarkdownTable } from './audit-prompt.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

// Auto-load .env from ReCall-Wild root or current working directory
for (const envCandidate of [path.join(REPO_ROOT, '.env'), path.resolve(process.cwd(), '.env')]) {
  if (fs.existsSync(envCandidate)) {
    const lines = fs.readFileSync(envCandidate, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      if (key && !(key in process.env)) {
        process.env[key] = val;
      }
    }
    break;
  }
}

const args = process.argv.slice(2);

function getArg(flag, fallback = null) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
  return fallback;
}

const hasFlag = (flag) => args.includes(flag);

const bundlePath = getArg('--bundle');
const targetUrl = getArg('--url');
const targetName = targetUrl
  ? new URL(targetUrl).host.replace(/[^a-zA-Z0-9.-]/g, '_')
  : bundlePath
    ? path.basename(bundlePath, '.js')
    : 'unknown-target';

let providerArg = getArg('--provider');
let modelArg = getArg('--model');

// Auto-detect provider from model name if --provider is omitted
let provider = (providerArg || '').toLowerCase();
if (!provider && modelArg) {
  const m = modelArg.toLowerCase();
  if (m.startsWith('gemini')) provider = 'gemini';
  else if (m.startsWith('deepseek')) provider = 'deepseek';
  else if (m.startsWith('gpt-') || m.startsWith('o1') || m.startsWith('o3')) provider = 'openai';
  else if (m.includes('qwen') || m.includes('llama') || m.includes(':')) provider = 'ollama';
}
if (!provider) provider = 'deepseek';

let model = modelArg;
if (!model) {
  if (provider === 'gemini') model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  else if (provider === 'deepseek') model = process.env.DEEPSEEK_MODEL || 'deepseek-chat';
  else if (provider === 'openai') model = process.env.OPENAI_MODEL || 'gpt-4o';
  else if (provider === 'ollama') model = process.env.OLLAMA_MODEL || 'qwen3.5:27b';
  else model = 'deepseek-chat';
}

const endpoint = getArg(
  '--endpoint',
  provider === 'gemini'
    ? process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'
    : provider === 'deepseek'
      ? process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com/v1/chat/completions'
      : provider === 'openai'
        ? process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1/chat/completions'
        : process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434/v1/chat/completions'
);
const chunkSize = parseInt(getArg('--chunk-size', '12000'), 10);
const chunkOverlap = parseInt(getArg('--overlap', '500'), 10);
const maxChunks = parseInt(getArg('--max-chunks', '20'), 10);
const outDir = path.resolve(
  process.cwd(),
  getArg('--out', `results/rq4-ab/${targetName}/condition1-baseline`)
);
const dryRun = hasFlag('--dry-run');

if ((!bundlePath && !targetUrl) || hasFlag('--help') || hasFlag('-h')) {
  console.log(`
RQ4 A/B Study — Condition 1: Baseline (WITHOUT ReCall)

Options:
  --bundle <path>       Path to local raw minified JavaScript bundle
  --url <http(s)://...> Live website or localhost URL to crawl & scan
  --provider <name>     'deepseek' (default), 'gemini', 'openai', or 'ollama'
  --model <name>        Model ID (e.g. 'gemini-2.5-flash', 'deepseek-chat', 'gpt-4o')
  --endpoint <url>      Custom completions URL
  --chunk-size <n>      Characters per chunk (default: 12000)
  --overlap <n>         Overlap characters between chunks (default: 500)
  --max-chunks <n>      Max chunks to scan per bundle (default: 20)
  --out <dir>           Output directory (default: results/rq4-ab/<host-or-file>/condition1-baseline)
  --dry-run             Verify chunking and prompt construction without API calls
`);
  process.exit(bundlePath || targetUrl ? 0 : 1);
}

let resolvedBundle = bundlePath ? path.resolve(process.cwd(), bundlePath) : null;
if (resolvedBundle && !fs.existsSync(resolvedBundle)) {
  console.error(`Error: Bundle file not found: ${resolvedBundle}`);
  process.exit(1);
}

let apiKey = '';
if (provider === 'gemini') {
  apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';
} else if (provider === 'deepseek') {
  apiKey = process.env.DEEPSEEK_API_KEY || '';
} else if (provider === 'openai') {
  apiKey = process.env.OPENAI_API_KEY || '';
} else if (provider === 'ollama') {
  apiKey = 'ollama';
}

if (!dryRun && provider !== 'ollama' && !apiKey) {
  const envName = provider === 'gemini' ? 'GEMINI_API_KEY' : provider === 'openai' ? 'OPENAI_API_KEY' : 'DEEPSEEK_API_KEY';
  console.error(`Error: ${envName} environment variable is not set.`);
  console.error(`Run: export ${envName}="your-api-key-here"`);
  process.exit(1);
}

/**
 * Split raw minified JavaScript into deterministic overlapping chunks
 */
function chunkCode(code, size, overlap, limit) {
  const chunks = [];
  const step = Math.max(1, size - overlap);
  for (let start = 0; start < code.length && chunks.length < limit; start += step) {
    const end = Math.min(code.length, start + size);
    const slice = code.slice(start, end);
    const sha256 = crypto.createHash('sha256').update(slice).digest('hex').slice(0, 12);
    chunks.push({
      index: chunks.length + 1,
      start,
      end,
      length: slice.length,
      sha256,
      code: slice
    });
    if (end >= code.length) break;
  }
  return chunks;
}

/**
 * Call Chat Completions API (DeepSeek / Gemini / OpenAI / Ollama)
 */
async function auditChunkWithLLM(chunk) {
  const userPrompt = `Inspect the following raw, minified client-side JavaScript bundle chunk (Condition 1: Baseline without function recovery) and return any potential security vulnerability warnings in strict JSON format.

Chunk ID: ${chunk.index} (bytes ${chunk.start}-${chunk.end})
\`\`\`javascript
${chunk.code}
\`\`\``;

  const t0 = performance.now();
  const isNativeGemini = endpoint.includes(':generateContent');
  const requestUrl = (isNativeGemini && !endpoint.includes('key='))
    ? `${endpoint}${endpoint.includes('?') ? '&' : '?'}key=${apiKey}`
    : endpoint;

  const headers = { 'Content-Type': 'application/json' };
  let requestBody;

  if (isNativeGemini) {
    requestBody = JSON.stringify({
      system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
      contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
      generationConfig: {
        temperature: 0.0,
        response_mime_type: 'application/json'
      }
    });
  } else {
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
    requestBody = JSON.stringify({
      model,
      temperature: 0.0,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt }
      ]
    });
  }

  const res = await fetch(requestUrl, {
    method: 'POST',
    headers,
    body: requestBody
  });

  const elapsedMs = Math.round(performance.now() - t0);
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`HTTP ${res.status} from ${provider} (${model}): ${errText.slice(0, 300)}`);
  }

  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content
    || data?.candidates?.[0]?.content?.parts?.[0]?.text
    || '{"warnings":[]}';
  const usageRaw = data?.usage || data?.usageMetadata || {};
  const promptTokens = usageRaw.prompt_tokens ?? usageRaw.promptTokenCount ?? 0;
  const completionTokens = usageRaw.completion_tokens ?? usageRaw.candidatesTokenCount ?? 0;
  const totalTokens = usageRaw.total_tokens ?? usageRaw.totalTokenCount ?? (promptTokens + completionTokens);
  const usage = {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: totalTokens
  };

  let parsed = { warnings: [] };
  try {
    const cleaned = content.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
    parsed = JSON.parse(cleaned);
    if (!Array.isArray(parsed.warnings)) parsed.warnings = [];
  } catch (err) {
    parsed = { warnings: [], parseError: err.message, rawResponse: content.slice(0, 500) };
  }

  return {
    chunkIndex: chunk.index,
    byteRange: [chunk.start, chunk.end],
    sha256: chunk.sha256,
    elapsedMs,
    usage,
    warnings: parsed.warnings,
    ...(parsed.parseError ? { parseError: parsed.parseError } : {})
  };
}

async function main() {
  fs.mkdirSync(outDir, { recursive: true });

  if (targetUrl && !resolvedBundle) {
    const captureDir = path.join(outDir, 'captured-bundle');
    const captured = await captureFromUrl(targetUrl, captureDir);
    if (!captured.bundleFiles || captured.bundleFiles.length === 0) {
      throw new Error(`No external JavaScript bundles found at ${targetUrl}`);
    }
    // Select the largest captured JS bundle (typically the main application bundle)
    const sorted = [...captured.bundleFiles].sort((a, b) => b.bytes - a.bytes);
    resolvedBundle = path.join(captureDir, sorted[0].path);
    console.log(
      `[Capture] Selected primary bundle: ${sorted[0].path} (${(sorted[0].bytes / 1024).toFixed(1)} KB) from ${sorted[0].url}\n`
    );
  }

  const rawCode = fs.readFileSync(resolvedBundle, 'utf8');
  const bundleSha256 = crypto.createHash('sha256').update(rawCode).digest('hex');
  const chunks = chunkCode(rawCode, chunkSize, chunkOverlap, maxChunks);

  console.log('===================================================================');
  console.log('  RQ4 A/B Study — Condition 1: Baseline (WITHOUT ReCall)');
  console.log('===================================================================');
  console.log(`Target:      ${targetName}`);
  if (targetUrl) console.log(`Source URL:  ${targetUrl}`);
  console.log(`Bundle:      ${resolvedBundle} (${(rawCode.length / 1024).toFixed(1)} KB)`);
  console.log(`Provider:    ${provider} (${model})`);
  console.log(`Endpoint:    ${endpoint}`);
  console.log(`Chunks:      ${chunks.length} (size=${chunkSize}, overlap=${chunkOverlap}, max=${maxChunks})`);
  console.log(`Output Dir:  ${outDir}`);
  console.log(`Mode:        ${dryRun ? 'DRY RUN (No API calls)' : 'LIVE API SCAN'}\n`);

  if (dryRun) {
    const dryReport = {
      condition: 'condition1_baseline_without_recall',
      dryRun: true,
      target: targetName,
      bundlePath: resolvedBundle,
      bundleBytes: rawCode.length,
      bundleSha256,
      provider,
      model,
      chunksPrepared: chunks.map(({ code, ...meta }) => meta)
    };
    const outFile = path.join(outDir, 'condition1-dryrun.json');
    fs.writeFileSync(outFile, JSON.stringify(dryReport, null, 2));
    console.log(`[Dry Run] Successfully prepared ${chunks.length} deterministic chunks.`);
    console.log(`[Dry Run] Metadata written to: ${outFile}`);
    return;
  }

  const chunkResults = [];
  const allWarnings = [];
  let totalPromptTokens = 0;
  let totalCompletionTokens = 0;
  let totalTokensUsed = 0;
  const startAll = performance.now();

  for (const chunk of chunks) {
    process.stdout.write(`Scanning chunk ${chunk.index}/${chunks.length} (${chunk.length} chars)... `);
    try {
      const result = await auditChunkWithLLM(chunk);
      chunkResults.push(result);
      totalPromptTokens += result.usage?.prompt_tokens || 0;
      totalCompletionTokens += result.usage?.completion_tokens || 0;
      totalTokensUsed += result.usage?.total_tokens || 0;

      for (const w of result.warnings) {
        allWarnings.push({ chunkIndex: chunk.index, ...w });
      }
      console.log(`done (${result.elapsedMs}ms) -> ${result.warnings.length} warning(s)`);
    } catch (err) {
      console.log(`FAILED: ${err.message}`);
      chunkResults.push({
        chunkIndex: chunk.index,
        byteRange: [chunk.start, chunk.end],
        sha256: chunk.sha256,
        error: err.message,
        warnings: []
      });
    }
  }

  if (totalTokensUsed === 0) {
    totalTokensUsed = totalPromptTokens + totalCompletionTokens;
  }
  const totalElapsedMs = Math.round(performance.now() - startAll);

  // Aggregate by category and severity
  const byCategory = {};
  const bySeverity = { high: 0, medium: 0, low: 0 };
  for (const w of allWarnings) {
    const cat = w.category || 'Other';
    byCategory[cat] = (byCategory[cat] || 0) + 1;
    const sev = (w.severity || 'low').toLowerCase();
    if (sev in bySeverity) bySeverity[sev]++;
  }

  const report = {
    condition: 'condition1_baseline_without_recall',
    timestamp: new Date().toISOString(),
    target: targetName,
    bundlePath: resolvedBundle,
    bundleBytes: rawCode.length,
    bundleSha256,
    provider,
    model,
    chunkConfig: { chunkSize, chunkOverlap, chunksScanned: chunks.length },
    summary: {
      totalWarnings: allWarnings.length,
      bySeverity,
      byCategory,
      totalElapsedMs,
      totalPromptTokens,
      totalCompletionTokens,
      totalTokens: totalTokensUsed
    },
    warnings: allWarnings,
    chunkResults
  };

  const jsonPath = path.join(outDir, 'condition1-baseline.json');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  // Generate clean Markdown summary
  const mdLines = [
    `# RQ4 Condition 1 (Baseline — Without ReCall) Report`,
    ``,
    `- **Target:** \`${targetName}\``,
    `- **Bundle:** \`${path.basename(resolvedBundle)}\` (${(rawCode.length / 1024).toFixed(1)} KB)`,
    `- **LLM Provider / Model:** \`${provider}\` / \`${model}\``,
    `- **Chunks Scanned:** ${chunks.length}`,
    `- **Total Runtime:** ${(totalElapsedMs / 1000).toFixed(2)}s`,
    `- **Total Tokens Used:** **${totalTokensUsed.toLocaleString()}** (Prompt: ${totalPromptTokens.toLocaleString()}, Completion: ${totalCompletionTokens.toLocaleString()})`,
    `- **Total Warnings Reported (N_before):** **${allWarnings.length}**`,
    ``,
    `## Warning Breakdown by Severity`,
    `| Severity | Count |`,
    `| :--- | :--- |`,
    `| High | ${bySeverity.high} |`,
    `| Medium | ${bySeverity.medium} |`,
    `| Low | ${bySeverity.low} |`,
    ``,
    `## Warning Breakdown by Category`,
    `| Category | Count |`,
    `| :--- | :--- |`,
    ...(Object.keys(byCategory).length > 0
      ? Object.entries(byCategory).map(([k, v]) => `| ${k} | ${v} |`)
      : [`| None | 0 |`]),
    ``,
    `## Detailed Warnings`,
    ...renderWarningsMarkdownTable(
      allWarnings,
      '> No potential vulnerability warnings detected in raw minified bundle.'
    )
  ];

  const mdPath = path.join(outDir, 'condition1-baseline.md');
  fs.writeFileSync(mdPath, mdLines.join('\n') + '\n');

  console.log('\n===================================================================');
  console.log(`  Condition 1 Complete! Total Warnings (N_before): ${allWarnings.length}`);
  console.log(`  Total Tokens Used: ${totalTokensUsed.toLocaleString()} (Prompt: ${totalPromptTokens.toLocaleString()}, Completion: ${totalCompletionTokens.toLocaleString()})`);
  console.log(`  JSON Report: ${jsonPath}`);
  console.log(`  MD Report:   ${mdPath}`);
  console.log('===================================================================');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
