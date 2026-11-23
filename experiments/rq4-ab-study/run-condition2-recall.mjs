#!/usr/bin/env node
/**
 * RQ4 A/B Study — Condition 2: ReCall-Enhanced (WITH ReCall)
 *
 * Runs the EXACT same defensive client-side security audit prompt, model,
 * and deterministic chunking as Condition 1, while supplying ReCall's
 * recovered library & function identities for each overlapping chunk.
 *
 * Usage (Live URL or Localhost — automatically runs ReCall recovery inline!):
 *   node --max-old-space-size=4096 experiments/rq4-ab-study/run-condition2-recall.mjs \
 *     --url http://localhost:3000 \
 *     --lib lodash \
 *     --max-chunks 20
 *
 * Usage (Local Bundle):
 *   node --max-old-space-size=4096 experiments/rq4-ab-study/run-condition2-recall.mjs \
 *     --bundle output/captured-bundle/chunk_1_index-Gx3_I0g8.js \
 *     --lib lodash \
 *     --max-chunks 20
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { captureFromUrl, captureLocalBundle } from '../../src/capture.mjs';
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
const libraryName = getArg('--lib', 'lodash');
const localRefArg = getArg('--local-ref', null);
const windowSize = parseInt(getArg('--window', '5'), 10);
const explicitRecoveryDir = getArg('--recovery-dir', null);
const maxValCalls = parseInt(getArg('--max-val-calls', '100'), 10);
const doCompare = hasFlag('--compare');
const forceRecover = hasFlag('--force-recover');

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
  getArg('--out', `results/rq4-ab/${targetName}/condition2-recall`)
);
const dryRun = hasFlag('--dry-run');

if ((!bundlePath && !targetUrl) || hasFlag('--help') || hasFlag('-h')) {
  console.log(`
RQ4 A/B Study — Condition 2: ReCall-Enhanced (WITH ReCall)
Automatically runs ReCall library identification & function recovery inline before scanning!

Options:
  --url <http(s)://...>   Live website or localhost URL to crawl, recover, & scan
  --bundle <path>         Path to local raw minified JavaScript bundle
  --lib <name>            Target library name for ReCall recovery (default: lodash)
  --local-ref <dir>       Optional local library source dir (skips npm download)
  --window <n>            Candidate npm version window size (default: 5)
  --recovery-dir <path>   Optional existing ReCall recovery dir to reuse (default: auto-run inline)
  --force-recover         Re-run ReCall recovery even if cached recovery artifacts exist
  --compare               Auto-compare against Condition 1 baseline and generate ab-comparison.md
  --provider <name>       'deepseek' (default), 'gemini', 'openai', or 'ollama'
  --model <name>          Model ID (e.g. 'gemini-2.5-flash', 'deepseek-chat', 'gpt-4o')
  --endpoint <url>        Custom completions URL
  --chunk-size <n>        Characters per chunk (default: 12000; MUST match Condition 1)
  --overlap <n>           Overlap characters between chunks (default: 500; MUST match Condition 1)
  --max-chunks <n>        Max chunks to scan per bundle (default: 20; MUST match Condition 1)
  --out <dir>             Output directory (default: results/rq4-ab/<host-or-file>/condition2-recall)
  --dry-run               Verify recovery & chunk mapping without LLM API calls
`);
  process.exit(bundlePath || targetUrl ? 0 : 1);
}

let resolvedBundle = bundlePath ? path.resolve(process.cwd(), bundlePath) : null;
if (resolvedBundle && !fs.existsSync(resolvedBundle)) {
  console.error(`Error: Bundle file not found: ${resolvedBundle}`);
  process.exit(1);
}

let resolvedRecoveryDir = explicitRecoveryDir
  ? path.resolve(process.cwd(), explicitRecoveryDir)
  : path.join(outDir, 'recovery-artifacts');

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
  console.error(`Error: ${envName} environment variable is not set in environment or .env.`);
  console.error(`Run: export ${envName}="your-api-key-here"`);
  process.exit(1);
}

/**
 * Parse ReCall recovery mappings from either:
 *  1. recovered-functions.json (full ReCall run: POG + AST + Model Validation)
 *  2. anchors.json (+ optional source.json / bundle.json for names)
 */
function loadReCallMappings(recoveryDir, bundleFilename) {
  const mappings = [];
  const detectedLibraries = new Set();

  const recoveredPath = path.join(recoveryDir, 'recovered-functions.json');
  const anchorsPath = path.join(recoveryDir, 'anchors.json');
  const sourcePath = path.join(recoveryDir, 'source.json');
  const bundleMetaPath = path.join(recoveryDir, 'bundle.json');

  // 1. Prefer full recovered-functions.json if present
  if (fs.existsSync(recoveredPath)) {
    const data = JSON.parse(fs.readFileSync(recoveredPath, 'utf8'));
    for (const entry of data.functions || []) {
      const bFile = entry?.bundle?.file || entry?.bundle?.id || '';
      if (bundleFilename && !bFile.includes(bundleFilename)) continue;
      const span = entry?.bundle?.span;
      if (!Array.isArray(span) || span.length !== 2) continue;

      const libName = entry?.source?.library?.name || 'unknown-lib';
      const libVer = entry?.source?.library?.version || 'unknown';
      detectedLibraries.add(`${libName}@${libVer}`);

      mappings.push({
        bundleStart: span[0],
        bundleEnd: span[1],
        bundledName: entry?.bundle?.name || '<anonymous>',
        recoveredName: entry?.source?.name || '<anonymous>',
        sourceFile: entry?.source?.file ? path.basename(entry.source.file) : 'unknown',
        library: `${libName}@${libVer}`,
        method: entry.method || 'recovered'
      });
    }
    return { sourceType: 'recovered-functions.json', mappings, libraries: [...detectedLibraries] };
  }

  // 2. Fallback to anchors.json (+ source.json / bundle.json lookup for function names)
  if (fs.existsSync(anchorsPath)) {
    const anchorsData = JSON.parse(fs.readFileSync(anchorsPath, 'utf8'));

    const sourceById = new Map();
    if (fs.existsSync(sourcePath)) {
      try {
        const sData = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
        for (const fn of sData.functions || []) sourceById.set(fn.id, fn);
      } catch {}
    }

    const bundleById = new Map();
    if (fs.existsSync(bundleMetaPath)) {
      try {
        const bData = JSON.parse(fs.readFileSync(bundleMetaPath, 'utf8'));
        for (const fn of bData.functions || []) bundleById.set(fn.id, fn);
      } catch {}
    }

    for (const m of anchorsData.matches || []) {
      const unit = m.unit || m.bundleId || '';
      if (bundleFilename && !unit.includes(bundleFilename)) continue;

      // Parse byte span from bundleId like "file:chunk_1_index-Gx3_I0g8.js:202777:203885"
      const spanMatch = (m.bundleId || '').match(/:(\d+):(\d+)$/);
      if (!spanMatch) continue;
      const bundleStart = parseInt(spanMatch[1], 10);
      const bundleEnd = parseInt(spanMatch[2], 10);

      // Parse library & source file from sourceId like '["lodash","4.17.15","","file:lodash.js"]:471002:475353'
      let libName = 'unknown-lib';
      let libVer = 'unknown';
      let srcFile = 'unknown';
      const srcJsonMatch = (m.sourceId || '').match(/^(\[[^\]]+\])/);
      if (srcJsonMatch) {
        try {
          const arr = JSON.parse(srcJsonMatch[1]);
          libName = arr[0] || libName;
          libVer = arr[1] || libVer;
          srcFile = (arr[3] || '').replace(/^file:/, '') || srcFile;
        } catch {}
      }
      detectedLibraries.add(`${libName}@${libVer}`);

      const sFn = sourceById.get(m.sourceId);
      const bFn = bundleById.get(m.bundleId);

      mappings.push({
        bundleStart,
        bundleEnd,
        bundledName: bFn?.name || '<minified>',
        recoveredName: sFn?.name || path.basename(srcFile, '.js'),
        sourceFile: srcFile,
        library: `${libName}@${libVer}`,
        method: m.kind || 'pog-anchor'
      });
    }
    return { sourceType: 'anchors.json', mappings, libraries: [...detectedLibraries] };
  }

  throw new Error(
    `No recovered-functions.json or anchors.json found in ${recoveryDir}. Run ReCall recovery first.`
  );
}

/**
 * IDENTICAL deterministic chunking to Condition 1
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
 * Find all ReCall recovered functions overlapping a chunk's byte range
 */
function getOverlappingMappings(chunk, mappings) {
  return mappings.filter((m) => m.bundleStart < chunk.end && m.bundleEnd > chunk.start);
}

/**
 * Call official OpenAI-compatible Chat Completions API with ReCall-recovered function context
 */
async function auditChunkWithReCall(chunk, overlapping, allLibraries) {
  const librarySummary =
    allLibraries.length > 0 ? allLibraries.join(', ') : 'None identified';

  const mappingLines =
    overlapping.length > 0
      ? overlapping
          .slice(0, 60) // Cap per-chunk annotation list to keep prompt clean
          .map(
            (m) =>
              `- bytes ${m.bundleStart}-${m.bundleEnd}: bundled \`${m.bundledName}\` -> recovered \`${m.recoveredName}\` (${m.library}, file: ${m.sourceFile}, via ${m.method})`
          )
          .join('\n')
      : '- (No recovered third-party library functions overlap this specific byte range; code may be application logic or runtime glue.)';

  const userPrompt = `Inspect the following client-side JavaScript bundle chunk (Condition 2: Enhanced with ReCall recovered function information) and return any potential security vulnerability warnings in strict JSON format.

### ReCall Recovered Context
- Identified third-party libraries & versions in this bundle: ${librarySummary}
- Recovered function mappings overlapping this chunk (bytes ${chunk.start}-${chunk.end}):
${mappingLines}

Use these recovered library versions and original function identities to recognize known vulnerable library APIs (e.g., template injection, prototype pollution, unsafe DOM sinks) and security-relevant call chains in the code below.

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
  const usage = data?.usage || data?.usageMetadata || {};

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
    recoveredFunctionsInChunk: overlapping.length,
    elapsedMs,
    usage,
    warnings: parsed.warnings,
    ...(parsed.parseError ? { parseError: parsed.parseError } : {})
  };
}

function generateABComparison(cond1Path, cond2Report, outputDir) {
  const c1 = JSON.parse(fs.readFileSync(cond1Path, 'utf8'));
  const nBefore = c1?.summary?.totalWarnings ?? 0;
  const nAfter = cond2Report?.summary?.totalWarnings ?? 0;
  const delta = nAfter - nBefore;
  const pctGain =
    nBefore > 0
      ? `${delta >= 0 ? '+' : ''}${((delta / nBefore) * 100).toFixed(1)}%`
      : nAfter > 0
        ? '+∞ (0 -> ' + nAfter + ')'
        : '0.0%';

  const md = [
    `# RQ4 A/B Comparison Report: Before vs. After ReCall`,
    ``,
    `- **Target:** \`${cond2Report.target}\``,
    `- **Bundle:** \`${path.basename(cond2Report.bundlePath)}\``,
    `- **LLM Model:** \`${cond2Report.provider}\` / \`${cond2Report.model}\``,
    `- **ReCall Libraries Identified:** ${cond2Report.recallContext.libraries.join(', ') || 'None'}`,
    `- **ReCall Recovered Functions Mapped:** ${cond2Report.recallContext.totalMappingsForBundle}`,
    ``,
    `## Side-by-Side Result Difference`,
    ``,
    `| Metric | Condition 1 (Without ReCall) | Condition 2 (With ReCall) | Difference (Δ) |`,
    `| :--- | :---: | :---: | :---: |`,
    `| **Total Vulnerability Warnings** | **${nBefore}** | **${nAfter}** | **${delta >= 0 ? '+' : ''}${delta} (${pctGain})** |`,
    `| High Severity | ${c1.summary?.bySeverity?.high ?? 0} | ${cond2Report.summary.bySeverity.high} | ${cond2Report.summary.bySeverity.high - (c1.summary?.bySeverity?.high ?? 0)} |`,
    `| Medium Severity | ${c1.summary?.bySeverity?.medium ?? 0} | ${cond2Report.summary.bySeverity.medium} | ${cond2Report.summary.bySeverity.medium - (c1.summary?.bySeverity?.medium ?? 0)} |`,
    `| Low Severity | ${c1.summary?.bySeverity?.low ?? 0} | ${cond2Report.summary.bySeverity.low} | ${cond2Report.summary.bySeverity.low - (c1.summary?.bySeverity?.low ?? 0)} |`,
    `| Chunks Scanned | ${c1.chunkConfig?.chunksScanned ?? '?'} | ${cond2Report.chunkConfig.chunksScanned} | 0 (Identical) |`,
    `| Total Runtime (s) | ${((c1.summary?.totalElapsedMs ?? 0) / 1000).toFixed(2)}s | ${(cond2Report.summary.totalElapsedMs / 1000).toFixed(2)}s | — |`
  ].join('\n');

  const compPath = path.join(outputDir, 'ab-comparison.md');
  fs.writeFileSync(compPath, md + '\n');
  console.log(`\n================ A/B COMPARISON SUMMARY ================`);
  console.log(`  Condition 1 (Without ReCall): ${nBefore} warning(s)`);
  console.log(`  Condition 2 (With ReCall):    ${nAfter} warning(s)`);
  console.log(`  Difference (Δ):               ${delta >= 0 ? '+' : ''}${delta} (${pctGain})`);
  console.log(`  Comparison Report:            ${compPath}`);
  console.log(`========================================================`);
}

function hasRecoveryArtifacts(dir) {
  return (
    fs.existsSync(path.join(dir, 'recovered-functions.json')) ||
    fs.existsSync(path.join(dir, 'anchors.json'))
  );
}

async function main() {
  fs.mkdirSync(outDir, { recursive: true });

  const captureDir = path.join(outDir, 'captured-bundle');
  let capturedManifestPath = null;

  if (targetUrl && !resolvedBundle) {
    const captured = await captureFromUrl(targetUrl, captureDir);
    if (!captured.bundleFiles || captured.bundleFiles.length === 0) {
      throw new Error(`No external JavaScript bundles found at ${targetUrl}`);
    }
    capturedManifestPath = captured.manifestPath;
    const sorted = [...captured.bundleFiles].sort((a, b) => b.bytes - a.bytes);
    resolvedBundle = path.join(captureDir, sorted[0].path);
    console.log(
      `[Capture] Selected primary bundle: ${sorted[0].path} (${(sorted[0].bytes / 1024).toFixed(1)} KB)\n`
    );
  }

  // Automatically run ReCall recovery inline if recovery artifacts do not exist yet
  if (forceRecover || !hasRecoveryArtifacts(resolvedRecoveryDir)) {
    console.log(`[ReCall Inline] Running automatic ReCall recovery for library: ${libraryName}...`);
    if (!capturedManifestPath) {
      const captured = captureLocalBundle(resolvedBundle, captureDir);
      capturedManifestPath = captured.manifestPath;
      // Ensure resolvedBundle points to the packaged filename so unit names match ReCall artifacts
      if (captured.bundleFiles?.[0]?.path) {
        resolvedBundle = path.join(captureDir, captured.bundleFiles[0].path);
      }
    }

    const { identifyLibraryVersion } = await import('../../src/identify.mjs');
    const { executeRecovery } = await import('../../src/recover.mjs');

    let ollamaAvailable = false;
    try {
      const probe = await fetch('http://127.0.0.1:11434/api/version', {
        signal: AbortSignal.timeout(1000)
      });
      if (probe.ok) ollamaAvailable = true;
    } catch {
      ollamaAvailable = false;
    }

    const useDeepSeekForRecovery = !ollamaAvailable && Boolean(process.env.DEEPSEEK_API_KEY);
    const prepareOnly = !ollamaAvailable && !useDeepSeekForRecovery;

    const idResult = await identifyLibraryVersion(capturedManifestPath, libraryName, 'latest', {
      windowSize,
      localReferenceDir: localRefArg ? path.resolve(process.cwd(), localRefArg) : null
    });
    console.log(
      `[ReCall Inline] Identified ${idResult.pkgName}@${idResult.identifiedVersion} (${idResult.matchedAnchors} POG anchors)`
    );

    if (!idResult.referenceDir) {
      throw new Error(`Could not resolve reference directory for library '${libraryName}'.`);
    }

    await executeRecovery({
      bundleManifestPath: capturedManifestPath,
      referencesDir: idResult.referenceDir,
      outputDir: resolvedRecoveryDir,
      prepareOnly,
      useDeepSeek: useDeepSeekForRecovery,
      maxValidationCalls: maxValCalls
    });
    console.log(`[ReCall Inline] Recovery artifacts saved to: ${resolvedRecoveryDir}\n`);
  } else {
    console.log(`[ReCall Inline] Reusing existing recovery artifacts from: ${resolvedRecoveryDir}\n`);
  }

  const rawCode = fs.readFileSync(resolvedBundle, 'utf8');
  const bundleFilename = path.basename(resolvedBundle);
  const bundleSha256 = crypto.createHash('sha256').update(rawCode).digest('hex');
  const chunks = chunkCode(rawCode, chunkSize, chunkOverlap, maxChunks);

  const recallData = loadReCallMappings(resolvedRecoveryDir, bundleFilename);

  console.log('===================================================================');
  console.log('  RQ4 A/B Study — Condition 2: ReCall-Enhanced (WITH ReCall)');
  console.log('===================================================================');
  console.log(`Target:            ${targetName}`);
  console.log(`Bundle:            ${resolvedBundle} (${(rawCode.length / 1024).toFixed(1)} KB)`);
  console.log(`ReCall Source:     ${recallData.sourceType} (${resolvedRecoveryDir})`);
  console.log(`Libraries Found:   ${recallData.libraries.join(', ') || 'None'}`);
  console.log(`Mapped Functions:  ${recallData.mappings.length} matching this bundle`);
  console.log(`Provider / Model:  ${provider} (${model})`);
  console.log(`Chunks:            ${chunks.length} (size=${chunkSize}, overlap=${chunkOverlap}, max=${maxChunks})`);
  console.log(`Output Dir:        ${outDir}`);
  console.log(`Mode:              ${dryRun ? 'DRY RUN (No API calls)' : 'LIVE API SCAN'}\n`);

  if (dryRun) {
    const preview = chunks.map((c) => {
      const ov = getOverlappingMappings(c, recallData.mappings);
      return {
        chunkIndex: c.index,
        byteRange: [c.start, c.end],
        sha256: c.sha256,
        overlappingRecoveredFunctions: ov.length,
        sampleFunctions: ov.slice(0, 5).map((m) => `${m.bundledName} -> ${m.recoveredName} (${m.library})`)
      };
    });
    const outFile = path.join(outDir, 'condition2-dryrun.json');
    fs.writeFileSync(
      outFile,
      JSON.stringify(
        {
          condition: 'condition2_with_recall',
          dryRun: true,
          target: targetName,
          libraries: recallData.libraries,
          totalMappingsForBundle: recallData.mappings.length,
          chunks: preview
        },
        null,
        2
      )
    );
    console.log(`[Dry Run] Mapped ${recallData.mappings.length} ReCall functions across ${chunks.length} chunks.`);
    console.log(`[Dry Run] Metadata written to: ${outFile}`);
    return;
  }

  const chunkResults = [];
  const allWarnings = [];
  let totalPromptTokens = 0;
  let totalCompletionTokens = 0;
  const startAll = performance.now();

  for (const chunk of chunks) {
    const overlapping = getOverlappingMappings(chunk, recallData.mappings);
    process.stdout.write(
      `Scanning chunk ${chunk.index}/${chunks.length} (${chunk.length} chars, ${overlapping.length} recovered fn)... `
    );
    try {
      const result = await auditChunkWithReCall(chunk, overlapping, recallData.libraries);
      chunkResults.push(result);
      totalPromptTokens += result.usage?.prompt_tokens || 0;
      totalCompletionTokens += result.usage?.completion_tokens || 0;

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
        recoveredFunctionsInChunk: overlapping.length,
        error: err.message,
        warnings: []
      });
    }
  }

  const totalElapsedMs = Math.round(performance.now() - startAll);

  const byCategory = {};
  const bySeverity = { high: 0, medium: 0, low: 0 };
  for (const w of allWarnings) {
    const cat = w.category || 'Other';
    byCategory[cat] = (byCategory[cat] || 0) + 1;
    const sev = (w.severity || 'low').toLowerCase();
    if (sev in bySeverity) bySeverity[sev]++;
  }

  const report = {
    condition: 'condition2_with_recall',
    timestamp: new Date().toISOString(),
    target: targetName,
    bundlePath: resolvedBundle,
    bundleBytes: rawCode.length,
    bundleSha256,
    provider,
    model,
    recallContext: {
      recoveryDir: resolvedRecoveryDir,
      sourceType: recallData.sourceType,
      libraries: recallData.libraries,
      totalMappingsForBundle: recallData.mappings.length
    },
    chunkConfig: { chunkSize, chunkOverlap, chunksScanned: chunks.length },
    summary: {
      totalWarnings: allWarnings.length,
      bySeverity,
      byCategory,
      totalElapsedMs,
      totalPromptTokens,
      totalCompletionTokens
    },
    warnings: allWarnings,
    chunkResults
  };

  const jsonPath = path.join(outDir, 'condition2-recall.json');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  const mdLines = [
    `# RQ4 Condition 2 (ReCall-Enhanced — With ReCall) Report`,
    ``,
    `- **Target:** \`${targetName}\``,
    `- **Bundle:** \`${bundleFilename}\` (${(rawCode.length / 1024).toFixed(1)} KB)`,
    `- **LLM Provider / Model:** \`${provider}\` / \`${model}\``,
    `- **ReCall Libraries Identified:** ${recallData.libraries.join(', ') || 'None'}`,
    `- **ReCall Recovered Functions Mapped:** ${recallData.mappings.length}`,
    `- **Chunks Scanned:** ${chunks.length}`,
    `- **Total Runtime:** ${(totalElapsedMs / 1000).toFixed(2)}s`,
    `- **Total Warnings Reported (N_after):** **${allWarnings.length}**`,
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
    ...renderWarningsMarkdownTable(allWarnings)
  ];

  const mdPath = path.join(outDir, 'condition2-recall.md');
  fs.writeFileSync(mdPath, mdLines.join('\n') + '\n');

  console.log('\n===================================================================');
  console.log(`  Condition 2 Complete! Total Warnings (N_after): ${allWarnings.length}`);
  console.log(`  JSON Report: ${jsonPath}`);
  console.log(`  MD Report:   ${mdPath}`);
  console.log('===================================================================');

  if (doCompare) {
    const autoC1Path = path.resolve(
      process.cwd(),
      `results/rq4-ab/${targetName}/condition1-baseline/condition1-baseline.json`
    );
    if (fs.existsSync(autoC1Path)) {
      generateABComparison(autoC1Path, report, outDir);
    } else {
      console.warn(
        `Warning: Condition 1 report not found at ${autoC1Path}. Run Condition 1 first to enable --compare.`
      );
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
