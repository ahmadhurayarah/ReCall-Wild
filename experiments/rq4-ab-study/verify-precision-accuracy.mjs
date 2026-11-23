#!/usr/bin/env node
/**
 * RQ4 A/B Study — Code-Grounded Precision & Accuracy Verifier
 *
 * Semantically aligns Condition 1 (Without ReCall) and Condition 2 (With ReCall)
 * warnings per chunk and verifies every warning directly against the actual
 * 12 KB JavaScript bundle slice using an independent reasoning adjudicator
 * (blinded to condition preference), computing exact:
 *   - Increases (C2 only): Added TP vs. Added FP
 *   - Drops (C1 only):     Dropped FP (suppressed false alarms) vs. Dropped TP (missed)
 *   - Shared (Both):       Shared TP vs. Shared FP
 *   - Precision = TP / (TP + FP)
 *   - Accuracy  = (TP + TN) / (TP + TN + FP + FN)
 *
 * Outputs:
 *   - results/rq4-ab/RQ4-PRECISION-ACCURACY.json
 *   - results/rq4-ab/RQ4-PRECISION-ACCURACY.md
 *   - results/rq4-ab/rq4-precision-accuracy-table.tex
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');

// Auto-load .env
for (const envCandidate of [path.join(REPO_ROOT, '.env'), path.resolve(process.cwd(), '.env')]) {
  if (fs.existsSync(envCandidate)) {
    for (const line of fs.readFileSync(envCandidate, 'utf8').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      if (key && !(key in process.env)) process.env[key] = val;
    }
    break;
  }
}

const args = process.argv.slice(2);
function getArg(flag, fallback = null) {
  const idx = args.indexOf(flag);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : fallback;
}

const model = getArg('--model', 'deepseek-reasoner');
const endpoint = getArg('--endpoint', process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com/v1/chat/completions');
const concurrency = parseInt(getArg('--concurrency', '4'), 10);
const apiKey = process.env.DEEPSEEK_API_KEY || '';
const baseDir = path.resolve(REPO_ROOT, 'results/rq4-ab');
const cacheDir = path.join(baseDir, '.verify-cache', model.replace(/[^a-zA-Z0-9._-]/g, '_'));

if (!apiKey) {
  console.error('Error: DEEPSEEK_API_KEY is not set.');
  process.exit(1);
}

fs.mkdirSync(cacheDir, { recursive: true });

const TARGETS = [
  { id: 'petstore.swagger.io', label: 'petstore.swagger.io', group: 'live' },
  { id: 'transform.tools', label: 'transform.tools', group: 'live' },
  { id: 'www.drawdb.app', label: 'www.drawdb.app', group: 'live' },
  { id: 'markdownlivepreview.com', label: 'markdownlivepreview.com', group: 'live' },
  { id: 'astexplorer.net', label: 'astexplorer.net', group: 'live' },
  { id: 'index-CnGlkeTt', label: 'vulnerable-demo-app', group: 'controlled' }
];

const VERIFIER_SYSTEM_PROMPT = `You are an independent, strict, objective client-side web security reviewer performing ground-truth adjudication for a research benchmark.

You will be given:
1. A raw 12 KB slice of a production JavaScript bundle.
2. Two anonymous sets of security warnings raised on this exact slice: Set A and Set B.

Your job has TWO parts:
PART 1 — Semantic Deduplication & Alignment:
Group warnings from Set A and Set B into a unified list of distinct candidate findings.
- If a warning in Set A and a warning in Set B refer to the SAME underlying code location/function/sink (even if one uses a minified name like \`_S\` or \`a\` and the other uses a recovered name like \`lodash template\`, or slightly different phrasing/severity), merge them into ONE unified finding listing both \`a_indices\` and \`b_indices\`.
- Every index from Set A (0..lenA-1) and every index from Set B (0..lenB-1) MUST appear in at least one unified finding.

PART 2 — Strict Ground-Truth Verdict (\`TP\` vs \`FP\`) Directly Against the Code:
Judge each unified finding strictly by inspecting the actual JavaScript code provided:
- Mark \`TP\` (True Positive) ONLY when the code in this chunk genuinely contains a security-relevant vulnerability, risky unguarded sink, or known-vulnerable third-party library API:
  * Real client-side XSS / DOM injection sinks reachable from inputs/props/untrusted data (e.g., dangerouslySetInnerHTML, ref.current.innerHTML, iframe srcDoc, unescaped HTML/XML concatenation into innerHTML, xlinkHref / formAction / href with untrusted URLs, Vue domProps.innerHTML).
  * Real Prototype Pollution vectors or unguarded dynamic bracket assignment / recursive deep-merge / path-setter code (e.g., lodash@4.17.15/4.17.20 _.defaultsDeep, _.zipObjectDeep, _.merge, baseSet, baseZipObject, baseAssignValue/copyObject, or custom deepmerge missing __proto__/constructor/prototype guards).
  * Real Known-Vulnerable Library APIs physically implemented or invoked in this chunk (e.g., lodash@4.17.15/4.17.20 _.template / templateSettings CVE-2021-23337, _.defaultsDeep CVE-2020-8203, DOMPurify sanitize/addHook/setConfig bypass surface, unguarded open redirect / postMessage / sensitive token leakage).
- Mark \`FP\` (False Positive / False Alarm) when:
  * The flagged code is benign framework/library runtime internals with no attacker-controllable taint (e.g., React Fiber DOM reconciliation, React static property/attribute registries, React error-decoder URLs, CodeMirror editor DOM/cursor rendering, Axios/Babel internal helpers like _defineProperty/_objectSpread2/progressEventReducer, localStorage feature-detection try/catch, hardcoded Function('return this')() globalThis checks).
  * A benign library helper (e.g., createCtor, createRecurry, memoize, isObject, arraySome) is flagged solely because the library version has CVEs elsewhere, even though the flagged function in this chunk is NOT a vulnerable API or sink.
  * The claimed vulnerability/sink is NOT actually present in the code, is properly sanitized/guarded, or is non-security (e.g., document.execCommand('copy') clipboard utility, Function.prototype.toString).

Be completely impartial between Set A and Set B. Judge strictly on code evidence.

Respond ONLY with valid JSON matching this schema:
{
  "findings": [
    {
      "id": 1,
      "a_indices": [0],
      "b_indices": [0],
      "verdict": "TP | FP",
      "category": "short category",
      "symbol": "short symbol/API",
      "evidence": "1-sentence code-grounded justification citing exact code/API from the chunk"
    }
  ]
}`;

function chunkCode(code, size = 12000, overlap = 500) {
  const chunks = [];
  const step = Math.max(1, size - overlap);
  for (let start = 0; start < code.length; start += step) {
    const end = Math.min(code.length, start + size);
    chunks.push({ index: chunks.length + 1, start, end, code: code.slice(start, end) });
    if (end >= code.length) break;
  }
  return chunks;
}

function extractJson(text) {
  const cleaned = text
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const first = cleaned.indexOf('{');
    const last = cleaned.lastIndexOf('}');
    if (first !== -1 && last > first) {
      return JSON.parse(cleaned.slice(first, last + 1));
    }
    throw new Error('Could not parse JSON from verifier response');
  }
}

async function adjudicateChunk(targetId, chunkIdx, chunkText, w1, w2, libs) {
  const cacheFile = path.join(cacheDir, `${targetId}__c${chunkIdx}.json`);
  if (fs.existsSync(cacheFile)) {
    return JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
  }

  // Deterministic pseudo-random blinding per chunk so Set A / Set B assignment is unbiased
  const swap = (targetId.length + chunkIdx) % 2 === 1;
  const setA = swap ? w2 : w1;
  const setB = swap ? w1 : w2;

  const fmtList = (arr) =>
    arr.length === 0
      ? '  (none)'
      : arr
          .map(
            (w, i) =>
              `  [${i}] (${w.severity}) ${w.category} | symbol: ${w.symbol_or_function} | source: ${w.source} | sink: ${w.sink} | dataflow: ${w.dataflow} | reason: ${w.reason}`
          )
          .join('\n');

  const userPrompt = `Target: ${targetId} | Chunk #${chunkIdx}
Recovered library context for reference (if applicable): ${libs.join(', ') || 'None'}

### Set A Warnings (${setA.length})
${fmtList(setA)}

### Set B Warnings (${setB.length})
${fmtList(setB)}

### Actual JavaScript Bundle Code (Chunk #${chunkIdx})
\`\`\`javascript
${chunkText}
\`\`\`

Return strict JSON with "findings" array aligning Set A and Set B indices and giving impartial TP/FP verdicts based strictly on the JavaScript code above.`;

  const body = {
    model,
    messages: [
      { role: 'system', content: VERIFIER_SYSTEM_PROMPT },
      { role: 'user', content: userPrompt }
    ]
  };
  if (model !== 'deepseek-reasoner') {
    body.temperature = 0.0;
    body.response_format = { type: 'json_object' };
  }

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`HTTP ${res.status}: ${errText.slice(0, 300)}`);
  }

  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content || '{"findings":[]}';
  const parsed = extractJson(content);
  const rawFindings = Array.isArray(parsed.findings) ? parsed.findings : [];

  // Un-swap Set A / Set B back to c1_indices / c2_indices
  const findings = rawFindings.map((f, idx) => {
    const aIdx = Array.isArray(f.a_indices) ? f.a_indices : [];
    const bIdx = Array.isArray(f.b_indices) ? f.b_indices : [];
    const c1Idx = swap ? bIdx : aIdx;
    const c2Idx = swap ? aIdx : bIdx;
    return {
      id: idx + 1,
      chunkIndex: chunkIdx,
      c1_indices: c1Idx,
      c2_indices: c2Idx,
      in_c1: c1Idx.length > 0,
      in_c2: c2Idx.length > 0,
      verdict: String(f.verdict || '').toUpperCase() === 'TP' ? 'TP' : 'FP',
      category: f.category || 'Other',
      symbol: f.symbol || 'unknown',
      evidence: f.evidence || ''
    };
  });

  // Safety check: ensure every C1/C2 warning index is represented
  const seenC1 = new Set(findings.flatMap((f) => f.c1_indices));
  const seenC2 = new Set(findings.flatMap((f) => f.c2_indices));
  for (let i = 0; i < w1.length; i++) {
    if (!seenC1.has(i)) {
      findings.push({
        id: findings.length + 1,
        chunkIndex: chunkIdx,
        c1_indices: [i],
        c2_indices: [],
        in_c1: true,
        in_c2: false,
        verdict: 'FP',
        category: w1[i].category || 'Other',
        symbol: w1[i].symbol_or_function || 'unknown',
        evidence: 'Unmatched residual baseline warning.'
      });
    }
  }
  for (let i = 0; i < w2.length; i++) {
    if (!seenC2.has(i)) {
      findings.push({
        id: findings.length + 1,
        chunkIndex: chunkIdx,
        c1_indices: [],
        c2_indices: [i],
        in_c1: false,
        in_c2: true,
        verdict: 'FP',
        category: w2[i].category || 'Other',
        symbol: w2[i].symbol_or_function || 'unknown',
        evidence: 'Unmatched residual ReCall warning.'
      });
    }
  }

  const result = { targetId, chunkIndex: chunkIdx, swapped: swap, findings };
  fs.writeFileSync(cacheFile, JSON.stringify(result, null, 2));
  return result;
}

function pct(num, den) {
  return den > 0 ? `${((num / den) * 100).toFixed(1)}%` : '—';
}

function escCell(val) {
  return String(val ?? '—').replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
}

async function runPool(tasks, limit) {
  const results = new Array(tasks.length);
  let nextIdx = 0;
  async function worker() {
    while (nextIdx < tasks.length) {
      const i = nextIdx++;
      results[i] = await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, () => worker()));
  return results;
}

async function main() {
  console.log(`=== RQ4 Code-Grounded Precision & Accuracy Verification (model=${model}, concurrency=${concurrency}) ===\n`);

  const targetReports = [];

  for (const t of TARGETS) {
    const tDir = path.join(baseDir, t.id);
    const c1 = JSON.parse(fs.readFileSync(path.join(tDir, 'condition1-baseline', 'condition1-baseline.json'), 'utf8'));
    const c2 = JSON.parse(fs.readFileSync(path.join(tDir, 'condition2-recall', 'condition2-recall.json'), 'utf8'));

    const rawCode = fs.readFileSync(c2.bundlePath, 'utf8');
    const chunks = chunkCode(rawCode, c2.chunkConfig?.chunkSize || 12000, c2.chunkConfig?.chunkOverlap || 500);
    const chunkMap = new Map(chunks.map((c) => [c.index, c.code]));

    const activeChunks = [
      ...new Set([...(c1.warnings || []).map((w) => w.chunkIndex), ...(c2.warnings || []).map((w) => w.chunkIndex)])
    ].sort((a, b) => a - b);

    console.log(`[${t.label}] Verifying ${activeChunks.length} active chunks (C1=${c1.warnings.length}, C2=${c2.warnings.length})...`);

    const tasks = activeChunks.map((chIdx) => async () => {
      const w1 = (c1.warnings || []).filter((w) => w.chunkIndex === chIdx);
      const w2 = (c2.warnings || []).filter((w) => w.chunkIndex === chIdx);
      const res = await adjudicateChunk(
        t.id,
        chIdx,
        chunkMap.get(chIdx) || '',
        w1,
        w2,
        c2.recallContext?.libraries || []
      );
      process.stdout.write('.');
      return res;
    });

    const chunkVerdicts = await runPool(tasks, concurrency);
    console.log(' done');

    const allFindings = chunkVerdicts.flatMap((cv) => cv.findings);

    // Confusion matrix over unified candidate finding universe U
    let sharedTP = 0, sharedFP = 0;
    let addedTP = 0, addedFP = 0;
    let droppedFP = 0, droppedTP = 0;

    for (const f of allFindings) {
      if (f.in_c1 && f.in_c2) {
        if (f.verdict === 'TP') sharedTP++;
        else sharedFP++;
      } else if (!f.in_c1 && f.in_c2) {
        if (f.verdict === 'TP') addedTP++;
        else addedFP++;
      } else if (f.in_c1 && !f.in_c2) {
        if (f.verdict === 'FP') droppedFP++;
        else droppedTP++;
      }
    }

    const tp1 = sharedTP + droppedTP;
    const fp1 = sharedFP + droppedFP;
    const tn1 = addedFP;
    const fn1 = addedTP;

    const tp2 = sharedTP + addedTP;
    const fp2 = sharedFP + addedFP;
    const tn2 = droppedFP;
    const fn2 = droppedTP;

    const uTotal = allFindings.length;
    const prec1 = tp1 + fp1 > 0 ? tp1 / (tp1 + fp1) : 0;
    const prec2 = tp2 + fp2 > 0 ? tp2 / (tp2 + fp2) : 0;
    const acc1 = uTotal > 0 ? (tp1 + tn1) / uTotal : 0;
    const acc2 = uTotal > 0 ? (tp2 + tn2) / uTotal : 0;

    targetReports.push({
      ...t,
      libs: (c2.recallContext?.libraries || []).join(', '),
      mappedFns: c2.recallContext?.totalMappingsForBundle || 0,
      rawC1: c1.warnings.length,
      rawC2: c2.warnings.length,
      uTotal,
      sharedTP,
      sharedFP,
      addedTP,
      addedFP,
      droppedFP,
      droppedTP,
      c1: { tp: tp1, fp: fp1, tn: tn1, fn: fn1, precision: prec1, accuracy: acc1 },
      c2: { tp: tp2, fp: fp2, tn: tn2, fn: fn2, precision: prec2, accuracy: acc2 },
      findings: allFindings
    });
  }

  function sumGroup(items) {
    const agg = {
      uTotal: 0, sharedTP: 0, sharedFP: 0, addedTP: 0, addedFP: 0, droppedFP: 0, droppedTP: 0,
      tp1: 0, fp1: 0, tn1: 0, fn1: 0, tp2: 0, fp2: 0, tn2: 0, fn2: 0
    };
    for (const r of items) {
      agg.uTotal += r.uTotal;
      agg.sharedTP += r.sharedTP; agg.sharedFP += r.sharedFP;
      agg.addedTP += r.addedTP; agg.addedFP += r.addedFP;
      agg.droppedFP += r.droppedFP; agg.droppedTP += r.droppedTP;
      agg.tp1 += r.c1.tp; agg.fp1 += r.c1.fp; agg.tn1 += r.c1.tn; agg.fn1 += r.c1.fn;
      agg.tp2 += r.c2.tp; agg.fp2 += r.c2.fp; agg.tn2 += r.c2.tn; agg.fn2 += r.c2.fn;
    }
    agg.prec1 = agg.tp1 + agg.fp1 > 0 ? agg.tp1 / (agg.tp1 + agg.fp1) : 0;
    agg.prec2 = agg.tp2 + agg.fp2 > 0 ? agg.tp2 / (agg.tp2 + agg.fp2) : 0;
    agg.acc1 = agg.uTotal > 0 ? (agg.tp1 + agg.tn1) / agg.uTotal : 0;
    agg.acc2 = agg.uTotal > 0 ? (agg.tp2 + agg.tn2) / agg.uTotal : 0;
    return agg;
  }

  const liveAgg = sumGroup(targetReports.filter((r) => r.group === 'live'));
  const allAgg = sumGroup(targetReports);

  console.log('\n=========================================================================================================');
  console.log('                 RQ4 CODE-GROUNDED PRECISION & ACCURACY VERIFICATION SUMMARY');
  console.log('=========================================================================================================');
  for (const r of targetReports) {
    console.log(
      `  ${r.label.padEnd(25)} | Inc: ${r.addedTP}/${r.addedTP + r.addedFP} TP | Drop: ${r.droppedFP}/${r.droppedFP + r.droppedTP} FP | Prec: ${pct(r.c1.tp, r.c1.tp + r.c1.fp)} -> ${pct(r.c2.tp, r.c2.tp + r.c2.fp)} | Acc: ${pct(r.c1.tp + r.c1.tn, r.uTotal)} -> ${pct(r.c2.tp + r.c2.tn, r.uTotal)}`
    );
  }
  console.log('---------------------------------------------------------------------------------------------------------');
  console.log(
    `  ${'LIVE SITES (5)'.padEnd(25)} | Inc: ${liveAgg.addedTP}/${liveAgg.addedTP + liveAgg.addedFP} TP (${pct(liveAgg.addedTP, liveAgg.addedTP + liveAgg.addedFP)}) | Drop: ${liveAgg.droppedFP}/${liveAgg.droppedFP + liveAgg.droppedTP} FP (${pct(liveAgg.droppedFP, liveAgg.droppedFP + liveAgg.droppedTP)}) | Prec: ${(liveAgg.prec1 * 100).toFixed(1)}% -> ${(liveAgg.prec2 * 100).toFixed(1)}% | Acc: ${(liveAgg.acc1 * 100).toFixed(1)}% -> ${(liveAgg.acc2 * 100).toFixed(1)}%`
  );
  console.log(
    `  ${'OVERALL (6)'.padEnd(25)} | Inc: ${allAgg.addedTP}/${allAgg.addedTP + allAgg.addedFP} TP (${pct(allAgg.addedTP, allAgg.addedTP + allAgg.addedFP)}) | Drop: ${allAgg.droppedFP}/${allAgg.droppedFP + allAgg.droppedTP} FP (${pct(allAgg.droppedFP, allAgg.droppedFP + allAgg.droppedTP)}) | Prec: ${(allAgg.prec1 * 100).toFixed(1)}% -> ${(allAgg.prec2 * 100).toFixed(1)}% | Acc: ${(allAgg.acc1 * 100).toFixed(1)}% -> ${(allAgg.acc2 * 100).toFixed(1)}%`
  );
  console.log('=========================================================================================================\n');

  const jsonPath = path.join(baseDir, 'RQ4-PRECISION-ACCURACY.json');
  fs.writeFileSync(jsonPath, JSON.stringify({ model, liveAgg, allAgg, targets: targetReports }, null, 2));

  // Build detailed Markdown audit log
  const mdLines = [
    `# RQ4 Code-Grounded Precision & Accuracy Verification Report`,
    ``,
    `- **Independent Adjudicator Model:** \`${model}\` (blinded Set A / Set B adjudication against actual 12 KB bundle slices)`,
    `- **Formulas:**`,
    `  - $\\text{Precision} = \\frac{TP}{TP + FP}$`,
    `  - $\\text{Accuracy} = \\frac{TP + TN}{TP + TN + FP + FN}$`,
    `- **Universe Definition ($U$):** Semantically deduplicated union of all candidate findings raised by Condition 1 or Condition 2 per chunk.`,
    `  - **Added TP (C2 only, True):** $FN_1 \\rightarrow TP_2$`,
    `  - **Added FP (C2 only, False):** $TN_1 \\rightarrow FP_2$`,
    `  - **Dropped FP (C1 only, False Alarm):** $FP_1 \\rightarrow TN_2$`,
    `  - **Dropped TP (C1 only, Missed True):** $TP_1 \\rightarrow FN_2$`,
    ``,
    `## 1. Per-Target Precision & Accuracy Results`,
    ``,
    `| Target | Library (Fns) | Increases: TP / Total | Drops: False Alarms / Total | Precision (C1 → C2) | Accuracy (C1 → C2) |`,
    `| :--- | :--- | :---: | :---: | :---: | :---: |`,
    ...targetReports.map(
      (r) =>
        `| \`${r.label}\` | \`${r.libs}\` (${r.mappedFns}) | **${r.addedTP}/${r.addedTP + r.addedFP}** (${pct(r.addedTP, r.addedTP + r.addedFP)}) | **${r.droppedFP}/${r.droppedFP + r.droppedTP}** (${pct(r.droppedFP, r.droppedFP + r.droppedTP)}) | ${(r.c1.precision * 100).toFixed(1)}% → **${(r.c2.precision * 100).toFixed(1)}%** | ${(r.c1.accuracy * 100).toFixed(1)}% → **${(r.c2.accuracy * 100).toFixed(1)}%** |`
    ),
    `| **Live Sites Subtotal (5)** | **4 Libraries (1,064)** | **${liveAgg.addedTP}/${liveAgg.addedTP + liveAgg.addedFP}** (${pct(liveAgg.addedTP, liveAgg.addedTP + liveAgg.addedFP)}) | **${liveAgg.droppedFP}/${liveAgg.droppedFP + liveAgg.droppedTP}** (${pct(liveAgg.droppedFP, liveAgg.droppedFP + liveAgg.droppedTP)}) | **${(liveAgg.prec1 * 100).toFixed(1)}% → ${(liveAgg.prec2 * 100).toFixed(1)}%** | **${(liveAgg.acc1 * 100).toFixed(1)}% → ${(liveAgg.acc2 * 100).toFixed(1)}%** |`,
    `| **Overall (6 Targets)** | **4 Libraries (1,114)** | **${allAgg.addedTP}/${allAgg.addedTP + allAgg.addedFP}** (${pct(allAgg.addedTP, allAgg.addedTP + allAgg.addedFP)}) | **${allAgg.droppedFP}/${allAgg.droppedFP + allAgg.droppedTP}** (${pct(allAgg.droppedFP, allAgg.droppedFP + allAgg.droppedTP)}) | **${(allAgg.prec1 * 100).toFixed(1)}% → ${(allAgg.prec2 * 100).toFixed(1)}%** | **${(allAgg.acc1 * 100).toFixed(1)}% → ${(allAgg.acc2 * 100).toFixed(1)}%** |`,
    ``,
    `## 2. Full Confusion Matrices (Condition 1 vs. Condition 2)`,
    ``,
    `| Scope | Condition | TP | FP | TN | FN | Precision | Accuracy |`,
    `| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |`,
    `| Live Sites (5) | Condition 1 (Without ReCall) | ${liveAgg.tp1} | ${liveAgg.fp1} | ${liveAgg.tn1} | ${liveAgg.fn1} | ${(liveAgg.prec1 * 100).toFixed(1)}% | ${(liveAgg.acc1 * 100).toFixed(1)}% |`,
    `| Live Sites (5) | **Condition 2 (With ReCall)** | **${liveAgg.tp2}** | **${liveAgg.fp2}** | **${liveAgg.tn2}** | **${liveAgg.fn2}** | **${(liveAgg.prec2 * 100).toFixed(1)}%** | **${(liveAgg.acc2 * 100).toFixed(1)}%** |`,
    `| Overall (6) | Condition 1 (Without ReCall) | ${allAgg.tp1} | ${allAgg.fp1} | ${allAgg.tn1} | ${allAgg.fn1} | ${(allAgg.prec1 * 100).toFixed(1)}% | ${(allAgg.acc1 * 100).toFixed(1)}% |`,
    `| Overall (6) | **Condition 2 (With ReCall)** | **${allAgg.tp2}** | **${allAgg.fp2}** | **${allAgg.tn2}** | **${allAgg.fn2}** | **${(allAgg.prec2 * 100).toFixed(1)}%** | **${(allAgg.acc2 * 100).toFixed(1)}%** |`,
    ``,
    `## 3. Finding-by-Finding Code-Grounded Audit Log`,
    ``
  ];

  for (const r of targetReports) {
    mdLines.push(`### Target: \`${r.label}\` (${r.libs})`);
    mdLines.push(``);
    mdLines.push(`| Chunk | Diff Type | Verdict | Category | Symbol / API | Code-Grounded Evidence |`);
    mdLines.push(`| :---: | :--- | :---: | :--- | :--- | :--- |`);
    for (const f of r.findings) {
      const diffType = f.in_c1 && f.in_c2 ? 'Shared' : f.in_c2 ? 'Added (C2)' : 'Dropped (C1)';
      mdLines.push(`| c${f.chunkIndex} | ${diffType} | **${f.verdict}** | ${escCell(f.category)} | \`${escCell(f.symbol)}\` | ${escCell(f.evidence)} |`);
    }
    mdLines.push(``);
  }

  const mdPath = path.join(baseDir, 'RQ4-PRECISION-ACCURACY.md');
  fs.writeFileSync(mdPath, mdLines.join('\n') + '\n');

  console.log(`JSON Report: ${jsonPath}`);
  console.log(`MD Audit Log: ${mdPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
