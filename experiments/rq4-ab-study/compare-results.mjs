#!/usr/bin/env node
/**
 * RQ4 A/B Study — Standalone Results Comparison & APIs/Sinks Catalog Generator
 *
 * Compares Condition 1 (Without ReCall) vs. Condition 2 (With ReCall)
 * reports and generates:
 *   1. Terminal summary table
 *   2. Per-target ab-comparison.md
 *   3. Per-target apis-sinks-report.md & apis-sinks-report.json
 *      (complete list of exposed APIs, controllable sources, sinks, dataflows,
 *       category metrics, and ReCall recovered functions)
 *   4. Master results/rq4-ab/RQ4-AB-SUMMARY.md
 *   5. Master results/rq4-ab/RQ4-APIS-SINKS-CATALOG.md
 *   6. Ready-to-paste LaTeX table: results/rq4-ab/rq4-ab-table.tex
 *
 * Usage:
 *   node experiments/rq4-ab-study/compare-results.mjs
 *   node experiments/rq4-ab-study/compare-results.mjs www.drawdb.app
 */

import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const filterTarget = args[0] && !args[0].startsWith('-') ? args[0] : null;
const baseDir = path.resolve(process.cwd(), 'results/rq4-ab');

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
RQ4 A/B Study — Standalone Comparison & APIs/Sinks Catalog Tool

Usage:
  node experiments/rq4-ab-study/compare-results.mjs                Compare ALL targets in results/rq4-ab/
  node experiments/rq4-ab-study/compare-results.mjs <target-name>  Compare one target (e.g., www.drawdb.app)
`);
  process.exit(0);
}

if (!fs.existsSync(baseDir)) {
  console.error(`No results directory found at: ${baseDir}`);
  console.error('Run Condition 1 and Condition 2 first.');
  process.exit(1);
}

function escCell(val) {
  return String(val ?? '—')
    .replace(/\r?\n/g, ' ')
    .replace(/\|/g, '\\|')
    .trim();
}

function formatGain(before, after) {
  const delta = after - before;
  const sign = delta >= 0 ? '+' : '';
  if (before > 0) {
    return `${sign}${delta} (${sign}${((delta / before) * 100).toFixed(1)}%)`;
  }
  return after > 0 ? `+${delta} (0 -> ${after})` : '0 (0.0%)';
}

function countByCategory(warnings = []) {
  const counts = {};
  for (const w of warnings) {
    const cat = w.category || 'Other';
    counts[cat] = (counts[cat] || 0) + 1;
  }
  return counts;
}

function warningKey(w) {
  return `${w.chunkIndex}|${(w.category || '').toLowerCase()}|${(w.sink || '').toLowerCase().slice(0, 40)}`;
}

function loadRecoveredFunctions(tDir) {
  const recPath = path.join(tDir, 'condition2-recall', 'recovery-artifacts', 'recovered-functions.json');
  if (!fs.existsSync(recPath)) return [];
  try {
    const data = JSON.parse(fs.readFileSync(recPath, 'utf8'));
    return (data.functions || []).map((f) => ({
      bundledName: f?.bundle?.name || '<anonymous>',
      recoveredName: f?.source?.name || '<anonymous>',
      library: `${f?.source?.library?.name || 'unknown'}@${f?.source?.library?.version || 'unknown'}`,
      sourceFile: f?.source?.file ? path.basename(f.source.file) : 'unknown',
      bundleFile: f?.bundle?.file ? path.basename(f.bundle.file) : 'unknown',
      span: f?.bundle?.span || [],
      method: f?.method || 'recovered'
    }));
  } catch {
    return [];
  }
}

function compareTarget(targetDirName) {
  const tDir = path.join(baseDir, targetDirName);
  const c1Path = path.join(tDir, 'condition1-baseline', 'condition1-baseline.json');
  const c2Path = path.join(tDir, 'condition2-recall', 'condition2-recall.json');

  if (!fs.existsSync(c1Path) || !fs.existsSync(c2Path)) {
    return null;
  }

  const c1 = JSON.parse(fs.readFileSync(c1Path, 'utf8'));
  const c2 = JSON.parse(fs.readFileSync(c2Path, 'utf8'));

  const before = c1.summary?.totalWarnings ?? 0;
  const after = c2.summary?.totalWarnings ?? 0;
  const delta = after - before;
  const gainStr = formatGain(before, after);

  const highBefore = c1.summary?.bySeverity?.high ?? 0;
  const highAfter = c2.summary?.bySeverity?.high ?? 0;
  const medBefore = c1.summary?.bySeverity?.medium ?? 0;
  const medAfter = c2.summary?.bySeverity?.medium ?? 0;
  const lowBefore = c1.summary?.bySeverity?.low ?? 0;
  const lowAfter = c2.summary?.bySeverity?.low ?? 0;

  const libs = c2.recallContext?.libraries?.join(', ') || 'None';
  const mappedFns = c2.recallContext?.totalMappingsForBundle ?? 0;
  const chunks = c2.chunkConfig?.chunksScanned ?? c1.chunkConfig?.chunksScanned ?? 0;
  const model = `${c2.provider || c1.provider}/${c2.model || c1.model}`;

  const cat1 = countByCategory(c1.warnings);
  const cat2 = countByCategory(c2.warnings);
  const allCats = [...new Set([...Object.keys(cat1), ...Object.keys(cat2)])].sort();

  const c1Keys = new Set((c1.warnings || []).map(warningKey));
  const c2Keys = new Set((c2.warnings || []).map(warningKey));

  const c2Annotated = (c2.warnings || []).map((w) => ({
    ...w,
    diffStatus: c1Keys.has(warningKey(w)) ? 'Shared' : 'NEW (ReCall)'
  }));

  const suppressedFromC1 = (c1.warnings || []).filter((w) => !c2Keys.has(warningKey(w)));
  const recoveredFns = loadRecoveredFunctions(tDir);

  // Unique exposed sinks and APIs in Condition 2
  const uniqueSinks = [...new Set((c2.warnings || []).map((w) => w.sink).filter(Boolean))];
  const uniqueSources = [...new Set((c2.warnings || []).map((w) => w.source).filter(Boolean))];
  const uniqueApis = [...new Set((c2.warnings || []).map((w) => w.symbol_or_function).filter(Boolean))];

  // 1. Per-target Markdown comparison
  const perTargetMd = [
    `# RQ4 A/B Comparison: \`${targetDirName}\``,
    ``,
    `- **Model:** \`${model}\``,
    `- **Chunks Scanned:** ${chunks} (identical in both conditions)`,
    `- **ReCall Libraries Identified:** ${libs}`,
    `- **ReCall Functions Mapped:** ${mappedFns}`,
    ``,
    `## Severity Metrics`,
    ``,
    `| Metric | Condition 1 (Without ReCall) | Condition 2 (With ReCall) | Difference (Δ) |`,
    `| :--- | :---: | :---: | :---: |`,
    `| **Total Warnings** | **${before}** | **${after}** | **${gainStr}** |`,
    `| High Severity | ${highBefore} | ${highAfter} | ${highAfter - highBefore >= 0 ? '+' : ''}${highAfter - highBefore} |`,
    `| Medium Severity | ${medBefore} | ${medAfter} | ${medAfter - medBefore >= 0 ? '+' : ''}${medAfter - medBefore} |`,
    `| Low Severity | ${lowBefore} | ${lowAfter} | ${lowAfter - lowBefore >= 0 ? '+' : ''}${lowAfter - lowBefore} |`,
    `| Runtime (s) | ${((c1.summary?.totalElapsedMs ?? 0) / 1000).toFixed(2)}s | ${((c2.summary?.totalElapsedMs ?? 0) / 1000).toFixed(2)}s | — |`,
    ``,
    `## Category Metrics`,
    ``,
    `| Category | Without ReCall | With ReCall | Difference (Δ) |`,
    `| :--- | :---: | :---: | :---: |`,
    ...allCats.map((cat) => {
      const b = cat1[cat] || 0;
      const a = cat2[cat] || 0;
      const d = a - b;
      return `| ${escCell(cat)} | ${b} | ${a} | ${d >= 0 ? '+' : ''}${d} |`;
    })
  ].join('\n');

  const perTargetPath = path.join(tDir, 'ab-comparison.md');
  fs.writeFileSync(perTargetPath, perTargetMd + '\n');

  // 2. Per-target Detailed APIs, Sinks, Dataflows & Recovered Functions Report (.md + .json)
  const apiSinksMd = [
    `# Exposed APIs, Sinks, Dataflows & Recovered Functions: \`${targetDirName}\``,
    ``,
    `- **Target:** \`${targetDirName}\``,
    `- **Bundle:** \`${path.basename(c2.bundlePath || '')}\``,
    `- **Model:** \`${model}\``,
    `- **Chunks Scanned:** ${chunks}`,
    `- **ReCall Libraries Identified:** ${libs}`,
    `- **ReCall Recovered Functions:** ${recoveredFns.length} (${mappedFns} mapped to primary bundle)`,
    `- **Unique Flagged APIs/Symbols (Condition 2):** ${uniqueApis.length}`,
    `- **Unique Exposed Sinks (Condition 2):** ${uniqueSinks.length}`,
    `- **Unique Controllable Sources (Condition 2):** ${uniqueSources.length}`,
    ``,
    `---`,
    ``,
    `## 1. Summary Metrics (Without ReCall vs. With ReCall)`,
    ``,
    `| Metric | Without ReCall | With ReCall | Difference (Δ) |`,
    `| :--- | :---: | :---: | :---: |`,
    `| **Total Warnings** | **${before}** | **${after}** | **${gainStr}** |`,
    `| High Severity | ${highBefore} | ${highAfter} | ${highAfter - highBefore >= 0 ? '+' : ''}${highAfter - highBefore} |`,
    `| Medium Severity | ${medBefore} | ${medAfter} | ${medAfter - medBefore >= 0 ? '+' : ''}${medAfter - medBefore} |`,
    `| Low Severity | ${lowBefore} | ${lowAfter} | ${lowAfter - lowBefore >= 0 ? '+' : ''}${lowAfter - lowBefore} |`,
    ...allCats.map((cat) => {
      const b = cat1[cat] || 0;
      const a = cat2[cat] || 0;
      const d = a - b;
      return `| Category: ${escCell(cat)} | ${b} | ${a} | ${d >= 0 ? '+' : ''}${d} |`;
    }),
    ``,
    `---`,
    ``,
    `## 2. All Exposed APIs, Sources, Sinks & Dataflows (Condition 2 — With ReCall)`,
    ``,
    `| # | Chunk | Status | Severity | Category | Exposed API / Symbol | Controllable Source | Exposed Sink | Dataflow | Website Impact |`,
    `| :---: | :---: | :--- | :---: | :--- | :--- | :--- | :--- | :--- | :--- |`,
    ...c2Annotated.map(
      (w, idx) =>
        `| ${idx + 1} | c${w.chunkIndex} | **${w.diffStatus}** | ${escCell((w.severity || '').toUpperCase())} | ${escCell(w.category)} | \`${escCell(w.symbol_or_function)}\` | ${escCell(w.source)} | \`${escCell(w.sink)}\` | ${escCell(w.dataflow)} | ${escCell(w.website_impact)} |`
    ),
    ``,
    `---`,
    ``,
    `## 3. Baseline Warnings Suppressed After ReCall (Condition 1 Only — Noise Filtered)`,
    ``,
    suppressedFromC1.length > 0
      ? [
          `| # | Chunk | Severity | Category | Raw Symbol | Source | Sink |`,
          `| :---: | :---: | :---: | :--- | :--- | :--- | :--- |`,
          ...suppressedFromC1.map(
            (w, idx) =>
              `| ${idx + 1} | c${w.chunkIndex} | ${escCell((w.severity || '').toUpperCase())} | ${escCell(w.category)} | \`${escCell(w.symbol_or_function)}\` | ${escCell(w.source)} | \`${escCell(w.sink)}\` |`
          )
        ].join('\n')
      : `_No baseline warnings were suppressed on this target._`,
    ``,
    `---`,
    ``,
    `## 4. Complete List of ReCall Recovered Functions (${recoveredFns.length})`,
    ``,
    recoveredFns.length > 0
      ? [
          `| # | Bundled Name | Recovered Function Name | Library | Source File | Method | Byte Span |`,
          `| :---: | :--- | :--- | :--- | :--- | :--- | :--- |`,
          ...recoveredFns.map(
            (f, idx) =>
              `| ${idx + 1} | \`${escCell(f.bundledName)}\` | \`${escCell(f.recoveredName)}\` | ${escCell(f.library)} | \`${escCell(f.sourceFile)}\` | ${escCell(f.method)} | ${Array.isArray(f.span) && f.span.length === 2 ? `${f.span[0]}-${f.span[1]}` : '—'} |`
          )
        ].join('\n')
      : `_No recovered-functions.json found._`
  ].join('\n');

  const apiSinksMdPath = path.join(tDir, 'apis-sinks-report.md');
  fs.writeFileSync(apiSinksMdPath, apiSinksMd + '\n');

  const apiSinksJsonPath = path.join(tDir, 'apis-sinks-report.json');
  fs.writeFileSync(
    apiSinksJsonPath,
    JSON.stringify(
      {
        target: targetDirName,
        model,
        chunks,
        libraries: c2.recallContext?.libraries || [],
        recoveredFunctionCount: recoveredFns.length,
        mappedFunctionCount: mappedFns,
        metrics: {
          before,
          after,
          delta,
          highBefore,
          highAfter,
          medBefore,
          medAfter,
          lowBefore,
          lowAfter,
          byCategoryBefore: cat1,
          byCategoryAfter: cat2
        },
        uniqueApis,
        uniqueSinks,
        uniqueSources,
        warningsWithReCall: c2Annotated,
        suppressedBaselineWarnings: suppressedFromC1,
        recoveredFunctions: recoveredFns
      },
      null,
      2
    )
  );

  return {
    target: targetDirName,
    model,
    chunks,
    libs,
    mappedFns,
    recoveredFnTotal: recoveredFns.length,
    before,
    after,
    delta,
    gainStr,
    highBefore,
    highAfter,
    medBefore,
    medAfter,
    lowBefore,
    lowAfter,
    cat1,
    cat2,
    c2Annotated,
    uniqueApis,
    uniqueSinks,
    perTargetPath,
    apiSinksMdPath,
    apiSinksJsonPath
  };
}

const candidates = filterTarget
  ? [filterTarget]
  : fs
      .readdirSync(baseDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();

const rows = [];
for (const name of candidates) {
  const row = compareTarget(name);
  if (row) rows.push(row);
}

if (rows.length === 0) {
  console.log('No completed Condition 1 + Condition 2 pairs found yet.');
  console.log(`Checked under: ${baseDir}`);
  process.exit(0);
}

const totalBefore = rows.reduce((s, r) => s + r.before, 0);
const totalAfter = rows.reduce((s, r) => s + r.after, 0);
const totalHighB = rows.reduce((s, r) => s + r.highBefore, 0);
const totalHighA = rows.reduce((s, r) => s + r.highAfter, 0);
const totalMedB = rows.reduce((s, r) => s + r.medBefore, 0);
const totalMedA = rows.reduce((s, r) => s + r.medAfter, 0);
const totalLowB = rows.reduce((s, r) => s + r.lowBefore, 0);
const totalLowA = rows.reduce((s, r) => s + r.lowAfter, 0);
const totalGain = formatGain(totalBefore, totalAfter);

// Aggregate category metrics across all targets
const aggCat1 = {};
const aggCat2 = {};
for (const r of rows) {
  for (const [k, v] of Object.entries(r.cat1)) aggCat1[k] = (aggCat1[k] || 0) + v;
  for (const [k, v] of Object.entries(r.cat2)) aggCat2[k] = (aggCat2[k] || 0) + v;
}
const aggCats = [...new Set([...Object.keys(aggCat1), ...Object.keys(aggCat2)])].sort();

console.log('===========================================================================================');
console.log('                      RQ4 A/B COMPARISON: BEFORE vs. AFTER RECALL');
console.log('===========================================================================================');
for (const r of rows) {
  console.log(
    `  ${r.target.padEnd(25)} | High: ${r.highBefore}->${r.highAfter} | Med: ${r.medBefore}->${r.medAfter} | Low: ${r.lowBefore}->${r.lowAfter} | Total: ${String(r.before).padStart(3)}->${String(r.after).padStart(3)} (${r.gainStr})`
  );
}
console.log('-------------------------------------------------------------------------------------------');
console.log(
  `  ${'TOTAL'.padEnd(25)} | High: ${totalHighB}->${totalHighA} | Med: ${totalMedB}->${totalMedA} | Low: ${totalLowB}->${totalLowA} | Total: ${String(totalBefore).padStart(3)}->${String(totalAfter).padStart(3)} (${totalGain})`
);
console.log('===========================================================================================\n');

// 3. Master Markdown summary (with High / Medium / Low + Category breakdown)
const masterMd = [
  `# RQ4 A/B Study Master Summary (Before vs. After ReCall)`,
  ``,
  `## Per-Target Severity & Total Comparison`,
  ``,
  `| Target | Chunks | ReCall Library (Mapped Fns) | High (B → A) | Medium (B → A) | Low Noise (B → A) | Total (B → A) |`,
  `| :--- | :---: | :--- | :---: | :---: | :---: | :---: |`,
  ...rows.map(
    (r) =>
      `| \`${r.target}\` | ${r.chunks} | ${r.libs} (${r.mappedFns}) | ${r.highBefore} → ${r.highAfter} | ${r.medBefore} → ${r.medAfter} | ${r.lowBefore} → ${r.lowAfter} | ${r.before} → ${r.after} (**${r.gainStr}**) |`
  ),
  `| **Total** | **${rows.reduce((s, r) => s + r.chunks, 0)}** | **${rows.reduce((s, r) => s + r.mappedFns, 0)} fns** | **${totalHighB} → ${totalHighA}** | **${totalMedB} → ${totalMedA}** | **${totalLowB} → ${totalLowA}** | **${totalBefore} → ${totalAfter} (${totalGain})** |`,
  ``,
  `## Category-Level Metrics Across All Targets`,
  ``,
  `| Vulnerability / API Category | Without ReCall | With ReCall | Difference (Δ) |`,
  `| :--- | :---: | :---: | :---: |`,
  ...aggCats.map((cat) => {
    const b = aggCat1[cat] || 0;
    const a = aggCat2[cat] || 0;
    return `| ${escCell(cat)} | ${b} | ${a} | **${formatGain(b, a)}** |`;
  })
].join('\n');

const masterMdPath = path.join(baseDir, 'RQ4-AB-SUMMARY.md');
fs.writeFileSync(masterMdPath, masterMd + '\n');

// 4. Master APIs & Sinks Catalog across all targets
const catalogMd = [
  `# RQ4 Master Catalog: Exposed APIs, Controllable Sources, Sinks & Dataflows`,
  ``,
  `Aggregated defensive audit inventory across **${rows.length} targets** (**${rows.reduce((s, r) => s + r.chunks, 0)} chunks**, **${rows.reduce((s, r) => s + r.mappedFns, 0)} ReCall-recovered functions**).`,
  ``,
  `## 1. Overall Category & API Metrics`,
  ``,
  `| Category | Without ReCall | With ReCall | Difference (Δ) |`,
  `| :--- | :---: | :---: | :---: |`,
  ...aggCats.map((cat) => {
    const b = aggCat1[cat] || 0;
    const a = aggCat2[cat] || 0;
    return `| ${escCell(cat)} | ${b} | ${a} | **${formatGain(b, a)}** |`;
  }),
  ``,
  `## 2. Per-Target Exposed APIs & Sinks Overview`,
  ``,
  `| Target | Library (Fns) | Unique Flagged APIs | Unique Sinks | High+Med (B → A) | Detailed Per-Target Report |`,
  `| :--- | :--- | :---: | :---: | :---: | :--- |`,
  ...rows.map(
    (r) =>
      `| \`${r.target}\` | ${r.libs} (${r.mappedFns}) | ${r.uniqueApis.length} | ${r.uniqueSinks.length} | ${r.highBefore + r.medBefore} → ${r.highAfter + r.medAfter} | [apis-sinks-report.md](${r.target}/apis-sinks-report.md) |`
  ),
  ``,
  `---`,
  ``,
  ...rows.flatMap((r) => [
    `## Target: \`${r.target}\` (${r.libs}, ${r.mappedFns} recovered functions)`,
    ``,
    `| # | Chunk | Status | Severity | Category | Exposed API / Symbol | Source | Sink | Dataflow |`,
    `| :---: | :---: | :--- | :---: | :--- | :--- | :--- | :--- | :--- |`,
    ...r.c2Annotated.map(
      (w, idx) =>
        `| ${idx + 1} | c${w.chunkIndex} | **${w.diffStatus}** | ${escCell((w.severity || '').toUpperCase())} | ${escCell(w.category)} | \`${escCell(w.symbol_or_function)}\` | ${escCell(w.source)} | \`${escCell(w.sink)}\` | ${escCell(w.dataflow)} |`
    ),
    ``
  ])
].join('\n');

const catalogMdPath = path.join(baseDir, 'RQ4-APIS-SINKS-CATALOG.md');
fs.writeFileSync(catalogMdPath, catalogMd + '\n');

// 5. Ready-to-paste LaTeX table for manuscript/sections/rq4.tex
const texLines = [
  `\\begin{table}[htbp]`,
  `\\caption{Downstream LLM vulnerability warning comparison before and after supplying ReCall-recovered function information.}`,
  `\\label{tab:rq4-ab-comparison}`,
  `\\centering\\small`,
  `\\begin{tabular}{lcccccc}`,
  `\\toprule`,
  `\\textbf{Target} & \\textbf{Chunks} & \\textbf{High (B$\\rightarrow$A)} & \\textbf{Med (B$\\rightarrow$A)} & \\textbf{Low (B$\\rightarrow$A)} & \\textbf{Total (B$\\rightarrow$A)} & \\textbf{Delta ($\\Delta$)} \\\\`,
  `\\midrule`,
  ...rows.map(
    (r) =>
      `\\texttt{${r.target.replace(/_/g, '\\_')}} & ${r.chunks} & ${r.highBefore}$\\rightarrow$${r.highAfter} & ${r.medBefore}$\\rightarrow$${r.medAfter} & ${r.lowBefore}$\\rightarrow$${r.lowAfter} & ${r.before}$\\rightarrow$${r.after} & ${r.gainStr.replace(/%/g, '\\%').replace(/->/g, '$\\rightarrow$')} \\\\`
  ),
  `\\midrule`,
  `\\textbf{Total} & \\textbf{${rows.reduce((s, r) => s + r.chunks, 0)}} & \\textbf{${totalHighB}$\\rightarrow$${totalHighA}} & \\textbf{${totalMedB}$\\rightarrow$${totalMedA}} & \\textbf{${totalLowB}$\\rightarrow$${totalLowA}} & \\textbf{${totalBefore}$\\rightarrow$${totalAfter}} & \\textbf{${totalGain.replace(/%/g, '\\%').replace(/->/g, '$\\rightarrow$')}} \\\\`,
  `\\bottomrule`,
  `\\end{tabular}`,
  `\\end{table}`
];

const texPath = path.join(baseDir, 'rq4-ab-table.tex');
fs.writeFileSync(texPath, texLines.join('\n') + '\n');

console.log(`Master Summary MD:      ${masterMdPath}`);
console.log(`Master APIs/Sinks MD:   ${catalogMdPath}`);
console.log(`LaTeX Table:            ${texPath}`);
