#!/usr/bin/env node
/**
 * ReCall-Wild Unified CLI
 * Usage:
 *   recall-wild pipeline <url-or-file> <library-name> [--out <dir>]
 *   recall-wild identify <bundle-file> <library-name> [--window <n>]
 *   recall-wild audit <url-or-file> <library-name>
 */
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

import {captureFromUrl, captureLocalBundle} from '../src/capture.mjs';
import {identifyLibraryVersion} from '../src/identify.mjs';
import {executeRecovery} from '../src/recover.mjs';
import {generateRQ4Report} from '../src/audit.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
ReCall-Wild: In-the-Wild Function Recovery & Downstream Security Audit CLI

Commands:
  pipeline <target> <library> [options]    Run full 4-stage practical pipeline
  identify <bundle> <library> [options]    Identify exact library & npm version
  audit <target> <library> [options]       Run security audit for CVE vulnerabilities
  help                                     Show this help message

Options:
  --out <dir>          Output directory for generated artifacts (default: ./output)
  --window <n>         Candidate version pool window size (default: 5)
  --local-ref <dir>    Use local library source directory as reference
  --prepare-only       Run static analysis and AST checks (skip remote GPU validation)

Examples:
  node bin/recall-wild.mjs pipeline https://example.com/app lodash
  node bin/recall-wild.mjs identify bundle.js react
  node bin/recall-wild.mjs pipeline ./bundle.js lodash --local-ref ./reference/lodash
`);
}

function getOption(flag, defaultValue = null) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return defaultValue;
}

const hasFlag = flag => args.includes(flag);

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  const target = args[1];
  const library = args[2];
  const outDir = path.resolve(process.cwd(), getOption('--out', './output'));
  const localRef = getOption('--local-ref', null);
  const windowSize = parseInt(getOption('--window', '5'), 10);
  let prepareOnly = hasFlag('--prepare-only');

  // Auto-detect if Ollama is available; if not, automatically fall back to static/AST mode
  if (!prepareOnly) {
    try {
      const probe = await fetch('http://127.0.0.1:11434/api/version', {signal: AbortSignal.timeout(1000)});
      if (!probe.ok) prepareOnly = true;
    } catch {
      console.log(`[ReCall-Wild] Notice: Local Ollama endpoint (127.0.0.1:11434) not reachable.`);
      console.log(`              Running in AST-first static mode. (Full GPU validation active on AutoDL server).\n`);
      prepareOnly = true;
    }
  }

  if (!target || !library) {
    console.error(`Error: Both <target> and <library> arguments are required.`);
    printHelp();
    process.exit(1);
  }

  console.log(`=======================================================`);
  console.log(`  ReCall-Wild: Function Recovery & Security Pipeline   `);
  console.log(`=======================================================`);
  console.log(`Target:  ${target}`);
  console.log(`Library: ${library}`);
  console.log(`Output:  ${outDir}\n`);

  fs.mkdirSync(outDir, {recursive: true});

  if (command === 'identify') {
    // Run Step 1 (Capture Local) + Step 2 (Version ID)
    const captured = captureLocalBundle(path.resolve(process.cwd(), target), path.join(outDir, 'captured-bundle'));
    const idResult = await identifyLibraryVersion(captured.manifestPath, library, 'latest', {
      windowSize,
      localReferenceDir: localRef ? path.resolve(process.cwd(), localRef) : null
    });
    console.log(`\nIdentified Version: ${idResult.pkgName}@${idResult.identifiedVersion} (Confidence: ${(idResult.confidence * 100).toFixed(1)}%)`);
    return;
  }

  if (command === 'pipeline' || command === 'audit') {
    // Step 1: Capture
    console.log(`--- [Step 1/4] Capturing JavaScript Bundle ---`);
    let captured;
    if (target.startsWith('http://') || target.startsWith('https://')) {
      captured = await captureFromUrl(target, path.join(outDir, 'captured-bundle'));
    } else {
      captured = captureLocalBundle(path.resolve(process.cwd(), target), path.join(outDir, 'captured-bundle'));
    }

    // Step 2: Version Identification
    console.log(`\n--- [Step 2/4] Identifying Library & Version ---`);
    const idResult = await identifyLibraryVersion(captured.manifestPath, library, 'latest', {
      windowSize,
      localReferenceDir: localRef ? path.resolve(process.cwd(), localRef) : null
    });
    console.log(`Identified: ${idResult.pkgName}@${idResult.identifiedVersion}`);

    // Step 3: ReCall Function Recovery
    console.log(`\n--- [Step 3/4] Running ReCall Function Recovery ---`);
    const recoveryResult = await executeRecovery({
      bundleManifestPath: captured.manifestPath,
      referencesDir: idResult.referenceDir,
      outputDir: path.join(outDir, 'recovery-artifacts'),
      prepareOnly
    });

    // Step 4: Downstream Security & Yield Audit
    console.log(`\n--- [Step 4/4] Downstream Security & Yield Audit ---`);
    const report = await generateRQ4Report({
      targetName: target,
      bundlerInfo: recoveryResult.bundler,
      anchors: recoveryResult.anchors,
      summary: recoveryResult.summary,
      recovered: recoveryResult.recovered,
      libraries: [idResult],
      outputDir: outDir
    });

    console.log(`\n=======================================================`);
    console.log(`  ReCall-Wild Execution Complete!                      `);
    console.log(`  Executive Report: ${report.mdPath}                   `);
    console.log(`=======================================================`);
  } else {
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
  }
}

main().catch(err => {
  console.error('\n[Error in ReCall-Wild]:', err.message);
  process.exit(1);
});
