/**
 * Step 3: ReCall Function Recovery Adapter
 * Executes ReCall's multi-stage pipeline on the captured bundle and identified references.
 */
import fs from 'node:fs';
import path from 'node:path';
import {performance} from 'node:perf_hooks';
import {RECALL_ROOT} from './identify.mjs';
import {createDeepSeekModelClient} from './deepseek-models.mjs';

const {runDirectory, exportRecovered, summarizeRecovery} = await import(path.join(RECALL_ROOT, 'src/workflow/run.mjs'));
const {recoverFunctions} = await import(path.join(RECALL_ROOT, 'components/pipeline/index.mjs'));
const {readJSON, writeJSON} = await import(path.join(RECALL_ROOT, 'src/shared/artifacts.mjs'));

export async function executeRecovery({
  bundleManifestPath,
  referencesDir,
  outputDir,
  prepareOnly = true,
  useDeepSeek = false,
  maxValidationCalls = 100,
  clean = true,
  resume = false
}) {
  console.log(`[ReCall Engine] Starting function recovery...`);
  console.log(`  Bundle: ${bundleManifestPath}`);
  console.log(`  References: ${referencesDir}`);
  console.log(`  Output: ${outputDir}`);
  if (useDeepSeek) {
    console.log(`  Validator: DeepSeek API (${process.env.DEEPSEEK_MODEL || 'deepseek-chat'}) + Local AST/Token Ranking (budget=${maxValidationCalls} calls)`);
  }

  if (clean && !resume && fs.existsSync(outputDir)) {
    fs.rmSync(outputDir, {recursive: true, force: true});
  }
  fs.mkdirSync(outputDir, {recursive: true});

  const bundleDir = path.dirname(bundleManifestPath);

  let lastStage = null;
  const onProgress = event => {
    if (event.stage !== lastStage) {
      lastStage = event.stage;
      const detail = event.recovered !== undefined ? ` [${event.recovered}/${event.targets || '?'} functions mapped]` : '';
      console.log(`  [ReCall Progress] Stage: ${event.stage}${detail} (${(event.elapsedMs / 1000).toFixed(1)}s)`);
    }
  };

  // When using DeepSeek, run prepareOnly via runDirectory (no Ollama preflight required),
  // then run full recoverFunctions() with our injected DeepSeek model client!
  const result = await runDirectory({
    output: outputDir,
    captured: bundleDir,
    references: referencesDir,
    prepareOnly: useDeepSeek ? true : prepareOnly,
    resume,
    onProgress,
    config: {
      recovery: {
        minFeatures: 1,
        minAnchors: 1
      }
    }
  });

  if (useDeepSeek) {
    const started = performance.now();
    const source = readJSON(path.join(outputDir, 'source.json'));
    const bundle = readJSON(path.join(outputDir, 'bundle.json'));
    const sourceGraph = readJSON(path.join(outputDir, 'sourceGraph.json'));
    const bundleGraph = readJSON(path.join(outputDir, 'bundleGraph.json'));
    const anchors = readJSON(path.join(outputDir, 'anchors.json'));
    const libraries = readJSON(path.join(outputDir, 'libraries.json'));

    const models = createDeepSeekModelClient({
      cacheDir: path.join(outputDir, 'model-cache')
    });

    console.log(`  [ReCall Progress] Stage: full-recovery (AST-first + DeepSeek validation)...`);
    const recResult = await recoverFunctions({
      source,
      bundle,
      sourceGraph,
      bundleGraph,
      anchors,
      libraries,
      models,
      config: {
        minFeatures: 1,
        minAnchors: 1,
        maxValidationCalls
      }
    });

    const recoveredExport = exportRecovered(recResult, source, bundle);
    const summaryObj = summarizeRecovery(recResult, bundle);

    writeJSON(path.join(outputDir, 'recovery.json'), recResult, {overwrite: true});
    writeJSON(path.join(outputDir, 'recovered-functions.json'), recoveredExport, {overwrite: true});
    writeJSON(path.join(outputDir, 'summary.json'), summaryObj, {overwrite: true});
    writeJSON(
      path.join(outputDir, 'status.json'),
      {status: recResult.status, validator: 'deepseek', elapsedMs: performance.now() - started},
      {overwrite: true}
    );

    console.log(
      `  [ReCall Progress] Stage: finished [${summaryObj.recoveredFunctions} recovered: ${summaryObj.anchorFunctions} POG + ${summaryObj.astRecoveredFunctions} AST + ${summaryObj.modelRecoveredFunctions} DeepSeek] (${((performance.now() - started) / 1000).toFixed(1)}s)`
    );
  }

  const summaryPath = path.join(outputDir, 'summary.json');
  const summary = fs.existsSync(summaryPath) ? readJSON(summaryPath) : null;
  const anchorsPath = path.join(outputDir, 'anchors.json');
  const anchors = fs.existsSync(anchorsPath) ? readJSON(anchorsPath) : null;
  const recoveredPath = path.join(outputDir, 'recovered-functions.json');
  const recovered = fs.existsSync(recoveredPath) ? readJSON(recoveredPath) : null;
  const bundlerPath = path.join(outputDir, 'bundleBundler.json');
  const bundler = fs.existsSync(bundlerPath) ? readJSON(bundlerPath) : null;

  return {
    status: recovered ? 'finished' : result?.status || 'prepared',
    summary,
    anchors,
    recovered,
    bundler,
    outputDir
  };
}
