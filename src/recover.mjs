/**
 * Step 3: ReCall Function Recovery Adapter
 * Executes ReCall's multi-stage pipeline on the captured bundle and identified references.
 */
import fs from 'node:fs';
import path from 'node:path';
import {RECALL_ROOT} from './identify.mjs';

const {runDirectory} = await import(path.join(RECALL_ROOT, 'src/workflow/run.mjs'));
const {readJSON} = await import(path.join(RECALL_ROOT, 'src/shared/artifacts.mjs'));

export async function executeRecovery({bundleManifestPath, referencesDir, outputDir, prepareOnly = true, clean = true, resume = false}) {
  console.log(`[ReCall Engine] Starting function recovery...`);
  console.log(`  Bundle: ${bundleManifestPath}`);
  console.log(`  References: ${referencesDir}`);
  console.log(`  Output: ${outputDir}`);

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

  const result = await runDirectory({
    output: outputDir,
    captured: bundleDir,
    references: referencesDir,
    prepareOnly,
    resume,
    onProgress,
    config: {
      recovery: {
        minFeatures: 1,
        minAnchors: 1
      }
    }
  });

  const summaryPath = path.join(outputDir, 'summary.json');
  const summary = fs.existsSync(summaryPath) ? readJSON(summaryPath) : null;
  const anchorsPath = path.join(outputDir, 'anchors.json');
  const anchors = fs.existsSync(anchorsPath) ? readJSON(anchorsPath) : null;
  const recoveredPath = path.join(outputDir, 'recovered-functions.json');
  const recovered = fs.existsSync(recoveredPath) ? readJSON(recoveredPath) : null;
  const bundlerPath = path.join(outputDir, 'bundleBundler.json');
  const bundler = fs.existsSync(bundlerPath) ? readJSON(bundlerPath) : null;

  return {
    status: result?.status || 'prepared',
    summary,
    anchors,
    recovered,
    bundler,
    outputDir
  };
}
