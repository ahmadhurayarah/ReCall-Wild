import {test} from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';

import {captureLocalBundle} from '../src/capture.mjs';
import {selectCandidateVersions, identifyLibraryVersion, RECALL_ROOT} from '../src/identify.mjs';
import {executeRecovery} from '../src/recover.mjs';
import {lookupVulnerabilities} from '../src/osv.mjs';
import {generateRQ4Report} from '../src/audit.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_OUT = path.resolve(__dirname, '../output/test-run');

test('captureLocalBundle correctly packages bundle directory into manifest', () => {
  const minimalBundleDir = path.join(RECALL_ROOT, 'examples/minimal/bundle');
  const captured = captureLocalBundle(minimalBundleDir, path.join(TEST_OUT, 'captured'));

  assert(fs.existsSync(captured.manifestPath), 'bundle.json should exist');
  const manifest = JSON.parse(fs.readFileSync(captured.manifestPath, 'utf8'));
  assert.equal(manifest.schemaVersion, 'recall.bundle-manifest/v1');
  assert(captured.bundleFiles.length > 0, 'Bundle files should not be empty');
});

test('selectCandidateVersions correctly windows candidate version list', () => {
  const versions = ['1.0.0', '1.0.1', '1.1.0', '1.2.0', '2.0.0', '2.1.0', '3.0.0'];
  const windowed = selectCandidateVersions(versions, '1.2.0', 3);
  assert.deepEqual(windowed, ['1.1.0', '1.2.0', '2.0.0']);

  const latest = selectCandidateVersions(versions, 'latest', 2);
  assert.deepEqual(latest, ['2.1.0', '3.0.0']);
});

test('identifyLibraryVersion successfully matches anchors with local reference', async () => {
  const minimalBundleDir = path.join(RECALL_ROOT, 'examples/minimal/bundle');
  const captured = captureLocalBundle(minimalBundleDir, path.join(TEST_OUT, 'captured'));
  const minimalSourceDir = path.join(RECALL_ROOT, 'examples/minimal/source');

  const result = await identifyLibraryVersion(captured.manifestPath, 'example-library', '1.0.0', {
    localReferenceDir: minimalSourceDir
  });

  assert.equal(result.pkgName, 'example-library');
  assert.equal(result.identifiedVersion, '1.0.0');
  assert(result.matchedAnchors > 0, 'Should find at least 1 POG anchor match');
});

test('executeRecovery executes ReCall static recovery without errors', async () => {
  const minimalBundleDir = path.join(RECALL_ROOT, 'examples/minimal/bundle');
  const captured = captureLocalBundle(minimalBundleDir, path.join(TEST_OUT, 'captured'));
  const minimalSourceDir = path.join(RECALL_ROOT, 'examples/minimal/source');

  const recovery = await executeRecovery({
    bundleManifestPath: captured.manifestPath,
    referencesDir: minimalSourceDir,
    outputDir: path.join(TEST_OUT, 'recovery'),
    prepareOnly: true
  });

  assert.equal(recovery.status, 'prepared');
  assert(recovery.anchors !== null, 'Anchors artifact should exist');
});

test('lookupVulnerabilities matches known CVEs from offline advisory catalog', async () => {
  const vulns = await lookupVulnerabilities('lodash', '4.17.15');
  assert(vulns.length > 0, 'Should detect vulnerabilities for lodash 4.17.15');
  assert(vulns.some(v => v.id.startsWith('CVE-')), 'Should contain standard CVE identifiers');
});

test('generateRQ4Report produces both structured JSON and academic Markdown', async () => {
  const report = await generateRQ4Report({
    targetName: 'test-bundle.js',
    bundlerInfo: {bundler: 'Webpack 5'},
    anchors: {matches: [{bundleId: 'b1', sourceId: 's1'}]},
    summary: {parsedTargetFunctions: 10, astRecoveredFunctions: 4, modelRecoveredFunctions: 2},
    recovered: null,
    libraries: [{pkgName: 'lodash', identifiedVersion: '4.17.15', matchedAnchors: 1, confidence: 0.9}],
    outputDir: path.join(TEST_OUT, 'audit')
  });

  assert(fs.existsSync(report.jsonPath), 'JSON report should be generated');
  assert(fs.existsSync(report.mdPath), 'Markdown report should be generated');

  const mdContent = fs.readFileSync(report.mdPath, 'utf8');
  assert(mdContent.includes('Scientific Function Recovery Yield'));
  assert(mdContent.includes('Downstream Security & CVE Audit'));
});
