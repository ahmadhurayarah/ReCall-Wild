/**
 * Step 2: Library & Version Identification Module
 * Matches bundled POG fingerprints against version candidate pools from npm registries
 * or local references to identify the exact library and version.
 */
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';
import {gunzipSync} from 'node:zlib';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const RECALL_ROOT = process.env.RECALL_ROOT || [
  path.resolve(__dirname, '../../ReCall'),
  path.resolve(__dirname, '../ReCall'),
  path.resolve(__dirname, '../../../ReCall'),
  '/root/autodl-tmp/workspace/ReCall'
].find(p => fs.existsSync(p)) || path.resolve(__dirname, '../../ReCall');

const REGISTRIES = [
  'https://registry.npmjs.org',
  'https://registry.npmmirror.com' // Fallback for mainland China / AutoDL servers
];

// Dynamically import ReCall POG components
const {extractFeatures, identifyAnchors} = await import(path.join(RECALL_ROOT, 'components/pog/index.mjs'));
const {discoverJavaScript, referenceManifest} = await import(path.join(RECALL_ROOT, 'src/workflow/inputs.mjs'));
const {readJSON, writeJSON} = await import(path.join(RECALL_ROOT, 'src/shared/artifacts.mjs'));

/**
 * Fetch package version history from registry
 */
export async function fetchRegistryManifest(pkgName) {
  let lastError;
  for (const reg of REGISTRIES) {
    const url = `${reg}/${encodeURIComponent(pkgName)}`;
    try {
      const res = await fetch(url, {headers: {'Accept': 'application/json'}});
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(`Failed to fetch metadata for ${pkgName} from registries: ${lastError?.message || 'Not found'}`);
}

/**
 * Select a sliding window of candidate versions around a base version
 */
export function selectCandidateVersions(allVersions, baseVersion = 'latest', windowSize = 5) {
  if (baseVersion === 'latest') {
    return allVersions.slice(-windowSize);
  }
  const idx = allVersions.indexOf(baseVersion);
  if (idx === -1) {
    return allVersions.slice(-windowSize);
  }
  const half = Math.floor(windowSize / 2);
  const start = Math.max(0, idx - half);
  const end = Math.min(allVersions.length, start + windowSize);
  return allVersions.slice(start, end);
}

/**
 * Extract tar.gz into destination directory using pure Node.js
 */
export function extractPackageTarball(tarGzBuffer, destDir) {
  fs.mkdirSync(destDir, {recursive: true});
  const tarBuffer = gunzipSync(tarGzBuffer);
  let offset = 0;

  while (offset < tarBuffer.length - 512) {
    const header = tarBuffer.subarray(offset, offset + 512);
    if (header.every(b => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '').trim();
    if (!name) break;

    const sizeStr = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeStr, 8) || 0;
    const type = header[156];
    offset += 512;

    const cleanName = name.replace(/^package\//, '');
    // Skip pre-minified distributions (*.min.js) so ReCall always recovers readable original symbol names
    if (/\.min\.(?:[cm]?js)$/i.test(cleanName)) {
      offset += Math.ceil(size / 512) * 512;
      continue;
    }
    const outPath = path.join(destDir, cleanName);

    if (type === 0x35 || name.endsWith('/')) { // Directory
      fs.mkdirSync(outPath, {recursive: true});
    } else if (size > 0) { // Regular file
      fs.mkdirSync(path.dirname(outPath), {recursive: true});
      const fileData = tarBuffer.subarray(offset, offset + size);
      fs.writeFileSync(outPath, fileData);
    }
    offset += Math.ceil(size / 512) * 512;
  }
}

/**
 * Download a specific npm version tarball and unpack it
 */
export async function downloadPackageVersion(pkgName, version, destDir) {
  if (fs.existsSync(destDir) && fs.readdirSync(destDir).length > 0) {
    return destDir;
  }
  let tarballUrl = null;
  for (const reg of REGISTRIES) {
    const metaUrl = `${reg}/${encodeURIComponent(pkgName)}/${version}`;
    try {
      const res = await fetch(metaUrl);
      if (res.ok) {
        const data = await res.json();
        tarballUrl = data?.dist?.tarball;
        if (tarballUrl) break;
      }
    } catch {}
  }

  if (!tarballUrl) {
    tarballUrl = `https://registry.npmjs.org/${pkgName}/-/${pkgName}-${version}.tgz`;
  }

  const res = await fetch(tarballUrl);
  if (!res.ok) throw new Error(`HTTP ${res.status} downloading ${tarballUrl}`);
  const arrayBuf = await res.arrayBuffer();
  extractPackageTarball(Buffer.from(arrayBuf), destDir);
  return destDir;
}

/**
 * Identify library version against candidate versions pool using POG fingerprints
 */
export async function identifyLibraryVersion(bundleManifestPath, pkgName, knownOrBaseVersion = 'latest', {windowSize = 5, localReferenceDir = null, poolsDir = null} = {}) {
  console.log(`[VersionID] Identifying version for library: ${pkgName}...`);

  // 1. Ingest bundle files into POG features
  const bundleDir = path.dirname(bundleManifestPath);
  const bundleFeatures = extractFeatures(discoverJavaScript(bundleDir));

  // Fast path: if a local reference directory is explicitly provided
  if (localReferenceDir && fs.existsSync(localReferenceDir)) {
    console.log(`[VersionID] Using provided local reference: ${localReferenceDir}`);
    let detectedVer = '1.0.0';
    try {
      const pkgPath = path.join(localReferenceDir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (pkgData.version) detectedVer = pkgData.version;
      }
    } catch {}
    const sourceFeatures = extractFeatures(referenceManifest(localReferenceDir, {includeTypeScript: true}));
    const anchors = identifyAnchors(sourceFeatures, bundleFeatures, {minFeatures: 1, minAnchors: 1});
    return {
      pkgName,
      identifiedVersion: detectedVer,
      confidence: 1.0,
      matchedAnchors: anchors.matches.length,
      candidateRankings: [{version: detectedVer, score: anchors.matches.length, anchors: anchors.matches}],
      referenceDir: localReferenceDir
    };
  }

  // 2. Fetch candidates from npm (with offline fallback to cached pools)
  const basePoolsDir = poolsDir || path.resolve(__dirname, '../pools', pkgName);
  let meta = null;
  try {
    meta = await fetchRegistryManifest(pkgName);
  } catch (err) {
    if (fs.existsSync(basePoolsDir)) {
      const cached = fs.readdirSync(basePoolsDir).filter(f => {
        try { return fs.statSync(path.join(basePoolsDir, f)).isDirectory(); } catch { return false; }
      });
      if (cached.length > 0) {
        console.log(`[VersionID] Registry fetch failed (${err.message}). Using ${cached.length} cached versions from pools/${pkgName}...`);
        meta = { versions: Object.fromEntries(cached.map(v => [v, {}])) };
      }
    }
    if (!meta) throw err;
  }

  const allVersions = Object.keys(meta.versions || {});
  const candidateVersions = selectCandidateVersions(allVersions, knownOrBaseVersion, windowSize);
  console.log(`[VersionID] Evaluating ${candidateVersions.length} candidate versions:`, candidateVersions);

  fs.mkdirSync(basePoolsDir, {recursive: true});

  const scores = [];
  for (const ver of candidateVersions) {
    const verDir = path.join(basePoolsDir, ver);
    try {
      await downloadPackageVersion(pkgName, ver, verDir);
      const sourceFeatures = extractFeatures(referenceManifest(verDir, {includeTypeScript: true}));
      const anchors = identifyAnchors(sourceFeatures, bundleFeatures, {minFeatures: 5, minAnchors: 1});

      scores.push({
        version: ver,
        score: anchors.matches.length,
        anchors: anchors.matches,
        referenceDir: verDir
      });
      console.log(`  Version ${ver}: ${anchors.matches.length} matching anchors`);
    } catch (err) {
      console.warn(`  Failed evaluating ${ver}: ${err.message}`);
    }
  }

  scores.sort((a, b) => b.score - a.score);
  const best = scores[0] || {version: knownOrBaseVersion, score: 0, referenceDir: null};

  return {
    pkgName,
    identifiedVersion: best.version,
    confidence: best.score > 0 ? Math.min(1.0, best.score / 10) : 0,
    matchedAnchors: best.score,
    candidateRankings: scores,
    referenceDir: best.referenceDir
  };
}
