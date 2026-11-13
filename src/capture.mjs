/**
 * Step 1: Capture Module
 * Downloads live scripts from an HTTP(S) URL or packages local JavaScript bundles
 * into a standardized ReCall inventory manifest.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function digest(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

export async function captureFromUrl(urlStr, outputDir) {
  fs.mkdirSync(outputDir, {recursive: true});
  console.log(`[Capture] Navigating to: ${urlStr}`);
  
  const res = await fetch(urlStr, {headers: {'User-Agent': 'ReCall-Research-Crawler/1.0'}});
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${urlStr}`);
  const html = await res.text();
  fs.writeFileSync(path.join(outputDir, 'index.html'), html);

  // Extract <script src="...">
  const scriptRegex = /<script\b[^>]*?\bsrc=["']([^"']+)["'][^>]*>/gi;
  const scriptUrls = [];
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    const src = match[1];
    if (src && !src.startsWith('data:')) {
      const fullUrl = new URL(src, urlStr).href;
      scriptUrls.push(fullUrl);
    }
  }

  console.log(`[Capture] Found ${scriptUrls.length} external scripts in page.`);
  const bundleFiles = [];
  let idx = 0;

  for (const scriptUrl of scriptUrls) {
    try {
      console.log(`  Downloading script [${++idx}/${scriptUrls.length}]: ${scriptUrl}`);
      const sRes = await fetch(scriptUrl);
      if (!sRes.ok) continue;
      const code = await sRes.text();
      const filename = `chunk_${idx}_${path.basename(new URL(scriptUrl).pathname) || 'bundle.js'}`;
      const localPath = path.join(outputDir, filename);
      fs.writeFileSync(localPath, code);

      bundleFiles.push({
        id: `chunk-${idx}`,
        path: filename,
        url: scriptUrl,
        sha256: digest(code),
        bytes: Buffer.byteLength(code)
      });
    } catch (err) {
      console.warn(`  Warning: Failed to fetch script ${scriptUrl}: ${err.message}`);
    }
  }

  const manifest = {
    schemaVersion: 'recall.bundle-manifest/v1',
    targetUrl: urlStr,
    capturedAt: new Date().toISOString(),
    files: bundleFiles
  };

  const manifestPath = path.join(outputDir, 'bundle.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return {manifestPath, bundleFiles};
}

export function captureLocalBundle(targetPath, outputDir) {
  fs.mkdirSync(outputDir, {recursive: true});
  const stat = fs.statSync(targetPath);
  const bundleFiles = [];

  if (stat.isDirectory()) {
    // If directory contains bundle.json already, use it
    const existing = path.join(targetPath, 'bundle.json');
    if (fs.existsSync(existing)) {
      return {manifestPath: existing, bundleFiles: JSON.parse(fs.readFileSync(existing, 'utf8')).files || []};
    }
    const files = fs.readdirSync(targetPath).filter(f => f.endsWith('.js') || f.endsWith('.mjs'));
    for (const f of files) {
      const code = fs.readFileSync(path.join(targetPath, f), 'utf8');
      const dest = path.join(outputDir, f);
      fs.writeFileSync(dest, code);
      bundleFiles.push({id: f, path: f, sha256: digest(code), bytes: Buffer.byteLength(code)});
    }
  } else {
    const code = fs.readFileSync(targetPath, 'utf8');
    const f = path.basename(targetPath);
    const dest = path.join(outputDir, f);
    fs.writeFileSync(dest, code);
    bundleFiles.push({id: f, path: f, sha256: digest(code), bytes: Buffer.byteLength(code)});
  }

  const manifest = {
    schemaVersion: 'recall.bundle-manifest/v1',
    source: targetPath,
    capturedAt: new Date().toISOString(),
    files: bundleFiles
  };
  const manifestPath = path.join(outputDir, 'bundle.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  return {manifestPath, bundleFiles};
}
