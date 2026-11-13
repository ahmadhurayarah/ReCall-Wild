/**
 * Step 4: RQ4 Analysis & Downstream Security Auditor
 * Computes recovery yield metrics and audits recovered functions for CVE vulnerabilities.
 */
import fs from 'node:fs';
import path from 'node:path';
import {lookupVulnerabilities} from './osv.mjs';

export async function generateRQ4Report({targetName, bundlerInfo, anchors, summary, recovered, libraries, outputDir}) {
  console.log(`[RQ4 Audit] Generating practical evaluation report...`);

  // 1. Compute Yield Metrics
  const totalBundleFunctions = summary?.parsedTargetFunctions || anchors?.matches?.length || 0;
  const anchorCount = anchors?.matches?.length || 0;
  const astRecovered = summary?.astRecoveredFunctions || 0;
  const modelRecovered = summary?.modelRecoveredFunctions || 0;
  const totalRecovered = anchorCount + astRecovered + modelRecovered;
  const recoveryYield = totalBundleFunctions > 0 ? ((totalRecovered / totalBundleFunctions) * 100).toFixed(2) + '%' : 'N/A';

  // 2. Audit identified libraries for CVEs
  const securityFindings = [];
  for (const lib of libraries) {
    const vulns = await lookupVulnerabilities(lib.pkgName, lib.identifiedVersion);
    for (const v of vulns) {
      securityFindings.push({
        library: lib.pkgName,
        version: lib.identifiedVersion,
        cve: v.id,
        severity: v.severity,
        summary: v.summary,
        vulnerableFunctions: v.vulnerableFunctions || []
      });
    }
  }

  const reportData = {
    target: targetName,
    analyzedAt: new Date().toISOString(),
    yieldMetrics: {
      totalFunctionsInBundle: totalBundleFunctions,
      pogAnchorsFound: anchorCount,
      astRecoveredFunctions: astRecovered,
      modelRecoveredFunctions: modelRecovered,
      totalRecoveredFunctions: totalRecovered,
      recoveryYieldPercentage: recoveryYield,
      detectedBundler: bundlerInfo?.bundler || 'Unknown / Custom'
    },
    identifiedLibraries: libraries.map(l => ({
      library: l.pkgName,
      version: l.identifiedVersion,
      matchedAnchors: l.matchedAnchors,
      confidence: (l.confidence * 100).toFixed(1) + '%'
    })),
    securityAudit: {
      totalVulnerabilitiesFound: securityFindings.length,
      findings: securityFindings
    }
  };

  fs.mkdirSync(outputDir, {recursive: true});
  const jsonPath = path.join(outputDir, 'rq4-report.json');
  fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2));

  // Generate Academic Markdown Report
  const mdLines = [
    `# ReCall RQ4 In-The-Wild Security & Function Recovery Report`,
    ``,
    `**Target Analyzed:** \`${targetName}\`  `,
    `**Analysis Date:** ${reportData.analyzedAt}  `,
    `**Detected Bundler:** ${reportData.yieldMetrics.detectedBundler}  `,
    ``,
    `---`,
    ``,
    `## 1. Scientific Function Recovery Yield`,
    ``,
    `| Metric | Count | Description |`,
    `| :--- | :--- | :--- |`,
    `| **Total Functions in Bundle** | **${totalBundleFunctions}** | Minified candidate functions parsed in target |`,
    `| **POG Anchors (Feature-Matched)** | **${anchorCount}** | Exact property-operation graph anchor seeds |`,
    `| **AST-Recovered Functions** | **${astRecovered}** | Zero-shot normalized AST structure matches |`,
    `| **Model-Recovered Functions (Qwen)** | **${modelRecovered}** | High-confidence model-validated functions |`,
    `| **Overall Recovery Yield** | **${recoveryYield}** | Percentage of identified library functions recovered |`,
    ``,
    `---`,
    ``,
    `## 2. Identified Third-Party Libraries`,
    ``,
    `| Library | Identified Version | POG Anchors | Confidence |`,
    `| :--- | :--- | :--- | :--- |`,
    ...libraries.map(l => `| \`${l.pkgName}\` | **\`${l.identifiedVersion}\`** | ${l.matchedAnchors} | ${(l.confidence * 100).toFixed(1)}% |`),
    ``,
    `---`,
    ``,
    `## 3. Downstream Security & CVE Audit`,
    ``
  ];

  if (securityFindings.length === 0) {
    mdLines.push(`> ✅ **No known high-severity CVEs identified for the recovered libraries and versions.**`);
  } else {
    mdLines.push(`| CVE Identifier | Severity | Affected Library | Summary |`);
    mdLines.push(`| :--- | :--- | :--- | :--- |`);
    for (const f of securityFindings) {
      mdLines.push(`| **${f.cve}** | \`${f.severity}\` | \`${f.library}@${f.version}\` | ${f.summary} |`);
    }
  }

  const mdPath = path.join(outputDir, 'rq4-report.md');
  fs.writeFileSync(mdPath, mdLines.join('\n'));

  console.log(`[RQ4 Audit] Reports saved to:`);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);

  return {jsonPath, mdPath, reportData};
}
