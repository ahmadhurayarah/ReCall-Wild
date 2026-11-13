<h1 align="center">ReCall-Wild</h1>
<p align="center"><strong>In-the-wild function recovery & downstream security audit for bundled JavaScript.</strong></p>
<p align="center">Capture live bundles · identify npm versions · ReCall AST/POG recovery · audit CVE vulnerabilities</p>
<p align="center">
  <a href="package.json"><img alt="Node.js 24 or later" src="https://img.shields.io/badge/Node.js-24%2B-339933?logo=nodedotjs&amp;logoColor=white"></a>
  <img alt="Zero Dependencies" src="https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Node)-blue">
  <img alt="Matching: POG + AST" src="https://img.shields.io/badge/Matching-POG%20%2B%20AST-059669">
  <img alt="Downstream CVE Audit" src="https://img.shields.io/badge/Downstream-CVE%20Audit-red">
</p>
<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#cli-usage">CLI usage</a> ·
  <a href="#empirical-benchmark">Empirical benchmark</a> ·
  <a href="#outputs">Outputs</a>
</p>

---

## Overview

`ReCall-Wild` is the practical-use research toolkit and CLI companion for **ReCall** (*"Accurate and Scalable Function Recovery for Bundled JavaScript"*).

While laboratory benchmarks operate on curated subjects with preserved sourcemap answers, `ReCall-Wild` addresses **RQ4: Practical Use**: recovering function identities from real-world, minified production JavaScript in the wild and conducting automated supply chain vulnerability audits.

- **Zero third-party dependencies.** Built entirely on modern native Node.js standard libraries (`node:fs`, `node:crypto`, `node:zlib`, `fetch`). No heavy local package installation required.
- **Dual-registry candidate pooling.** Automatically resolves version candidate pools from npm with instant fallback to mirrors (`npmmirror.com`) to avoid network timeouts.
- **AST-first structural matching.** Uses ReCall's normalized AST comparisons and Property Operation Graph (POG) fingerprints before dispatching model requests.
- **Automated CVE correlation.** Cross-references recovered function boundaries with the Open Source Vulnerability (OSV) database to pinpoint active vulnerabilities inside minified production code.

---

## How It Works

The operational pipeline processes minified targets through four sequential stages:

```text
1. Capture                     2. Version ID                 3. ReCall Recovery             4. Security & Yield Audit
┌───────────────────────┐      ┌─────────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│ HTTP URL or Local     │ ───► │ POG Fingerprint     │ ───►  │ Anchors + Graphs     │ ───►  │ Function Yield Metrics │
│ Minified Chunks       │      │ Pools (from npm)    │       │ + Normalized AST     │       │ + Known CVE Mapping    │
└───────────────────────┘      └─────────────────────┘       └──────────────────────┘       └────────────────────────┘
```

1. **Capture (`src/capture.mjs`):** Downloads production JavaScript files directly from a target live URL or ingests local production chunks into a standard ReCall inventory manifest (`bundle.json`).
2. **Version Identification (`src/identify.mjs`):** Generates candidate version release tarballs from npm registries, extracts POG fingerprints, and ranks candidate versions by anchor density against the target bundle.
3. **Function Recovery (`src/recover.mjs`):** Executes ReCall's multi-stage recovery engine: POG Anchors $\to$ Module Graphs $\to$ Radius-1 Neighborhoods $\to$ AST Check $\to$ Model Validation.
4. **Security & Yield Audit (`src/audit.mjs`, `src/osv.mjs`):** Computes overall function recovery yields across bundlers and cross-references recovered functions with known CVE advisories.

---

## Quick Start

Requires **Node.js 24+** and sibling [`ReCall`](../ReCall) core engine.

```sh
# 1. Install / link project (takes < 1 second; zero external downloads)
npm install

# 2. Run the native test suite
npm test
```

---

## CLI Usage

Commands can be invoked directly through the unified binary or via `npm`:

```sh
# Analyze a live website URL:
node bin/recall-wild.mjs pipeline https://editor.swagger.io lodash

# Analyze a local minified bundle:
node bin/recall-wild.mjs pipeline /path/to/bundle.js lodash

# Run standalone version identification:
node bin/recall-wild.mjs identify /path/to/bundle.js react --window 5

# Force AST-first static mode (skips GPU model queries):
node bin/recall-wild.mjs pipeline /path/to/bundle.js lodash --prepare-only
```

---

## In-The-Wild Website Analysis

### Real-World Example:
```bash
node bin/recall-wild.mjs pipeline https://editor.swagger.io lodash
```

### What ReCall-Wild Does Automatically (Under the Hood):

```text
               1. Crawl & Ingest
Live Website ─────────────────────► Downloads all production <script src="..."> chunks
(e.g., Swagger-UI)                  into output/captured-bundle/
                                          │
                                          ▼
                               2. Version Identification
                                    Downloads candidate releases from npm
                                    (e.g., lodash@4.17.15 ... 4.17.21)
                                    Matches POG fingerprints to find EXACT version
                                          │
                                          ▼
                               3. ReCall Function Recovery
                                    Reconstructs original function boundaries
                                    from minified code (e.g. `function a(e,t)` -> `debounce`)
                                          │
                                          ▼
                               4. Downstream Security & CVE Audit
                                    Queries OSV.dev database for known CVEs
                                    Checks if the vulnerable functions are inside the bundle!
```

---

## Empirical Benchmark

To evaluate cross-target recovery yields and security findings across the target catalog:

```sh
npm run eval:rq4
```

This generates an aggregated summary table formatted for LaTeX/Markdown manuscripts under `results/rq4-benchmark-summary.md`.

---

## Outputs

After running the pipeline, generated artifacts are saved to `output/` (or `results/` for benchmark suites):

* **`output/captured-bundle/`**: All raw minified `.js` scripts extracted directly from the live website or local target.
* **`output/rq4-report.md`**: Executive summary and empirical table displaying:
  * Total functions found in the live website bundle.
  * Exact library and npm version detected.
  * Recovery yield percentage.
  * **Downstream Security Findings**: Any active CVE vulnerabilities found in those production functions.
* **`output/rq4-report.json`**: Machine-readable data for papers and benchmarks.
* **`output/recovery-artifacts/`**: Full ReCall graph, anchor, and module artifacts.

---

## Repository Structure

```text
ReCall-Wild/
├── bin/
│   └── recall-wild.mjs            # Unified CLI binary
├── src/                           # Core operational modules
│   ├── capture.mjs                # Step 1: Ingest live URL / local bundle
│   ├── identify.mjs               # Step 2: Library & npm version identification
│   ├── recover.mjs                # Step 3: ReCall function recovery adapter
│   ├── osv.mjs                    # OSV vulnerability database & offline advisories
│   ├── audit.mjs                  # Step 4: Practical yield & security reporting
│   └── index.mjs                  # SDK exports
├── experiments/                   # Research question benchmark suite
│   └── rq4-in-the-wild/           # In-the-wild benchmark runner & target catalog
│       ├── targets.json           # Catalog of evaluation targets
│       └── run-benchmark.mjs      # Aggregated benchmark summary generator
├── test/                          # Native Node.js test suite
│   └── pipeline.test.mjs
├── docs/                          # Academic documentation & technical reference
│   ├── RECALL_NOTES.md            # Technical reference & architecture guide
│   ├── EXAMPLES.md                # Walkthrough with concrete JSON artifacts
│   ├── REAL_WORLD_ANALOGY.md      # Conceptual analogies & mental models
│   └── *.pdf                      # Academic manuscripts
├── package.json                   # Matches ReCall project conventions
└── README.md
```

---

## License
MIT License. Built as an open-source evaluation suite for JavaScript function recovery and supply chain security analysis.
