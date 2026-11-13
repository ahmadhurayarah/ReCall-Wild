/**
 * Security Vulnerability Auditor (OSV & Offline Advisory Catalog)
 * Queries known CVEs for identified library versions and maps them to functions.
 */

// Embedded offline advisory catalog for common frontend packages
const OFFLINE_ADVISORIES = {
  'lodash': [
    {
      id: 'CVE-2021-23337',
      summary: 'Command Injection in template',
      affected: '< 4.17.21',
      severity: 'HIGH',
      functions: ['template']
    },
    {
      id: 'CVE-2020-8203',
      summary: 'Prototype Pollution in zipObjectDeep',
      affected: '< 4.17.19',
      severity: 'HIGH',
      functions: ['zipObjectDeep', 'set', 'setWith']
    },
    {
      id: 'CVE-2019-10744',
      summary: 'Prototype Pollution in defaultsDeep',
      affected: '< 4.17.12',
      severity: 'CRITICAL',
      functions: ['defaultsDeep', 'merge', 'mergeWith']
    }
  ],
  'jquery': [
    {
      id: 'CVE-2020-11022',
      summary: 'Cross-site Scripting (XSS) in htmlPrefilter',
      affected: '>= 1.2.0 < 3.5.0',
      severity: 'MEDIUM',
      functions: ['htmlPrefilter', 'buildFragment']
    },
    {
      id: 'CVE-2019-11358',
      summary: 'Prototype Pollution in jQuery.extend',
      affected: '< 3.4.0',
      severity: 'MEDIUM',
      functions: ['extend']
    }
  ],
  'axios': [
    {
      id: 'CVE-2023-45857',
      summary: 'Cross-Site Request Forgery (CSRF) via data-upload',
      affected: '< 1.6.0',
      severity: 'HIGH',
      functions: ['request', 'post', 'put']
    }
  ]
};

/**
 * Query OSV database for known package vulnerabilities
 */
export async function lookupVulnerabilities(pkgName, version) {
  const findings = [];

  // 1. Check OSV live API
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        package: {name: pkgName, ecosystem: 'npm'},
        version: version
      })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.vulns && Array.isArray(data.vulns)) {
        for (const v of data.vulns) {
          findings.push({
            id: v.id,
            summary: v.summary || v.details?.slice(0, 100) || 'Known Vulnerability',
            severity: v.database_specific?.severity || 'UNKNOWN',
            source: 'OSV.dev'
          });
        }
      }
    }
  } catch {
    // Live query failed (offline or network block), fall back to offline catalog
  }

  // 2. Check offline fallback catalog
  const catalog = OFFLINE_ADVISORIES[pkgName.toLowerCase()] || [];
  for (const item of catalog) {
    if (!findings.some(f => f.id === item.id)) {
      findings.push({
        id: item.id,
        summary: item.summary,
        severity: item.severity,
        affectedVersions: item.affected,
        vulnerableFunctions: item.functions,
        source: 'Offline Advisory Catalog'
      });
    }
  }

  return findings;
}
