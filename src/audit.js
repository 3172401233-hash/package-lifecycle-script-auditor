'use strict';

const { buildGraph } = require('./graph');
const { extractHooks } = require('./hooks');
const { analyzeScript } = require('./analyze-script');

function audit(options) {
  const { packageJson, lockfile, packageManifests } = options;
  if (!packageJson || typeof packageJson !== 'object') {
    throw new TypeError('audit: `packageJson` (object) is required');
  }
  if (!lockfile || typeof lockfile !== 'object') {
    throw new TypeError('audit: `lockfile` (object) is required');
  }

  const graph = buildGraph(packageJson, lockfile);
  const manifests = packageManifests || {};
  const packages = [];

  const rootEntry = {
    name: packageJson.name || '(root)',
    version: packageJson.version || null,
    lockfilePath: '',
    direct: true,
    chain: [packageJson.name || '(root)'],
    hooks: [],
    missingScripts: !packageJson.scripts || Object.keys(packageJson.scripts).length === 0,
  };
  for (const hook of extractHooks(packageJson)) {
    const analysis = analyzeScript(hook.script);
    rootEntry.hooks.push({ name: hook.name, script: hook.script, ...analysis });
  }
  packages.push(rootEntry);

  for (const [path, node] of graph.nodes) {
    const manifest = manifests[path] || manifests[node.name] || null;
    const chain = graph.chains.get(path) || null;
    const entry = {
      name: node.name,
      version: node.version,
      lockfilePath: path,
      direct: chain !== null && chain.length === 1,
      chain,
      hooks: [],
      missingScripts: false,
    };
    if (!manifest) {
      entry.missingScripts = true;
      entry.note = 'No package manifest provided; lifecycle scripts cannot be audited statically';
    } else if (!manifest.scripts || extractHooks(manifest).length === 0) {
      entry.missingScripts = true;
    } else {
      for (const hook of extractHooks(manifest)) {
        const analysis = analyzeScript(hook.script);
        entry.hooks.push({ name: hook.name, script: hook.script, ...analysis });
      }
    }
    packages.push(entry);
  }

  const allFindings = [];
  for (const pkg of packages) {
    for (const hook of pkg.hooks) {
      for (const finding of hook.findings) {
        allFindings.push({
          package: pkg.name,
          version: pkg.version,
          lockfilePath: pkg.lockfilePath,
          chain: pkg.chain,
          hook: hook.name,
          ...finding,
        });
      }
    }
  }

  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const summary = {
    packagesAudited: packages.length,
    packagesWithHooks: packages.filter((p) => p.hooks.length > 0).length,
    packagesMissingScripts: packages.filter((p) => p.missingScripts).length,
    hooksFound: packages.reduce((n, p) => n + p.hooks.length, 0),
    findingsBySeverity: Object.fromEntries(
      severityOrder.map((s) => [s, allFindings.filter((f) => f.severity === s).length])
    ),
    cycles: graph.cycles,
  };

  return { summary, packages, findings: allFindings };
}

module.exports = { audit };
