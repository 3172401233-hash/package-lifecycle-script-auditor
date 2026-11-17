'use strict';

function packageNameFromPath(lockfilePath) {
  if (!lockfilePath) return null;
  const segments = lockfilePath.split('/');
  const last = segments[segments.length - 1];
  if (last.startsWith('@')) {
    return `${last}/${segments[segments.length - 1]}`;
  }
  const idx = lockfilePath.lastIndexOf('node_modules/');
  return idx === -1 ? last : lockfilePath.slice(idx + 'node_modules/'.length);
}

function parseLockfile(lockfile) {
  const nodes = new Map();
  if (lockfile.packages && typeof lockfile.packages === 'object') {
    for (const [path, entry] of Object.entries(lockfile.packages)) {
      if (path === '') continue;
      const name = entry.name || packageNameFromPath(path);
      nodes.set(path, {
        id: path,
        name,
        version: entry.version || null,
        dependencies: Object.keys(entry.dependencies || {}),
        dev: Boolean(entry.dev),
      });
    }
    return { format: 'packages', nodes };
  }
  if (lockfile.dependencies && typeof lockfile.dependencies === 'object') {
    const visit = (deps, prefix) => {
      for (const [name, entry] of Object.entries(deps)) {
        const path = `${prefix}node_modules/${name}`;
        nodes.set(path, {
          id: path,
          name,
          version: entry.version || null,
          dependencies: Object.keys(entry.dependencies || {}),
          dev: Boolean(entry.dev),
        });
        if (entry.dependencies) visit(entry.dependencies, `${path}/`);
      }
    };
    visit(lockfile.dependencies, '');
    return { format: 'dependencies', nodes };
  }
  return { format: 'unknown', nodes };
}

function resolveDependency(nodes, fromPath, depName) {
  let prefix = fromPath;
  while (true) {
    const candidate = prefix ? `${prefix}/node_modules/${depName}` : `node_modules/${depName}`;
    if (nodes.has(candidate)) return candidate;
    if (!prefix) return null;
    const idx = prefix.lastIndexOf('/node_modules/');
    if (idx === -1) {
      prefix = prefix.includes('/') ? '' : '';
      if (prefix === '') {
        const direct = `node_modules/${depName}`;
        return nodes.has(direct) ? direct : null;
      }
      continue;
    }
    prefix = prefix.slice(0, idx);
  }
}

function buildEdges(nodes) {
  const edges = new Map();
  for (const [id, node] of nodes) {
    const targets = [];
    for (const depName of node.dependencies) {
      const resolved = resolveDependency(nodes, id, depName);
      if (resolved) targets.push(resolved);
    }
    edges.set(id, targets);
  }
  return edges;
}

function directDependencyNames(packageJson) {
  const names = new Set();
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const name of Object.keys(packageJson[field] || {})) names.add(name);
  }
  return names;
}

function computeChains(nodes, edges, packageJson) {
  const direct = directDependencyNames(packageJson);
  const chains = new Map();
  const queue = [];
  for (const name of direct) {
    const rootPath = `node_modules/${name}`;
    if (nodes.has(rootPath) && !chains.has(rootPath)) {
      chains.set(rootPath, [name]);
      queue.push(rootPath);
    }
  }
  while (queue.length > 0) {
    const current = queue.shift();
    const currentChain = chains.get(current);
    for (const next of edges.get(current) || []) {
      if (!chains.has(next)) {
        chains.set(next, [...currentChain, nodes.get(next).name]);
        queue.push(next);
      }
    }
  }
  return chains;
}

function findCycles(nodes, edges) {
  const cycles = [];
  const state = new Map();
  const stack = [];
  const visit = (id) => {
    state.set(id, 'visiting');
    stack.push(id);
    for (const next of edges.get(id) || []) {
      if (state.get(next) === 'visiting') {
        const start = stack.indexOf(next);
        const cycle = stack.slice(start).map((p) => nodes.get(p).name);
        cycle.push(nodes.get(next).name);
        const key = cycle.join('->');
        if (!cycles.some((c) => c.join('->') === key)) cycles.push(cycle);
      } else if (!state.has(next)) {
        visit(next);
      }
    }
    stack.pop();
    state.set(id, 'done');
  };
  for (const id of nodes.keys()) {
    if (!state.has(id)) visit(id);
  }
  return cycles;
}

function buildGraph(packageJson, lockfile) {
  const { format, nodes } = parseLockfile(lockfile);
  const edges = buildEdges(nodes);
  const chains = computeChains(nodes, edges, packageJson);
  const cycles = findCycles(nodes, edges);
  return { format, nodes, edges, chains, cycles };
}

module.exports = { buildGraph, parseLockfile, packageNameFromPath };
