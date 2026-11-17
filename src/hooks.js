'use strict';

const AUDITED_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'preprepare',
  'postprepare',
  'prepack',
  'postpack',
  'prepublish',
];

function extractHooks(manifest) {
  const hooks = [];
  const scripts = (manifest && manifest.scripts) || {};
  for (const name of AUDITED_HOOKS) {
    if (typeof scripts[name] === 'string' && scripts[name].trim() !== '') {
      hooks.push({ name, script: scripts[name] });
    }
  }
  return hooks;
}

module.exports = { extractHooks, AUDITED_HOOKS };
