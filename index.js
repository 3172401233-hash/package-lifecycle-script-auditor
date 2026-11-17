'use strict';

const { audit } = require('./src/audit');
const { analyzeScript } = require('./src/analyze-script');
const { buildGraph } = require('./src/graph');
const { extractHooks, AUDITED_HOOKS } = require('./src/hooks');
const { tokenize } = require('./src/tokenize');

module.exports = { audit, analyzeScript, buildGraph, extractHooks, AUDITED_HOOKS, tokenize };
