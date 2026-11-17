'use strict';

const { tokenize } = require('./tokenize');

const URL_PATTERN = /^https?:\/\//i;
const SHELL_PROGRAMS = new Set(['sh', 'bash', 'zsh', 'dash', 'ash', 'ksh']);
const NODE_PROGRAMS = new Set(['node', 'nodejs']);
const DOWNLOAD_PROGRAMS = new Set(['curl', 'wget', 'fetch']);
const BUILD_TOOLS = new Set([
  'node-gyp', 'make', 'gmake', 'cmake', 'ninja', 'prebuild-install',
  'node-pre-gyp', 'tsc', 'babel', 'webpack', 'rollup', 'esbuild', 'npm', 'npx',
]);
const KNOWN_GLOBALS = new Set([
  'echo', 'cd', 'exit', 'true', 'false', 'test', '[', 'env', 'export', 'set',
  'rm', 'cp', 'mv', 'mkdir', 'ln', 'cat', 'grep', 'sed', 'awk', 'tar', 'unzip',
  'git', 'python', 'python3', 'perl', 'chmod', 'chown', 'touch', 'which',
  'command', 'exec', 'eval', 'xargs', 'find', 'uname', 'if', 'then', 'else',
  'fi', 'for', 'while', 'do', 'done', 'case', 'esac', 'in', 'node-gyp',
]);

const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', '{', '!', 'time']);

function splitPipelines(tokens) {
  const pipelines = [];
  let current = [];
  for (const token of tokens) {
    if (token.type === 'op' && (token.value === '&&' || token.value === '||' || token.value === ';' || token.value === '&')) {
      if (current.length > 0) pipelines.push(current);
      current = [];
    } else {
      current.push(token);
    }
  }
  if (current.length > 0) pipelines.push(current);
  return pipelines;
}

function splitCommands(pipeline) {
  const commands = [];
  let current = [];
  for (const token of pipeline) {
    if (token.type === 'op' && token.value === '|') {
      if (current.length > 0) commands.push(current);
      current = [];
    } else {
      current.push(token);
    }
  }
  if (current.length > 0) commands.push(current);
  return commands;
}

function basename(program) {
  const parts = program.split('/');
  return parts[parts.length - 1];
}

function isLocalPath(program) {
  return /^\.{1,2}\//.test(program) || (program.includes('/') && !program.startsWith('/'));
}

function analyzeCommand(commandTokens, context) {
  const findings = [];
  let words = commandTokens.filter((t) => t.type === 'word');
  while (words.length > 0 && SHELL_KEYWORDS.has(words[0].value)) {
    words = words.slice(1);
  }
  if (words.length === 0) return findings;

  for (const token of commandTokens) {
    if (token.type === 'op' && (token.value === '>' || token.value === '>>' || token.value === '2>' || token.value === '2>>')) {
      const idx = commandTokens.indexOf(token);
      const target = commandTokens.slice(idx + 1).find((t) => t.type === 'word');
      findings.push({
        rule: 'shell-redirection',
        severity: 'medium',
        message: `Shell redirection '${token.value}' writes to ${target ? `'${target.value}'` : 'a file'}`,
        evidence: { script: context.script, offset: token.offset, token: token.value },
      });
    }
  }

  const program = words[0].value;
  const programBase = basename(program);
  const args = words.slice(1);

  for (const arg of args) {
    if (URL_PATTERN.test(arg.value)) {
      findings.push({
        rule: 'network-url',
        severity: 'medium',
        message: `References remote URL '${arg.value}'`,
        evidence: { script: context.script, offset: arg.offset, token: arg.value },
      });
    }
  }

  if (SHELL_PROGRAMS.has(programBase)) {
    findings.push({
      rule: 'shell-interpreter',
      severity: 'medium',
      message: `Invokes shell interpreter '${program}'`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
    const inline = args.find((a) => a.value === '-c');
    if (inline) {
      findings.push({
        rule: 'shell-inline-code',
        severity: 'high',
        message: `Passes inline code to '${program} -c'`,
        evidence: { script: context.script, offset: inline.offset, token: '-c' },
      });
    }
    const scriptArg = args.find((a) => !a.value.startsWith('-') && isLocalPath(a.value));
    if (scriptArg) {
      findings.push({
        rule: 'local-executable',
        severity: 'high',
        message: `Shell interpreter '${program}' executes local script '${scriptArg.value}'`,
        evidence: { script: context.script, offset: scriptArg.offset, token: scriptArg.value },
      });
    }
  }

  if (NODE_PROGRAMS.has(programBase)) {
    findings.push({
      rule: 'node-exec',
      severity: 'low',
      message: `Invokes Node.js runtime '${program}'`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
    const evalFlag = args.find((a) => a.value === '-e' || a.value === '--eval' || a.value === '-p' || a.value === '--print');
    if (evalFlag) {
      findings.push({
        rule: 'node-eval',
        severity: 'high',
        message: `Executes inline JavaScript via '${program} ${evalFlag.value}'`,
        evidence: { script: context.script, offset: evalFlag.offset, token: evalFlag.value },
      });
    }
  }

  if (DOWNLOAD_PROGRAMS.has(programBase)) {
    findings.push({
      rule: 'remote-download',
      severity: 'high',
      message: `Downloads remote content with '${program}'`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
  }

  if (programBase === 'chmod' && args.some((a) => a.value.includes('+x') || /^[0-7]*[1357][0-7]{2}$/.test(a.value))) {
    findings.push({
      rule: 'chmod-executable',
      severity: 'medium',
      message: 'Marks a file executable with chmod',
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
  }

  if (isLocalPath(program) && !NODE_PROGRAMS.has(programBase) && !SHELL_PROGRAMS.has(programBase)) {
    findings.push({
      rule: 'local-executable',
      severity: 'high',
      message: `Executes local file '${program}' from the package`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
  }

  if (!KNOWN_GLOBALS.has(programBase) && !BUILD_TOOLS.has(programBase) && !isLocalPath(program)
      && !SHELL_PROGRAMS.has(programBase) && !NODE_PROGRAMS.has(programBase) && !DOWNLOAD_PROGRAMS.has(programBase)) {
    findings.push({
      rule: 'external-command',
      severity: 'low',
      message: `Invokes external command '${program}' (resolved from PATH at install time)`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
  }

  if (BUILD_TOOLS.has(programBase)) {
    findings.push({
      rule: 'build-tool',
      severity: 'info',
      message: `Invokes build tool '${program}'`,
      evidence: { script: context.script, offset: words[0].offset, token: program },
    });
  }

  return findings;
}

function detectPlatformConditionals(script, tokens) {
  const findings = [];
  const platformPatterns = [
    { pattern: /process\.platform/, label: 'process.platform' },
    { pattern: /process\.arch/, label: 'process.arch' },
    { pattern: /os\.platform\s*\(/, label: 'os.platform()' },
    { pattern: /\$OSTYPE/, label: '$OSTYPE' },
    { pattern: /\buname\b/, label: 'uname' },
  ];
  for (const { pattern, label } of platformPatterns) {
    const match = script.match(pattern);
    if (match) {
      findings.push({
        rule: 'platform-conditional',
        severity: 'info',
        message: `Behavior varies by platform (references ${label})`,
        evidence: { script, offset: match.index, token: match[0] },
      });
    }
  }
  for (const token of tokens) {
    if (token.type === 'word' && (token.value === 'if' || token.value === 'case' || token.value === '[')) {
      const hasConditional = findings.some((f) => f.rule === 'platform-conditional');
      if (hasConditional) break;
    }
  }
  return findings;
}

function analyzeScript(script) {
  const tokens = tokenize(script);
  const findings = [];
  const pipelines = splitPipelines(tokens);

  for (const pipeline of pipelines) {
    const commands = splitCommands(pipeline);
    const commandFindings = commands.map((cmd) => analyzeCommand(cmd, { script }));
    for (const list of commandFindings) findings.push(...list);

    if (commands.length > 1) {
      const programs = commands.map((cmd) => {
        const first = cmd.find((t) => t.type === 'word');
        return first ? basename(first.value) : '';
      });
      const downloads = programs.some((p) => DOWNLOAD_PROGRAMS.has(p));
      const executes = programs.some((p) => SHELL_PROGRAMS.has(p) || NODE_PROGRAMS.has(p));
      if (downloads && executes) {
        const pipeToken = pipeline.find((t) => t.type === 'op' && t.value === '|');
        findings.push({
          rule: 'download-and-execute',
          severity: 'critical',
          message: 'Pipes downloaded remote content directly into an interpreter',
          evidence: { script, offset: pipeToken ? pipeToken.offset : 0, token: '|' },
        });
      }
    }
  }

  findings.push(...detectPlatformConditionals(script, tokens));

  const capabilities = [...new Set(findings.map((f) => f.rule))];
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const maxSeverity = findings.reduce((acc, f) => {
    return severityOrder.indexOf(f.severity) > severityOrder.indexOf(acc) ? f.severity : acc;
  }, 'info');

  return { findings, capabilities, maxSeverity };
}

module.exports = { analyzeScript };
