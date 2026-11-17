'use strict';

const OPERATORS = ['&&', '||', '>>', '<<', '2>', '2>>', '>', '<', ';', '|', '&', '(', ')'];

function tokenize(script) {
  const tokens = [];
  let i = 0;
  const n = script.length;
  while (i < n) {
    const ch = script[i];
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < n && script[i] !== '\n') i += 1;
      continue;
    }
    let op = null;
    for (const candidate of OPERATORS) {
      if (script.startsWith(candidate, i)) {
        op = candidate;
        break;
      }
    }
    if (op) {
      tokens.push({ type: 'op', value: op, offset: i });
      i += op.length;
      continue;
    }
    const start = i;
    let value = '';
    while (i < n) {
      const c = script[i];
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '#') break;
      if (OPERATORS.some((candidate) => script.startsWith(candidate, i))) break;
      if (c === "'" ) {
        const end = script.indexOf("'", i + 1);
        if (end === -1) {
          value += script.slice(i + 1);
          i = n;
        } else {
          value += script.slice(i + 1, end);
          i = end + 1;
        }
        continue;
      }
      if (c === '"') {
        i += 1;
        while (i < n && script[i] !== '"') {
          if (script[i] === '\\' && i + 1 < n) {
            value += script[i + 1];
            i += 2;
          } else {
            value += script[i];
            i += 1;
          }
        }
        i += 1;
        continue;
      }
      if (c === '\\' && i + 1 < n) {
        value += script[i + 1];
        i += 2;
        continue;
      }
      value += c;
      i += 1;
    }
    tokens.push({ type: 'word', value, offset: start });
  }
  return tokens;
}

module.exports = { tokenize };
