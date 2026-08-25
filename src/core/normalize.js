'use strict';

/**
 * Constant folding for source text.
 *
 * A signature engine matches what is written. Malware writes the same thing
 * differently: "Log" + "in Data", a name assigned once and used later, a
 * reversed literal, a \x escape. None of that changes behaviour, all of it
 * defeats a regex.
 *
 * This produces a second, normalised view of a file — literals folded,
 * single-assignment constants substituted, escapes and reverse/join idioms
 * resolved — which is scanned alongside the original. It is not a parser and
 * does not pretend to be: it is a cheap approximation of "what does this
 * string actually say", and it is deliberately allowed to be lossy, because
 * the normalised text is never executed, only searched.
 */

const MAX_INPUT = 1024 * 1024;
const MAX_PASSES = 4;
const MAX_CONSTS = 400;
const MAX_CONST_LEN = 300;

/** Cheap pre-check: is there anything here worth normalising? */
function worthNormalising(text) {
  return /["'`]\s*[+.]\s*["'`]/.test(text) ||          // "a" + "b" / "a" . "b"
         /\[\s*::\s*-\s*1\s*\]/.test(text) ||          // python reverse slice
         /\.reverse\s*\(\s*\)/.test(text) ||
         /\.join\s*\(/.test(text) ||
         /\\x[0-9a-fA-F]{2}/.test(text) ||
         /\\u\{?[0-9a-fA-F]{4}/.test(text) ||
         /(?:^|\n)\s*(?:const|let|var)?\s*[A-Za-z_$][\w$]*\s*=\s*["'`][^"'`\n]{2,}["'`]/.test(text);
}

function reverseString(s) {
  return s.split('').reverse().join('');
}

/** "a" + "b"  ->  "ab"   (also PHP's "a" . "b", and adjacent literals) */
function foldConcat(text) {
  let out = text;
  let guard = 0;
  // Only explicit operators. An "adjacent literals" rule (Python/C implicit
  // concatenation) was also tried and removed: inside a list, `"a", "b"` is
  // ambiguous with the literal `", "`, and it silently ate array elements.
  const patterns = [
    /(["'])((?:(?!\1)[^\\\n]|\\.){0,400})\1\s*\+\s*(["'])((?:(?!\3)[^\\\n]|\\.){0,400})\3/g,
    /(["'])((?:(?!\1)[^\\\n]|\\.){0,400})\1\s*\.\s*(["'])((?:(?!\3)[^\\\n]|\\.){0,400})\3/g
  ];
  let changed = true;
  while (changed && guard++ < 12) {
    changed = false;
    for (const re of patterns) {
      re.lastIndex = 0;
      const next = out.replace(re, (m, q1, a, q2, b) => {
        changed = true;
        return q1 + a + b + q1;
      });
      if (next !== out) out = next;
    }
  }
  return out;
}

/** Resolve \xHH and \uHHHH to the characters they stand for. */
function foldEscapes(text) {
  return text
    .replace(/\\x([0-9a-fA-F]{2})/g, (m, h) => {
      const c = parseInt(h, 16);
      return c >= 32 && c <= 126 ? String.fromCharCode(c) : m;
    })
    .replace(/\\u\{?([0-9a-fA-F]{4,6})\}?/g, (m, h) => {
      const c = parseInt(h, 16);
      return c >= 32 && c <= 126 ? String.fromCharCode(c) : m;
    });
}

/** "abc"[::-1] and "abc".split('').reverse().join('') -> "cba" */
function foldReverse(text) {
  let out = text.replace(/(["'])((?:(?!\1)[^\\\n]){1,300})\1\s*\[\s*::\s*-\s*1\s*\]/g,
    (m, q, s) => q + reverseString(s) + q);
  out = out.replace(/(["'])((?:(?!\1)[^\\\n]){1,300})\1\s*\.\s*split\s*\(\s*(["'])\3\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(["'])\4\s*\)/g,
    (m, q, s) => q + reverseString(s) + q);
  out = out.replace(/reversed\s*\(\s*(["'])((?:(?!\1)[^\\\n]){1,300})\1\s*\)/g,
    (m, q, s) => q + reverseString(s) + q);
  return out;
}

/**
 * "".join(["a","b"]) and ["a","b"].join("") -> "ab"
 *
 * These patterns are written out in full rather than composed from a shared
 * sub-pattern: embedding a source string that contains backreferences shifts
 * every group number, and the composed regex then quietly never matches.
 */
const LIT = '(?:"[^"\\n]{0,200}"|\'[^\'\\n]{0,200}\')';
const LIST = '\\[\\s*(?:' + LIT + '\\s*,\\s*){0,60}' + LIT + '\\s*,?\\s*\\]';
const JOIN_SUFFIX = new RegExp('(?:""|\'\')\\s*\\.\\s*join\\s*\\(\\s*(' + LIST + ')\\s*\\)', 'g');
const JOIN_PREFIX = new RegExp('(' + LIST + ')\\s*\\.\\s*join\\s*\\(\\s*(?:""|\'\')\\s*\\)', 'g');

function foldJoin(text) {
  let out = text.replace(JOIN_SUFFIX, (m, list) => '"' + literalsOf(list).join('') + '"');
  out = out.replace(JOIN_PREFIX, (m, list) => '"' + literalsOf(list).join('') + '"');
  return out;
}

function literalsOf(list) {
  const out = [];
  const re = /"([^"\n]{0,200})"|'([^'\n]{0,200})'/g;
  let m;
  while ((m = re.exec(list))) out.push(m[1] !== undefined ? m[1] : m[2]);
  return out;
}

/**
 * Substitute names that are assigned a string literal exactly once.
 * Single assignment only — a name written twice is not a constant.
 */
function propagateConstants(text) {
  const assign = /(?:^|\n)[ \t]*(?:const|let|var|final|readonly)?[ \t]*([A-Za-z_$][\w$]{0,60})[ \t]*=[ \t]*(["'])((?:(?!\2)[^\\\n]|\\.){1,300})\2[ \t]*[;\r]?(?=\n|$)/g;
  const counts = new Map();
  const values = new Map();
  let m;
  while ((m = assign.exec(text)) && values.size < MAX_CONSTS) {
    const name = m[1];
    counts.set(name, (counts.get(name) || 0) + 1);
    values.set(name, m[3]);
  }
  if (!values.size) return text;

  let out = text;
  for (const [name, value] of values) {
    if (counts.get(name) !== 1) continue;
    // Single-letter names are explicitly allowed: `a = "Log" + "in Data"` is
    // the whole point. The value has to carry some content to be worth it.
    if (value.length > MAX_CONST_LEN || value.length < 3) continue;
    // Reserved-ish names would wreck the text for no gain.
    if (/^(?:if|for|in|is|as|or|and|not|def|class|return|this|self)$/i.test(name)) continue;
    const use = new RegExp('(?<![\\w$."\'`])' + name.replace(/[$]/g, '\\$') + '(?![\\w$])', 'g');
    let hits = 0;
    out = out.replace(use, (mm, off) => {
      // leave the assignment line itself alone
      hits++;
      return hits === 1 ? mm : '"' + value + '"';
    });
  }
  return out;
}

/**
 * Inline lists that are assigned once and later joined:
 *   PARTS = ["Log", "in", " ", "Data"]   ->   "".join(["Log", ...])
 * so that foldJoin can collapse them.
 */
function propagateLists(text) {
  const assign = /(?:^|\n)[ \t]*(?:const|let|var)?[ \t]*([A-Za-z_$][\w$]{0,60})[ \t]*=[ \t]*(\[[^\][\n]{0,600}\])[ \t]*[;\r]?(?=\n|$)/g;
  const values = new Map();
  const counts = new Map();
  let m;
  while ((m = assign.exec(text)) && values.size < 120) {
    if (!/["']/.test(m[2])) continue;
    counts.set(m[1], (counts.get(m[1]) || 0) + 1);
    values.set(m[1], m[2]);
  }
  let out = text;
  for (const [name, list] of values) {
    if (counts.get(name) !== 1) continue;
    const use = new RegExp('(?<![\\w$."\'`])' + name.replace(/[$]/g, '\\$') + '(?![\\w$])\\s*(?=\\)|\\.\\s*join)', 'g');
    out = out.replace(use, list);
  }
  return out;
}

/**
 * @returns { text, changed } — the normalised view, or the original unchanged.
 */
function normalize(text) {
  if (!text || text.length > MAX_INPUT || !worthNormalising(text)) {
    return { text, changed: false };
  }
  let out = text;
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    const before = out;
    out = foldEscapes(out);
    out = foldReverse(out);
    out = propagateLists(out);
    out = foldJoin(out);
    out = foldConcat(out);
    out = propagateConstants(out);
    out = foldConcat(out);
    if (out === before) break;
    if (out.length > text.length * 4 + 4096) break;   // runaway substitution
  }
  return { text: out, changed: out !== text };
}

module.exports = { normalize, worthNormalising };
