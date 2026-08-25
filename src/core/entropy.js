'use strict';

/** Shannon entropy in bits/byte over a buffer or string. */
function entropy(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  if (!buf.length) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Heuristics for "this text file does not look like source any more".
 * Returns null, or { entropy, maxLine, reason }.
 */
function textAnomaly(text, rel) {
  const len = text.length;
  if (len < 512) return null;
  const lines = text.split('\n');
  let maxLine = 0;
  for (const l of lines) if (l.length > maxLine) maxLine = l.length;
  const h = entropy(text.slice(0, 262144));
  const avgLine = len / lines.length;
  const isMin = /\.min\.(?:js|css)$/i.test(rel) || /(?:^|\/)(?:bundle|vendor|chunk)[.\-\w]*\.js$/i.test(rel);

  if (h > 5.9 && maxLine > 2000 && !isMin) {
    return { entropy: h, maxLine, reason: 'very high entropy with machine-generated line lengths' };
  }
  if (maxLine > 20000 && !isMin) {
    return { entropy: h, maxLine, reason: 'a single line of ' + maxLine.toLocaleString() + ' characters' };
  }
  if (h > 5.4 && avgLine > 400 && lines.length < 40 && !isMin) {
    return { entropy: h, maxLine, reason: 'few lines, each dense and high-entropy' };
  }
  return null;
}

module.exports = { entropy, textAnomaly };
