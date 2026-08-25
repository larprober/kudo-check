'use strict';

const zlib = require('zlib');

/**
 * Fresh regex objects per invocation. These are stateful (/g keeps
 * lastIndex) and decodeLayers recurses into itself — sharing one set
 * between the outer and inner call makes the outer loop re-match the
 * same blob until it hits the output cap.
 */
function patterns() {
  return {
    B64: /["'`]([A-Za-z0-9+/]{44,}={0,2})["'`]/g,
    B64_BARE: /(?:^|[\s=(,])([A-Za-z0-9+/]{120,}={0,2})(?=$|[\s),;'"`])/gm,
    HEXSTR: /["'`]((?:[0-9a-fA-F]{2}){40,})["'`]/g,
    XESC: /((?:\\x[0-9a-fA-F]{2}){24,})/g,
    CHARCODE: /String\.fromCharCode\s*\(([\d\s,]{40,})\)/g,
    URLENC: /((?:%[0-9a-fA-F]{2}){30,})/g
  };
}

function printableRatio(buf) {
  if (!buf.length) return 0;
  let ok = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) ok++;
  }
  return ok / buf.length;
}

function tryInflate(buf) {
  try {
    if (buf[0] === 0x1f && buf[1] === 0x8b) return zlib.gunzipSync(buf);
    if (buf[0] === 0x78 && (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda)) return zlib.inflateSync(buf);
  } catch { /* not compressed */ }
  return null;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Pull encoded blobs out of source and decode one or two layers deep.
 * Returns [{ text, encoding, line, bytes, compressed, executable }]
 */
function decodeLayers(text, depth = 0, maxOut = 24, seen = new Set()) {
  const out = [];
  if (depth > 1 || text.length > 4 * 1024 * 1024) return out;
  const P = patterns();

  const push = (raw, encoding, index, note) => {
    if (out.length >= maxOut || !raw || !raw.length) return;
    let buf = raw;
    let compressed = false;
    const inf = tryInflate(buf);
    if (inf) { buf = inf; compressed = true; }
    const exe = buf.length > 2 && (
      (buf[0] === 0x4d && buf[1] === 0x5a) ||
      (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) ||
      (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03)
    );
    if (!exe && printableRatio(buf) < 0.85) return;
    const decoded = buf.toString('utf8');
    const key = encoding + ':' + buf.length + ':' + decoded.slice(0, 120);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      text: decoded.slice(0, 200000),
      encoding: encoding + (compressed ? '+deflate' : ''),
      line: lineOf(text, index),
      bytes: buf.length,
      compressed,
      executable: exe,
      note: note || null
    });
    if (!exe) {
      for (const nested of decodeLayers(decoded, depth + 1, 6, seen)) {
        nested.encoding = encoding + ' → ' + nested.encoding;
        nested.line = lineOf(text, index);
        out.push(nested);
      }
    }
  };

  let m;
  P.B64.lastIndex = 0;
  while ((m = P.B64.exec(text)) && out.length < maxOut) {
    if (m[1].length % 4 === 0 || m[1].endsWith('=')) push(Buffer.from(m[1], 'base64'), 'base64', m.index);
  }
  P.B64_BARE.lastIndex = 0;
  while ((m = P.B64_BARE.exec(text)) && out.length < maxOut) {
    push(Buffer.from(m[1], 'base64'), 'base64', m.index);
  }
  P.HEXSTR.lastIndex = 0;
  while ((m = P.HEXSTR.exec(text)) && out.length < maxOut) {
    push(Buffer.from(m[1], 'hex'), 'hex', m.index);
  }
  P.XESC.lastIndex = 0;
  while ((m = P.XESC.exec(text)) && out.length < maxOut) {
    push(Buffer.from(m[1].replace(/\\x/g, ''), 'hex'), 'hex-escape', m.index);
  }
  P.URLENC.lastIndex = 0;
  while ((m = P.URLENC.exec(text)) && out.length < maxOut) {
    try { push(Buffer.from(decodeURIComponent(m[1]), 'utf8'), 'url-encoded', m.index); } catch { /* malformed */ }
  }
  P.CHARCODE.lastIndex = 0;
  while ((m = P.CHARCODE.exec(text)) && out.length < maxOut) {
    const codes = m[1].split(',').map((n) => parseInt(n.trim(), 10)).filter((n) => n >= 0 && n < 65536);
    if (codes.length > 12) push(Buffer.from(String.fromCharCode.apply(null, codes), 'utf8'), 'char-codes', m.index);
  }

  return out;
}

module.exports = { decodeLayers, printableRatio };
