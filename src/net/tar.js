'use strict';

const zlib = require('zlib');

/**
 * Minimal tar reader. Handles ustar and GNU long-name entries, which is
 * everything GitHub's tarballs contain.
 * @returns [{ rel, buf }]
 */
function untar(buf, opts = {}) {
  const maxFiles = opts.maxFiles || 20000;
  const maxSize = opts.maxSize || 12 * 1024 * 1024;
  const stripComponents = opts.stripComponents == null ? 1 : opts.stripComponents;
  const out = [];
  let off = 0;
  let longName = null;

  while (off + 512 <= buf.length && out.length < maxFiles) {
    const hdr = buf.subarray(off, off + 512);
    if (hdr.every((b) => b === 0)) break;

    const str = (start, len) => {
      const s = hdr.subarray(start, start + len).toString('utf8');
      const z = s.indexOf('\0');
      return (z === -1 ? s : s.slice(0, z)).trim();
    };

    let name = str(0, 100);
    const sizeOct = str(124, 12);
    const type = String.fromCharCode(hdr[156]);
    const prefix = str(345, 155);
    const size = parseInt(sizeOct, 8) || 0;
    const dataStart = off + 512;
    const padded = Math.ceil(size / 512) * 512;
    off = dataStart + padded;

    if (type === 'L') {                       // GNU long filename
      longName = buf.subarray(dataStart, dataStart + size).toString('utf8').replace(/\0+$/, '');
      continue;
    }
    if (longName) { name = longName; longName = null; }
    if (prefix) name = prefix + '/' + name;
    if (type !== '0' && type !== '' && type !== '\0') continue;   // only regular files
    if (size > maxSize) continue;

    let rel = name.split('/').filter(Boolean);
    if (stripComponents) rel = rel.slice(stripComponents);
    if (!rel.length) continue;
    // refuse path traversal from a hostile archive
    if (rel.some((p) => p === '..')) continue;

    out.push({ rel: rel.join('/'), buf: buf.subarray(dataStart, dataStart + size) });
  }
  return out;
}

function gunzip(buf) {
  return zlib.gunzipSync(buf, { maxOutputLength: 512 * 1024 * 1024 });
}

module.exports = { untar, gunzip };
