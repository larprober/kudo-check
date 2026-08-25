'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', '.idea', '.vscode', '__pycache__', '.pytest_cache',
  '.gradle', '.next', '.nuxt', '.cache', '.venv', 'venv', 'env', 'dist-info'
]);

/** Directories that are noisy but occasionally carry the payload. Scanned at
 *  reduced depth unless --include-deps is passed. */
const DEP_DIRS = new Set(['node_modules', 'vendor', 'bower_components', 'site-packages', 'target', 'build', 'dist', 'out']);

const BINARY_EXT = new Set([
  'exe', 'dll', 'sys', 'scr', 'msi', 'com', 'cpl', 'ocx', 'drv', 'efi',
  'so', 'dylib', 'o', 'a', 'bin', 'elf', 'ko',
  'jar', 'class', 'dex', 'apk', 'aab', 'pyc', 'pyd', 'pyo', 'wasm', 'nupkg',
  'zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tar', 'iso', 'img', 'cab', 'vhd'
]);

const MEDIA_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'icns', 'svg', 'tiff',
  'mp3', 'mp4', 'wav', 'ogg', 'webm', 'avi', 'mov', 'flac', 'psd',
  'ttf', 'otf', 'woff', 'woff2', 'eot', 'pdf',
  // design/binary-ish document formats that are not source but parse as text
  'ai', 'eps', 'indd', 'sketch', 'fig', 'xcf', 'blend', 'afdesign', 'afphoto'
]);

/** Paths that are legitimately full of scary strings. Findings here are kept
 *  but their weight is discounted by the scorer. */
const CONTEXT_DISCOUNT = [
  /(?:^|[\\/])(?:tests?|__tests__|spec|fixtures?|samples?|examples?|mocks?|testdata)[\\/]/i,
  /(?:^|[\\/])(?:docs?|documentation|man)[\\/]/i,
  /\.(?:md|rst|txt|adoc)$/i,
  /(?:^|[\\/])(?:CHANGELOG|README|SECURITY|CONTRIBUTING)/i,
  /\.(?:test|spec)\.[jt]sx?$/i,
  /(?:^|[\\/])(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|composer\.lock)$/i
];

function ext(p) {
  const m = /\.([A-Za-z0-9_+-]{1,10})$/.exec(p);
  return m ? m[1].toLowerCase() : '';
}

function discounted(rel) {
  return CONTEXT_DISCOUNT.some((re) => re.test(rel));
}

function kindOf(rel, buf) {
  const e = ext(rel);
  if (MEDIA_EXT.has(e)) return 'media';
  if (BINARY_EXT.has(e)) return 'binary';
  if (!buf) return 'text';
  const probe = buf.subarray(0, Math.min(buf.length, 8192));
  let nul = 0;
  let high = 0;
  for (let i = 0; i < probe.length; i++) {
    const b = probe[i];
    if (b === 0) nul++;
    else if (b > 0x7e) high++;
  }
  if (nul > 0) return 'binary';
  if (probe.length && high / probe.length > 0.35) return 'binary';
  return 'text';
}

/**
 * Walk a directory into a flat file list.
 * Returns [{ rel, abs, size, kind, discounted }]
 */
function walkDir(root, opts = {}) {
  const maxFiles = opts.maxFiles || 40000;
  const maxSize = opts.maxSize || 12 * 1024 * 1024;
  const includeDeps = !!opts.includeDeps;
  const out = [];
  const skipped = { deps: 0, big: 0, media: 0 };

  (function rec(dir, depth) {
    if (out.length >= maxFiles || depth > 24) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (out.length >= maxFiles) return;
      const abs = path.join(dir, ent.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (ent.isSymbolicLink()) continue;
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        if (DEP_DIRS.has(ent.name) && !includeDeps) { skipped.deps++; continue; }
        rec(abs, depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      let st;
      try { st = fs.statSync(abs); } catch { continue; }
      const e = ext(rel);
      if (MEDIA_EXT.has(e) && st.size < 4 * 1024 * 1024) { skipped.media++; continue; }
      if (st.size > maxSize) { skipped.big++; continue; }
      out.push({ rel, abs, size: st.size, kind: null, discounted: discounted(rel) });
    }
  })(root, 0);

  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files: out, skipped };
}

/** Build the same shape from an in-memory list (used by the GitHub fetcher). */
function fromMemory(entries) {
  return {
    files: entries.map((e) => ({
      rel: e.rel, abs: null, size: e.buf.length, buf: e.buf,
      kind: null, discounted: discounted(e.rel)
    })),
    skipped: { deps: 0, big: 0, media: 0 }
  };
}

function readFile(f) {
  if (f.buf) return f.buf;
  try { return fs.readFileSync(f.abs); } catch { return null; }
}

module.exports = { walkDir, fromMemory, readFile, kindOf, ext, BINARY_EXT, MEDIA_EXT };
