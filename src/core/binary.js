'use strict';

const crypto = require('crypto');
const { entropy } = require('./entropy');

const MAGIC = [
  { id: 'pe', label: 'Windows PE executable', test: (b) => b[0] === 0x4d && b[1] === 0x5a, risk: 'high' },
  { id: 'elf', label: 'Linux ELF binary', test: (b) => b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46, risk: 'high' },
  { id: 'macho', label: 'macOS Mach-O binary', test: (b) => [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe].includes(b.readUInt32BE(0)), risk: 'high' },
  { id: 'class', label: 'Java class file', test: (b) => b.readUInt32BE(0) === 0xcafebabe, risk: 'medium' },
  { id: 'zip', label: 'ZIP / JAR / APK archive', test: (b) => b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5 || b[2] === 7), risk: 'medium' },
  { id: 'msi', label: 'MSI / OLE compound file', test: (b) => b.readUInt32BE(0) === 0xd0cf11e0, risk: 'high' },
  { id: 'rar', label: 'RAR archive', test: (b) => b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21, risk: 'medium' },
  { id: 'sevenz', label: '7-Zip archive', test: (b) => b[0] === 0x37 && b[1] === 0x7a && b[2] === 0xbc && b[3] === 0xaf, risk: 'medium' },
  { id: 'dex', label: 'Android DEX', test: (b) => b.subarray(0, 3).toString('latin1') === 'dex', risk: 'high' }
];

/** Markers that show up inside packed or bundled executables. */
const IN_BINARY = [
  { id: 'upx', label: 'UPX-packed', re: /UPX[0-9!]/ },
  { id: 'pyinstaller', label: 'PyInstaller bundle', re: /pyi-windows-manifest|PyInstaller|_MEIPASS/ },
  { id: 'nuitka', label: 'Nuitka build', re: /Nuitka|__nuitka/ },
  { id: 'electron', label: 'Electron app', re: /electron\.asar|node_modules\.asar/ },
  { id: 'dotnet', label: '.NET assembly', re: /mscoree\.dll|BSJB/ },
  { id: 'themida', label: 'Themida/VMProtect armoured', re: /Themida|VMProtect|\.vmp\d/ },
  { id: 'autoit', label: 'AutoIt compiled script', re: /AU3!EA0[6-9]|AutoIt3/ },
  { id: 'golang', label: 'Go binary', re: /Go build ID:/ },
  { id: 'confuser', label: 'ConfuserEx protected', re: /ConfusedByAttribute|ConfuserEx/ }
];

/** Extract printable ASCII runs from a binary, like `strings`. */
function extractStrings(buf, min = 6, cap = 400000) {
  const out = [];
  let cur = [];
  const limit = Math.min(buf.length, 8 * 1024 * 1024);
  let total = 0;
  for (let i = 0; i < limit && total < cap; i++) {
    const b = buf[i];
    if (b >= 32 && b <= 126) {
      cur.push(b);
    } else {
      if (cur.length >= min) { const s = Buffer.from(cur).toString('latin1'); out.push(s); total += s.length; }
      cur = [];
    }
  }
  if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
  // UTF-16LE runs (common in Windows binaries)
  cur = [];
  for (let i = 0; i + 1 < limit && total < cap; i += 2) {
    const b = buf[i];
    if (b >= 32 && b <= 126 && buf[i + 1] === 0) cur.push(b);
    else {
      if (cur.length >= min) { const s = Buffer.from(cur).toString('latin1'); out.push(s); total += s.length; }
      cur = [];
    }
  }
  if (cur.length >= min) out.push(Buffer.from(cur).toString('latin1'));
  return out;
}

function identify(buf) {
  const info = { format: null, label: null, risk: 'low', markers: [], entropy: 0, sha256: null };
  if (!buf || buf.length < 8) return info;
  for (const m of MAGIC) {
    let ok = false;
    try { ok = m.test(buf); } catch { ok = false; }
    if (ok) { info.format = m.id; info.label = m.label; info.risk = m.risk; break; }
  }
  const head = buf.subarray(0, Math.min(buf.length, 1024 * 512)).toString('latin1');
  const tail = buf.length > 1024 * 512 ? buf.subarray(buf.length - 262144).toString('latin1') : '';
  for (const m of IN_BINARY) if (m.re.test(head) || m.re.test(tail)) info.markers.push(m.label);
  info.entropy = entropy(buf.subarray(0, Math.min(buf.length, 1024 * 1024)));
  info.sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  return info;
}

module.exports = { identify, extractStrings, MAGIC };
