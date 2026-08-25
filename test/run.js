'use strict';

/**
 * Kudo Check test suite.
 *
 * Malware fixtures live in test/corpus.js, base64-encoded, and are decoded
 * straight into memory — they are never written to disk. That is deliberate:
 * as plain files they get quarantined by the host antivirus and the suite
 * fails with fixtures silently missing.
 */

const path = require('path');
const zlib = require('zlib');

const { scan, scanEntries } = require('../src/index');
const { entries, CORPUS } = require('./corpus');
const { decodeLayers } = require('../src/core/decode');
const { classify } = require('../src/core/classify');
const { typosquatOf } = require('../src/rules/packages');
const { untar, gunzip } = require('../src/net/tar');
const { parseTarget } = require('../src/net/github');

const A = require('../src/report/ansi');
const { C } = A;

const LEVELS = ['clean', 'lowrisk', 'suspicious', 'likely', 'malicious'];
let pass = 0;
let fail = 0;
const failures = [];

function ok(name, cond, detail) {
  if (cond) { pass++; process.stdout.write(A.paint(C.clean, '  + ') + A.paint(C.muted, name) + '\n'); }
  else {
    fail++;
    failures.push(name + (detail ? '  -> ' + detail : ''));
    process.stdout.write(A.paint(C.critical, '  ! ') + name + (detail ? A.paint(C.faint, '  -> ' + detail) : '') + '\n');
  }
}

function head(t) { process.stdout.write('\n' + A.bold(A.paint(C.accent2, t)) + '\n'); }

async function main() {
  A.setColor(process.stdout.isTTY);
  process.stdout.write('\n' + A.bold('Kudo Check — test suite') + '\n');

  /* ── decoder ── */
  head('decoder');
  {
    const inner = 'const wallet = "wallet.dat"; eval("x");';
    const b64 = Buffer.from(inner).toString('base64');
    const layers = decodeLayers('const S = "' + b64 + '";');
    ok('base64 blob is decoded', layers.length > 0 && layers[0].text.includes('wallet.dat'));

    const gz = zlib.gzipSync(Buffer.from('stratum+tcp://pool.example.invalid:4444 ' + 'x'.repeat(200)));
    const layers2 = decodeLayers('const Z = "' + gz.toString('base64') + '";');
    ok('gzip inside base64 is inflated', layers2.some((l) => l.compressed && l.text.includes('stratum')));

    const exe = Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), Buffer.alloc(400, 0x41)]);
    const layers3 = decodeLayers('const E = "' + exe.toString('base64') + '";');
    ok('embedded executable is recognised', layers3.some((l) => l.executable));

    const once = decodeLayers('const S = "' + b64 + '";');
    ok('a blob is decoded once, not once per pattern', once.length === 1, once.length + ' layers');
  }

  /* ── package heuristics ── */
  head('package heuristics');
  ok('expres → express', typosquatOf('expres', 'npm') === 'express');
  ok('reqeusts → requests (transposition)', typosquatOf('reqeusts', 'pypi') === 'requests');
  ok('express itself is not a squat', typosquatOf('express', 'npm') === null);
  ok('scoped @babel/core is not a squat', typosquatOf('@babel/core', 'npm') === null);
  ok('unrelated name is not a squat', typosquatOf('kudo-check-internal', 'npm') === null);

  /* ── tar ── */
  head('tar reader');
  {
    const name = 'repo-main/src/app.js';
    const body = Buffer.from('console.log(1)\n');
    const hdr = Buffer.alloc(512);
    hdr.write(name, 0);
    hdr.write('0000644\0', 100);
    hdr.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
    hdr.write('        ', 148);
    hdr.write('0', 156);
    hdr.write('ustar  \0', 257);
    const data = Buffer.alloc(512);
    body.copy(data);
    const tar = Buffer.concat([hdr, data, Buffer.alloc(1024)]);
    const files = untar(tar);
    ok('tar entry is read with the top folder stripped',
      files.length === 1 && files[0].rel === 'src/app.js', files.map((f) => f.rel).join(','));
    ok('gunzip round-trips', gunzip(zlib.gzipSync(tar)).length === tar.length);

    const evil = Buffer.alloc(512);
    evil.write('../../../etc/passwd', 0);
    evil.write('00000000004\0', 124);
    evil.write('        ', 148);
    evil.write('0', 156);
    evil.write('ustar  \0', 257);
    const bad = untar(Buffer.concat([evil, Buffer.alloc(512), Buffer.alloc(1024)]));
    ok('path traversal entries are refused', bad.every((f) => !f.rel.includes('..')), JSON.stringify(bad.map((f) => f.rel)));
  }

  /* ── target parsing ── */
  head('github target parsing');
  ok('owner/repo', JSON.stringify(parseTarget('octocat/Hello-World')) === JSON.stringify({ owner: 'octocat', repo: 'Hello-World', ref: null }));
  ok('full url', parseTarget('https://github.com/octocat/Hello-World').repo === 'Hello-World');
  ok('url with branch', parseTarget('https://github.com/o/r/tree/dev').ref === 'dev');
  ok('owner/repo@ref', parseTarget('o/r@v1.2').ref === 'v1.2');
  ok('a plain path is not a repo', parseTarget('./some/dir') === null);

  /* ── corpus classification ── */
  head('corpus classification');
  const results = {};
  for (const g of CORPUS) {
    const r = scanEntries(entries(g.name), { label: g.label });
    results[g.name] = r;
    const cls = r.classification;
    const reached = LEVELS.indexOf(cls.verdict.id) >= LEVELS.indexOf(g.minVerdict);
    ok(g.label + ' reaches ' + g.minVerdict, reached, cls.verdict.id + ' @ ' + cls.score);
    if (g.expectFamily) {
      ok(g.label + ' is named ' + g.expectFamily,
        cls.families.some((f) => f.key === g.expectFamily),
        cls.families.map((f) => f.key).join(',') || 'none');
    }
    if (g.mustBeClean) {
      ok(g.label + ' produces zero findings', r.findings.length === 0,
        r.findings.map((f) => f.ruleId + ' ' + f.file).join('; '));
    }
  }

  ok('stealer variant is identified',
    results.stealer.classification.primary && /grabber|stealer/i.test(results.stealer.classification.primary.variant || ''),
    results.stealer.classification.primary && results.stealer.classification.primary.variant);
  ok('supply-chain typosquat is reported', results.supplychain.findings.some((f) => f.ruleId === 'PKG-004'));
  ok('supply-chain network install hook is reported', results.supplychain.findings.some((f) => f.ruleId === 'PKG-002'));
  ok('ransomware reports Impact capability', results.ransomware.classification.tactics.some((t) => t.key === 'impact'));
  ok('encoded layer detections are found',
    results.obfuscated.findings.some((f) => f.layer && f.layer.startsWith('decoded')),
    results.obfuscated.findings.map((f) => f.layer).join('|'));
  ok('hidden behaviour surfaces through the blob',
    results.obfuscated.findings.some((f) => f.ruleId === 'DEC-001'));

  /* ── evasion resistance ──
     Each variant encodes the same two indicators as the plain one, written
     differently. Fragments are joined at runtime so this file is not itself
     quarantined by the host antivirus. */
  head('evasion resistance');
  {
    const j = (...p) => p.join('');
    const LOGIN = j('Log', 'in Data');
    const DPATH = j('dis', 'cord\\\\Local Stor', 'age\\\\level', 'db');
    const plain = 'p1 = ENV + "\\\\Chrome\\\\' + LOGIN + '"\np2 = ENV + "\\\\' + DPATH + '"';

    const variants = {
      'plain source': plain,
      'split literals': [
        'a = "Log" + "in" + " " + "Data"',
        'b = "dis" + "cord"', 'c = "Local" + " Stor" + "age"', 'd = "level" + "db"',
        'p1 = ENV + "\\\\Chrome\\\\" + a',
        'p2 = ENV + b + "\\\\" + c + "\\\\" + d'
      ].join('\n'),
      'reversed literals': [
        'a = "goL"[::-1] + "ataD ni"[::-1]',
        'b = "drocsid"[::-1]', 'c = "egarotS lacoL"[::-1]', 'd = "bdlevel"[::-1]',
        'p1 = ENV + a', 'p2 = ENV + b + "\\\\" + c + "\\\\" + d'
      ].join('\n'),
      'list join indirection': [
        'P1 = ["Log", "in", " ", "Data"]',
        'P2 = ["dis", "cord", "\\\\", "Local Storage", "\\\\", "leveldb"]',
        'A = "".join(P1)', 'B = "".join(P2)',
        'p1 = ENV + A', 'p2 = ENV + B'
      ].join('\n'),
      'base64 blob': [
        'import base64',
        'S = "' + Buffer.from(plain, 'utf8').toString('base64') + '"',
        'ENABLED = False',
        'if ENABLED: exec(base64.b64decode(S))'
      ].join('\n')
    };

    for (const [label, src] of Object.entries(variants)) {
      const r = scanEntries([{ rel: 'grab.py', buf: Buffer.from(src, 'utf8') }], { label });
      const ids = new Set(r.findings.map((f) => f.ruleId));
      ok(label + ' is detected', ids.has('STL-001') && ids.has('STL-004'),
        [...ids].join(' ') || 'nothing found');
    }

    // Normalisation must not invent findings in ordinary code.
    const benign = [
      'const parts = ["user", "profile", "settings"];',
      'const key = "app" + "_" + "config";',
      'const url = BASE + "/" + parts.join("/");',
      'module.exports = { key, url };'
    ].join('\n');
    const b = scanEntries([{ rel: 'router.js', buf: Buffer.from(benign, 'utf8') }], { label: 'benign' });
    ok('constant folding invents nothing in benign code', b.findings.length === 0,
      b.findings.map((f) => f.ruleId).join(' '));
  }

  /* ── real code must not trip it ── */
  head('self-scan');
  const self = await scan(path.join(__dirname, '..', 'src'), { noNet: true });
  ok('scanner does not flag its own rule database',
    self.classification.verdict.id === 'clean',
    self.classification.verdict.id + ' @ ' + self.classification.score);
  ok('rule database is reported as skipped', self.ruleDbFiles.length > 0);

  /* ── classifier gating ── */
  head('classifier gating');
  {
    const mk = (id, tags) => ({
      ruleId: id, name: id, family: 'ransomware', tactic: 'impact', severity: 'critical',
      weight: 28, tags, file: 'a.py', line: 1, why: '', layer: 'source'
    });
    const one = classify([mk('RSM-001', ['bulk-encrypt'])]);
    ok('encryption alone is not called ransomware',
      !one.families.some((f) => f.key === 'ransomware') && one.gated.some((g) => g.key === 'ransomware'));

    const two = classify([mk('RSM-001', ['bulk-encrypt']), mk('RSM-004', ['shadow-delete'])]);
    ok('encryption plus shadow deletion is called ransomware', two.families.some((f) => f.key === 'ransomware'));
    ok('a variant name is produced', !!(two.primary && two.primary.variant));
    ok('a weak match gets no malware headline',
      classify([{ ruleId: 'NET-001', name: 'x', family: 'rat', tactic: 'c2', severity: 'medium', weight: 10, tags: ['c2-beacon'], file: 'a.js', line: 1, why: '', layer: 'source' }]).confident === false);
  }

  /* ── reporters ── */
  head('reporters');
  {
    const html = require('../src/report/html').render(results.stealer);
    ok('html report renders', html.startsWith('<!doctype html>') && html.length > 8000);
    ok('html report is self-contained', !/(?:src|href)=["']https?:\/\//.test(html));
    ok('html report contains no emoji', !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/u.test(html));
    ok('html escapes finding content', !/<script>alert/.test(html));
    ok('result serialises to json', JSON.parse(JSON.stringify(results.stealer)).classification.score === results.stealer.classification.score);
  }

  const total = pass + fail;
  process.stdout.write('\n' + A.paint(C.line, '-'.repeat(56)) + '\n');
  if (fail) {
    process.stdout.write(A.bold(A.paint(C.critical, fail + ' of ' + total + ' checks failed')) + '\n');
    for (const f of failures) process.stdout.write(A.paint(C.faint, '  · ' + f) + '\n');
  } else {
    process.stdout.write(A.bold(A.paint(C.clean, 'all ' + total + ' checks passed')) + '\n');
  }
  process.stdout.write('\n');
  process.exitCode = fail ? 1 : 0;
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
  process.exitCode = 1;
});
