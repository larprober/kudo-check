'use strict';

const fs = require('fs');
const path = require('path');

const A = require('./report/ansi');
const term = require('./report/term');
const html = require('./report/html');
const { scan, VERSION } = require('./index');

const FLAGS = {
  '--json': 'json', '--html': 'html', '--all': 'all', '--limit': 'limit',
  '--include-deps': 'includeDeps', '--no-decode': 'noDecode', '--no-normalize': 'noNormalize', '--no-strings': 'noStrings',
  '--no-net': 'noNet', '--no-color': 'noColor', '--quiet': 'quiet', '--fail-on': 'failOn',
  '--no-explain': 'noExplain', '-h': 'help', '--help': 'help', '-v': 'version', '--version': 'version',
  '--rules': 'rules', '--open': 'open', '--demo': 'demo'
};

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { opts._.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('-')) {
      const key = FLAGS[a];
      if (!key) throw new Error('Unknown option: ' + a + '   (try --help)');
      if (['json', 'html', 'limit', 'failOn'].includes(key)) {
        const next = argv[i + 1];
        if (key === 'json' && (!next || next.startsWith('-'))) opts.json = true;
        else { opts[key] = next; i++; }
      } else opts[key] = true;
    } else opts._.push(a);
  }
  return opts;
}

function help() {
  const { C } = A;
  const b = (s) => A.bold(s);
  const d = (s) => A.paint(C.faint, s);
  const h = (s) => A.paint(C.accent2, s);
  return [
    '',
    term.banner(VERSION),
    h('USAGE'),
    '  kudo <target> [options]',
    '',
    d('  target can be a directory, a single file, a GitHub URL, or owner/repo'),
    '',
    h('EXAMPLES'),
    '  kudo .                                  ' + d('scan the current project'),
    '  kudo ./suspicious-download              ' + d('scan a folder'),
    '  kudo octocat/Hello-World                ' + d('fetch and scan a GitHub repo'),
    '  kudo https://github.com/user/repo       ' + d('same, full URL'),
    '  kudo user/repo@dev                      ' + d('a specific branch or tag'),
    '  kudo . --html report.html --open        ' + d('write and open the visual report'),
    '  kudo . --json result.json --quiet       ' + d('machine-readable output for CI'),
    '  kudo --demo ransomware                  ' + d('scan a built-in inert sample, from memory'),
    '',
    h('OPTIONS'),
    '  ' + b('--html <file>') + '      write the designed HTML report',
    '  ' + b('--open') + '             open the HTML report when it is written',
    '  ' + b('--json [file]') + '      JSON to a file, or to stdout when no file is given',
    '  ' + b('--all') + '              list every detection instead of the top 40',
    '  ' + b('--limit <n>') + '        how many detections to print (default 40)',
    '  ' + b('--no-explain') + '       drop the plain-English reason under each detection',
    '  ' + b('--include-deps') + '     also scan node_modules, vendor, dist, build',
    '  ' + b('--no-decode') + '        skip base64/hex/gzip layer decoding',
    '  ' + b('--no-normalize') + '     skip the constant-folding de-obfuscation pass',
    '  ' + b('--no-strings') + '       skip string extraction from binaries',
    '  ' + b('--no-net') + '           never touch the network (local targets only)',
    '  ' + b('--fail-on <level>') + '  exit non-zero at clean|lowrisk|suspicious|likely|malicious',
    '  ' + b('--rules') + '            print the signature inventory and exit',
    '  ' + b('--demo [name]') + '      scan a built-in inert sample (stealer, ransomware, rat,',
    '                     miner, supplychain, obfuscated, clean)',
    '  ' + b('--no-color') + '  ' + b('--quiet') + '  ' + b('--version') + '  ' + b('--help'),
    '',
    h('EXIT CODES'),
    '  0  below the fail threshold      1  threshold met      2  scan error',
    '',
    d('  GITHUB_TOKEN is used for API calls when set, which raises the rate limit.'),
    ''
  ].join('\n');
}

function rulesInventory() {
  const { SIGNATURES } = require('./rules/signatures');
  const { FAMILIES } = require('./rules/families');
  const { C } = A;
  const lines = ['', term.banner(VERSION)];
  const byFam = new Map();
  for (const s of SIGNATURES) {
    if (!byFam.has(s.family)) byFam.set(s.family, []);
    byFam.get(s.family).push(s);
  }
  for (const [fam, list] of [...byFam.entries()].sort()) {
    const def = FAMILIES[fam] || { label: fam };
    lines.push(A.bold(A.paint(C.accent2, def.label.toUpperCase())) + A.paint(C.faint, '  ' + list.length + ' signatures'));
    for (const s of list.sort((a, b) => a.id.localeCompare(b.id))) {
      lines.push('  ' + A.sevMark(s.severity) + ' ' + A.paint(C.faint, A.pad(s.id, 9)) +
        A.paint(C.ink, A.pad(s.name, 46)) + A.paint(C.faint, 'w' + s.weight + (s.span ? '  span' : '')));
    }
    lines.push('');
  }
  lines.push(A.paint(C.faint, SIGNATURES.length + ' signatures across ' + byFam.size + ' families, plus manifest, entropy, decoder, filename and binary heuristics.'));
  lines.push('');
  return lines.join('\n');
}

const LEVELS = ['clean', 'lowrisk', 'suspicious', 'likely', 'malicious'];

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    process.stderr.write(A.paint(A.C.critical, e.message) + '\n');
    return 2;
  }
  if (opts.noColor) A.setColor(false);
  if (opts.version) { process.stdout.write('kudo-check ' + VERSION + '\n'); return 0; }
  if (opts.help || (!opts._.length && !opts.rules && !opts.demo)) { process.stdout.write(help() + '\n'); return opts.help ? 0 : 2; }
  if (opts.rules) { process.stdout.write(rulesInventory() + '\n'); return 0; }

  if (opts.demo) {
    // The demo corpus is decoded into memory and never written to disk.
    const { scanEntries } = require('./index');
    let corpus;
    try { corpus = require('../test/corpus'); } catch {
      process.stderr.write(A.paint(A.C.high, 'The demo corpus (test/corpus.js) is not present in this install.\n'));
      return 2;
    }
    const which = opts._[0] || 'stealer';
    const group = corpus.CORPUS.find((g) => g.name === which);
    if (!group) {
      process.stderr.write('Unknown demo group: ' + which + '\n  Available: ' +
        corpus.CORPUS.map((g) => g.name).join(', ') + '\n');
      return 2;
    }
    const result = scanEntries(corpus.entries(which), { label: 'demo corpus: ' + group.label });
    term.render(result, { all: !!opts.all, limit: opts.limit ? parseInt(opts.limit, 10) : 40, explain: !opts.noExplain });
    if (opts.html) {
      const file = typeof opts.html === 'string' ? opts.html : 'kudo-report.html';
      fs.writeFileSync(file, html.render(result));
      process.stdout.write(A.paint(A.C.faint, '  HTML report written to ') + path.resolve(file) + '\n');
    }
    return 0;
  }

  const target = opts._[0];
  const quiet = !!opts.quiet || opts.json === true;
  const status = quiet ? () => {} : (msg) => {
    process.stderr.write('\r' + A.paint(A.C.faint, '  ' + msg.padEnd(60).slice(0, 60)));
  };

  let result;
  try {
    result = await scan(target, {
      includeDeps: !!opts.includeDeps,
      noDecode: !!opts.noDecode,
      noNormalize: !!opts.noNormalize,
      noStrings: !!opts.noStrings,
      noNet: !!opts.noNet,
      onStatus: status
    });
  } catch (e) {
    if (!quiet) process.stderr.write('\r' + ' '.repeat(64) + '\r');
    process.stderr.write(A.paint(A.C.critical, 'Scan failed: ') + e.message + '\n');
    return 2;
  }
  if (!quiet) process.stderr.write('\r' + ' '.repeat(64) + '\r');

  if (opts.json === true) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    if (typeof opts.json === 'string') {
      fs.writeFileSync(opts.json, JSON.stringify(result, null, 2));
    }
    if (!quiet) {
      term.render(result, {
        all: !!opts.all,
        limit: opts.limit ? parseInt(opts.limit, 10) : 40,
        explain: !opts.noExplain
      });
    }
    if (typeof opts.json === 'string' && !quiet) {
      process.stdout.write(A.paint(A.C.faint, '  JSON written to ') + path.resolve(opts.json) + '\n');
    }
  }

  if (opts.html) {
    const file = typeof opts.html === 'string' ? opts.html : 'kudo-report.html';
    fs.writeFileSync(file, html.render(result));
    if (!quiet) process.stdout.write(A.paint(A.C.faint, '  HTML report written to ') + path.resolve(file) + '\n');
    if (opts.open) {
      const { spawn } = require('child_process');
      const cmd = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      const args = process.platform === 'win32' ? ['/c', 'start', '', path.resolve(file)] : [path.resolve(file)];
      try { spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref(); } catch { /* best effort */ }
    }
  }

  const failOn = opts.failOn ? String(opts.failOn).toLowerCase() : 'likely';
  const idx = LEVELS.indexOf(failOn);
  if (idx === -1) {
    process.stderr.write(A.paint(A.C.high, 'Unknown --fail-on level: ' + failOn + '\n'));
    return 2;
  }
  return LEVELS.indexOf(result.classification.verdict.id) >= idx ? 1 : 0;
}

module.exports = { main, parseArgs };
