'use strict';

const A = require('./ansi');
const { C } = A;

const W = () => Math.max(72, Math.min(104, process.stdout.columns || 96));

/* The Kudo mark: a shield drawn in half-blocks, with a scan line through it. */
const MARK = [
  '▗▄▄▄▄▄▄▖',
  '▐█▀▀▀▀█▌',
  '▐█▄▄▄▄█▌',
  ' ▜██████▛',
  '  ▝▀▀▀▀▘'
];

function out(s) { process.stdout.write(s + '\n'); }

function rule(w, color) {
  const c = color || C.line;
  return A.paint(c, '─'.repeat(w));
}

function panel(title, lines, color, width) {
  const w = width || W();
  const c = color || C.line;
  const head = A.paint(c, '╭─ ') + A.bold(A.paint(c, title)) + ' ' + A.paint(c, '─'.repeat(Math.max(0, w - 6 - title.length)) + '╮');
  const body = lines.map((l) => A.paint(c, '│ ') + A.pad(l, w - 4) + A.paint(c, ' │'));
  const foot = A.paint(c, '╰' + '─'.repeat(w - 2) + '╯');
  return [head, ...body, foot].join('\n');
}

function banner(version) {
  const w = W();
  const lines = [];
  const g = [C.accent, C.accent, C.accent2, C.accent2, C.accent2];
  const text = [
    '',
    A.bold('KUDO CHECK') + '  ' + A.dim(A.paint(C.faint, 'v' + version)),
    A.paint(C.muted, 'static malware analysis for repositories'),
    '',
    ''
  ];
  for (let i = 0; i < MARK.length; i++) {
    lines.push('  ' + A.paint(g[i], A.pad(MARK[i], 10)) + '  ' + (text[i] || ''));
  }
  return lines.join('\n');
}

function kv(label, value, labelWidth = 9) {
  return A.paint(C.faint, A.pad(label, labelWidth)) + value;
}

function verdictPanel(result) {
  const w = W();
  const { classification: cls, target } = result;
  const v = cls.verdict;
  const col = A.riskColor(cls.score);
  const inner = w - 4;

  const scoreTxt = A.bold(A.paint(col, String(cls.score))) + A.paint(C.faint, ' / 100');
  const head = A.bold(A.paint(col, v.label.toUpperCase()));
  const lines = [];
  lines.push(A.pad(head, inner - A.width(scoreTxt)) + scoreTxt);
  lines.push(A.meter(cls.score, 100, inner, null));
  lines.push('');
  if (cls.primary && cls.confident) {
    const p = cls.primary;
    const name = p.variant ? p.variant : p.label;
    lines.push(A.bold(A.paint(C.ink, name)) + A.paint(C.faint, '  ·  ' + p.label + '  ·  ' + p.confidence + ' confidence'));
  }
  for (const l of A.wrap(v.line, inner)) lines.push(A.paint(C.muted, l));
  if (cls.diagnosis) {
    lines.push('');
    for (const l of A.wrap(cls.diagnosis, inner)) lines.push(A.paint(C.ink, l));
  }
  return panel('VERDICT', lines, col, w);
}

function familySection(cls) {
  if (!cls.families.length && !cls.gated.length) return '';
  const w = W();
  const lines = [];
  const nameW = 26;
  const barW = Math.max(12, w - nameW - 30);

  for (const f of cls.families) {
    const col = A.riskColor(f.score);
    const conf = A.paint(C.faint, A.pad(f.confidence, 9, 'right'));
    lines.push(
      A.bold(A.paint(C.ink, A.pad(f.label, nameW))) +
      A.meter(f.score, 100, barW, col) +
      A.paint(col, A.pad(String(f.score), 5, 'right')) + conf
    );
    const detail = (f.variant ? f.variant + ' · ' : '') + f.ruleCount + ' signature' + (f.ruleCount === 1 ? '' : 's') +
      ' · ' + f.rules.slice(0, 5).join(' ') + (f.rules.length > 5 ? ' +' + (f.rules.length - 5) : '');
    lines.push(A.paint(C.faint, '  └ ' + detail));
    for (const l of A.wrap(f.blurb, w - 8, '    ')) lines.push(A.paint(C.muted, '    ' + l.trim()));
    lines.push('');
  }

  if (cls.gated.length) {
    lines.push(A.paint(C.faint, 'Not named — partial behaviour only:'));
    for (const g of cls.gated.slice(0, 5)) {
      lines.push(A.paint(C.faint, '  ' + A.pad(g.label, nameW) + 'score ' + A.pad(String(g.score), 4) + g.blockedBy));
    }
    lines.push('');
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return section('CLASSIFICATION', lines);
}

function capabilitySection(cls) {
  if (!cls.tactics.length) return '';
  const w = W();
  const labelW = 22;
  const max = Math.max(...cls.tactics.map((t) => t.count));
  const lines = cls.tactics.map((t) => {
    const cells = Math.max(1, Math.round((t.count / max) * 14));
    const col = A.riskColor(Math.min(100, 30 + t.count * 12));
    let bar = '';
    for (let i = 0; i < 14; i++) bar += i < cells ? A.paint(col, '▰') : A.paint(C.line, '▱');
    return A.paint(C.ink, A.pad(t.label, labelW)) + bar +
      A.paint(C.faint, '  ' + A.pad(String(t.count), 3, 'right') + '  ') +
      A.paint(C.muted, A.pad(t.top.name, Math.max(10, w - labelW - 25)).slice(0, Math.max(10, w - labelW - 25)));
  });
  return section('CAPABILITY PROFILE', lines);
}

function section(title, lines) {
  const w = W();
  const head = A.bold(A.paint(C.accent2, title)) + ' ' + A.paint(C.line, '─'.repeat(Math.max(0, w - title.length - 1)));
  return '\n' + head + '\n\n' + lines.join('\n') + '\n';
}

function findingsSection(findings, opts) {
  if (!findings.length) return '';
  const w = W();
  const limit = opts.all ? findings.length : Math.min(findings.length, opts.limit || 40);
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) =>
    order[a.severity] - order[b.severity] ||
    a.file.localeCompare(b.file) || a.line - b.line);
  const shown = sorted.slice(0, limit);

  const byFile = new Map();
  for (const f of shown) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  const lines = [];
  for (const [file, list] of byFile) {
    const worst = list[0].severity;
    lines.push(A.bold(A.paint(A.riskColor(worst === 'critical' ? 95 : worst === 'high' ? 70 : worst === 'medium' ? 45 : 20), file)) +
      (list[0].discounted ? A.paint(C.faint, '   (test/docs path — weight reduced)') : ''));
    for (const f of list) {
      const loc = A.paint(C.faint, ':' + f.line);
      const idTag = A.paint(C.faint, f.ruleId);
      const head = '  ' + A.sevMark(f.severity) + ' ' + idTag + '  ' + A.paint(C.ink, f.name) + loc;
      lines.push(head);
      if (f.layer && f.layer !== 'source') lines.push(A.paint(C.accent, '       ' + f.layer));
      if (f.snippet) {
        for (const l of A.wrap(f.snippet, w - 10).slice(0, 2)) lines.push(A.paint(C.muted, '       ' + l));
      }
      if (opts.explain !== false && (f.severity === 'critical' || f.severity === 'high')) {
        for (const l of A.wrap(f.why, w - 10)) lines.push(A.italic(A.paint(C.faint, '       ' + l)));
      }
    }
    lines.push('');
  }
  if (findings.length > limit) {
    lines.push(A.paint(C.faint, '  … ' + (findings.length - limit) + ' more detections. Use --all to list them, or --html for the full report.'));
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return section('DETECTIONS  (' + findings.length + ')', lines);
}

function iocSection(iocs) {
  if (!iocs.length) return '';
  const w = W();
  const kindLabel = {
    url: 'URL', ip: 'IP', webhook: 'DISCORD WEBHOOK', telegram: 'TELEGRAM BOT',
    onion: 'ONION', btc: 'BTC WALLET', eth: 'ETH WALLET', xmr: 'XMR WALLET'
  };
  const priority = ['webhook', 'telegram', 'onion', 'xmr', 'btc', 'eth', 'ip', 'url'];
  const sorted = [...iocs].sort((a, b) => priority.indexOf(a.kind) - priority.indexOf(b.kind) || b.count - a.count);
  const lines = sorted.slice(0, 24).map((i) => {
    const hot = ['webhook', 'telegram', 'onion', 'btc', 'eth', 'xmr'].includes(i.kind);
    return A.paint(hot ? C.high : C.faint, A.pad(kindLabel[i.kind] || i.kind, 17)) +
      A.paint(hot ? C.ink : C.muted, i.value.length > w - 24 ? i.value.slice(0, w - 27) + '…' : i.value) +
      A.paint(C.faint, i.count > 1 ? '  ×' + i.count : '');
  });
  if (sorted.length > 24) lines.push(A.paint(C.faint, '… ' + (sorted.length - 24) + ' more'));
  return section('INDICATORS', lines);
}

function artifactSection(artifacts) {
  if (!artifacts.length) return '';
  const w = W();
  const lines = artifacts.slice(0, 15).map((a) => {
    const risk = a.risk === 'high' ? C.critical : a.risk === 'medium' ? C.medium : C.faint;
    return A.paint(risk, '▪ ') + A.paint(C.ink, A.pad(a.file, Math.min(42, w - 44))) +
      A.paint(C.muted, A.pad(a.label || 'binary', 24)) +
      A.paint(C.faint, (a.size / 1024).toFixed(0) + ' KB  H=' + a.entropy.toFixed(2) +
        (a.markers.length ? '  ' + a.markers.join(', ') : ''));
  });
  return section('BINARY ARTIFACTS', lines);
}

function trustSection(meta, signals) {
  if (!meta || meta.error) return '';
  const lines = [];
  lines.push(kv('repo', A.paint(C.ink, meta.fullName || '')) );
  if (meta.description) lines.push(kv('about', A.paint(C.muted, meta.description.slice(0, 70))));
  lines.push(kv('stars', A.paint(C.ink, String(meta.stars)) + A.paint(C.faint, '   forks ' + meta.forks + '   created ' + String(meta.createdAt).slice(0, 10))));
  lines.push('');
  for (const s of signals) {
    const col = s.level === 'warn' ? C.high : s.level === 'good' ? C.clean : C.faint;
    lines.push(A.paint(col, '  ' + (s.level === 'warn' ? '▲' : s.level === 'good' ? '●' : '○') + ' ') +
      A.paint(C.ink, A.pad(s.text, 34)) + A.paint(C.faint, s.why));
  }
  return section('REPOSITORY SIGNALS', lines);
}

function footer(result) {
  const w = W();
  const s = result.stats;
  const c = result.classification.counts;
  const bits = [
    A.paint(C.critical, c.critical + ' critical'),
    A.paint(C.high, c.high + ' high'),
    A.paint(C.medium, c.medium + ' medium'),
    A.paint(C.low, (c.low || 0) + ' low')
  ].join(A.paint(C.faint, ' · '));
  return '\n' + rule(w) + '\n' +
    bits + A.paint(C.faint, '   |   ') +
    A.paint(C.faint, s.files + ' files, ' + (s.bytes / 1048576).toFixed(1) + ' MB scanned in ' + (result.elapsedMs / 1000).toFixed(1) + 's') + '\n';
}

function render(result, opts = {}) {
  const parts = [];
  parts.push('');
  parts.push(banner(result.version));
  parts.push(kv('target', A.paint(C.ink, result.target.label)));
  if (result.target.ref) parts.push(kv('ref', A.paint(C.muted, result.target.ref)));
  parts.push(kv('scanned', A.paint(C.muted,
    result.stats.files + ' files · ' + result.stats.text + ' source · ' + result.stats.binary + ' binary' +
    (result.stats.decoded ? ' · ' + result.stats.decoded + ' encoded blob' + (result.stats.decoded === 1 ? '' : 's') + ' decoded' : ''))));
  parts.push('');
  parts.push(verdictPanel(result));
  const fam = familySection(result.classification);
  if (fam) parts.push(fam);
  const cap = capabilitySection(result.classification);
  if (cap) parts.push(cap);
  const det = findingsSection(result.findings, opts);
  if (det) parts.push(det);
  const art = artifactSection(result.artifacts);
  if (art) parts.push(art);
  const ioc = iocSection(result.iocs);
  if (ioc) parts.push(ioc);
  const trust = trustSection(result.meta, result.trust || []);
  if (trust) parts.push(trust);
  parts.push(footer(result));
  out(parts.join('\n'));
}

module.exports = { render, banner, MARK };
