'use strict';

const { icon, logoMark } = require('./icons');
const { TACTICS } = require('../rules/families');

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const FAMILY_ICON = {
  infostealer: 'stealer', rat: 'rat', ransomware: 'ransom', wiper: 'wiper',
  cryptominer: 'miner', clipper: 'clipper', keylogger: 'keylog', spyware: 'spy',
  loader: 'loader', botnet: 'botnet', worm: 'worm', rootkit: 'evasion',
  persistence: 'persist', supplychain: 'supply', packer: 'packed',
  hacktool: 'hacktool', phishing: 'phish', adware: 'adware'
};

function severityMeter(sev) {
  const n = { critical: 4, high: 3, medium: 2, low: 1, info: 1 }[sev] || 1;
  let cells = '';
  for (let i = 0; i < 4; i++) cells += '<i class="' + (i < n ? 'on' : '') + '"></i>';
  return '<span class="sev sev-' + sev + '" title="' + sev + '">' + cells + '</span>';
}

/** Half-circle risk gauge. The needle sits at the score; the arc is a ramp. */
function gauge(score, verdictId) {
  const r = 86;
  const cx = 104;
  const cy = 104;
  const circ = Math.PI * r;                    // half circumference
  const frac = Math.max(0, Math.min(100, score)) / 100;
  const angle = Math.PI * (1 - frac);
  const nx = cx + Math.cos(angle) * r;
  const ny = cy - Math.sin(angle) * r;
  const ix = cx + Math.cos(angle) * (r - 16);
  const iy = cy - Math.sin(angle) * (r - 16);
  return '' +
  '<svg class="gauge" viewBox="0 0 208 128" role="img" aria-label="Risk score ' + score + ' of 100">' +
    '<defs><linearGradient id="riskRamp" x1="0" y1="0" x2="1" y2="0">' +
      '<stop offset="0%" stop-color="var(--ok)"/>' +
      '<stop offset="38%" stop-color="var(--warn)"/>' +
      '<stop offset="66%" stop-color="var(--high)"/>' +
      '<stop offset="100%" stop-color="var(--crit)"/>' +
    '</linearGradient></defs>' +
    '<path d="M18 104 A86 86 0 0 1 190 104" class="gauge-track"/>' +
    '<path d="M18 104 A86 86 0 0 1 190 104" class="gauge-fill" ' +
      'style="stroke-dasharray:' + circ.toFixed(1) + ';stroke-dashoffset:' + (circ * (1 - frac)).toFixed(1) + '"/>' +
    '<line x1="' + ix.toFixed(1) + '" y1="' + iy.toFixed(1) + '" x2="' + nx.toFixed(1) + '" y2="' + ny.toFixed(1) + '" class="gauge-needle"/>' +
    '<text x="104" y="96" class="gauge-score verdict-' + verdictId + '">' + score + '</text>' +
    '<text x="104" y="118" class="gauge-cap">RISK SCORE</text>' +
  '</svg>';
}

function familyCard(f) {
  const conf = '<span class="chip chip-' + f.confidence + '">' + esc(f.confidence) + ' confidence</span>';
  return '' +
  '<article class="fam">' +
    '<header>' +
      '<span class="fam-ic">' + icon(FAMILY_ICON[f.key] || 'info', 22) + '</span>' +
      '<div class="fam-id">' +
        '<h3>' + esc(f.variant || f.label) + '</h3>' +
        '<p>' + esc(f.variant ? f.label : f.ruleCount + ' distinct signatures') + '</p>' +
      '</div>' +
      '<div class="fam-score"><b>' + f.score + '</b><span>score</span></div>' +
    '</header>' +
    '<div class="bar"><span style="width:' + Math.min(100, f.score) + '%"></span></div>' +
    '<p class="fam-blurb">' + esc(f.blurb) + '</p>' +
    '<footer>' + conf + '<span class="rules">' + f.rules.map((r) => '<code>' + esc(r) + '</code>').join('') + '</span></footer>' +
  '</article>';
}

function tacticRows(tactics) {
  if (!tactics.length) return '';
  const max = Math.max(...tactics.map((t) => t.count));
  return tactics.map((t) => {
    const cells = Math.max(1, Math.round((t.count / max) * 12));
    let bar = '';
    for (let i = 0; i < 12; i++) bar += '<i class="' + (i < cells ? 'on' : '') + '"></i>';
    return '<tr>' +
      '<th scope="row">' + esc(t.label) + '</th>' +
      '<td class="tac-bar">' + bar + '</td>' +
      '<td class="tac-n">' + t.count + '</td>' +
      '<td class="tac-top">' + esc(t.top.name) + '</td>' +
    '</tr>';
  }).join('');
}

function findingRow(f) {
  return '' +
  '<li class="find" data-sev="' + f.severity + '" data-fam="' + esc(f.family) + '" ' +
      'data-text="' + esc((f.name + ' ' + f.file + ' ' + f.ruleId + ' ' + (f.snippet || '')).toLowerCase()) + '">' +
    '<div class="find-head">' +
      severityMeter(f.severity) +
      '<code class="rid">' + esc(f.ruleId) + '</code>' +
      '<span class="fname">' + esc(f.name) + '</span>' +
      '<span class="floc">' + esc(f.file) + '<b>:' + f.line + '</b></span>' +
    '</div>' +
    (f.layer && f.layer !== 'source' ? '<div class="layer">' + icon('layers', 13) + esc(f.layer) + '</div>' : '') +
    (f.snippet ? '<pre class="snip"><code>' + esc(f.snippet) + '</code></pre>' : '') +
    '<p class="why">' + esc(f.why) + '</p>' +
  '</li>';
}

function render(result) {
  const cls = result.classification;
  const v = cls.verdict;
  const findings = [...result.findings].sort((a, b) =>
    SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);

  const counts = cls.counts;
  const stat = (label, value, sub) =>
    '<div class="stat"><b>' + esc(value) + '</b><span>' + esc(label) + '</span>' + (sub ? '<i>' + esc(sub) + '</i>' : '') + '</div>';

  const iocLabels = {
    url: 'URL', ip: 'IP address', webhook: 'Discord webhook', telegram: 'Telegram bot',
    onion: 'Onion service', btc: 'Bitcoin address', eth: 'Ethereum address', xmr: 'Monero address'
  };
  const hotIoc = new Set(['webhook', 'telegram', 'onion', 'btc', 'eth', 'xmr']);

  const title = 'Kudo Check — ' + (result.target.label || 'scan');

  return `<!doctype html>
<html lang="en" data-verdict="${esc(v.id)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
:root{
  --bg:#0d1017; --panel:#141924; --panel-2:#1b2130; --line:#242c3c; --line-soft:#1e2534;
  --ink:#e6ecf7; --muted:#93a0b8; --faint:#5f6c85;
  --accent:#7c78ff; --accent-2:#4fd2ff;
  --crit:#ff5c6a; --high:#ff9547; --warn:#f6c854; --low:#5cb0ff; --ok:#4ad69a;
  --mono:ui-monospace,"SF Mono","Cascadia Mono","JetBrains Mono",Consolas,monospace;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --radius:14px; --shadow:0 1px 2px rgba(0,0,0,.4),0 12px 32px -18px rgba(0,0,0,.8);
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    --bg:#f6f7fb; --panel:#ffffff; --panel-2:#f2f4f9; --line:#e0e5ef; --line-soft:#eaeef6;
    --ink:#141a26; --muted:#5a6478; --faint:#8b95a8;
    --accent:#5b56e0; --accent-2:#0f8fbf;
    --crit:#d92b3f; --high:#c96a10; --warn:#a8830a; --low:#2f74c9; --ok:#12855c;
    --shadow:0 1px 2px rgba(16,24,40,.06),0 12px 28px -18px rgba(16,24,40,.35);
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:36px 24px 80px}
.ic{flex:none;vertical-align:-.15em}
h1,h2,h3{margin:0;font-weight:640;letter-spacing:-.015em}
code,pre{font-family:var(--mono)}

/* ── masthead ── */
.mast{display:flex;align-items:center;gap:16px;padding-bottom:22px;border-bottom:1px solid var(--line)}
.logo-mark{color:var(--accent);flex:none}
.mast h1{font-size:20px;letter-spacing:.02em}
.mast h1 span{color:var(--faint);font-weight:500}
.mast p{margin:2px 0 0;color:var(--muted);font-size:13px}
.mast .target{margin-left:auto;text-align:right;font-size:13px;color:var(--muted);max-width:46%}
.mast .target b{display:block;color:var(--ink);font-family:var(--mono);font-size:13px;word-break:break-all}

/* ── verdict ── */
.hero{display:grid;grid-template-columns:236px 1fr;gap:28px;align-items:center;
  background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:26px 28px;margin:26px 0;box-shadow:var(--shadow);position:relative;overflow:hidden}
.hero::before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--verdict-color)}
.gauge{width:100%;height:auto;display:block}
.gauge-track{fill:none;stroke:var(--line);stroke-width:13;stroke-linecap:round}
.gauge-fill{fill:none;stroke:url(#riskRamp);stroke-width:13;stroke-linecap:round;
  transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)}
.gauge-needle{stroke:var(--ink);stroke-width:3;stroke-linecap:round}
.gauge-score{fill:var(--verdict-color);font:700 40px/1 var(--sans);text-anchor:middle;letter-spacing:-.03em}
.gauge-cap{fill:var(--faint);font:600 10px/1 var(--sans);text-anchor:middle;letter-spacing:.16em}
.verdict-label{display:inline-flex;align-items:center;gap:9px;font-size:12px;font-weight:700;
  letter-spacing:.14em;text-transform:uppercase;color:var(--verdict-color);
  border:1px solid color-mix(in srgb,var(--verdict-color) 45%,transparent);
  background:color-mix(in srgb,var(--verdict-color) 12%,transparent);
  padding:5px 12px;border-radius:999px}
.hero h2{font-size:26px;margin:14px 0 8px;letter-spacing:-.02em}
.hero .diag{color:var(--ink);margin:0 0 10px;font-size:15px}
.hero .tone{color:var(--muted);margin:0;font-size:14px}
[data-verdict="malicious"]{--verdict-color:var(--crit)}
[data-verdict="likely"]{--verdict-color:var(--high)}
[data-verdict="suspicious"]{--verdict-color:var(--warn)}
[data-verdict="lowrisk"]{--verdict-color:var(--low)}
[data-verdict="clean"]{--verdict-color:var(--ok)}

/* ── stats ── */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(126px,1fr));gap:12px;margin:0 0 30px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.stat b{display:block;font-size:21px;letter-spacing:-.02em}
.stat span{display:block;font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em;margin-top:3px}
.stat i{display:block;font-style:normal;font-size:12px;color:var(--muted);margin-top:4px}
.stat.c-critical b{color:var(--crit)} .stat.c-high b{color:var(--high)}
.stat.c-medium b{color:var(--warn)} .stat.c-low b{color:var(--low)}

/* ── sections ── */
section{margin:34px 0}
.sec-head{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.sec-head h2{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent-2)}
.sec-head .ic{color:var(--accent-2)}
.sec-head .count{color:var(--faint);font-size:12px;font-family:var(--mono)}
.sec-head hr{flex:1;border:0;border-top:1px solid var(--line);margin:0}

/* ── family cards ── */
.fams{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:14px}
.fam{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow)}
.fam header{display:flex;align-items:flex-start;gap:12px}
.fam-ic{width:38px;height:38px;display:grid;place-items:center;border-radius:10px;
  background:var(--panel-2);border:1px solid var(--line);color:var(--accent);flex:none}
.fam-id{flex:1;min-width:0}
.fam h3{font-size:16px}
.fam-id p{margin:1px 0 0;font-size:12px;color:var(--faint)}
.fam-score{text-align:right;flex:none}
.fam-score b{font-size:20px;letter-spacing:-.02em}
.fam-score span{display:block;font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em}
.bar{height:5px;background:var(--line);border-radius:99px;overflow:hidden;margin:14px 0 12px}
.bar span{display:block;height:100%;border-radius:99px;
  background:linear-gradient(90deg,var(--ok),var(--warn) 45%,var(--high) 70%,var(--crit))}
.fam-blurb{margin:0 0 14px;font-size:13.5px;color:var(--muted)}
.fam footer{display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  border-top:1px solid var(--line-soft);padding-top:12px}
.chip{font-size:11px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;
  padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.chip-high{color:var(--crit);border-color:color-mix(in srgb,var(--crit) 45%,transparent);
  background:color-mix(in srgb,var(--crit) 12%,transparent)}
.chip-medium{color:var(--high);border-color:color-mix(in srgb,var(--high) 45%,transparent)}
.chip-low{color:var(--muted)}
.rules{display:flex;gap:5px;flex-wrap:wrap}
.rules code{font-size:10.5px;color:var(--faint);background:var(--panel-2);
  border:1px solid var(--line-soft);border-radius:5px;padding:2px 6px}

/* ── tables ── */
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
thead th{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);
  border-bottom:1px solid var(--line)}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  overflow:hidden;box-shadow:var(--shadow)}
.tac-bar i{display:inline-block;width:9px;height:15px;border-radius:2px;background:var(--line);margin-right:3px}
.tac-bar i.on{background:linear-gradient(180deg,var(--high),var(--crit))}
.tac-n{font-family:var(--mono);color:var(--muted);width:48px}
.tac-top{color:var(--muted)}
td.ioc-val{font-family:var(--mono);font-size:12.5px;word-break:break-all}
tr.hot td.ioc-kind{color:var(--high);font-weight:600}
td.sha{font-family:var(--mono);font-size:11px;color:var(--faint);word-break:break-all}

/* ── detections ── */
.filters{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.filters button{font:inherit;font-size:12px;font-weight:600;color:var(--muted);cursor:pointer;
  background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:5px 13px}
.filters button[aria-pressed="true"]{color:var(--ink);border-color:var(--accent);
  background:color-mix(in srgb,var(--accent) 14%,transparent)}
.filters .search{margin-left:auto;display:flex;align-items:center;gap:8px;background:var(--panel);
  border:1px solid var(--line);border-radius:999px;padding:5px 14px;color:var(--faint)}
.filters input{font:inherit;font-size:13px;background:none;border:0;outline:none;color:var(--ink);width:190px}
.finds{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.find{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--line);
  border-radius:11px;padding:13px 16px}
.find[data-sev="critical"]{border-left-color:var(--crit)}
.find[data-sev="high"]{border-left-color:var(--high)}
.find[data-sev="medium"]{border-left-color:var(--warn)}
.find[data-sev="low"]{border-left-color:var(--low)}
.find.hide{display:none}
.find-head{display:flex;align-items:center;gap:11px;flex-wrap:wrap}
.sev{display:inline-flex;gap:2px;flex:none}
.sev i{width:5px;height:13px;border-radius:1.5px;background:var(--line)}
.sev-critical i.on{background:var(--crit)} .sev-high i.on{background:var(--high)}
.sev-medium i.on{background:var(--warn)} .sev-low i.on{background:var(--low)}
.sev-info i.on{background:var(--faint)}
.rid{font-size:11px;color:var(--faint);background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:5px;padding:2px 7px;flex:none}
.fname{font-weight:600;font-size:14.5px}
.floc{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--faint);word-break:break-all}
.floc b{color:var(--muted);font-weight:600}
.layer{display:inline-flex;align-items:center;gap:6px;margin-top:9px;font-size:11.5px;
  color:var(--accent-2);border:1px dashed color-mix(in srgb,var(--accent-2) 45%,transparent);
  border-radius:6px;padding:2px 8px}
.snip{margin:10px 0 0;padding:10px 12px;background:var(--panel-2);border:1px solid var(--line-soft);
  border-radius:8px;overflow-x:auto;font-size:12.5px;color:var(--muted)}
.snip code{white-space:pre}
.why{margin:9px 0 0;font-size:13px;color:var(--muted)}
.empty{color:var(--faint);font-size:13.5px;padding:18px;text-align:center}

/* ── signals ── */
.signals{display:grid;gap:10px}
.signal{display:flex;gap:11px;align-items:flex-start;background:var(--panel);
  border:1px solid var(--line);border-radius:11px;padding:12px 15px}
.signal.warn .ic{color:var(--high)} .signal.good .ic{color:var(--ok)} .signal.info .ic{color:var(--faint)}
.signal b{font-size:13.5px;font-weight:620} .signal p{margin:2px 0 0;font-size:13px;color:var(--muted)}

footer.foot{margin-top:44px;padding-top:18px;border-top:1px solid var(--line);
  display:flex;gap:14px;align-items:center;color:var(--faint);font-size:12px;flex-wrap:wrap}
footer.foot .ic{color:var(--faint)}
footer.foot .note{margin-left:auto;max-width:56ch;text-align:right}

@media (max-width:760px){
  .hero{grid-template-columns:1fr;gap:14px}
  .mast{flex-wrap:wrap}.mast .target{margin-left:0;text-align:left;max-width:100%}
  .filters .search{margin-left:0;width:100%}.filters input{width:100%}
}
@media print{
  body{background:#fff}.filters{display:none}.find{break-inside:avoid}
  .fam,.panel,.hero{box-shadow:none}
}
</style>
</head>
<body>
<div class="wrap">

  <header class="mast">
    ${logoMark(46)}
    <div>
      <h1>KUDO<span>&nbsp;CHECK</span></h1>
      <p>Static malware analysis report</p>
    </div>
    <div class="target">
      scanned target<b>${esc(result.target.label)}</b>
      ${result.target.ref ? '<span>ref ' + esc(result.target.ref) + '</span>' : ''}
    </div>
  </header>

  <div class="hero">
    <div>${gauge(cls.score, v.id)}</div>
    <div>
      <span class="verdict-label">${icon(v.id === 'clean' ? 'check' : 'alert', 14)}${esc(v.label)}</span>
      <h2>${esc(cls.headline)}</h2>
      <p class="diag">${esc(cls.diagnosis)}</p>
      <p class="tone">${esc(v.line)}</p>
    </div>
  </div>

  <div class="stats">
    ${stat('files', result.stats.files.toLocaleString(), (result.stats.bytes / 1048576).toFixed(1) + ' MB')}
    ${stat('detections', String(result.findings.length), cls.ruleCount + ' distinct rules')}
    ${'<div class="stat c-critical"><b>' + counts.critical + '</b><span>critical</span></div>'}
    ${'<div class="stat c-high"><b>' + counts.high + '</b><span>high</span></div>'}
    ${'<div class="stat c-medium"><b>' + counts.medium + '</b><span>medium</span></div>'}
    ${stat('scan time', (result.elapsedMs / 1000).toFixed(1) + 's', result.stats.decoded + ' blobs decoded')}
  </div>

  ${cls.families.length ? `
  <section>
    <div class="sec-head">${icon('layers', 16)}<h2>Classification</h2><span class="count">${cls.families.length} famil${cls.families.length === 1 ? 'y' : 'ies'}</span><hr></div>
    <div class="fams">${cls.families.map(familyCard).join('')}</div>
  </section>` : ''}

  ${cls.tactics.length ? `
  <section>
    <div class="sec-head">${icon('signal', 16)}<h2>Capability profile</h2><hr></div>
    <div class="panel"><table>
      <thead><tr><th>Tactic</th><th>Weight</th><th>Hits</th><th>Strongest detection</th></tr></thead>
      <tbody>${tacticRows(cls.tactics)}</tbody>
    </table></div>
  </section>` : ''}

  <section>
    <div class="sec-head">${icon('alert', 16)}<h2>Detections</h2><span class="count">${result.findings.length}</span><hr></div>
    <div class="filters">
      <button data-sev="all" aria-pressed="true">All</button>
      <button data-sev="critical" aria-pressed="false">Critical</button>
      <button data-sev="high" aria-pressed="false">High</button>
      <button data-sev="medium" aria-pressed="false">Medium</button>
      <button data-sev="low" aria-pressed="false">Low</button>
      <label class="search">${icon('search', 15)}<input type="search" id="q" placeholder="filter by file, rule or text" aria-label="Filter detections"></label>
    </div>
    <ul class="finds" id="finds">${findings.map(findingRow).join('')}</ul>
    <p class="empty" id="noresults" hidden>Nothing matches that filter.</p>
    ${findings.length ? '' : '<p class="empty">No detections. Every signature, decoder and heuristic came back negative.</p>'}
  </section>

  ${result.iocs.length ? `
  <section>
    <div class="sec-head">${icon('signal', 16)}<h2>Indicators</h2><span class="count">${result.iocs.length}</span><hr></div>
    <div class="panel"><table>
      <thead><tr><th>Type</th><th>Value</th><th>Seen</th></tr></thead>
      <tbody>${result.iocs.slice(0, 80).map((i) =>
        '<tr class="' + (hotIoc.has(i.kind) ? 'hot' : '') + '"><td class="ioc-kind">' + esc(iocLabels[i.kind] || i.kind) +
        '</td><td class="ioc-val">' + esc(i.value) + '</td><td class="tac-n">' + i.count + '</td></tr>').join('')}</tbody>
    </table></div>
  </section>` : ''}

  ${result.artifacts.length ? `
  <section>
    <div class="sec-head">${icon('binary', 16)}<h2>Binary artifacts</h2><span class="count">${result.artifacts.length}</span><hr></div>
    <div class="panel"><table>
      <thead><tr><th>File</th><th>Format</th><th>Size</th><th>Entropy</th><th>SHA-256</th></tr></thead>
      <tbody>${result.artifacts.slice(0, 40).map((a) =>
        '<tr><td>' + esc(a.file) + '</td><td>' + esc(a.label || 'unknown') +
        (a.markers.length ? '<br><span style="color:var(--high);font-size:12px">' + esc(a.markers.join(', ')) + '</span>' : '') +
        '</td><td class="tac-n">' + (a.size / 1024).toFixed(0) + ' KB</td>' +
        '<td class="tac-n">' + a.entropy.toFixed(2) + '</td>' +
        '<td class="sha">' + esc(a.sha256) + '</td></tr>').join('')}</tbody>
    </table></div>
  </section>` : ''}

  ${(result.trust && result.trust.length) ? `
  <section>
    <div class="sec-head">${icon('github', 16)}<h2>Repository signals</h2><hr></div>
    <div class="signals">${result.trust.map((s) =>
      '<div class="signal ' + esc(s.level) + '">' + icon(s.level === 'warn' ? 'alert' : s.level === 'good' ? 'check' : 'info', 17) +
      '<div><b>' + esc(s.text) + '</b><p>' + esc(s.why) + '</p></div></div>').join('')}
    </div>
  </section>` : ''}

  <footer class="foot">
    ${icon('clock', 14)}<span>${esc(new Date(result.generatedAt).toLocaleString())}</span>
    <span>·</span><span>Kudo Check v${esc(result.version)}</span>
    <p class="note">Static analysis only. It reasons about code as written — it cannot observe what a program does at runtime, and a clean result is evidence, not proof.</p>
  </footer>

</div>
<script>
(function(){
  var finds = Array.prototype.slice.call(document.querySelectorAll('.find'));
  var buttons = Array.prototype.slice.call(document.querySelectorAll('.filters button'));
  var q = document.getElementById('q');
  var none = document.getElementById('noresults');
  var sev = 'all';
  function apply(){
    var term = (q && q.value || '').trim().toLowerCase();
    var shown = 0;
    finds.forEach(function(el){
      var okSev = sev === 'all' || el.dataset.sev === sev;
      var okTxt = !term || el.dataset.text.indexOf(term) !== -1;
      var show = okSev && okTxt;
      el.classList.toggle('hide', !show);
      if (show) shown++;
    });
    if (none) none.hidden = shown !== 0 || finds.length === 0;
  }
  buttons.forEach(function(b){
    b.addEventListener('click', function(){
      sev = b.dataset.sev;
      buttons.forEach(function(o){ o.setAttribute('aria-pressed', String(o === b)); });
      apply();
    });
  });
  if (q) q.addEventListener('input', apply);
})();
</script>
</body>
</html>`;
}

module.exports = { render };
