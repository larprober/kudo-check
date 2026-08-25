'use strict';

const { SIGNATURES } = require('../rules/signatures');
const { analyzeManifest } = require('./manifest');
const { decodeLayers } = require('./decode');
const { textAnomaly, entropy } = require('./entropy');
const { identify, extractStrings } = require('./binary');
const { readFile, kindOf, ext } = require('./walk');
const { normalize } = require('./normalize');

const MAX_LINE = 60000;         // characters of a single line handed to a regex
const MAX_SPAN = 1024 * 1024;   // characters of a file handed to span rules
const PER_RULE_PER_FILE = 4;    // cap repeated hits of one rule in one file

const IOC = {
  url: /https?:\/\/[^\s"'`<>()\\]{4,180}/g,
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/g,
  webhook: /https?:\/\/(?:\w+\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g,
  telegram: /api\.telegram\.org\/bot[\d]+:[\w-]+/g,
  onion: /\b[a-z2-7]{16,56}\.onion\b/gi,
  btc: /\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  eth: /\b0x[a-fA-F0-9]{40}\b/g,
  xmr: /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g
};

const BENIGN_HOST = /^https?:\/\/(?:(?:www\.)?(?:github\.com|githubusercontent\.com|npmjs\.(?:com|org)|nodejs\.org|python\.org|pypi\.org|golang\.org|maven\.org|w3\.org|schemas?\.|apache\.org|mozilla\.org|opensource\.org|creativecommons\.org|json-schema\.org|unpkg\.com|jsdelivr\.net|cloudflare\.com|google\.com|googleapis\.com|microsoft\.com|stackoverflow\.com|wikipedia\.org|mit-license\.org|localhost|127\.0\.0\.1))/i;

const SUSPICIOUS_NAME = [
  { re: /\.(?:txt|pdf|jpg|png|docx?|xlsx?|mp[34])\.(?:exe|scr|bat|cmd|com|pif|vbs|js|jar|lnk)$/i,
    name: 'Double extension disguises an executable', weight: 26, sev: 'critical' },
  { re: /[‪-‮⁦-⁩]/,
    name: 'Right-to-left override in the filename', weight: 28, sev: 'critical' },
  { re: /(?:^|\/)(?:svchost|csrss|lsass|winlogon|explorer|chrome|discord|steam)\.(?:exe|scr|bat|py|js)$/i,
    name: 'Filename impersonates a system or app process', weight: 22, sev: 'high' },
  { re: /(?:^|\/)(?:crack|keygen|patcher?|loader|activator|hwid[_-]?spoofer|cheat[_-]?engine)[^/]*\.(?:exe|bat|cmd|scr|msi)$/i,
    name: 'Filename matches a crack/keygen/loader bundle', weight: 20, sev: 'high' }
];


const RULE_DB_MARKER = 'KUDO' + '-SIGNATURE-DATABASE';
const RULE_PATH = /(?:^|\/)(?:rules?|signatures?|patterns?|detections?|yara|sigma)[\/_-]|\.(?:yar|yara)$|(?:^|\/)(?:signatures?|rules?)\.(?:js|ts|json|ya?ml|py)$/i;

/**
 * Is this file a detection-rule database rather than executable malware?
 * Scanning our own signature set — or someone else's YARA repo — otherwise
 * produces a confident "malicious" verdict on a security tool.
 */
function isRuleDatabase(rel, text) {
  if (text.includes(RULE_DB_MARKER)) return 'kudo signature database';
  if (!RULE_PATH.test(rel)) return null;
  const regexLines = (text.match(/^\s*(?:re|pattern|regex|match)\s*[:=]\s*[/r"']/gim) || []).length;
  const ruleMeta = (text.match(/^\s*(?:severity|weight|family|tags|meta|condition|strings)\s*[:=]/gim) || []).length;
  if (regexLines >= 12 && ruleMeta >= 12) return 'detection rule set';
  if (/^\s*rule\s+\w+\s*[:{]/m.test(text) && /\bcondition\s*:/.test(text)) return 'YARA rule file';
  return null;
}

function mkFinding(rule, file, line, snippet, layer) {
  return {
    ruleId: rule.id,
    name: rule.name,
    family: rule.family,
    tactic: rule.tactic,
    severity: rule.severity,
    weight: rule.weight,
    tags: rule.tags,
    file,
    line,
    snippet,
    why: rule.why,
    layer: layer || 'source'
  };
}

function trim(s, n = 180) {
  const t = String(s).replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

/** Run the signature set over one blob of text. */
function matchText(text, rel, layer, fileExt, out, budget) {
  const counts = new Map();
  const lines = text.split('\n');
  const lower = new Array(lines.length);

  for (let i = 0; i < lines.length; i++) {
    if (budget.stop) return;
    const raw = lines[i].length > MAX_LINE ? lines[i].slice(0, MAX_LINE) : lines[i];
    if (!raw) continue;
    const low = lower[i] || (lower[i] = raw.toLowerCase());
    for (const rule of SIGNATURES) {
      if (rule.span) continue;
      if (rule.ext && !rule.ext.includes(fileExt)) continue;
      if (rule.hint && low.indexOf(rule.hint) === -1) continue;
      const key = rule.id;
      if ((counts.get(key) || 0) >= PER_RULE_PER_FILE) continue;
      rule.re.lastIndex = 0;
      let m;
      try { m = rule.re.exec(raw); } catch { continue; }
      if (!m) continue;
      counts.set(key, (counts.get(key) || 0) + 1);
      out.push(mkFinding(rule, rel, i + 1, trim(raw), layer));
      budget.hits++;
      if (budget.hits > 4000) { budget.stop = true; return; }
    }
  }

  const span = text.length > MAX_SPAN ? text.slice(0, MAX_SPAN) : text;
  for (const rule of SIGNATURES) {
    if (!rule.span) continue;
    if (rule.ext && !rule.ext.includes(fileExt)) continue;
    rule.re.lastIndex = 0;
    let m;
    try { m = rule.re.exec(span); } catch { continue; }
    if (!m) continue;
    const line = span.slice(0, m.index).split('\n').length;
    out.push(mkFinding(rule, rel, line, trim(m[0], 200), layer));
  }
}

function collectIoc(text, bag) {
  for (const [kind, re] of Object.entries(IOC)) {
    re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = re.exec(text)) && n < 60) {
      n++;
      const v = m[0];
      if (kind === 'url' && BENIGN_HOST.test(v)) continue;
      // private, loopback, and the RFC 5737 / RFC 3849 documentation ranges
      if (kind === 'ip' && /^(?:0\.|127\.|255\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|1\.2\.3\.4)/.test(v)) continue;
      const key = kind + '|' + v;
      bag.set(key, (bag.get(key) || 0) + 1);
    }
  }
}

/**
 * Scan a prepared file list.
 * @returns { findings, artifacts, iocs, stats }
 */
function scanFiles(files, opts = {}) {
  const findings = [];
  const artifacts = [];
  const iocBag = new Map();
  const stats = { files: 0, text: 0, binary: 0, media: 0, bytes: 0, decoded: 0, anomalies: 0, ruleDbs: 0, normalized: 0 };
  const ruleDbFiles = [];
  const budget = { hits: 0, stop: false };
  const onProgress = opts.onProgress || null;

  files.forEach((f, idx) => {
    if (onProgress && idx % 25 === 0) onProgress(idx, files.length, f.rel);
    const buf = readFile(f);
    if (!buf) return;
    stats.files++;
    stats.bytes += buf.length;
    const e = ext(f.rel);
    const kind = kindOf(f.rel, buf);
    f.kind = kind;

    for (const s of SUSPICIOUS_NAME) {
      if (s.re.test(f.rel)) {
        findings.push({
          ruleId: 'NAM-' + (SUSPICIOUS_NAME.indexOf(s) + 1),
          name: s.name, family: 'loader', tactic: 'evasion', severity: s.sev,
          weight: s.weight, tags: ['exec-payload', 'anti-analysis'],
          file: f.rel, line: 1, snippet: f.rel,
          why: 'The filename itself is engineered to make a user run something they think is harmless.',
          layer: 'filename'
        });
      }
    }

    if (kind === 'media') { stats.media++; return; }

    if (kind === 'binary') {
      stats.binary++;
      const info = identify(buf);
      const art = {
        file: f.rel, size: buf.length, format: info.format, label: info.label,
        markers: info.markers, entropy: info.entropy, sha256: info.sha256, risk: info.risk
      };
      artifacts.push(art);
      // "committed to the repository" is a repo-context judgement. When the
      // user points Kudo Check straight at one binary, they already know it is
      // a binary — saying so is noise, not a finding.
      if (!opts.singleFile &&
          (info.format === 'pe' || info.format === 'elf' || info.format === 'macho' || info.format === 'msi' || info.format === 'dex')) {
        findings.push({
          ruleId: 'BIN-001',
          name: 'Executable binary committed to the repository',
          family: 'loader', tactic: 'execution',
          severity: f.discounted ? 'medium' : 'high',
          weight: f.discounted ? 10 : 22,
          tags: ['exec-payload'],
          file: f.rel, line: 1,
          snippet: info.label + ', ' + (buf.length / 1024).toFixed(0) + ' KB, entropy ' + info.entropy.toFixed(2),
          why: 'A prebuilt executable cannot be reviewed. Whatever it does, it does it on the machine of anyone who runs the project.',
          layer: 'binary'
        });
      }
      if (info.markers.some((m) => /UPX|Themida|VMProtect|ConfuserEx/.test(m))) {
        findings.push({
          ruleId: 'BIN-002', name: 'Binary is packed or armoured (' + info.markers.join(', ') + ')',
          family: 'packer', tactic: 'evasion', severity: 'high', weight: 20, tags: ['obfuscation'],
          file: f.rel, line: 1, snippet: info.markers.join(', '),
          why: 'Packing hides the binary’s contents from static inspection. Common for legitimate size reduction, universal in malware.',
          layer: 'binary'
        });
      }
      if (!opts.noStrings && buf.length < 24 * 1024 * 1024) {
        const strs = extractStrings(buf);
        if (strs.length) matchText(strs.join('\n'), f.rel, 'binary strings', e, findings, budget);
        collectIoc(strs.join('\n').slice(0, 400000), iocBag);
      }
      return;
    }

    stats.text++;
    const text = buf.toString('utf8');

    const ruleDb = isRuleDatabase(f.rel, text);
    if (ruleDb) {
      stats.ruleDbs = (stats.ruleDbs || 0) + 1;
      ruleDbFiles.push({ file: f.rel, kind: ruleDb });
      if (!opts.scanRuleDbs) return;
      f.discounted = true;
    }

    for (const mf of analyzeManifest(f.rel, text)) findings.push(mf);

    const before = findings.length;
    matchText(text, f.rel, 'source', e, findings, budget);
    collectIoc(text.length > 600000 ? text.slice(0, 600000) : text, iocBag);

    // Second view: literals folded, constants substituted, escapes resolved.
    // Only detections that were invisible in the raw text are kept — those are
    // precisely the ones the author took steps to hide.
    if (!opts.noNormalize) {
      const norm = normalize(text);
      if (norm.changed) {
        const already = new Set(findings.slice(before).map((x) => x.ruleId));
        const staged = [];
        matchText(norm.text, f.rel, 'normalized', e, staged, budget);
        const fresh = staged.filter((x) => !already.has(x.ruleId));
        if (fresh.length) {
          stats.normalized = (stats.normalized || 0) + 1;
          for (const x of fresh) {
            x.layer = 'normalized source (constant folding)';
            findings.push(x);
          }
        }
        collectIoc(norm.text.length > 600000 ? norm.text.slice(0, 600000) : norm.text, iocBag);
      }
    }

    const anom = textAnomaly(text, f.rel);
    if (anom) {
      stats.anomalies++;
      findings.push({
        ruleId: 'ENT-001', name: 'Source file does not look hand-written',
        family: 'packer', tactic: 'evasion', severity: 'medium', weight: 14, tags: ['obfuscation'],
        file: f.rel, line: 1,
        snippet: anom.reason + ' (entropy ' + anom.entropy.toFixed(2) + ')',
        why: 'High-entropy, machine-shaped source is how a payload avoids being read.',
        layer: 'source'
      });
    }

    if (!opts.noDecode && text.length < 3 * 1024 * 1024) {
      for (const layer of decodeLayers(text)) {
        stats.decoded++;
        const label = 'decoded ' + layer.encoding + ' @ line ' + layer.line;
        if (layer.executable) {
          findings.push({
            ruleId: 'DEC-002', name: 'Encoded executable embedded in source',
            family: 'loader', tactic: 'execution', severity: 'critical', weight: 30,
            tags: ['exec-payload', 'obfuscation', 'memory-exec'],
            file: f.rel, line: layer.line,
            snippet: layer.encoding + ' blob decodes to a ' + (layer.bytes / 1024).toFixed(0) + ' KB executable',
            why: 'A whole executable hidden inside a source file, base64 or otherwise, is a dropper carrying its own payload.',
            layer: 'source'
          });
          continue;
        }
        const before = findings.length;
        matchText(layer.text, f.rel, label, e, findings, budget);
        if (findings.length > before) {
          findings.push({
            ruleId: 'DEC-001', name: 'Malicious code found inside an encoded blob',
            family: 'packer', tactic: 'evasion', severity: 'critical', weight: 24,
            tags: ['obfuscation', 'exec-payload'],
            file: f.rel, line: layer.line,
            snippet: layer.encoding + ' blob (' + layer.bytes + ' bytes) hid ' + (findings.length - before) + ' further detection(s)',
            why: 'The encoding existed specifically to keep those detections out of sight.',
            layer: 'source'
          });
        }
        collectIoc(layer.text, iocBag);
      }
    }
  });

  const dmap = new Map(files.map((f) => [f.rel, !!f.discounted]));
  for (const fi of findings) fi.discounted = !!dmap.get(fi.file);

  /**
   * The test/docs discount exists because documentation quotes dangerous code
   * and test suites contain fixtures. It is not a hiding place: a README does
   * not carry four distinct critical signatures. Where that density shows up,
   * the discount is withdrawn and the file is treated at full weight.
   */
  const criticalByFile = new Map();
  for (const fi of findings) {
    if (fi.severity !== 'critical') continue;
    if (!criticalByFile.has(fi.file)) criticalByFile.set(fi.file, new Set());
    criticalByFile.get(fi.file).add(fi.ruleId);
  }
  const unmasked = [];
  for (const [file, rules] of criticalByFile) {
    if (rules.size >= 4 && dmap.get(file)) {
      unmasked.push({ file, criticalRules: rules.size });
      for (const fi of findings) if (fi.file === file) fi.discounted = false;
    }
  }

  const iocs = [...iocBag.entries()]
    .map(([k, count]) => {
      const i = k.indexOf('|');
      return { kind: k.slice(0, i), value: k.slice(i + 1), count };
    })
    .sort((a, b) => b.count - a.count);

  return { findings, artifacts, iocs, stats, ruleDbFiles, unmasked };
}

module.exports = { scanFiles, entropy };
