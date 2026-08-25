'use strict';

const { FAMILIES, TACTICS, SEVERITY_ORDER } = require('../rules/families');

/* Weight multipliers applied per finding before scoring. */
function layerFactor(f) {
  if (f.layer === 'manifest') return 1.15;          // runs on install, not on use
  if (f.layer && f.layer.startsWith('decoded')) return 1.3;  // hidden on purpose
  if (f.layer && f.layer.startsWith('normalized')) return 1.2; // written to evade a scanner
  if (f.layer === 'binary strings') return 0.8;     // strings can be incidental
  if (f.layer === 'binary' || f.layer === 'filename') return 1.0;
  return 1.0;
}

function contextFactor(f) {
  return f.discounted ? 0.3 : 1.0;
}

const VERDICTS = [
  { min: 85, id: 'malicious',   label: 'Malicious',        tone: 'critical', line: 'Do not run this. Do not install it. Treat any machine that already ran it as compromised.' },
  { min: 62, id: 'likely',      label: 'Likely Malicious', tone: 'high',     line: 'The behaviour here matches known malware closely enough that running it is not a reasonable risk.' },
  { min: 36, id: 'suspicious',  label: 'Suspicious',       tone: 'medium',   line: 'Real red flags, but they could belong to a legitimate tool. Read the flagged lines before you trust it.' },
  { min: 14, id: 'lowrisk',     label: 'Low Risk',         tone: 'low',      line: 'Nothing that looks like malware. A few patterns worth a glance if this is going near anything sensitive.' },
  { min: 0,  id: 'clean',       label: 'Clean',            tone: 'clean',    line: 'No malicious behaviour detected by any signature, decoder or heuristic in this scan.' }
];

/** Narrow a family down to a recognisable variant name. */
function variantOf(family, ids, tags, iocKinds) {
  const has = (x) => ids.has(x);
  const tag = (x) => tags.has(x);

  switch (family) {
    case 'infostealer':
      if (has('STL-004') || has('STL-005')) return 'Discord token grabber';
      if (tag('wallet-theft') || has('STL-006')) return 'Crypto wallet stealer';
      if (has('STL-007')) return 'macOS keychain stealer';
      if (has('STL-008') || has('STL-009')) return 'Developer credential stealer';
      if (tag('credential-store')) return 'Browser credential stealer';
      return null;
    case 'rat':
      if (has('RAT-006') || iocKinds.has('telegram')) return 'Telegram-controlled RAT';
      if (has('RAT-005')) return 'Discord-controlled RAT';
      if (has('RAT-001') || has('RAT-002') || has('RAT-003')) return 'Reverse-shell backdoor';
      if (has('RAT-008')) return 'Commodity C2 implant';
      return null;
    case 'ransomware':
      if (has('RSM-004') || has('RSM-005')) return 'Crypto-ransomware with recovery sabotage';
      if (has('RSM-006')) return 'File-marking crypto-ransomware';
      return null;
    case 'loader':
      if (has('DEC-002')) return 'Dropper with an embedded payload';
      if (has('LDR-001')) return 'Pipe-to-shell dropper';
      if (has('LDR-005') || has('LDR-006')) return 'Shellcode loader';
      if (has('LDR-002') || has('LDR-007')) return 'Fileless PowerShell loader';
      return 'Staged downloader';
    case 'cryptominer':
      return has('MIN-004') ? 'Throttled stealth miner' : 'Pool-connected coin miner';
    case 'supplychain':
      if (has('PKG-002') || has('SUP-002')) return 'Malicious install hook';
      if (has('PKG-004') || has('PKG-003')) return 'Typosquatted dependency';
      if (has('PKG-008') || has('SUP-004')) return 'CI secret exfiltration';
      return 'Build-time attack';
    case 'spyware':
      if (has('SPY-002') || has('SPY-003')) return 'Camera / microphone surveillance';
      if (has('SPY-001')) return 'Screen surveillance implant';
      return null;
    case 'packer':
      return 'Obfuscated payload carrier';
    case 'hacktool':
      if (has('HTL-005')) return 'Credential dumping tool';
      if (has('HTL-002') || has('HTL-001')) return 'Process injection tool';
      return null;
    case 'worm':
      return has('WRM-001') || has('WRM-002') ? 'Removable-media worm' : 'Self-replicating spreader';
    default:
      return null;
  }
}

/**
 * Score findings into a verdict.
 * @returns { score, verdict, families[], primary, tactics[], counts, gated[] }
 */
function classify(findings, iocs = []) {
  const iocKinds = new Set(iocs.map((i) => i.kind));

  // Collapse to one entry per rule, remembering distinct files.
  const byRule = new Map();
  for (const f of findings) {
    const k = f.ruleId;
    let e = byRule.get(k);
    if (!e) {
      e = { rule: f, files: new Set(), hits: 0, maxFactor: 0, sumFactor: 0 };
      byRule.set(k, e);
    }
    e.files.add(f.file);
    e.hits++;
    const factor = layerFactor(f) * contextFactor(f);
    e.maxFactor = Math.max(e.maxFactor, factor);
    if (SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(e.rule.severity)) e.rule = f;
  }

  const famAgg = new Map();
  for (const e of byRule.values()) {
    const fam = e.rule.family;
    if (!FAMILIES[fam]) continue;
    let a = famAgg.get(fam);
    if (!a) {
      a = { key: fam, raw: 0, rules: new Set(), tags: new Set(), findings: [], criticals: 0 };
      famAgg.set(fam, a);
    }
    // First distinct file at full weight, each further file adds 25%, cap 2x.
    const spread = Math.min(2, 1 + 0.25 * (e.files.size - 1));
    a.raw += e.rule.weight * e.maxFactor * spread;
    a.rules.add(e.rule.ruleId);
    for (const t of e.rule.tags || []) a.tags.add(t);
    if (e.rule.severity === 'critical' && e.maxFactor >= 0.8) a.criticals++;
  }

  const named = [];
  const gated = [];
  for (const a of famAgg.values()) {
    const def = FAMILIES[a.key];
    const score = Math.min(def.weightCap, Math.round(a.raw));
    const enoughRules = a.rules.size >= def.minRules;
    const satisfied = (def.requires || []).every((grp) => grp.some((t) => a.tags.has(t)));
    const entry = {
      key: a.key,
      label: def.label,
      icon: def.icon,
      blurb: def.blurb,
      score,
      rules: [...a.rules].sort(),
      ruleCount: a.rules.size,
      tags: [...a.tags],
      criticals: a.criticals,
      variant: variantOf(a.key, a.rules, a.tags, iocKinds)
    };
    entry.confidence = confidenceOf(entry, def, enoughRules && satisfied);
    if (enoughRules && satisfied) named.push(entry);
    else { entry.blockedBy = !enoughRules ? 'needs ' + def.minRules + ' distinct signatures, found ' + a.rules.size : 'missing corroborating behaviour'; gated.push(entry); }
  }

  named.sort((a, b) => b.score - a.score || b.ruleCount - a.ruleCount);
  gated.sort((a, b) => b.score - a.score);

  // Overall risk: strongest family dominates, others corroborate.
  let score = 0;
  if (named.length) {
    score = named[0].score;
    for (let i = 1; i < named.length; i++) score += named[i].score * 0.32;
    if (named.length >= 3) score += 6;
  }
  // Gated families still nudge the number without being named.
  for (const g of gated) score += Math.min(10, g.score * 0.18);
  score = Math.max(0, Math.min(100, Math.round(score)));

  const verdict = VERDICTS.find((v) => score >= v.min);

  const tacticAgg = new Map();
  for (const f of findings) {
    if (f.discounted) continue;
    const t = f.tactic || 'execution';
    if (!TACTICS[t]) continue;
    let e = tacticAgg.get(t);
    if (!e) { e = { key: t, label: TACTICS[t], count: 0, top: f }; tacticAgg.set(t, e); }
    e.count++;
    if (SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(e.top.severity)) e.top = f;
  }
  const order = Object.keys(TACTICS);
  const tactics = [...tacticAgg.values()].sort((a, b) => order.indexOf(a.key) - order.indexOf(b.key));

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const primary = named[0] || null;

  // Below "suspicious" we do not put a malware name in the headline. A weak
  // partial match is a lead to follow, not a diagnosis.
  const confident = !!primary && score >= 36;
  const headline = confident
    ? (primary.variant || primary.label)
    : (verdict.id === 'clean' ? 'No malware family matched' : 'Nothing rose to a malware classification');

  return {
    score,
    verdict,
    families: named,
    gated,
    primary,
    confident,
    headline,
    tactics,
    counts,
    ruleCount: byRule.size,
    diagnosis: diagnose(verdict, primary, named, counts, confident)
  };
}

function confidenceOf(entry, def, gatesPassed) {
  if (!gatesPassed) return 'unconfirmed';
  const ratio = entry.score / def.weightCap;
  if (ratio >= 0.75 && entry.ruleCount >= 3 && entry.criticals >= 2) return 'high';
  if (ratio >= 0.5 && entry.ruleCount >= 2) return 'medium';
  return 'low';
}

function diagnose(verdict, primary, named, counts, confident) {
  if (!primary) {
    if (verdict.id === 'clean') return 'No malware family matched. Nothing in this project behaves like a stealer, backdoor, miner, ransomware or dropper.';
    return 'Individually suspicious patterns were found, but they do not add up to a known malware family. Review them as code-quality or hardening issues.';
  }
  if (!confident) {
    return 'No family scored high enough to be called malware. The strongest signal was ' + primary.label +
      ' at ' + primary.score + '/100, on ' + primary.ruleCount + ' signature' + (primary.ruleCount === 1 ? '' : 's') +
      ' — worth reading, not worth alarm.';
  }
  const name = primary.variant ? primary.variant + ' (' + primary.label + ')' : primary.label;
  const others = named.slice(1, 4).map((f) => f.label);
  let s = 'Classified as ' + name + ' with ' + primary.confidence + ' confidence, on ' +
    primary.ruleCount + ' distinct signature' + (primary.ruleCount === 1 ? '' : 's') + '.';
  if (others.length) s += ' It also carries ' + others.join(', ') + ' behaviour.';
  if (counts.critical) s += ' ' + counts.critical + ' critical detection' + (counts.critical === 1 ? '' : 's') + ' in total.';
  return s;
}

module.exports = { classify, VERDICTS };
