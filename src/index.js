'use strict';

const fs = require('fs');
const path = require('path');

const { walkDir, fromMemory } = require('./core/walk');
const { scanFiles } = require('./core/scan');
const { classify } = require('./core/classify');
const gh = require('./net/github');

const VERSION = require('../package.json').version;

/**
 * Scan a local directory, a single file, or a GitHub repository.
 * @param {string} target
 * @param {object} opts
 * @returns {Promise<object>} result
 */
async function scan(target, opts = {}) {
  const t0 = Date.now();
  const log = opts.onStatus || (() => {});
  let files;
  let label = target;
  let meta = null;
  let ref = null;
  let source = 'local';

  const asPath = path.resolve(String(target));
  const localExists = fs.existsSync(asPath);

  if (!localExists && gh.parseTarget(target)) {
    const p = gh.parseTarget(target);
    source = 'github';
    label = 'github.com/' + p.owner + '/' + p.repo;
    ref = p.ref;
    if (!opts.noNet) {
      log('fetching repository metadata');
      meta = await gh.fetchMeta(p.owner, p.repo);
      if (meta && !meta.error && !ref) ref = meta.defaultBranch;
    }
    const entries = await gh.fetchRepo(p.owner, p.repo, p.ref, log);
    files = fromMemory(entries).files;
  } else if (localExists && fs.statSync(asPath).isDirectory()) {
    log('walking ' + asPath);
    label = asPath;
    files = walkDir(asPath, opts).files;
  } else if (localExists) {
    label = asPath;
    opts = Object.assign({}, opts, { singleFile: true });
    files = [{ rel: path.basename(asPath), abs: asPath, size: fs.statSync(asPath).size, kind: null, discounted: false }];
  } else {
    throw new Error('Target not found: ' + target + '\n  Pass a directory, a file, a GitHub URL, or owner/repo.');
  }

  if (!files.length) throw new Error('Nothing to scan — no readable files at ' + label);

  log('scanning ' + files.length + ' files');
  const { findings, artifacts, iocs, stats, ruleDbFiles, unmasked } = scanFiles(files, opts);
  const classification = classify(findings, iocs);
  const trust = meta ? gh.trustSignals(meta) : [];

  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    target: { input: String(target), label, ref, source },
    meta,
    trust,
    stats,
    findings,
    ruleDbFiles,
    unmasked,
    artifacts,
    iocs,
    classification,
    elapsedMs: Date.now() - t0
  };
}

/**
 * Scan an in-memory file list: [{ rel, buf }].
 * Used by the test corpus and by `kudo --demo`, so that fixture material
 * never has to exist on disk where a host antivirus can quarantine it.
 */
function scanEntries(entries, opts = {}) {
  const t0 = Date.now();
  const files = fromMemory(entries).files;
  const { findings, artifacts, iocs, stats, ruleDbFiles, unmasked } = scanFiles(files, opts);
  const classification = classify(findings, iocs);
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    target: { input: opts.label || 'memory', label: opts.label || 'in-memory corpus', ref: null, source: 'memory' },
    meta: null,
    trust: [],
    stats,
    findings,
    ruleDbFiles,
    unmasked,
    artifacts,
    iocs,
    classification,
    elapsedMs: Date.now() - t0
  };
}

module.exports = { scan, scanEntries, VERSION };
