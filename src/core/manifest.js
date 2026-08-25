'use strict';

const { KNOWN_BAD, HOOK_ALLOW, typosquatOf } = require('../rules/packages');

/**
 * Structural analysis of dependency manifests and CI config.
 * Produces findings in the same shape as signature hits so the classifier
 * can treat both alike.
 */

function mk(o) {
  return {
    ruleId: o.id,
    name: o.name,
    family: o.family,
    tactic: o.tactic || 'execution',
    severity: o.severity || 'medium',
    weight: o.weight,
    tags: o.tags || [],
    file: o.file,
    line: o.line || 1,
    snippet: o.snippet,
    why: o.why,
    layer: 'manifest'
  };
}

function lineOfKey(text, needle) {
  const i = text.indexOf(needle);
  if (i < 0) return 1;
  return text.slice(0, i).split('\n').length;
}

function analyzeNpm(rel, text, findings) {
  let pkg;
  try { pkg = JSON.parse(text); } catch { return; }

  const scripts = pkg.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish']) {
    const cmd = scripts[hook];
    if (typeof cmd !== 'string' || !cmd.trim()) continue;
    if (HOOK_ALLOW.test(cmd.trim())) continue;
    const net = /(?:curl|wget|Invoke-WebRequest|iwr|https?:\/\/|nc\s|powershell|certutil)/i.test(cmd);
    const evalish = /(?:eval|base64|atob|-enc|Function\()/i.test(cmd);
    findings.push(mk({
      id: net || evalish ? 'PKG-002' : 'PKG-001',
      name: net ? 'Install hook fetches from the network'
        : evalish ? 'Install hook decodes or evaluates code'
          : 'Install hook runs a non-standard command',
      family: 'supplychain', severity: net || evalish ? 'critical' : 'high',
      weight: net ? 30 : evalish ? 26 : 16,
      tags: net ? ['install-hook', 'remote-payload'] : ['install-hook'],
      file: rel, line: lineOfKey(text, '"' + hook + '"'),
      snippet: '"' + hook + '": ' + JSON.stringify(cmd).slice(0, 160),
      why: 'npm runs ' + hook + ' automatically during `npm install`, before anyone has read a single line of this package.'
    }));
  }

  const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
  for (const [name, spec] of Object.entries(deps)) {
    if (KNOWN_BAD.has(name.toLowerCase())) {
      findings.push(mk({
        id: 'PKG-003', name: 'Known-malicious dependency',
        family: 'supplychain', severity: 'critical', weight: 30, tags: ['typosquat'],
        file: rel, line: lineOfKey(text, '"' + name + '"'),
        snippet: '"' + name + '": ' + JSON.stringify(spec),
        why: 'This package name appears on the list of packages that shipped malware.'
      }));
      continue;
    }
    const squat = typosquatOf(name, 'npm');
    if (squat) {
      findings.push(mk({
        id: 'PKG-004', name: 'Dependency name typosquats "' + squat + '"',
        family: 'supplychain', severity: 'high', weight: 22, tags: ['typosquat'],
        file: rel, line: lineOfKey(text, '"' + name + '"'),
        snippet: '"' + name + '" vs the real "' + squat + '"',
        why: 'A one-character-off dependency name is how malicious packages get installed by mistake.'
      }));
    }
    if (typeof spec === 'string' && /^(?:https?|git\+https?):\/\//.test(spec) && !/registry\.npmjs\.org|github\.com/.test(spec)) {
      findings.push(mk({
        id: 'PKG-005', name: 'Dependency resolved from an arbitrary URL',
        family: 'supplychain', severity: 'high', weight: 18, tags: ['dep-confusion'],
        file: rel, line: lineOfKey(text, '"' + name + '"'),
        snippet: '"' + name + '": ' + JSON.stringify(spec),
        why: 'Fetching a dependency straight from a URL bypasses every registry-side control and can change under you.'
      }));
    }
  }
}

function analyzePypi(rel, text, findings) {
  const lines = text.split('\n');
  lines.forEach((raw, i) => {
    const line = raw.split('#')[0].trim();
    if (!line) return;
    const m = /^([A-Za-z0-9._-]+)\s*(?:[<>=!~]|$|\[)/.exec(line);
    if (!m) {
      if (/^(?:--index-url|--extra-index-url|-i)\s+https?:\/\//.test(line) && !/pypi\.org/.test(line)) {
        findings.push(mk({
          id: 'PKG-006', name: 'Third-party package index configured',
          family: 'supplychain', severity: 'high', weight: 20, tags: ['dep-confusion'],
          file: rel, line: i + 1, snippet: line.slice(0, 160),
          why: 'An alternate index can serve a package with the same name as a public one — dependency confusion.'
        }));
      }
      return;
    }
    const name = m[1].toLowerCase();
    if (KNOWN_BAD.has(name)) {
      findings.push(mk({
        id: 'PKG-003', name: 'Known-malicious dependency',
        family: 'supplychain', severity: 'critical', weight: 30, tags: ['typosquat'],
        file: rel, line: i + 1, snippet: line.slice(0, 160),
        why: 'This package name appears on the list of packages that shipped malware.'
      }));
      return;
    }
    const squat = typosquatOf(name, 'pypi');
    if (squat) {
      findings.push(mk({
        id: 'PKG-004', name: 'Dependency name typosquats "' + squat + '"',
        family: 'supplychain', severity: 'high', weight: 22, tags: ['typosquat'],
        file: rel, line: i + 1, snippet: line.slice(0, 160) + '  (real package: ' + squat + ')',
        why: 'A one-character-off dependency name is how malicious packages get installed by mistake.'
      }));
    }
  });
}

function analyzeWorkflow(rel, text, findings) {
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    if (/pull_request_target/.test(line)) {
      findings.push(mk({
        id: 'PKG-007', name: 'Workflow triggers on pull_request_target',
        family: 'supplychain', severity: 'medium', weight: 12, tags: ['install-hook'],
        file: rel, line: i + 1, snippet: line.trim().slice(0, 160),
        why: 'pull_request_target runs with repository secrets available to code proposed by strangers.'
      }));
    }
    if (/toJSON\(\s*secrets\s*\)/.test(line)) {
      findings.push(mk({
        id: 'PKG-008', name: 'Workflow serialises all repository secrets',
        family: 'supplychain', severity: 'critical', weight: 28, tags: ['install-hook'],
        file: rel, line: i + 1, snippet: line.trim().slice(0, 160),
        why: 'Dumping every secret into one value is the first half of a secret-exfiltration workflow.'
      }));
    }
    if (/curl|wget|Invoke-WebRequest/i.test(line) && /\|\s*(?:ba)?sh|\|\s*python/i.test(line)) {
      findings.push(mk({
        id: 'PKG-009', name: 'CI step pipes a download into a shell',
        family: 'supplychain', severity: 'high', weight: 20, tags: ['install-hook', 'remote-payload'],
        file: rel, line: i + 1, snippet: line.trim().slice(0, 160),
        why: 'The build executes whatever that server returns, with the runner’s credentials.'
      }));
    }
  });
}

const MANIFESTS = [
  { re: /(?:^|\/)package\.json$/, fn: analyzeNpm },
  { re: /(?:^|\/)requirements[\w.-]*\.txt$/i, fn: analyzePypi },
  { re: /(?:^|\/)Pipfile$/, fn: analyzePypi },
  { re: /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i, fn: analyzeWorkflow },
  { re: /(?:^|\/)\.gitlab-ci\.ya?ml$/i, fn: analyzeWorkflow }
];

function analyzeManifest(rel, text) {
  const findings = [];
  for (const m of MANIFESTS) if (m.re.test(rel)) m.fn(rel, text, findings);
  return findings;
}

module.exports = { analyzeManifest };
