'use strict';

const https = require('https');
const { untar, gunzip } = require('./tar');

const UA = 'KudoCheck/1.0 (+repository malware scanner)';

function parseTarget(input) {
  const t = String(input).trim().replace(/\.git$/, '');
  let m = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)(?:\/tree\/([^/?#]+))?/i.exec(t);
  if (m) return { owner: m[1], repo: m[2], ref: m[3] ? decodeURIComponent(m[3]) : null };
  m = /^([\w.-]+)\/([\w.-]+)(?:@([\w./-]+))?$/.exec(t);
  if (m) return { owner: m[1], repo: m[2], ref: m[3] || null };
  return null;
}

function get(url, opts = {}, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('too many redirects'));
    const req = https.get(url, {
      headers: Object.assign({
        'User-Agent': UA,
        'Accept': opts.json ? 'application/vnd.github+json' : '*/*'
      }, process.env.GITHUB_TOKEN ? { Authorization: 'Bearer ' + process.env.GITHUB_TOKEN } : {}),
      timeout: opts.timeout || 45000
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        return resolve(get(next, opts, redirects + 1));
      }
      const chunks = [];
      let len = 0;
      const cap = opts.maxBytes || 220 * 1024 * 1024;
      res.on('data', (c) => {
        len += c.length;
        if (len > cap) { req.destroy(new Error('response exceeded ' + cap + ' bytes')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
  });
}

/** Repository metadata used for the trust signals in the report. */
async function fetchMeta(owner, repo) {
  try {
    const r = await get('https://api.github.com/repos/' + owner + '/' + repo, { json: true, maxBytes: 2 * 1024 * 1024 });
    if (r.status !== 200) return { error: 'HTTP ' + r.status };
    const j = JSON.parse(r.body.toString('utf8'));
    return {
      fullName: j.full_name,
      description: j.description,
      stars: j.stargazers_count,
      forks: j.forks_count,
      openIssues: j.open_issues_count,
      createdAt: j.created_at,
      pushedAt: j.pushed_at,
      defaultBranch: j.default_branch,
      archived: j.archived,
      isFork: j.fork,
      license: j.license && j.license.spdx_id,
      size: j.size,
      owner: j.owner && j.owner.login,
      ownerType: j.owner && j.owner.type
    };
  } catch (e) {
    return { error: e.message };
  }
}

/** Reputation heuristics that have nothing to do with the code itself. */
function trustSignals(meta) {
  const out = [];
  if (!meta || meta.error) return out;
  const now = Date.now();
  const ageDays = meta.createdAt ? (now - Date.parse(meta.createdAt)) / 86400000 : null;
  if (ageDays != null && ageDays < 30) {
    out.push({ level: 'warn', text: 'Repository is ' + Math.max(1, Math.round(ageDays)) + ' days old', why: 'Malware repositories are usually created shortly before they are advertised.' });
  }
  if (meta.stars != null && meta.stars < 5) {
    out.push({ level: 'warn', text: 'Only ' + meta.stars + ' star' + (meta.stars === 1 ? '' : 's'), why: 'No community has vouched for this code.' });
  } else if (meta.stars >= 500) {
    out.push({ level: 'good', text: meta.stars.toLocaleString('en-US') + ' stars', why: 'A widely watched repository is a harder place to hide a payload.' });
  }
  if (meta.isFork) out.push({ level: 'warn', text: 'This is a fork', why: 'Forks of popular projects are a common way to ship a modified, hostile copy.' });
  if (!meta.license) out.push({ level: 'info', text: 'No license declared', why: 'Weak signal on its own, common in throwaway repositories.' });
  if (meta.archived) out.push({ level: 'info', text: 'Repository is archived', why: 'No longer maintained; unpatched issues will stay unpatched.' });
  if (meta.pushedAt) {
    const idle = (now - Date.parse(meta.pushedAt)) / 86400000;
    if (idle > 730) out.push({ level: 'info', text: 'No commits in ' + Math.round(idle / 365) + ' years', why: 'Stale code accumulates unfixed vulnerabilities.' });
  }
  return out;
}

/** Download and unpack a repository into an in-memory file list. */
async function fetchRepo(owner, repo, ref, onProgress) {
  const refs = ref ? [ref] : ['HEAD'];
  let lastErr = null;
  for (const r of refs) {
    const url = r === 'HEAD'
      ? 'https://api.github.com/repos/' + owner + '/' + repo + '/tarball'
      : 'https://codeload.github.com/' + owner + '/' + repo + '/tar.gz/' + encodeURIComponent(r);
    try {
      if (onProgress) onProgress('downloading ' + owner + '/' + repo + (ref ? '@' + ref : ''));
      const res = await get(url);
      if (res.status === 404) { lastErr = new Error('repository or ref not found (404)'); continue; }
      if (res.status === 403) throw new Error('GitHub rate limit or access denied (403). Set GITHUB_TOKEN to raise the limit.');
      if (res.status !== 200) { lastErr = new Error('HTTP ' + res.status); continue; }
      if (onProgress) onProgress('unpacking ' + (res.body.length / 1048576).toFixed(1) + ' MB');
      const tar = gunzip(res.body);
      const entries = untar(tar);
      if (!entries.length) throw new Error('archive contained no files');
      return entries;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('download failed');
}

module.exports = { parseTarget, fetchRepo, fetchMeta, trustSignals };
