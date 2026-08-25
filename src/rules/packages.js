'use strict';

/** High-traffic package names used as typosquat reference points. */
const POPULAR_NPM = [
  'express', 'react', 'react-dom', 'lodash', 'axios', 'chalk', 'commander', 'debug',
  'moment', 'request', 'async', 'bluebird', 'underscore', 'uuid', 'dotenv', 'colors',
  'webpack', 'babel-core', 'typescript', 'jquery', 'mongoose', 'socket.io', 'redux',
  'body-parser', 'cors', 'jsonwebtoken', 'bcrypt', 'mysql', 'pg', 'redis', 'sequelize',
  'nodemon', 'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'rimraf', 'glob',
  'minimist', 'yargs', 'inquirer', 'ora', 'node-fetch', 'ws', 'cheerio', 'puppeteer',
  'discord.js', 'electron', 'next', 'vue', 'angular', 'rxjs', 'protobufjs', 'ini',
  'crossenv', 'cross-env', 'fs-extra', 'semver', 'tslib', 'classnames', 'styled-components'
];

const POPULAR_PYPI = [
  'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'setuptools', 'pillow',
  'beautifulsoup4', 'selenium', 'scipy', 'matplotlib', 'pytest', 'six', 'certifi',
  'cryptography', 'boto3', 'click', 'jinja2', 'sqlalchemy', 'pyyaml', 'colorama',
  'discord.py', 'aiohttp', 'tensorflow', 'torch', 'scikit-learn', 'openpyxl', 'lxml',
  'python-dateutil', 'pycryptodome', 'psutil', 'paramiko', 'tqdm', 'websockets'
];

/** Packages that were, or are, known-malicious. Small curated set. */
const KNOWN_BAD = new Set([
  'crossenv', 'cross-env.js', 'babelcli', 'ffmpeg.js', 'nodefabric', 'node-fabric',
  'sqliter', 'mongose', 'shadow-installer', 'coa-parser', 'rc-vue', 'event-stream',
  'flatmap-stream', 'ua-parser-js-bak', 'node-ipc-fix', 'colors-fix', 'discordi.js',
  'discord.dll', 'discord-selfbot-v13', 'noblox.js-proxy', 'noblox.js-proxies',
  'colourama', 'jeilyfish', 'python3-dateutil', 'pytz3-deb', 'setup-tools', 'requesys',
  'request-promise-tool', 'ctx', 'phpass', 'pymafka', 'python-dateutils'
]);

/** Legitimate scripts that are allowed to appear in install hooks. */
const HOOK_ALLOW = /^(?:echo|exit|true|:|node-gyp|prebuild-install|husky|patch-package|npm run build|tsc|electron-builder install-app-deps|node scripts\/postinstall(?:\.js)?)\b/;

/**
 * Optimal string alignment distance — Levenshtein plus adjacent transposition.
 * Transposition has to count as one edit: "reqeusts" for "requests" is the
 * single most common typosquat shape there is.
 */
function levenshtein(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 3) return 9;
  const d = [];
  for (let i = 0; i <= a.length; i++) { d[i] = new Array(b.length + 1); d[i][0] = i; }
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[a.length][b.length];
}

/** Returns the popular package this name is suspiciously close to, or null. */
function typosquatOf(name, ecosystem) {
  const list = ecosystem === 'pypi' ? POPULAR_PYPI : POPULAR_NPM;
  const raw = String(name).toLowerCase();
  // Scoped packages carry their owner in the name: @babel/core is not a
  // typosquat of "cors". Comparing the bare part produced exactly that.
  if (raw.startsWith('@')) return null;
  const n = raw;
  if (list.includes(n)) return null;
  for (const p of list) {
    if (n === p) return null;
    const d = levenshtein(n, p);
    if (d === 1 && p.length >= 4) return p;
    // separator and homoglyph swaps: lodash.js vs lodash, react-dom vs reactdom
    if (n.replace(/[-._]/g, '') === p.replace(/[-._]/g, '') && n !== p) return p;
    if (n === p + 'js' || n === p + '.js' || n === 'node-' + p || n === p + '-js') return p;
  }
  return null;
}

module.exports = { POPULAR_NPM, POPULAR_PYPI, KNOWN_BAD, HOOK_ALLOW, typosquatOf, levenshtein };
