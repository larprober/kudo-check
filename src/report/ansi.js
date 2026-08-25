'use strict';

/** Truecolor ANSI helpers with a clean no-color fallback. */

let ENABLED = process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

function setColor(on) { ENABLED = !!on; }
function enabled() { return ENABLED; }

const esc = (n) => (ENABLED ? '[' + n + 'm' : '');
const rgb = (r, g, b) => (ENABLED ? '[38;2;' + r + ';' + g + ';' + b + 'm' : '');
const bg = (r, g, b) => (ENABLED ? '[48;2;' + r + ';' + g + ';' + b + 'm' : '');

const RESET = () => esc(0);
const BOLD = () => esc(1);
const DIM = () => esc(2);
const ITALIC = () => esc(3);

/* Palette — one system shared by the terminal and the HTML report. */
const C = {
  ink:      [226, 232, 240],
  muted:    [128, 141, 160],
  faint:    [88, 98, 114],
  line:     [52, 60, 74],
  critical: [255, 92, 106],
  high:     [255, 149, 71],
  medium:   [246, 200, 84],
  low:      [92, 176, 255],
  clean:    [74, 214, 154],
  accent:   [130, 122, 255],
  accent2:  [86, 214, 255]
};

const paint = (c, s) => rgb(c[0], c[1], c[2]) + s + RESET();
const bold = (s) => BOLD() + s + RESET();
const dim = (s) => DIM() + s + RESET();
const italic = (s) => ITALIC() + s + RESET();

/** Visible width, ignoring ANSI sequences. */
function width(s) {
  return String(s).replace(/\[[0-9;]*m/g, '').length;
}

function pad(s, n, align = 'left') {
  const w = width(s);
  if (w >= n) return s;
  const fill = ' '.repeat(n - w);
  if (align === 'right') return fill + s;
  if (align === 'center') {
    const l = Math.floor((n - w) / 2);
    return ' '.repeat(l) + s + ' '.repeat(n - w - l);
  }
  return s + fill;
}

/** Wrap to width, preserving a hanging indent. */
function wrap(text, w, indent = '') {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = '';
  for (const word of words) {
    if (!cur.length) cur = word;
    else if (cur.length + 1 + word.length <= w) cur += ' ' + word;
    else { lines.push(cur); cur = word; }
  }
  if (cur) lines.push(cur);
  return lines.map((l, i) => (i === 0 ? l : indent + l));
}

/** Interpolate the risk gradient: green → amber → red. */
function riskColor(score) {
  const stops = [
    [0, [74, 214, 154]],
    [35, [246, 200, 84]],
    [62, [255, 149, 71]],
    [85, [255, 92, 106]],
    [100, [255, 70, 90]]
  ];
  const s = Math.max(0, Math.min(100, score));
  for (let i = 1; i < stops.length; i++) {
    if (s <= stops[i][0]) {
      const [p0, c0] = stops[i - 1];
      const [p1, c1] = stops[i];
      const t = (s - p0) / (p1 - p0 || 1);
      return [0, 1, 2].map((k) => Math.round(c0[k] + (c1[k] - c0[k]) * t));
    }
  }
  return stops[stops.length - 1][1];
}

/** Horizontal meter with a colour ramp across its filled cells. */
function meter(value, max, cells = 32, color = null) {
  const ratio = Math.max(0, Math.min(1, value / (max || 1)));
  const filled = Math.round(ratio * cells);
  let out = '';
  for (let i = 0; i < cells; i++) {
    if (i < filled) {
      const c = color || riskColor(((i + 1) / cells) * 100);
      out += rgb(c[0], c[1], c[2]) + '█';
    } else {
      out += rgb(C.line[0], C.line[1], C.line[2]) + '░';
    }
  }
  return out + RESET();
}

/** Four-cell severity mark. Reads at a glance without a legend. */
function sevMark(sev) {
  const map = {
    critical: [4, C.critical],
    high: [3, C.high],
    medium: [2, C.medium],
    low: [1, C.low],
    info: [1, C.faint]
  };
  const [n, c] = map[sev] || map.info;
  let out = '';
  for (let i = 0; i < 4; i++) {
    out += i < n ? rgb(c[0], c[1], c[2]) + '▰' : rgb(C.line[0], C.line[1], C.line[2]) + '▱';
  }
  return out + RESET();
}

module.exports = { setColor, enabled, esc, rgb, bg, RESET, BOLD, DIM, C, paint, bold, dim, italic, width, pad, wrap, riskColor, meter, sevMark };
