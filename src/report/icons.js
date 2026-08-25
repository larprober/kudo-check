'use strict';

/**
 * Kudo Check icon set — hand-drawn on a 24×24 grid, 1.6 stroke, round joins,
 * currentColor throughout. One mark per malware family, plus report furniture.
 * No emoji anywhere in this program: every glyph here is geometry we control.
 */

const G = {

  /* ── the logo: a shield whose negative space carries the check ── */
  logo:
    '<path d="M12 2.2 20.6 5.4v6.9c0 5.3-3.7 8.7-8.6 9.9-4.9-1.2-8.6-4.6-8.6-9.9V5.4Z" fill="none"/>' +
    '<path d="M7.7 12.1l3 3.1 5.6-6.4" fill="none" stroke-width="2"/>' +
    '<path d="M3.4 15.1h17.2" stroke-dasharray="1.6 2.2" opacity=".55"/>',

  /* ── malware families ── */

  // credentials being lifted out of a keyhole
  stealer:
    '<circle cx="9" cy="14.4" r="3.1"/>' +
    '<path d="M11.2 12.2 16 7.4M14.1 9.3l1.7 1.7M15.6 7.8l1.9 1.9"/>' +
    '<path d="M18.4 4.6 21 2M21 2h-3.1M21 2v3.1" stroke-width="1.4"/>',

  // a console with a remote link arcing into it
  rat:
    '<rect x="2.6" y="6.4" width="14.2" height="12.4" rx="2.2"/>' +
    '<path d="M6 11.2l2.4 2.2L6 15.6M10.2 15.8h3.4"/>' +
    '<path d="M18.4 6.6a4.6 4.6 0 0 1 0 6.4M20.6 4.4a7.7 7.7 0 0 1 0 10.8" opacity=".85"/>',

  // padlock clamped over a document
  ransom:
    '<path d="M4.6 3.6h7.2l3.4 3.4v5.2" />' +
    '<path d="M11.6 3.6V7h3.6"/>' +
    '<path d="M4.6 3.6v16.8h4.2"/>' +
    '<rect x="11.4" y="13.6" width="9.2" height="7.2" rx="1.6"/>' +
    '<path d="M13.6 13.6v-2.2a2.4 2.4 0 0 1 4.8 0v2.2"/>' +
    '<path d="M16 16.6v1.8" stroke-width="1.8"/>',

  // a disk platter struck through
  wiper:
    '<ellipse cx="12" cy="6.4" rx="7.6" ry="2.9"/>' +
    '<path d="M4.4 6.4v11.2c0 1.6 3.4 2.9 7.6 2.9s7.6-1.3 7.6-2.9V6.4"/>' +
    '<path d="M4.4 12c0 1.6 3.4 2.9 7.6 2.9s7.6-1.3 7.6-2.9" opacity=".6"/>' +
    '<path d="M5.6 20.4 18.4 3.6" stroke-width="2"/>',

  // a processor doing work that is not yours
  miner:
    '<rect x="6.4" y="6.4" width="11.2" height="11.2" rx="2"/>' +
    '<path d="M9.8 10.2h4.4M9.8 12.6h4.4M9.8 15h2.6" opacity=".9"/>' +
    '<path d="M9.4 6.4V3.6M14.6 6.4V3.6M9.4 20.4v-2.8M14.6 20.4v-2.8M6.4 9.4H3.6M6.4 14.6H3.6M20.4 9.4h-2.8M20.4 14.6h-2.8"/>',

  // clipboard with a swap in it
  clipper:
    '<path d="M8.4 4.6H6.2a1.8 1.8 0 0 0-1.8 1.8v12.6a1.8 1.8 0 0 0 1.8 1.8h11.6a1.8 1.8 0 0 0 1.8-1.8V6.4a1.8 1.8 0 0 0-1.8-1.8h-2.2"/>' +
    '<rect x="8.4" y="2.6" width="7.2" height="4" rx="1.4"/>' +
    '<path d="M8.6 12.4h5.6l-1.8-1.8M15.4 16.2H9.8l1.8 1.8"/>',

  // keys with a recording dot
  keylog:
    '<rect x="2.6" y="6.6" width="18.8" height="11" rx="2.2"/>' +
    '<path d="M6.2 10.2h.02M9.6 10.2h.02M13 10.2h.02M16.4 10.2h.02M6.2 13.4h.02M9.6 13.4h.02M13 13.4h.02" stroke-width="2.2"/>' +
    '<path d="M8.4 16.4h7.2"/>' +
    '<circle cx="17.6" cy="13.4" r="1.5" fill="currentColor" stroke="none"/>',

  // an aperture watching
  spy:
    '<path d="M1.8 12S5.6 5.4 12 5.4 22.2 12 22.2 12 18.4 18.6 12 18.6 1.8 12 1.8 12Z"/>' +
    '<circle cx="12" cy="12" r="3.2"/>' +
    '<path d="M12 8.8v6.4M8.8 12h6.4" opacity=".45"/>',

  // second stage arriving in a tray
  loader:
    '<path d="M12 2.8v9.6M8.2 9l3.8 3.8L15.8 9" stroke-width="1.8"/>' +
    '<path d="M3.4 14.4v4.2a2.4 2.4 0 0 0 2.4 2.4h12.4a2.4 2.4 0 0 0 2.4-2.4v-4.2"/>' +
    '<path d="M3.4 14.4h4.4l1.4 2.4h5.6l1.4-2.4h4.4"/>',

  // a swarm under one controller
  botnet:
    '<circle cx="12" cy="4.6" r="2.4"/>' +
    '<circle cx="4.4" cy="18.4" r="2.4"/><circle cx="12" cy="18.4" r="2.4"/><circle cx="19.6" cy="18.4" r="2.4"/>' +
    '<path d="M12 7v3.6M12 10.6H4.4v5.4M12 10.6h7.6v5.4M12 10.6v5.4" opacity=".85"/>',

  // one copy becoming three
  worm:
    '<circle cx="5.4" cy="12" r="2.8"/><circle cx="12" cy="12" r="2.8" opacity=".8"/><circle cx="18.6" cy="12" r="2.8" opacity=".55"/>' +
    '<path d="M8.2 12h1M14.8 12h1"/>' +
    '<path d="M12 6.4V3.8M18.6 6.4V3.8" opacity=".7" stroke-dasharray="1.4 1.8"/>',

  // a shield that has been switched off
  evasion:
    '<path d="M12 2.6 20 5.6v6.5c0 4.9-3.4 8.1-8 9.2-4.6-1.1-8-4.3-8-9.2V5.6Z"/>' +
    '<path d="M5.4 4.6 18.6 19.4" stroke-width="2"/>',

  // it comes back after every reboot
  persist:
    '<path d="M20.4 11.4A8.4 8.4 0 1 0 18 17.8"/>' +
    '<path d="M20.6 5.6v5.6H15"/>' +
    '<circle cx="12" cy="12" r="2.6" fill="currentColor" stroke="none" opacity=".85"/>',

  // the package itself is the attack
  supply:
    '<path d="M20.4 7.8 12 3.4 3.6 7.8v8.4L12 20.6l8.4-4.4Z"/>' +
    '<path d="M3.6 7.8 12 12.2l8.4-4.4M12 12.2v8.4" opacity=".75"/>' +
    '<path d="M7.4 5.4 15.9 9.9" opacity=".55"/>',

  // wrapped layers hiding the real thing
  packed:
    '<path d="M12 2.8 21 7.4 12 12 3 7.4Z"/>' +
    '<path d="M3 12.2 12 16.8l9-4.6" opacity=".8"/>' +
    '<path d="M3 16.6 12 21.2l9-4.6" opacity=".55"/>',

  // code pushed into a process that did not ask for it
  hacktool:
    '<rect x="3.4" y="5.6" width="9.6" height="12.8" rx="2"/>' +
    '<path d="M20.6 12H13M16 8.6 20.6 12 16 15.4" stroke-width="1.8"/>' +
    '<path d="M6.4 9h3.6M6.4 12h3.6M6.4 15h2" opacity=".65"/>',

  // a hook baited with a login
  phish:
    '<rect x="3.4" y="4.4" width="12.4" height="9.2" rx="1.8"/>' +
    '<path d="M6.4 8h6.4M6.4 10.8h3.6" opacity=".8"/>' +
    '<path d="M19.4 3.6v9.8a4 4 0 0 1-8 0"/>' +
    '<path d="M17.4 3.6h4" opacity=".8"/>',

  // a page wearing someone else's advertising
  adware:
    '<rect x="2.6" y="4.4" width="18.8" height="15.2" rx="2.2"/>' +
    '<path d="M2.6 9h18.8"/>' +
    '<path d="M5.4 6.7h.02M8 6.7h.02" stroke-width="2"/>' +
    '<rect x="6" y="11.6" width="12" height="5.2" rx="1.2" opacity=".9" stroke-dasharray="2.4 2"/>' +
    '<path d="M9.4 14.2h5.2" opacity=".7"/>',

  /* ── report furniture ── */

  file: '<path d="M13.4 2.8H6.6a2 2 0 0 0-2 2v14.4a2 2 0 0 0 2 2h10.8a2 2 0 0 0 2-2V8.8Z"/><path d="M13.4 2.8v6h6"/>',
  binary: '<rect x="3.4" y="3.4" width="17.2" height="17.2" rx="2.4"/><path d="M7.6 8.2h2.2v7.6H7.6ZM14.2 8.2h2.2v7.6h-2.2Z" opacity=".9"/><path d="M7.6 19.4h8.8" opacity=".5"/>',
  signal: '<path d="M12 20.4V9.6"/><path d="M6.8 20.4v-6.2M17.2 20.4V5.6"/><circle cx="12" cy="6.6" r="2" opacity=".9"/>',
  github: '<path d="M9 20.6c-4.6 1.4-4.6-2.4-6.4-3m12.8 5v-3.7a3.2 3.2 0 0 0-.9-2.5c3-.3 6.1-1.5 6.1-6.6a5.1 5.1 0 0 0-1.4-3.6 4.8 4.8 0 0 0-.1-3.6s-1.2-.3-3.9 1.5a13.3 13.3 0 0 0-7 0C5.5 2.3 4.3 2.6 4.3 2.6a4.8 4.8 0 0 0-.1 3.6A5.1 5.1 0 0 0 2.8 9.9c0 5 3.1 6.2 6.1 6.6a3.2 3.2 0 0 0-.9 2.5v3.7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 6.8V12l3.4 2"/>',
  alert: '<path d="M10.3 3.6 1.9 17.8a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0Z"/><path d="M12 9.4v4.4M12 17.4h.02" stroke-width="2"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8.2 12.2l2.8 2.8 5-5.6" stroke-width="1.8"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 16v-4.4M12 8.2h.02" stroke-width="2"/>',
  search: '<circle cx="10.8" cy="10.8" r="7.2"/><path d="M21 21l-5.2-5.2"/>',
  chevron: '<path d="M8.4 5.4 15.6 12l-7.2 6.6" stroke-width="1.8"/>',
  layers: '<path d="M12 2.8 21 7.4 12 12 3 7.4Z"/><path d="M3 12.2 12 16.8l9-4.6" opacity=".7"/>',
  hash: '<path d="M9.4 3.6 7.6 20.4M16.4 3.6l-1.8 16.8M4.4 8.6h16M3.6 15.4h16"/>'
};

/** Render an icon as inline SVG. */
function icon(name, size = 20, cls = '') {
  const g = G[name] || G.info;
  return '<svg class="ic ' + cls + '" width="' + size + '" height="' + size + '" viewBox="0 0 24 24" ' +
    'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" ' +
    'aria-hidden="true" focusable="false">' + g + '</svg>';
}

/** The full logo lockup: mark, wordmark, and a scan sweep across the shield. */
function logoMark(size = 44) {
  return '<svg class="logo-mark" width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" ' +
    'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<defs>' +
      '<linearGradient id="kudoSweep" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="currentColor" stop-opacity="0"/>' +
        '<stop offset="50%" stop-color="currentColor" stop-opacity=".22"/>' +
        '<stop offset="100%" stop-color="currentColor" stop-opacity="0"/>' +
      '</linearGradient>' +
      '<clipPath id="kudoShield">' +
        '<path d="M12 2.2 20.6 5.4v6.9c0 5.3-3.7 8.7-8.6 9.9-4.9-1.2-8.6-4.6-8.6-9.9V5.4Z"/>' +
      '</clipPath>' +
    '</defs>' +
    '<g clip-path="url(#kudoShield)">' +
      '<rect x="0" y="0" width="24" height="24" fill="url(#kudoSweep)" stroke="none"/>' +
    '</g>' +
    G.logo +
    '</svg>';
}

module.exports = { icon, logoMark, GLYPHS: G };
