/* ------------------------------------------------------------------
   Icon set — inline SVG paths, no external requests.
   Keys are referenced by `icon` in data.js. Stroke-based, 24×24 grid,
   so they inherit colour and stay crisp at any size.
   When the hub's own icons are captured these can be swapped one by one.
   ------------------------------------------------------------------ */

window.VTS_ICONS = {
  // — section headers —
  chapel:
    '<path d="M12 2 L12 6 M10 4 L14 4 M12 6 L5 12 v9 h14 v-9 Z"/><path d="M10 21 v-5 a2 2 0 0 1 4 0 v5"/>',
  finance:
    '<path d="M12 2 v20"/><path d="M17 6.5c0-1.9-2.2-2.9-5-2.9s-5 .9-5 2.7c0 4.2 10 2.2 10 6.4 0 1.9-2.2 3-5 3s-5-1.1-5-3"/>',
  people:
    '<circle cx="9" cy="8" r="3.2"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 5.2a3.2 3.2 0 0 1 0 5.6"/><path d="M17.5 14.2A6.5 6.5 0 0 1 21.5 20"/>',
  key: '<circle cx="8" cy="12" r="4"/><path d="M12 12 h9"/><path d="M17 12 v3.5"/><path d="M20 12 v2.5"/>',

  // — worship —
  prayer:
    '<path d="M12 21c-1.5-1.2-2.5-2.6-2.5-4.4V8.5a1.5 1.5 0 0 1 3 0V13"/><path d="M12.5 13V6.5a1.5 1.5 0 0 1 3 0v8.2c0 3.4-1.6 5.1-3.5 6.3"/><path d="M9.5 12 7 14.5"/>',
  scroll:
    '<path d="M6 3h10a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6"/><path d="M6 3a2 2 0 0 0 0 4h2"/><path d="M6 21a2 2 0 0 0 0-4h2"/><path d="M10 9h5M10 13h5"/>',
  music:
    '<circle cx="7" cy="18" r="2.5"/><circle cx="17" cy="16" r="2.5"/><path d="M9.5 18V7l10-2v11"/><path d="M9.5 10.5l10-2"/>',
  index:
    '<path d="M5 4h13a1 1 0 0 1 1 1v15a1 1 0 0 1-1 1H5z"/><path d="M5 4v17"/><path d="M9 8h6M9 12h6M9 16h3"/>',
  calendar:
    '<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 10h17"/><path d="M8 3v4M16 3v4"/><path d="M8 14h3v3H8z"/>',
  kiosk:
    '<rect x="5" y="3" width="14" height="14" rx="1.5"/><path d="M8 20h8"/><path d="M12 17v3"/><path d="M9 7h6M9 10.5h6"/>',

  // — documents & forms —
  book: '<path d="M4 4.5A1.5 1.5 0 0 1 5.5 3H19v18H5.5A1.5 1.5 0 0 1 4 19.5z"/><path d="M4 17.5A1.5 1.5 0 0 1 5.5 16H19"/><path d="M8 7h7"/>',
  policy:
    '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 12h6M9 16h4"/>',
  form: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 13h6M9 17h6"/>',
  receipt:
    '<path d="M5 3h14v18l-2.3-1.6L14.4 21l-2.4-1.6L9.6 21l-2.3-1.6L5 21z"/><path d="M9 8h6M9 12h6"/>',
  check:
    '<rect x="3" y="6" width="18" height="12" rx="1.5"/><path d="M6.5 14h5"/><path d="M15 10.5h2.5"/>',
  plane:
    '<path d="M10.5 19.5 12 21l1.5-1.5"/><path d="M2.5 13.5 12 3l9.5 10.5"/><path d="M12 3v18"/><path d="M2.5 13.5 12 16l9.5-2.5"/>',
  bank: '<path d="M3 10 12 4l9 6"/><path d="M5 10v8M10 10v8M14 10v8M19 10v8"/><path d="M3 21h18"/>',
  tax: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9.5 12.5 14 17"/><circle cx="10" cy="13" r="1"/><circle cx="13.5" cy="16.5" r="1"/>',

  // — HR —
  medical:
    '<rect x="3" y="6.5" width="18" height="13" rx="2"/><path d="M9 6.5V5a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 15 5v1.5"/><path d="M12 10.5v5M9.5 13h5"/>',
  dental:
    '<path d="M12 4c2.5-1.5 6-1 6 2.5 0 4-1 5.5-1.5 9-.4 2.7-2.4 2.7-2.8 0-.3-2-.6-3-1.7-3s-1.4 1-1.7 3c-.4 2.7-2.4 2.7-2.8 0C7 12 6 10.5 6 6.5 6 3 9.5 2.5 12 4Z"/>',
  support:
    '<path d="M12 3a7 7 0 0 0-7 7v4"/><path d="M19 14v-4a7 7 0 0 0-3.5-6"/><rect x="3" y="12.5" width="3.5" height="5.5" rx="1.5"/><rect x="17.5" y="12.5" width="3.5" height="5.5" rx="1.5"/><path d="M19 18v.5a2.5 2.5 0 0 1-2.5 2.5H13"/>',
  share:
    '<circle cx="17" cy="6" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="17" cy="18" r="2.5"/><path d="M8.3 10.8 14.7 7.2M8.3 13.2l6.4 3.6"/>',

  // — systems —
  microsoft:
    '<rect x="3.5" y="3.5" width="7.5" height="7.5"/><rect x="13" y="3.5" width="7.5" height="7.5"/><rect x="3.5" y="13" width="7.5" height="7.5"/><rect x="13" y="13" width="7.5" height="7.5"/>',
  paycom:
    '<rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/>',
  brightspace:
    '<path d="M3 6.5 12 3l9 3.5-9 3.5z"/><path d="M7 11v4.5c0 1.4 2.2 2.5 5 2.5s5-1.1 5-2.5V11"/><path d="M20 8v5"/>',
  populi:
    '<circle cx="12" cy="7" r="3"/><path d="M5 20a7 7 0 0 1 14 0"/><path d="M9 12.5 12 15l3-2.5"/>',
  wrench:
    '<path d="M15.5 3.5a5 5 0 0 0-5.9 6.6L3 16.7 5.8 19.5l6.6-6.6a5 5 0 0 0 6.6-5.9l-3 3-2.5-2.5z"/>',
  edit: '<path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3z"/><path d="M14.5 5.5l3 3"/>',
  link: '<path d="M10 13.5a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5"/><path d="M14 10.5a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5"/>',

  // — fallback —
  doc: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>',
};

/** Wrap an icon key in an <svg>. Falls back to a generic document. */
window.vtsIcon = function (key, cls) {
  const paths = window.VTS_ICONS[key] || window.VTS_ICONS.doc;
  return (
    '<svg class="' + (cls || "icon") + '" viewBox="0 0 24 24" fill="none" ' +
    'stroke="currentColor" stroke-width="1.5" stroke-linecap="round" ' +
    'stroke-linejoin="round" aria-hidden="true">' + paths + "</svg>"
  );
};
