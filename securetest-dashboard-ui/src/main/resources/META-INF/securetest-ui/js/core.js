/* SecureTest AI dashboard — core helpers, API client and shared components.
 * All DOM is built with createElement/textContent (never innerHTML with data) so scanner output cannot inject markup. */
'use strict';

const ST = window.ST = {
  base: location.pathname.replace(/\/(index\.html)?$/, ''),
  me: null,
  modules: [],
  timers: new Set(),
  T: {
    severity: { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' },
    sevHelp: {
      CRITICAL: 'Severe, credible risk with major impact. Triage immediately; releases may be blocked.',
      HIGH: 'Significant weakness with plausible exploitation. Fix urgently with an owner and due date.',
      MEDIUM: 'Moderate impact or limited exploitability. Plan the fix in a normal sprint.',
      LOW: 'Limited impact or quality improvement. Backlog and periodic cleanup.',
      INFO: 'Observation or hardening opportunity without demonstrated impact.'
    },
    mode: { PASSIVE: 'Passive', ACTIVE: 'Active', RESOURCE_INTENSIVE: 'Resource-intensive' },
    location: { EMBEDDED: 'Runs in this app (background thread)', EXTERNAL_TOOL: 'Runs an installed tool (separate process)', REMOTE_SERVICE: 'Calls a remote service' }
  }
};
ST.api = ST.base + '/api/v1';

/* ------------------------------------------------------------------ DOM */
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else if (k === 'style' && typeof v === 'object') Object.assign(n.style, v);
      else if (v === true) n.setAttribute(k, '');
      else n.setAttribute(k, v);
    }
  }
  append(n, children);
  return n;
}
function append(n, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
const svgNS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs, ...children) {
  const n = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) n.setAttribute(k, v);
  for (const c of children.flat()) if (c) n.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

/* ------------------------------------------------------------------ formatting */
const fmt = {
  date(v) {
    if (!v) return '—';
    const d = new Date(v);
    if (isNaN(d)) return String(v);
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  },
  ago(v) {
    if (!v) return 'never';
    const s = (Date.now() - new Date(v).getTime()) / 1000;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return Math.floor(s / 86400) + ' d ago';
  },
  dur(ms) {
    if (ms === null || ms === undefined) return '—';
    if (ms < 1000) return ms + ' ms';
    const s = Math.round(ms / 1000);
    return s < 60 ? s + ' s' : Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
  },
  uptime(sec) {
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return (d ? d + 'd ' : '') + h + 'h ' + m + 'm';
  },
  num(v, suffix = '') { return v === null || v === undefined ? '—' : (typeof v === 'number' ? v.toLocaleString() : v) + suffix; },
  tz() { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return ''; } }
};

/* ------------------------------------------------------------------ API */
async function api(method, path, body, opts = {}) {
  const headers = { 'Accept': 'application/json' };
  if (method !== 'GET') headers['X-SecureTest-Request'] = '1';
  if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
  if (opts.idempotencyKey) headers['Idempotency-Key'] = opts.idempotencyKey;
  const res = await fetch(ST.api + path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 204) return null;
  const type = res.headers.get('Content-Type') || '';
  const data = type.includes('json') ? await res.json().catch(() => null) : await res.text();
  if (res.status === 401 && ST.me && ST.me.authMethod === 'oidc') { location.href = ST.base + '/oidc/login'; }
  if (!res.ok) {
    const err = new Error((data && data.message) || (data && data.error) || ('HTTP ' + res.status));
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}
const GET = (p) => api('GET', p);
const POST = (p, b, o) => api('POST', p, b === undefined ? {} : b, o);
const PUT = (p, b) => api('PUT', p, b);
const PATCH = (p, b) => api('PATCH', p, b);
const DEL = (p) => api('DELETE', p);
function q(params) {
  const s = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(Array.isArray(v) ? v.join(',') : v)).join('&');
  return s ? '?' + s : '';
}
function can(p) { return !!(ST.me && ST.me.permissions && ST.me.permissions.includes(p)); }

/* ------------------------------------------------------------------ feedback */
function toast(msg, kind = 'info', ms = 4500) {
  const t = el('div', { class: 'toast ' + kind }, msg);
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => t.remove(), ms);
}
function showError(e) {
  const details = e && e.data && Array.isArray(e.data.details) ? e.data.details : [];
  const lines = details.map(d => typeof d === 'string' ? d : (d.name ? d.name + ': ' + d.message : JSON.stringify(d)));
  toast(el('div', null, el('b', null, e.message || 'Error'), lines.length ? el('ul', { style: { margin: '6px 0 0', paddingLeft: '18px' } }, lines.map(l => el('li', null, l))) : null), 'err', 9000);
}
async function guard(fn) { try { return await fn(); } catch (e) { showError(e); return undefined; } }

/* ------------------------------------------------------------------ small components */
function sevBadge(s, label) { return s ? el('span', { class: 'badge sev-' + s, title: ST.T.sevHelp[s] || '' }, label || ST.T.severity[s] || s) : el('span', { class: 'muted' }, '—'); }
function stBadge(s) { return el('span', { class: 'badge st-' + s }, String(s || '—').replace(/_/g, ' ').toLowerCase().replace(/^./, c => c.toUpperCase())); }
function modeBadge(m) { return el('span', { class: 'badge mode-' + m }, ST.T.mode[m] || m); }
function kv(pairs) { return el('dl', { class: 'kv' }, pairs.filter(p => p).map(([k, v]) => [el('dt', null, k), el('dd', null, v === null || v === undefined || v === '' ? '—' : v)])); }
function stat(label, value, sub) { return el('div', { class: 'card tight stat' }, el('span', { class: 'label' }, label), el('span', { class: 'value' }, value), sub ? el('span', { class: 'sub' }, sub) : null); }
function card(title, ...body) { return el('section', { class: 'card' }, title ? el('h2', null, title) : null, ...body); }
function empty(msg) { return el('div', { class: 'empty' }, msg); }
function sevbar(counts) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const colors = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
  const total = order.reduce((a, k) => a + (counts[k] || 0), 0);
  const bar = el('div', { class: 'sevbar', role: 'img', 'aria-label': order.map(k => (counts[k] || 0) + ' ' + k.toLowerCase()).join(', ') });
  if (total) order.forEach(k => { if (counts[k]) bar.appendChild(el('span', { style: { width: (100 * counts[k] / total) + '%', background: colors[k] } })); });
  return bar;
}
function switchBtn(checked, label, onChange, disabled) {
  const b = el('button', { class: 'switch', role: 'switch', 'aria-checked': String(!!checked), 'aria-label': label, disabled: disabled || null, title: label });
  b.addEventListener('click', async (ev) => {
    ev.stopPropagation();
    const next = b.getAttribute('aria-checked') !== 'true';
    b.disabled = true;
    const ok = await onChange(next);
    b.disabled = !!disabled;
    if (ok !== false) b.setAttribute('aria-checked', String(next));
  });
  return b;
}

/** Simple sortable data table. columns: [{label, key|render, num, sort}] */
function table(columns, rows, opts = {}) {
  let sortKey = null, asc = true;
  const wrap = el('div', { class: 'table-wrap' });
  const draw = () => {
    clear(wrap);
    let data = rows.slice();
    if (sortKey !== null) {
      const c = columns[sortKey];
      const val = c.sort || (r => r[c.key]);
      data.sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * (asc ? 1 : -1); });
    }
    const thead = el('thead', null, el('tr', null, columns.map((c, i) => el('th', { class: c.num ? 'num' : null, scope: 'col', 'aria-sort': sortKey === i ? (asc ? 'ascending' : 'descending') : null },
      (c.key || c.sort) ? el('button', { class: 'link-btn', style: { color: 'inherit', fontWeight: 600 }, onclick: () => { asc = sortKey === i ? !asc : true; sortKey = i; draw(); } }, c.label, sortKey === i ? (asc ? ' ▲' : ' ▼') : '') : c.label))));
    const tbody = el('tbody');
    if (!data.length) tbody.appendChild(el('tr', null, el('td', { colspan: columns.length, class: 'muted' }, opts.empty || 'No data')));
    data.forEach(r => {
      const tr = el('tr', { class: opts.onRow ? 'clickable' : null, tabindex: opts.onRow ? '0' : null });
      if (opts.onRow) {
        tr.addEventListener('click', () => opts.onRow(r));
        tr.addEventListener('keydown', e => { if (e.key === 'Enter') opts.onRow(r); });
      }
      columns.forEach(c => tr.appendChild(el('td', { class: (c.num ? 'num ' : '') + (c.cls || '') }, c.render ? c.render(r) : fmt.num(r[c.key]))));
      tbody.appendChild(tr);
    });
    wrap.appendChild(el('table', null, opts.caption ? el('caption', { class: 'sr-only' }, opts.caption) : null, thead, tbody));
  };
  draw();
  return wrap;
}

function tabs(items, onSelect) {
  const bar = el('div', { class: 'tabs', role: 'tablist' });
  const body = el('div', { style: { marginTop: '12px' } });
  const select = (i) => {
    [...bar.children].forEach((b, j) => b.setAttribute('aria-selected', String(i === j)));
    clear(body);
    append(body, [items[i].render()]);
    if (onSelect) onSelect(i);
  };
  items.forEach((it, i) => bar.appendChild(el('button', { role: 'tab', 'aria-selected': 'false', onclick: () => select(i) }, it.label)));
  setTimeout(() => select(0));
  return el('div', null, bar, body);
}

/* ------------------------------------------------------------------ modal */
function modal(title, bodyNodes, footerNodes, opts = {}) {
  const root = document.getElementById('modalRoot');
  const prev = document.activeElement;
  const id = 'm' + Math.random().toString(36).slice(2);
  const close = () => { backdrop.remove(); document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); if (opts.onClose) opts.onClose(); };
  const dialog = el('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': id, style: opts.width ? { width: opts.width } : null },
    el('header', null, el('h2', { id }, title), el('button', { class: 'icon-btn', 'aria-label': 'Close', onclick: close }, '✕')),
    el('div', { class: 'body' }, bodyNodes),
    footerNodes ? el('footer', null, footerNodes) : null);
  const backdrop = el('div', { class: 'modal-backdrop', onclick: (e) => { if (e.target === backdrop && !opts.sticky) close(); } }, dialog);
  const onKey = (e) => {
    if (e.key === 'Escape' && !opts.sticky) close();
    if (e.key === 'Tab') {
      const f = [...dialog.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter(x => !x.disabled && x.offsetParent !== null);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    }
  };
  document.addEventListener('keydown', onKey);
  root.appendChild(backdrop);
  const first = dialog.querySelector('input, select, textarea, button.primary') || dialog.querySelector('button');
  if (first) first.focus();
  return { close, dialog };
}
function confirmDialog(title, message, okLabel = 'Confirm', danger = false) {
  return new Promise(resolve => {
    let m;
    const ok = el('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), onclick: () => { m.close(); resolve(true); } }, okLabel);
    const cancel = el('button', { class: 'btn', onclick: () => { m.close(); resolve(false); } }, 'Cancel');
    m = modal(title, [el('p', null, message)], [cancel, ok], { onClose: () => resolve(false) });
  });
}

/* ------------------------------------------------------------------ charts (inline SVG) */
function lineChart(series, opts = {}) {
  const W = 640, H = opts.height || 180, P = { l: 40, r: 10, t: 10, b: 22 };
  const all = series.flatMap(s => s.values.map(v => v.y)).filter(v => v !== null && v !== undefined);
  const xs = series.flatMap(s => s.values.map(v => v.x));
  const maxY = opts.max || Math.max(1, ...all) * 1.1, minX = Math.min(...xs), maxX = Math.max(...xs);
  const sx = x => P.l + (maxX === minX ? 0 : (x - minX) / (maxX - minX) * (W - P.l - P.r));
  const sy = y => H - P.b - (y / maxY) * (H - P.t - P.b);
  const g = svg('g', { class: 'grid' });
  for (let i = 0; i <= 4; i++) {
    const y = P.t + i * (H - P.t - P.b) / 4;
    g.appendChild(svg('line', { x1: P.l, x2: W - P.r, y1: y, y2: y }));
    g.appendChild(svg('text', { x: P.l - 6, y: y + 3, 'text-anchor': 'end' }, String(Math.round(maxY * (1 - i / 4) * 10) / 10)));
  }
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': opts.label || 'chart' }, g);
  series.forEach(se => {
    const pts = se.values.filter(v => v.y !== null && v.y !== undefined).map(v => sx(v.x) + ',' + sy(v.y)).join(' ');
    if (pts) s.appendChild(svg('polyline', { points: pts, fill: 'none', stroke: se.color, 'stroke-width': 2, 'stroke-linejoin': 'round' }));
  });
  if (opts.xLabels) {
    s.appendChild(svg('text', { x: P.l, y: H - 6 }, opts.xLabels[0]));
    s.appendChild(svg('text', { x: W - P.r, y: H - 6, 'text-anchor': 'end' }, opts.xLabels[1]));
  }
  const legend = el('div', { class: 'legend' }, series.map(se => el('span', null, el('i', { style: { background: se.color } }), se.name)));
  return el('div', null, s, legend);
}
function barChart(items, opts = {}) {
  // HTML bars scale with the container while keeping readable text
  const max = Math.max(1, ...items.map(i => i.value));
  return el('div', { role: 'img', 'aria-label': opts.label || items.map(i => i.label + ' ' + i.value).join(', '), style: { display: 'grid', gap: '6px' } },
    items.map(it => el('div', { style: { display: 'grid', gridTemplateColumns: '90px 1fr', alignItems: 'center', gap: '8px', fontSize: '13px' } },
      el('span', { class: 'muted' }, it.label),
      el('div', { style: { display: 'flex', alignItems: 'center', gap: '6px' } },
        el('span', { style: { display: 'block', height: '14px', borderRadius: '3px', background: it.color || 'var(--accent)', width: (it.value ? Math.max(1.5, 85 * it.value / max) : 0) + '%' } }),
        el('b', null, String(it.value))))));
}
function sevChart(counts) {
  const colors = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };
  return barChart(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(k => ({ label: ST.T.severity[k], value: counts[k] || 0, color: colors[k] })), { label: 'Open findings by priority' });
}

/* ------------------------------------------------------------------ code & diff viewers */
function codeView(lines, opts = {}) {
  const box = el('div', { class: 'code', role: 'region', 'aria-label': opts.label || 'Source code', tabindex: '0' });
  (lines || []).forEach(l => {
    box.appendChild(el('div', { class: 'ln' + (l.highlighted ? ' hl sev-' + (opts.severity || 'MEDIUM') : '') },
      el('span', { class: 'no' }, l.number), el('span', { class: 'tx' }, l.text)));
    if (l.highlighted && opts.note && l.number === opts.noteLine) box.appendChild(el('div', { class: 'note' }, opts.note));
  });
  if (!lines || !lines.length) box.appendChild(el('div', { class: 'note' }, 'No code available.'));
  return box;
}
function diffView(diffText) {
  const box = el('div', { class: 'code diff', role: 'region', 'aria-label': 'Proposed change (diff)', tabindex: '0' });
  let oldNo = 0, newNo = 0;
  (diffText || '').split('\n').forEach(line => {
    if (line.startsWith('diff --git')) { box.appendChild(el('div', { class: 'file' }, line.replace(/^diff --git a\/(\S+).*$/, '$1'))); return; }
    if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('#')) return;
    if (line.startsWith('@@')) {
      const m = /@@ -(\d+),?\d* \+(\d+)/.exec(line);
      if (m) { oldNo = +m[1]; newNo = +m[2]; }
      box.appendChild(el('div', { class: 'ln hunk' }, el('span', { class: 'no' }, '…'), el('span', { class: 'tx' }, line)));
      return;
    }
    if (!line) return;
    const kind = line[0] === '+' ? 'add' : line[0] === '-' ? 'del' : '';
    const no = kind === 'add' ? newNo++ : kind === 'del' ? oldNo++ : (oldNo++, newNo++);
    box.appendChild(el('div', { class: 'ln ' + kind }, el('span', { class: 'no' }, (kind === 'add' ? '+' : kind === 'del' ? '−' : '') + no), el('span', { class: 'tx' }, line.slice(1))));
  });
  return box;
}
function download(path) {
  const a = el('a', { href: ST.api + path, download: '' });
  document.body.appendChild(a); a.click(); a.remove();
}
function linkBtn(label, onClick) { return el('button', { class: 'link-btn', onclick: onClick }, label); }
function go(hash) { location.hash = hash; }
function every(ms, fn) {
  const id = setInterval(() => { if (document.visibilityState === 'visible') fn(); }, ms);
  ST.timers.add(id);
  return id;
}
function stopTimers() { ST.timers.forEach(clearInterval); ST.timers.clear(); }
function moduleName(id) { const m = ST.modules.find(x => x.id === id); return m ? m.name : id; }
function savedViews() { try { return JSON.parse(localStorage.getItem('securetest.views') || '{}'); } catch (e) { return {}; } }
function saveViews(v) { try { localStorage.setItem('securetest.views', JSON.stringify(v)); } catch (e) { /* storage unavailable */ } }
