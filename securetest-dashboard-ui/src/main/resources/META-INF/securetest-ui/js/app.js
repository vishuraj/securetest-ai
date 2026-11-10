/* SecureTest AI dashboard — navigation, routing and bootstrap. */
'use strict';

const NAV = [
  { sep: 'Dashboard' },
  { hash: '#/fleet', label: 'All services', fleet: true },
  { hash: '#/overview', label: 'Overview' },
  { hash: '#/findings', label: 'Findings', count: true },
  { hash: '#/scans', label: 'Scans' },
  { sep: 'Modules' },
  ...['health', 'metrics', 'testing', 'code-quality', 'vulnerability', 'api-security', 'performance', 'compliance', 'network-security', 'advanced-security', 'cloud-security', 'migration', 'pentest', 'attack-surface', 'ai-security']
    .map(id => ({ module: id, hash: '#/module/' + id })),
  { sep: 'Governance' },
  { hash: '#/engagements', label: 'Pentest engagements' },
  { hash: '#/attack-surface', label: 'Attack surface' },
  { hash: '#/compliance', label: 'Compliance' },
  { hash: '#/migration', label: 'Migration workflow' },
  { hash: '#/reports', label: 'Reports' },
  { hash: '#/integrations', label: 'Integrations' },
  { hash: '#/settings', label: 'Settings' },
  { hash: '#/audit', label: 'Audit' },
  { hash: '#/help', label: 'Help & glossary' }
];

function renderNav() {
  const list = document.getElementById('navList');
  const current = location.hash.split('?')[0] || '#/overview';
  clear(list);
  NAV.forEach(item => {
    if (item.fleet && !ST.fleet.enabled()) return; // monolith: no combined view
    if (item.sep) { list.appendChild(el('li', { class: 'sep', 'aria-hidden': 'true' }, item.sep)); return; }
    const m = item.module ? ST.modules.find(x => x.id === item.module) : null;
    const label = m ? m.name : item.label;
    const open = m ? Object.entries(m.openFindings || {}).filter(([k]) => k === 'CRITICAL' || k === 'HIGH').reduce((a, [, v]) => a + v, 0) : 0;
    list.appendChild(el('li', null, el('a', { href: item.hash, 'aria-current': current === item.hash ? 'page' : null },
      m ? el('span', { class: 'dot' + (m.enabled ? ' on' : ''), title: m.enabled ? 'enabled' : 'disabled' }) : null, label,
      m && !m.enabled ? el('span', { class: 'sr-only' }, ' (disabled)') : null,
      open ? el('span', { class: 'count', title: open + ' high/critical open' }, open) : null)));
  });
}

function updateGatePill(gate) {
  const p = document.getElementById('gatePill');
  if (!gate) return;
  p.hidden = false;
  clear(p).appendChild(el('a', { href: '#/findings?priority=CRITICAL,HIGH', title: gate.reasons.join('; ') || 'No blocking findings' }, 'Release gate ', stBadge(gate.status)));
}

ST.route = async function route() {
  stopTimers();
  clear(document.getElementById('modalRoot')); // dialogs never outlive the page that opened them
  const [path, query] = (location.hash || '#/overview').slice(1).split('?');
  const params = Object.fromEntries(new URLSearchParams(query || ''));
  const parts = path.split('/').filter(Boolean);
  const page = parts[0] || 'overview';
  const id = parts[1] ? decodeURIComponent(parts[1]) : null;
  const view = document.getElementById('view');
  renderNav();
  document.getElementById('sidebar').classList.remove('open');
  const fn = ST.pages[page];
  if (!fn) { clear(view).appendChild(empty('Page not found')); return; }
  clear(view).appendChild(el('p', { class: 'muted' }, 'Loading…'));
  document.title = (page === 'module' ? moduleName(id) : page === 'fleet' ? 'All services' : page.charAt(0).toUpperCase() + page.slice(1)) + ' · SecureTest AI';
  try {
    await fn(view, id, params);
  } catch (e) {
    clear(view).appendChild(el('div', { class: 'alert err' }, 'Failed to load: ' + e.message));
  }
  document.getElementById('main').focus({ preventScroll: true });
};

function applyTheme(t) {
  if (t) document.documentElement.setAttribute('data-theme', t); else document.documentElement.removeAttribute('data-theme');
}

async function boot() {
  try { applyTheme(localStorage.getItem('securetest.theme')); } catch (e) { /* ignore */ }
  document.getElementById('themeToggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('securetest.theme', next); } catch (e) { /* ignore */ }
  });
  const toggle = document.getElementById('navToggle');
  toggle.addEventListener('click', () => {
    const sb = document.getElementById('sidebar');
    sb.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(sb.classList.contains('open')));
  });
  try {
    ST.me = await GET('/me');
  } catch (e) {
    clear(document.getElementById('view')).appendChild(el('div', { class: 'alert err' }, e.status === 401 ? 'Authentication required.' : e.status === 403 ? e.message : 'Cannot reach the SecureTest API: ' + e.message));
    return;
  }
  clear(document.getElementById('userBox')).append(
    el('span', { class: 'avatar', 'aria-hidden': 'true' }, ST.me.name.charAt(0).toUpperCase()),
    el('span', null, el('div', null, ST.me.name), el('div', { class: 'small muted' }, ST.me.roles.join(', ').toLowerCase())),
    ST.me.authMethod === 'oidc' ? el('a', { class: 'btn small', href: ST.base + '/oidc/logout' }, 'Sign out') : '');
  if (ST.me.authMethod === 'local-dev') {
    document.getElementById('banner').appendChild(el('div', { class: 'alert info small', style: { marginBottom: '14px' } },
      'Local development access: loopback clients act as administrator. Configure basic or container authentication before exposing the dashboard on a network.'));
  }
  ST.fleet.banner();
  if (ST.me.policy.productionLike) {
    document.getElementById('banner').appendChild(el('div', { class: 'alert warn small', style: { marginBottom: '14px' } }, 'Production-like profile: source changes are disabled and active scans need approval.'));
  }
  try {
    const o = await GET('/modules');
    ST.modules = o;
    const ov = await GET('/overview').catch(() => null);
    if (ov) {
      clear(document.getElementById('appIdentity')).append(ov.application.name + ' · ' + ov.application.environment + (ov.application.version && ov.application.version !== 'unknown' ? ' · v' + ov.application.version : ''));
      updateGatePill(ov.gate);
    }
  } catch (e) { /* view will report */ }
  window.addEventListener('hashchange', ST.route);
  if (!location.hash) location.hash = ST.fleet.enabled() ? '#/fleet' : '#/overview'; else ST.route();
}

boot();
