/* SecureTest AI dashboard — "All services" view for microservice systems.
 * Shown only when the backend detects a microservice architecture (service discovery, configured services, Spring Cloud
 * infrastructure); a monolith never sees it. Each service's own dashboard opens through /fleet/{key}/ on this service. */
'use strict';

ST.fleet = {
  /** True when this dashboard is another service's, opened through the "All services" view. */
  proxied() { return ST.base.indexOf('/fleet/') >= 0; },
  hubBase() { return ST.base.slice(0, ST.base.indexOf('/fleet/')); },
  serviceKey() { const rest = ST.base.slice(ST.base.indexOf('/fleet/') + 7); return decodeURIComponent(rest.split('/')[0]); },
  enabled() { return !!(ST.me && ST.me.architecture && ST.me.architecture.mode === 'microservices') && !ST.fleet.proxied(); },
  /** Banner for a service's dashboard opened through another service. */
  banner() {
    if (!ST.fleet.proxied()) return;
    document.getElementById('banner').appendChild(el('div', { class: 'alert info small', style: { marginBottom: '14px' } },
      el('a', { href: ST.fleet.hubBase() + '/#/fleet' }, '← All services'), ' · You are viewing ', el('b', null, ST.fleet.serviceKey()),
      ' through another service\'s dashboard. Changes you make here apply to ', el('b', null, ST.fleet.serviceKey()), '.'));
  }
};

const MODULE_SHORT = {
  health: 'Health', metrics: 'Metrics', testing: 'Tests', 'code-quality': 'Quality', vulnerability: 'Vulns', 'api-security': 'API sec',
  performance: 'Perf', compliance: 'Compliance', 'network-security': 'Network', 'advanced-security': 'Alerts', 'cloud-security': 'Cloud', migration: 'Migration'
};

function fleetModules(mods) {
  const on = (mods || []).filter(m => m.enabled);
  if (!on.length) return el('span', { class: 'muted small' }, 'none enabled');
  return el('span', { class: 'chips' }, on.map(m => {
    const open = m.open || {};
    const hot = (open.CRITICAL || 0) + (open.HIGH || 0);
    return el('span', { class: 'badge st-' + m.state, title: m.name + ': ' + String(m.state).replace(/_/g, ' ').toLowerCase()
      + (hot ? ' · ' + hot + ' high/critical open' : '') + (m.lastSuccess ? ' · last run ' + fmt.ago(m.lastSuccess) : '') },
      MODULE_SHORT[m.id] || m.name, hot ? ' ' + hot : '');
  }));
}

function fleetOpen(s) {
  if (s.self) { go('#/overview'); return; }
  const target = (s.instances || []).find(i => i.status === 'OK') || (s.instances || [])[0];
  if (target) location.href = ST.base + '/fleet/' + encodeURIComponent(target.key) + '/';
}

ST.pages.fleet = async (view) => {
  if (!ST.fleet.enabled()) {
    clear(view).appendChild(el('div', null, el('h1', null, 'All services'),
      empty('This application runs as a single service (monolith), so there is no combined view. It appears automatically when SecureTest '
        + 'finds other services through service discovery, or when you list them in securetest.fleet.members.')));
    return;
  }
  let client = '';
  const draw = async (refresh) => {
    const f = await guard(() => GET('/fleet' + (refresh ? '?refresh=true' : '')));
    if (!f) return;
    const clients = f.clients || [];
    const shown = (f.services || []).filter(s => !client || s.client === client);
    const t = f.totals || {};
    const problems = [];
    (f.services || []).forEach(s => (s.instances || []).forEach(i => { if (i.status !== 'OK') problems.push(i); }));
    clear(view);
    append(view, [
      el('div', { class: 'page-head' },
        el('div', { class: 'grow' }, el('h1', null, 'All services'),
          el('div', { class: 'muted' }, (f.sources && f.sources.length ? 'Found through ' + f.sources.join(', ') : f.architecture.reason)
            + ' · updated ' + fmt.ago(f.generatedAt) + ' · refreshes every 15 s')),
        el('div', { class: 'row' },
          el('button', { class: 'btn', onclick: async () => {
            const r = await guard(() => POST('/reports', { type: 'portfolio', includeClosed: false }));
            if (r) { toast('Portfolio report ' + r.id + ' is being generated', 'ok'); go('#/report/' + r.id); }
          } }, 'Portfolio report'),
          el('button', { class: 'btn', onclick: () => draw(true) }, '↻ Refresh'))),
      !f.architecture.fleetTokenConfigured ? el('div', { class: 'alert info small' },
        'Services on other machines or containers trust each other through a shared secret. Set the same ', el('code', null, 'SECURETEST_FLEET_TOKEN'),
        ' on every service (for example in your config server or .env). Services on this machine work without it.') : null,
      el('div', { class: 'grid gauto' },
        stat('Services', fmt.num(t.services), fmt.num(t.instances) + ' instances'),
        stat('Reporting', fmt.num(t.reporting) + ' / ' + fmt.num(t.instances), 'instances with SecureTest answering'),
        stat('Down', t.down ? el('span', { class: 'badge st-DOWN' }, t.down) : fmt.num(0), 'not UP or unreachable'),
        stat('Release gate failing', t.gateFailing ? el('span', { class: 'badge st-FAIL' }, t.gateFailing) : fmt.num(0), 'services'),
        stat('Open critical', t.openCritical ? sevBadge('CRITICAL', String(t.openCritical)) : fmt.num(0), 'across all services'),
        stat('Open high', t.openHigh ? sevBadge('HIGH', String(t.openHigh)) : fmt.num(0), 'across all services')),
      clients.length ? card('Clients',
        el('div', { class: 'chips', role: 'group', 'aria-label': 'Client filter', style: { marginBottom: '10px' } },
          el('button', { class: 'chip', 'aria-pressed': String(!client), onclick: () => { client = ''; draw(false); } }, 'All clients'),
          clients.map(c => el('button', { class: 'chip', 'aria-pressed': String(client === c.name), onclick: () => { client = c.name; draw(false); } }, c.name))),
        table([
          { label: 'Client', key: 'name', render: c => el('b', null, c.name) },
          { label: 'Services', num: true, key: 'services' },
          { label: 'Instances', num: true, key: 'instances' },
          { label: 'Down', num: true, sort: c => c.down, render: c => c.down ? el('span', { class: 'badge st-DOWN' }, c.down) : '0' },
          { label: 'Gate failing', num: true, sort: c => c.gateFailing, render: c => c.gateFailing ? el('span', { class: 'badge st-FAIL' }, c.gateFailing) : '0' },
          { label: 'Critical / High', num: true, sort: c => c.openCritical * 1000 + c.openHigh, render: c => el('span', null,
              c.openCritical ? sevBadge('CRITICAL', String(c.openCritical)) : '0', ' / ', c.openHigh ? sevBadge('HIGH', String(c.openHigh)) : '0') }
        ], clients, { onRow: c => { client = c.name; draw(false); }, caption: 'Clients' })) : null,
      card(client ? 'Services · ' + client : 'Services',
        table([
          clients.length ? { label: 'Client', sort: s => s.client || '', render: s => s.client || el('span', { class: 'muted' }, '—') } : null,
          { label: 'Service', sort: s => s.name, render: s => el('span', null, el('b', null, s.name),
              s.self ? el('span', { class: 'badge st-INFO', style: { marginLeft: '6px' } }, 'this service') : null,
              s.role === 'infra' ? el('span', { class: 'badge st-DISABLED', style: { marginLeft: '6px' }, title: s.roleDetail || '' }, 'infra') : null) },
          { label: 'Instances', num: true, sort: s => s.total, render: s => s.up + ' / ' + s.total },
          { label: 'Health', sort: s => s.health, render: s => stBadge(s.health) },
          { label: 'Req/s', num: true, sort: s => s.ratePerSecond, render: s => s.httpRecording ? fmt.num(s.ratePerSecond) : el('span', { class: 'muted', title: 'Turn on Runtime Metrics for this service to record requests' }, '—') },
          { label: 'p95', num: true, sort: s => s.p95Ms, render: s => s.httpRecording ? s.p95Ms + ' ms' : el('span', { class: 'muted' }, '—') },
          { label: 'Errors', num: true, sort: s => s.errorRatePercent, render: s => s.httpRecording ? s.errorRatePercent + '%' : el('span', { class: 'muted' }, '—') },
          { label: 'Release gate', sort: s => s.gate, render: s => s.gate ? stBadge(s.gate) : el('span', { class: 'muted' }, '—') },
          { label: 'Critical / High', num: true, sort: s => s.openCritical * 1000 + s.openHigh, render: s => el('span', null,
              s.openCritical ? sevBadge('CRITICAL', String(s.openCritical)) : '0', ' / ', s.openHigh ? sevBadge('HIGH', String(s.openHigh)) : '0') },
          { label: 'Modules', render: s => fleetModules(s.modules) },
          { label: '', render: s => el('button', { class: 'btn small', onclick: (e) => { e.stopPropagation(); fleetOpen(s); } }, 'Open') }
        ].filter(Boolean), shown, { onRow: fleetOpen, caption: 'Services', empty: 'No services found yet' })),
      problems.length ? card('Needs attention',
        table([
          { label: 'Service', key: 'service' },
          { label: 'Instance', render: i => i.url || i.instanceId },
          { label: 'Status', render: i => stBadge(i.status) },
          { label: 'What to do', render: i => i.message || '' }
        ], problems, { caption: 'Instances that did not report' })) : null
    ]);
  };
  await draw(false);
  every(15000, () => draw(false));
};
