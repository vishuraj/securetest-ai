/* SecureTest AI dashboard — external attack surface (asset register, discovery, certificates, monitoring). */
'use strict';

ST.pages['attack-surface'] = async (view) => {
  if (!ST.modules.find(m => m.id === 'attack-surface' && m.enabled)) {
    clear(view).appendChild(el('div', null, el('h1', null, 'Attack surface'), el('div', { class: 'alert info' },
      'Turn on the Attack Surface module to register your domains, discover their hosts and watch certificates and exposed services. ',
      linkBtn('Open the module →', () => go('#/module/attack-surface')))));
    return;
  }
  const data = await guard(() => GET('/attack-surface'));
  if (!data) return;
  const t = data.totals;
  const host = el('input', { type: 'text', placeholder: 'example.com or app.example.com', 'aria-label': 'Domain or host' });
  const kind = el('select', { 'aria-label': 'Kind' }, el('option', { value: 'DOMAIN' }, 'Domain + subdomains'), el('option', { value: 'HOST' }, 'This host only'));
  const owner = el('input', { type: 'text', placeholder: 'Owner (optional)', 'aria-label': 'Owner' });
  const days = (a) => a.certificateExpires ? Math.floor((new Date(a.certificateExpires) - Date.now()) / 86400000) : null;
  clear(view);
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Attack surface'),
      el('div', { class: 'muted' }, 'Registering a domain authorizes SecureTest to check it and its subdomains. Nothing is checked until you scan or schedule monitoring.')),
      el('div', { class: 'row' },
        el('button', { class: 'btn primary', disabled: !can('EXECUTE') || null, onclick: () => go('#/module/attack-surface') }, 'Scan now'),
        el('button', { class: 'btn', disabled: !can('CONFIGURE') || data.monitoring.length > 0 || null, onclick: async () => {
          const r = await guard(() => POST('/attack-surface/monitoring', {}));
          if (r) { toast('Daily monitoring scheduled (06:00)', 'ok'); ST.route(); }
        } }, data.monitoring.length ? 'Monitoring on (daily)' : 'Monitor daily'))),
    el('div', { class: 'grid gauto' },
      stat('Registered', fmt.num(t.registered), 'domains and hosts'), stat('Discovered', fmt.num(t.discovered), 'hosts under your domains'),
      stat('Live', fmt.num(t.live), 'resolve in DNS'), stat('Certificates expiring', t.expiringCertificates ? el('span', { class: 'badge st-WARN' }, t.expiringCertificates) : '0', 'within 30 days'),
      stat('Exposed tools', t.sensitive ? el('span', { class: 'badge st-FAIL' }, t.sensitive) : '0', 'admin / CI / monitoring hosts')),
    can('CONFIGURE') ? card('Register an asset', el('div', { class: 'filters' }, host, kind, owner, el('button', { class: 'btn', onclick: async () => {
      const r = await guard(() => POST('/attack-surface/assets', { host: host.value, kind: kind.value, owner: owner.value || null }));
      if (r) { toast('Registered ' + r.host, 'ok'); ST.route(); }
    } }, 'Register'))) : null,
    card('Assets', table([
      { label: 'Host', sort: a => a.host, render: a => el('div', null, el('b', { class: 'mono' }, a.host),
          el('div', { class: 'small muted' }, a.source === 'MANUAL' ? (a.kind === 'DOMAIN' ? 'registered domain' : 'registered host') + (a.owner ? ' · ' + a.owner : '') : 'found under ' + a.parent)) },
      { label: 'DNS', render: a => a.lastChecked ? (a.resolves ? el('span', { class: 'small mono', title: a.addresses.join(', ') }, a.addresses[0] + (a.addresses.length > 1 ? ' +' + (a.addresses.length - 1) : '')) : stBadge('DOWN')) : el('span', { class: 'muted' }, 'not checked') },
      { label: 'HTTPS / HTTP', render: a => a.lastChecked ? (a.httpsStatus || '—') + ' / ' + (a.httpStatus || '—') : '—' },
      { label: 'Certificate', sort: a => days(a) === null ? 99999 : days(a), render: a => days(a) === null ? '—'
          : el('span', { class: 'badge ' + (days(a) < 0 ? 'st-FAIL' : days(a) <= 30 ? 'st-WARN' : 'st-PASS'), title: a.certificateIssuer || '' }, days(a) < 0 ? 'expired' : days(a) + ' days') },
      { label: 'Server', render: a => a.server ? el('span', { class: 'small mono' }, a.server) : '—' },
      { label: 'Tags', render: a => el('span', null, (a.tags || []).map(x => el('span', { class: 'tag' }, x))) },
      { label: 'Last seen', sort: a => a.lastSeen || '', render: a => fmt.ago(a.lastSeen) },
      { label: '', render: a => a.source === 'MANUAL' && can('CONFIGURE') ? linkBtn('Remove', async () => {
          if (!(await confirmDialog('Remove asset', 'Stop checking ' + a.host + (a.kind === 'DOMAIN' ? ' and its discovered hosts' : '') + '?', 'Remove', true))) return;
          const r = await guard(() => DEL('/attack-surface/assets/' + encodeURIComponent(a.host)));
          if (r) ST.route();
        }) : null }
    ], data.assets, { empty: 'No assets yet. Register a domain above.' }))
  ]);
};

ST.panels['attack-surface'] = async (panel) => {
  append(panel, [el('div', { class: 'alert info' }, 'Register domains and see discovered hosts on the ', linkBtn('Attack surface page →', () => go('#/attack-surface')), '.')]);
};
