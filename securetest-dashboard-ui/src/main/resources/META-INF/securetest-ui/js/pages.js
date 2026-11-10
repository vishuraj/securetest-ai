/* SecureTest AI dashboard — overview, modules, scan configuration modal, scans, findings. */
'use strict';

/* ================================================================== scan configuration modal (SRS 6.2) */
async function openScanModal(desc) {
  const profiles = await guard(() => GET('/profiles' + q({ scanner: desc.id }))) || [];
  const inputs = {};
  const fieldNode = (f) => {
    let input;
    const id = 'f_' + f.key;
    const def = f.defaultValue === null || f.defaultValue === undefined ? '' : f.defaultValue;
    switch (f.type) {
      case 'BOOLEAN':
        input = el('input', { type: 'checkbox', id });
        input.checked = def === 'true';
        inputs[f.key] = input;
        return el('label', { class: 'check', for: id }, input, el('span', null, f.label, f.help ? el('div', { class: 'hint muted small' }, f.help) : null));
      case 'SELECT':
        input = el('select', { id }, (f.options || []).map(o => el('option', { value: o, selected: o === def ? true : null }, o)));
        break;
      case 'NUMBER':
        input = el('input', { type: 'number', id, value: def, min: f.min, max: f.max });
        break;
      case 'TEXTAREA':
        input = el('textarea', { id });
        input.value = def;
        break;
      case 'SECRET':
        input = el('input', { type: 'password', id, autocomplete: 'off', spellcheck: 'false', placeholder: 'env://NAME, prop://key, file:///run/secrets/x or value' });
        break;
      default:
        input = el('input', { type: 'text', id, value: def, spellcheck: 'false' });
    }
    if (f.required) input.setAttribute('aria-required', 'true');
    inputs[f.key] = input;
    return el('label', { class: 'field', for: id }, el('span', null, f.label, f.required ? el('span', { class: 'req', 'aria-hidden': 'true' }, ' *') : null),
      input, f.help ? el('span', { class: 'hint' }, f.help) : null);
  };
  const fields = desc.fields || [];
  const creds = fields.filter(f => f.section === 'credentials');
  const required = fields.filter(f => f.section === 'required');
  const optional = fields.filter(f => f.section === 'optional');
  const preflightBox = el('div', { 'aria-live': 'polite' });
  const confirmBox = el('input', { type: 'checkbox', id: 'confirmRun' });
  const profileSelect = el('select', { 'aria-label': 'Load saved profile' }, el('option', { value: '' }, '— none —'), profiles.map(p => el('option', { value: p.name }, p.name)));
  const profileName = el('input', { type: 'text', placeholder: 'Profile name (optional)', 'aria-label': 'Save as profile name' });
  profileSelect.addEventListener('change', () => {
    const p = profiles.find(x => x.name === profileSelect.value);
    if (!p) return;
    Object.entries(p.options).forEach(([k, v]) => { const i = inputs[k]; if (!i) return; if (i.type === 'checkbox') i.checked = v === 'true'; else i.value = v; });
    if (p.droppedSecrets && p.droppedSecrets.length) toast('Raw credentials are never saved in profiles: re-enter ' + p.droppedSecrets.join(', '), 'info');
  });
  const collect = () => {
    const o = {};
    Object.entries(inputs).forEach(([k, i]) => { o[k] = i.type === 'checkbox' ? String(i.checked) : i.value; });
    return o;
  };
  const renderChecks = (checks) => {
    clear(preflightBox);
    preflightBox.appendChild(el('ul', { style: { listStyle: 'none', padding: 0, margin: 0 } }, checks.map(c => el('li', { style: { padding: '2px 0' } },
      el('span', { class: 'badge st-' + (c.level === 'OK' ? 'ok' : c.level === 'WARN' ? 'WARN' : 'ERROR') }, c.level), ' ', el('b', null, c.name), ': ', c.message))));
  };
  const needsApproval = desc.mode === 'ACTIVE' && ST.me.policy.requireApprovalForActiveScans;
  const body = [
    el('section', null, el('p', { class: 'section-title' }, 'Purpose and impact'),
      el('p', { style: { margin: '0 0 8px' } }, desc.purpose),
      el('div', { class: 'row', style: { marginBottom: '8px' } }, modeBadge(desc.mode), el('span', { class: 'tag' }, ST.T.location[desc.location] || desc.location),
        el('span', { class: 'tag' }, desc.toolName + ' ' + desc.toolVersion)),
      kv([['Accesses', desc.accessDescription], ['Estimated duration', desc.estimatedDuration], ['Resource use', desc.resourceUse],
        desc.prerequisites.length ? ['Prerequisites', el('ul', { style: { margin: 0, paddingLeft: '18px' } }, desc.prerequisites.map(p => el('li', null, p)))] : null])),
    el('section', null, el('p', { class: 'section-title' }, 'Permissions'),
      desc.permissions.length ? el('ul', { style: { margin: 0, paddingLeft: '18px' } }, desc.permissions.map(p => el('li', null, p)))
        : el('p', { class: 'muted', style: { margin: 0 } }, 'No external account permissions needed.'),
      el('p', { class: 'small muted', style: { margin: '6px 0 0' } }, 'Least privilege: use read-only roles and scoped tokens. Your SecureTest roles: ' + ST.me.roles.join(', '))),
    creds.length ? el('section', null, el('p', { class: 'section-title' }, 'Credentials'),
      el('div', { class: 'alert info small' }, 'Prefer secret references (env://, prop://, file://, secret://). Values are masked, never echoed back, never stored in the browser, and raw values are kept in server memory for this run only.'),
      el('div', { class: 'form-grid', style: { marginTop: '8px' } }, creds.map(fieldNode))) : null,
    required.length ? el('section', null, el('p', { class: 'section-title' }, 'Required inputs'), el('div', { class: 'form-grid' }, required.map(fieldNode))) : null,
    optional.length ? el('details', null, el('summary', null, 'Optional properties (safe defaults)'), el('div', { class: 'form-grid', style: { marginTop: '10px' } }, optional.map(fieldNode))) : null,
    el('section', null, el('p', { class: 'section-title' }, 'Saved configuration'), el('div', { class: 'form-grid' },
      el('label', { class: 'field' }, 'Load profile', profileSelect), el('label', { class: 'field' }, 'Save as profile', profileName))),
    el('section', null, el('p', { class: 'section-title' }, 'Preflight'), preflightBox.childNodes.length ? preflightBox : el('div', null, preflightBox, el('p', { class: 'muted small', style: { margin: 0 } }, 'Checks connectivity, tool availability, authorization, target allowlist and limits.'))),
    desc.requiresConfirmation ? el('section', null, el('p', { class: 'section-title' }, 'Confirmation'),
      el('div', { class: 'alert warn' }, el('b', null, (ST.T.mode[desc.mode] || desc.mode) + ' operation. '),
        'Estimated duration: ' + desc.estimatedDuration + '. Resource use: ' + desc.resourceUse + '.',
        needsApproval ? el('div', null, can('APPROVE') ? 'You hold APPROVE permission: your confirmation is recorded as the approval.' : 'This scan will wait for approval by a user with APPROVE permission.') : null),
      el('label', { class: 'check', for: 'confirmRun', style: { marginTop: '8px' } }, confirmBox,
        el('span', null, 'I confirm I am authorized to run this operation against the configured target, the environment owner has approved it, and it is not a production system unless explicitly permitted.'))) : null
  ];
  let m;
  const runBtn = el('button', { class: 'btn primary', disabled: !can('EXECUTE') || null }, desc.requiresConfirmation ? 'Confirm and run' : 'Run');
  const pfBtn = el('button', { class: 'btn', onclick: async () => {
    pfBtn.disabled = true;
    const checks = await guard(() => POST('/scanners/' + desc.id + '/preflight', collect()));
    pfBtn.disabled = false;
    if (checks) renderChecks(checks);
  } }, 'Run preflight');
  runBtn.addEventListener('click', async () => {
    if (desc.requiresConfirmation && !confirmBox.checked) { toast('Please confirm authorization first.', 'err'); confirmBox.focus(); return; }
    runBtn.disabled = true;
    try {
      const res = await POST('/scans', { scannerId: desc.id, options: collect(), confirmed: confirmBox.checked,
        profileName: profileName.value || profileSelect.value || null, saveProfile: !!profileName.value }, { idempotencyKey: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) });
      m.close();
      toast(res.job.status === 'AWAITING_APPROVAL' ? 'Scan submitted and awaiting approval.' : 'Scan started: ' + res.job.id, 'ok');
      openScanDrawer(res.job.id);
    } catch (e) {
      if (e.data && Array.isArray(e.data.details) && e.data.details.length && e.data.details[0].level) renderChecks(e.data.details);
      showError(e);
    } finally { runBtn.disabled = false; }
  });
  m = modal('Configure: ' + desc.name, body, [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), pfBtn, runBtn]);
}

/* ================================================================== scan detail */
function renderResults(results) {
  const out = el('div', { class: 'stack' });
  Object.entries(results || {}).forEach(([key, val]) => {
    let body;
    if (Array.isArray(val) && val.length && typeof val[0] === 'object') {
      const cols = Object.keys(val[0]).slice(0, 8).map(k => ({ label: k, key: k, render: r => typeof r[k] === 'object' ? JSON.stringify(r[k]) : fmt.num(r[k]) }));
      body = table(cols, val.slice(0, 300));
    } else if (val && typeof val === 'object' && !Array.isArray(val)) {
      body = kv(Object.entries(val).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)]));
    } else {
      body = el('pre', null, typeof val === 'string' ? val : JSON.stringify(val, null, 2));
    }
    out.appendChild(el('details', { open: true }, el('summary', null, key), el('div', { style: { marginTop: '8px' } }, body)));
  });
  return out;
}

function openScanDrawer(id) {
  const body = el('div', { class: 'stack' }, el('p', { class: 'muted' }, 'Loading…'));
  const footer = el('div', { class: 'row' });
  let timer = null;
  const m = modal('Scan ' + id, [body], [footer], { width: 'min(980px, 100%)', onClose: () => clearInterval(timer) });
  const draw = async () => {
    const j = await guard(() => GET('/scans/' + id));
    if (!j) return;
    clear(body); clear(footer);
    const terminal = ['COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED'].includes(j.status);
    append(body, [
      el('div', { class: 'row' }, el('h3', { style: { margin: 0 } }, j.scannerName), stBadge(j.status), el('span', { class: 'muted small' }, j.toolVersion)),
      j.status === 'RUNNING' || j.status === 'QUEUED' ? el('div', null, el('div', { class: 'progress', role: 'progressbar', 'aria-valuenow': j.progress, 'aria-valuemin': 0, 'aria-valuemax': 100 },
        el('span', { style: { width: (j.progress || 0) + '%' } })), el('div', { class: 'small muted' }, (j.progressMessage || '') + ' (' + (j.progress || 0) + '%)')) : null,
      j.error ? el('div', { class: 'alert err' }, j.error) : null,
      j.status === 'AWAITING_APPROVAL' ? el('div', { class: 'alert warn' }, 'Waiting for approval by a user with APPROVE permission (requested by ' + j.requestedBy + ').') : null,
      el('div', { class: 'grid g2' },
        kv([['Module', moduleName(j.moduleId)], ['Requested by', j.requestedBy], ['Approved by', j.approvedBy], ['Profile', j.profileName],
          ['Execution', j.executionLocation], ['Created', fmt.date(j.createdAt)], ['Started', fmt.date(j.startedAt)], ['Ended', fmt.date(j.endedAt)]]),
        kv([['Duration', fmt.dur(j.durationMs)], ['Findings', String(j.findingsCount)], ['Correlation', j.correlationId],
          ...Object.entries(j.options || {}).map(([k, v]) => [k, v])])),
      j.findingsCount ? el('div', null, sevbar(j.severityCounts || {}), el('div', { style: { marginTop: '6px' } }, linkBtn('View findings from this scanner →', () => { m.close(); go('#/findings?source=' + j.scannerId); }))) : null,
      j.artifacts && j.artifacts.length ? el('div', null, el('p', { class: 'section-title' }, 'Evidence artifacts'),
        el('div', { class: 'row' }, j.artifacts.map(a => el('button', { class: 'btn small', onclick: () => download('/scans/' + j.id + '/artifacts/' + encodeURIComponent(a)) }, '⬇ ' + a)))) : null,
      Object.keys(j.results || {}).length ? el('div', null, el('p', { class: 'section-title' }, 'Results'), renderResults(j.results)) : null,
      el('details', null, el('summary', null, 'Execution log (' + (j.log || []).length + ' lines)'), el('pre', { style: { marginTop: '8px' } }, (j.log || []).join('\n')))
    ]);
    if (!terminal && can('EXECUTE')) footer.appendChild(el('button', { class: 'btn danger', onclick: async () => { await guard(() => POST('/scans/' + id + '/cancel')); draw(); } }, 'Cancel scan'));
    if (j.status === 'AWAITING_APPROVAL' && can('APPROVE')) {
      footer.appendChild(el('button', { class: 'btn', onclick: async () => { await guard(() => POST('/scans/' + id + '/reject', { reason: 'Rejected from dashboard' })); draw(); } }, 'Reject'));
      footer.appendChild(el('button', { class: 'btn primary', onclick: async () => { await guard(() => POST('/scans/' + id + '/approve')); draw(); } }, 'Approve'));
    }
    footer.appendChild(el('button', { class: 'btn', onclick: () => m.close() }, 'Close'));
    if (terminal) { clearInterval(timer); ST.timers.delete(timer); }
  };
  draw();
  timer = every(2000, draw);
}

function scansTable(items, opts = {}) {
  return table([
    { label: 'Scan', key: 'id', render: r => el('span', { class: 'mono small' }, r.id) },
    { label: 'Scanner', key: 'scannerName' },
    opts.hideModule ? null : { label: 'Module', key: 'moduleId', render: r => moduleName(r.moduleId) },
    { label: 'Status', key: 'status', render: r => stBadge(r.status) },
    { label: 'Requested', key: 'createdAt', render: r => el('span', { title: fmt.date(r.createdAt) }, fmt.ago(r.createdAt)) },
    { label: 'By', key: 'requestedBy' },
    { label: 'Duration', key: 'durationMs', num: true, render: r => fmt.dur(r.durationMs) },
    { label: 'Findings', key: 'findingsCount', num: true },
    { label: 'Tool', key: 'toolVersion', render: r => el('span', { class: 'small muted' }, r.toolVersion) }
  ].filter(Boolean), items, { onRow: r => openScanDrawer(r.id), empty: 'No scans yet' });
}

/* ================================================================== overview */
ST.pages = ST.pages || {};
ST.pages.overview = async (view) => {
  const draw = async () => {
    const o = await guard(() => GET('/overview'));
    if (!o) return;
    ST.modules = o.modules;
    renderNav();
    const a = o.application, rt = o.runtime, cpu = rt.cpu || {}, mem = rt.memory || {}, http = rt.http || {}, th = rt.threads || {}, gc = rt.gc || {};
    const health = (o.health && o.health.status) || 'UNKNOWN';
    clear(view);
    append(view, [
      el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Overview'),
        el('div', { class: 'muted' }, a.name + ' · ' + a.environment + ' · last scan ' + fmt.ago(o.lastScan) + ' · times in ' + fmt.tz())),
        el('button', { class: 'btn', onclick: draw }, '↻ Refresh')),
      o.compatibility.length ? el('div', { class: 'stack' }, o.compatibility.map(c => el('div', { class: 'alert ' + (c.level === 'ERROR' ? 'err' : c.level === 'WARN' ? 'warn' : 'info') }, el('b', null, c.name + ': '), c.detail))) : null,
      o.awaitingApproval && can('APPROVE') ? el('div', { class: 'alert warn' }, o.awaitingApproval + ' active scan(s) await your approval. ', linkBtn('Review scans', () => go('#/scans'))) : null,
      el('div', { class: 'grid gauto' },
        stat('Application health', stBadge(health), (o.health.components ? Object.keys(o.health.components).length + ' components' : o.health.source)),
        stat('Process CPU', fmt.num(cpu.processPercent, '%'), cpu.availableProcessors + ' cores · system ' + fmt.num(cpu.systemPercent, '%')),
        stat('Heap memory', fmt.num(mem.heapUsedMb, ' MB'), mem.heapMaxMb ? 'of ' + mem.heapMaxMb + ' MB (' + mem.heapPercent + '%)' : ''),
        stat('Non-heap memory', fmt.num(mem.nonHeapUsedMb, ' MB'), 'committed ' + fmt.num(mem.nonHeapCommittedMb, ' MB')),
        stat('Uptime', fmt.uptime(rt.uptimeSeconds), 'since ' + fmt.date(rt.startTime)),
        stat('Threads', fmt.num(th.live), 'peak ' + th.peak + ' · daemon ' + th.daemon + (th.deadlocked ? ' · ' + th.deadlocked + ' deadlocked!' : '')),
        stat('Garbage collection', fmt.num(gc.totalCount), fmt.num(gc.totalTimeMs, ' ms total')),
        stat('Requests', http.recording ? fmt.num(http.ratePerSecond, ' /s') : '—', http.recording ? 'errors ' + http.errorRatePercent + '% (1 min)' : 'enable Runtime Metrics to record'),
        stat('Latency p50 / p95 / p99', http.recording ? http.p50Ms + ' / ' + http.p95Ms + ' / ' + http.p99Ms + ' ms' : '—', http.recording ? 'max ' + http.maxMs + ' ms' : '')),
      el('div', { class: 'grid g2' },
        card('Application', kv([['Name', a.name], ['Service ID', a.serviceId], ['Version', a.version], ['Environment', a.environment + (a.activeProfiles.length ? ' (' + a.activeProfiles.join(', ') + ')' : '')],
          ['Host / runtime', a.host + ' · Java ' + a.javaVersion + ' (' + a.javaVendor + ')'], ['Spring', 'Boot ' + a.springBootVersion + ' · Framework ' + a.springFrameworkVersion],
          ['Build tool', a.buildTool], ['Source workspace', o.sourceRoot || el('span', { class: 'muted' }, 'not configured')], ['Last scan', fmt.date(o.lastScan)]])),
        card('Open findings by priority', sevChart(o.findings.open),
          el('div', { class: 'row between', style: { marginTop: '8px' } },
            el('span', null, 'Release gate: ', stBadge(o.gate.status), ' ', el('span', { class: 'small muted' }, o.gate.reasons.join('; '))),
            linkBtn('All findings →', () => go('#/findings'))))),
      el('h2', null, 'Modules'),
      el('div', { class: 'grid gauto' }, o.modules.map(moduleCard)),
      card('Recent scans', scansTable(o.recentScans)),
      (o.alerts.length || o.notifications.length) ? card('Alerts and notifications', el('ul', { class: 'timeline' },
        [...o.alerts.map(x => el('li', null, el('b', null, fmt.date(x.at) + ' '), x.message)),
          ...o.notifications.map(n => el('li', null, el('span', { class: 'muted' }, fmt.date(n.at) + ' · ' + n.event + ' — '), n.message))])) : null
    ]);
    updateGatePill(o.gate);
  };
  await draw();
  every(10000, draw);
};

function moduleCard(m) {
  const counts = m.openFindings || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const c = el('div', { class: 'card module-card', role: 'link', tabindex: '0', 'aria-label': m.name + ' module, ' + m.state.replace(/_/g, ' ').toLowerCase() },
    el('div', { class: 'top' }, el('span', { class: 'name' }, m.name), stBadge(m.state),
      switchBtn(m.enabled, (m.enabled ? 'Disable ' : 'Enable ') + m.name, (v) => toggleModule(m, v), !can('CONFIGURE') || m.locked)),
    el('div', { class: 'small muted' }, m.summary),
    sevbar(counts),
    el('div', { class: 'row between small muted' }, el('span', null, total + ' open'), el('span', null, m.lastRun ? 'last run ' + fmt.ago(m.lastRun.createdAt) : 'never run'),
      m.locked ? el('span', { title: 'Locked by policy' }, '🔒 policy') : null));
  c.addEventListener('click', () => go('#/module/' + m.id));
  c.addEventListener('keydown', e => { if (e.key === 'Enter') go('#/module/' + m.id); });
  return c;
}

async function toggleModule(m, enabled) {
  if (!enabled && !(await confirmDialog('Disable ' + m.name + '?', 'New scans and schedules for this module stop. Queued jobs are cancelled; running jobs follow the safe-cancel policy.', 'Disable', true))) return false;
  const r = await guard(() => PUT('/modules/' + m.id + '/configuration', { enabled }));
  if (!r) return false;
  const i = ST.modules.findIndex(x => x.id === m.id);
  if (i >= 0) ST.modules[i] = r;
  renderNav();
  toast(m.name + (enabled ? ' enabled' : ' disabled'), 'ok');
  return true;
}

/* ================================================================== module page */
ST.pages.module = async (view, id) => {
  const draw = async () => {
    const [mods, scanners, scans, findings] = await Promise.all([
      guard(() => GET('/modules')), guard(() => GET('/scanners' + q({ module: id }))),
      guard(() => GET('/scans' + q({ module: id, size: 15 }))), guard(() => GET('/findings' + q({ module: id, size: 25 })))]);
    if (!mods) return;
    ST.modules = mods;
    renderNav();
    const m = mods.find(x => x.id === id);
    if (!m) { clear(view).appendChild(empty('Unknown module')); return; }
    clear(view);
    append(view, [
      el('div', { class: 'page-head' },
        el('div', { class: 'grow' }, el('h1', null, m.name), el('div', { class: 'muted' }, m.summary)),
        el('div', { class: 'row' }, stBadge(m.state),
          el('label', { class: 'row small' }, m.enabled ? 'Enabled' : 'Disabled',
            switchBtn(m.enabled, (m.enabled ? 'Disable ' : 'Enable ') + m.name, async (v) => { const ok = await toggleModule(m, v); if (ok !== false) draw(); return ok; }, !can('CONFIGURE') || m.locked)),
          m.locked ? el('span', { class: 'tag', title: 'Set by policy and cannot be changed here' }, '🔒 ' + m.toggleSource) : el('span', { class: 'small muted' }, 'source: ' + m.toggleSource))),
      el('div', { class: 'alert info small' }, m.help),
      !m.enabled ? el('div', { class: 'alert warn' }, 'This module is disabled. Enable it to run its checks. Nothing in a disabled module initializes or runs.') : null,
      (scanners && scanners.length) ? el('div', null, el('h2', null, 'Checks and integrations'),
        el('div', { class: 'grid gauto' }, scanners.map(s => scannerCard(s, m.enabled)))) : null,
      el('div', { id: 'modulePanel' }),
      scans && scans.items.length ? card('Recent runs', scansTable(scans.items, { hideModule: true })) : null,
      card('Open findings (' + (findings ? findings.total : 0) + ')', findings ? findingsTable(findings.items) : null,
        findings && findings.total > findings.items.length ? el('div', { style: { marginTop: '8px' } }, linkBtn('See all ' + findings.total + ' →', () => go('#/findings?module=' + id))) : null)
    ]);
    const panel = view.querySelector('#modulePanel');
    if (ST.panels[id]) ST.panels[id](panel, m);
  };
  await draw();
};

function scannerCard(s, enabled) {
  const d = s.descriptor;
  const last = s.lastRun;
  return el('div', { class: 'card stack' },
    el('div', { class: 'row between' }, el('h3', { style: { margin: 0 } }, d.name), modeBadge(d.mode)),
    el('div', { class: 'small' }, d.purpose),
    el('div', { class: 'row small muted' }, el('span', { class: 'tag' }, d.toolName), el('span', null, d.estimatedDuration)),
    last ? el('div', { class: 'small' }, 'Last run: ', stBadge(last.status), ' ', fmt.ago(last.createdAt), ' · ', fmt.dur(last.durationMs),
      last.status === 'COMPLETED' ? ' · ' + last.findingsCount + ' findings' : '', ' ', linkBtn('details', () => openScanDrawer(last.id))) : el('div', { class: 'small muted' }, 'Never run'),
    el('div', null, el('button', { class: 'btn primary', disabled: !enabled || !can('EXECUTE') || null, title: !enabled ? 'Enable the module first' : null, onclick: () => openScanModal(d) }, 'Configure & run')));
}

/* ================================================================== module-specific panels */
ST.panels = {};
function latestResult(scans, key) {
  const j = (scans || []).find(x => x.status === 'COMPLETED' && x.results && x.results[key]);
  return j ? { job: j, value: j.results[key] } : null;
}

ST.panels.health = async (panel) => {
  const h = await guard(() => GET('/health'));
  if (!h) return;
  const comps = h.application.components || {};
  append(panel, [card('Health indicators', el('div', { class: 'row', style: { marginBottom: '10px' } }, 'Overall: ', stBadge(h.application.status), el('span', { class: 'muted small' }, h.application.source)),
    Object.keys(comps).length ? table([{ label: 'Component', key: 'k' }, { label: 'Status', key: 'v', render: r => stBadge(r.v) }], Object.entries(comps).map(([k, v]) => ({ k, v }))) : el('p', { class: 'muted' }, 'No component details (only status is exposed; details are never shown).'),
    el('h3', { style: { marginTop: '14px' } }, 'SecureTest self-health'),
    kv([['Status', stBadge(h.securetest.status)], ['Storage writable', String(h.securetest.storageWritable)], ['Active jobs', String(h.securetest.activeJobs)],
      ['Scanners registered', String(h.securetest.scanners)], ['Control plane', h.securetest.controlPlane.enabled ? JSON.stringify(h.securetest.controlPlane) : 'not used (embedded mode)']]))]);
};

ST.panels.metrics = async (panel, m) => {
  const draw = async () => {
    const x = await guard(() => GET('/metrics?history=true'));
    if (!x) return;
    clear(panel);
    const hist = x.history || [];
    const pts = (k) => hist.map((p, i) => ({ x: i, y: p[k] }));
    const range = hist.length ? [fmt.date(hist[0].t), fmt.date(hist[hist.length - 1].t)] : null;
    append(panel, [
      !x.samplingEnabled ? el('div', { class: 'alert warn' }, 'Sampling is off. Enable this module to record history and HTTP timings (low-frequency, configurable interval).') : null,
      el('div', { class: 'grid g2' },
        card('CPU (%)', hist.length ? lineChart([{ name: 'process', color: 'var(--accent)', values: pts('processCpu') }, { name: 'system', color: 'var(--med)', values: pts('systemCpu') }], { max: 100, xLabels: range }) : empty('No history yet')),
        card('Heap (MB)', hist.length ? lineChart([{ name: 'heap used', color: 'var(--low)', values: pts('heapUsedMb') }, { name: 'non-heap', color: 'var(--info)', values: pts('nonHeapUsedMb') }], { xLabels: range }) : empty('No history yet')),
        card('HTTP throughput (req/s) and p95 (ms)', hist.length ? lineChart([{ name: 'req/s', color: 'var(--ok)', values: pts('rps') }, { name: 'p95 ms', color: 'var(--high)', values: pts('p95') }], { xLabels: range }) : empty('No history yet')),
        card('Threads', hist.length ? lineChart([{ name: 'live threads', color: 'var(--accent)', values: pts('threads') }], { xLabels: range }) : empty('No history yet'))),
      el('div', { class: 'grid g2' },
        card('Memory pools', table([{ label: 'Pool', key: 'name' }, { label: 'Type', key: 'type' }, { label: 'Used MB', key: 'usedMb', num: true }, { label: 'Max MB', key: 'maxMb', num: true }], x.memory.pools || [])),
        card('Garbage collectors', table([{ label: 'Collector', key: 'name' }, { label: 'Count', key: 'count', num: true }, { label: 'Time ms', key: 'timeMs', num: true }], x.gc.collectors || []),
          kv([['Classes loaded', String(x.classes.loaded)], ['File descriptors', x.cpu.openFileDescriptors !== undefined ? x.cpu.openFileDescriptors + ' / ' + x.cpu.maxFileDescriptors : 'n/a on this OS'],
            ['Load average', fmt.num(x.cpu.systemLoadAverage)], ['Micrometer http.server.requests', x.http.micrometer ? JSON.stringify(x.http.micrometer) : 'n/a']]))),
      x.customMeters && x.customMeters.length ? card('Custom Micrometer meters', table([{ label: 'Name', key: 'name' }, { label: 'Type', key: 'type' },
        { label: 'Tags', key: 'tags', render: r => r.tags.join(', ') }, { label: 'Values', key: 'values', render: r => JSON.stringify(r.values) }], x.customMeters)) : null,
      x.alerts.length ? card('Threshold alerts', el('ul', { class: 'timeline' }, x.alerts.map(a => el('li', null, fmt.date(a.at) + ' — ' + a.message)))) : null,
      el('div', { class: 'row' }, el('button', { class: 'btn', disabled: !x.samplingEnabled || null, onclick: async () => {
        const txt = await guard(() => GET('/metrics/prometheus'));
        if (txt) modal('Prometheus exposition', [el('pre', null, txt)]);
      } }, 'View Prometheus text'))
    ]);
  };
  await draw();
  every(15000, draw);
};

ST.panels['code-quality'] = async (panel) => {
  const scans = (await guard(() => GET('/scans?module=code-quality&size=50'))) || { items: [] };
  const metrics = latestResult(scans.items, 'metrics');
  const sonar = latestResult(scans.items, 'sonarMeasures');
  if (!metrics && !sonar) return;
  append(panel, [el('div', { class: 'grid g2' },
    metrics ? card('Built-in metrics', kv(Object.entries(metrics.value).map(([k, v]) => [k, String(v)])), el('div', { class: 'small muted' }, 'From scan ' + metrics.job.id + ' · ' + fmt.date(metrics.job.endedAt))) : null,
    sonar ? card('SonarQube measures', kv(Object.entries(sonar.value).map(([k, v]) => [k, k === 'qualityGate' ? stBadge(v === 'OK' ? 'PASS' : v === 'ERROR' ? 'FAIL' : v) : String(v)]))) : null)]);
};

ST.panels.vulnerability = async (panel) => {
  const scans = (await guard(() => GET('/scans?module=vulnerability&size=50'))) || { items: [] };
  const inv = latestResult(scans.items, 'inventory');
  if (!inv) return;
  append(panel, [card('Dependency inventory (' + inv.value.length + ' components)',
    el('div', { class: 'row', style: { marginBottom: '8px' } }, el('button', { class: 'btn', onclick: () => download('/sbom') }, '⬇ CycloneDX SBOM'),
      el('span', { class: 'small muted' }, 'From scan ' + inv.job.id + ' · ' + fmt.date(inv.job.endedAt))),
    table([{ label: 'Component', key: 'name' }, { label: 'Version', key: 'version' }, { label: 'License', key: 'license' }, { label: 'Package URL', key: 'purl', render: r => el('span', { class: 'mono small' }, r.purl) }], inv.value))]);
};

ST.panels.performance = async (panel) => {
  const scans = (await guard(() => GET('/scans?module=performance&size=50'))) || { items: [] };
  const runs = scans.items.filter(x => x.status === 'COMPLETED' && x.results && x.results.loadSummary);
  const jm = latestResult(scans.items, 'jmeterSummary');
  if (!runs.length && !jm) return;
  const nodes = [];
  if (runs.length) {
    const cur = runs[0].results.loadSummary, prev = runs.find((r, i) => i > 0 && r.results.loadSummary.target === cur.target);
    const delta = (k) => prev ? (() => { const d = cur[k] - prev.results.loadSummary[k]; return (d > 0 ? '+' : '') + Math.round(d * 10) / 10; })() : '';
    const tl = runs[0].results.loadTimeline || [];
    nodes.push(card('Latest load test — ' + cur.target,
      el('div', { class: 'row', style: { marginBottom: '10px' } }, 'Gate: ', stBadge(cur.gate), el('span', { class: 'small muted' }, 'thresholds p95 ≤ ' + cur.thresholds.p95Ms + ' ms, errors ≤ ' + cur.thresholds.maxErrorRatePct + '%')),
      el('div', { class: 'grid gauto' }, ['requests', 'throughputRps', 'p50Ms', 'p95Ms', 'p99Ms', 'errorRatePct'].map(k =>
        stat(k, fmt.num(cur[k]), prev ? 'vs baseline ' + delta(k) : 'no baseline yet'))),
      tl.length ? lineChart([{ name: 'req/s', color: 'var(--ok)', values: tl.map(p => ({ x: p.t, y: p.rps })) }, { name: 'p95 ms', color: 'var(--high)', values: tl.map(p => ({ x: p.t, y: p.p95 })) },
        { name: 'process CPU %', color: 'var(--accent)', values: tl.map(p => ({ x: p.t, y: p.cpu })) }], { xLabels: ['0 s', tl[tl.length - 1].t + ' s'], label: 'Load timeline' }) : null,
      prev ? el('div', { class: 'small muted' }, 'Baseline: scan ' + prev.id + ' (' + fmt.date(prev.endedAt) + ')') : null));
  }
  if (jm) nodes.push(card('JMeter samplers', table(Object.keys(jm.value.samplers[0] || {}).map(k => ({ label: k, key: k, num: k !== 'label' })), jm.value.samplers)));
  append(panel, nodes);
};

ST.panels['network-security'] = async (panel) => {
  const scans = (await guard(() => GET('/scans?module=network-security&size=50'))) || { items: [] };
  const tls = latestResult(scans.items, 'tlsHosts');
  const ports = latestResult(scans.items, 'openPorts');
  if (!tls && !ports) return;
  append(panel, [el('div', { class: 'grid g2' },
    tls ? card('TLS endpoints', table([{ label: 'Host', key: 'host' }, { label: 'Protocol', key: 'protocol' }, { label: 'Trusted', key: 'trusted', render: r => String(r.trusted) },
      { label: 'Expires in (d)', key: 'daysToExpiry', num: true }, { label: 'Cipher', key: 'cipher', render: r => el('span', { class: 'small mono' }, r.cipher || r.error || '') }], tls.value)) : null,
    ports ? card('Open ports (' + ports.job.options.host + ')', ports.value.length ? el('div', { class: 'chips' }, ports.value.map(p => el('span', { class: 'tag' }, p))) : empty('No open ports in the checked list')) : null)]);
};

ST.panels['advanced-security'] = async (panel) => {
  const [scans, integ] = await Promise.all([guard(() => GET('/scans?module=advanced-security&size=20')), guard(() => GET('/integrations'))]);
  const h = scans ? latestResult(scans.items, 'sensorHealth') : null;
  append(panel, [el('div', { class: 'grid g2' },
    h ? card('Sensor health', kv([['Events read', String(h.value.eventsRead)], ['Imported', String(h.value.imported)], ['Last event', fmt.date(h.value.lastEvent)]]),
      el('h3', { style: { marginTop: '10px' } }, 'By rule'), table([{ label: 'Rule', key: 'k' }, { label: 'Events', key: 'v', num: true }], Object.entries(h.value.byRule || {}).map(([k, v]) => ({ k, v })))) : null,
    integ ? card('Live event ingestion', integ.eventIngestion.enabled
      ? kv([['Endpoint', 'POST ' + integ.eventIngestion.path], ['Auth header', integ.eventIngestion.header], ['Formats', integ.eventIngestion.formats.join(', ')]])
      : el('p', { class: 'muted' }, 'Disabled. Set securetest.security.ingest-token-ref (e.g. env://SECURETEST_INGEST_TOKEN) to accept Falco/Wazuh/SIEM webhooks.'),
      el('p', { class: 'small muted' }, 'SecureTest correlates and explains alerts; it does not block attacks itself. Response automation is not performed.')) : null)]);
};

ST.panels.compliance = async (panel) => {
  append(panel, [el('div', { class: 'alert info' }, 'Framework mappings and evidence are on the ', linkBtn('Compliance page →', () => go('#/compliance')))]);
};
ST.panels.migration = async (panel) => {
  append(panel, [el('div', { class: 'alert info' }, 'Use the guided ', linkBtn('migration workflow →', () => go('#/migration')), ' (discover, assess, plan, preview, apply, validate, commit/undo).')]);
};

/* ================================================================== findings */
function findingsTable(items, opts = {}) {
  return table([
    { label: 'Priority', key: 'priority', sort: r => -(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(r.priority)), render: r => sevBadge(r.priority) },
    { label: 'Finding', key: 'title', render: r => el('div', null, el('div', null, r.title, r.regression ? el('span', { class: 'badge st-FAIL', style: { marginLeft: '6px' } }, 'regression') : null,
        r.verification ? el('span', { style: { marginLeft: '6px' } }, verificationBadge(r.verification)) : null),
      el('div', { class: 'small muted' }, r.id + ' · ' + (r.ruleId || '') + ' · ' + r.source)) },
    opts.hideModule ? null : { label: 'Module', key: 'moduleId', render: r => moduleName(r.moduleId) },
    { label: 'Location', key: 'filePath', render: r => el('span', { class: 'small mono truncate', title: r.filePath || r.asset || '' }, r.filePath ? r.filePath + ':' + r.lineStart : (r.asset || '—')) },
    { label: 'Source sev.', key: 'sourceSeverity', render: r => sevBadge(r.sourceSeverity) },
    { label: 'Status', key: 'status', render: r => stBadge(r.status) },
    { label: 'Last seen', key: 'lastDetected', render: r => el('span', { title: fmt.date(r.lastDetected) }, fmt.ago(r.lastDetected)) }
  ].filter(Boolean), items, { onRow: r => go('#/finding/' + r.id), empty: 'No findings — run a scan to populate this list.' });
}

ST.pages.findings = async (view, _id, params) => {
  const state = Object.assign({ q: '', priority: '', status: '', module: '', source: '', sort: '', includeClosed: '', page: '0' }, params);
  const result = await guard(() => GET('/findings' + q({ ...state, size: 50 })));
  if (!result) return;
  const update = (patch) => { const s = Object.assign({}, state, patch, patch.page === undefined ? { page: '0' } : {}); go('#/findings' + q(s)); };
  const search = el('input', { type: 'search', value: state.q, placeholder: 'Search title, rule, file, package, CVE…', 'aria-label': 'Search findings', style: { minWidth: '260px' } });
  search.addEventListener('keydown', e => { if (e.key === 'Enter') update({ q: search.value }); });
  const pr = state.priority ? state.priority.split(',') : [];
  const prChips = el('div', { class: 'chips', role: 'group', 'aria-label': 'Priority filter' }, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s =>
    el('button', { class: 'chip', 'aria-pressed': String(pr.includes(s)), onclick: () => update({ priority: (pr.includes(s) ? pr.filter(x => x !== s) : [...pr, s]).join(',') }) }, ST.T.severity[s])));
  const sel = (label, key, options) => el('label', { class: 'field' }, label, el('select', { onchange: (e) => update({ [key]: e.target.value }) },
    options.map(([v, t]) => el('option', { value: v, selected: state[key] === v ? true : null }, t))));
  const views = savedViews();
  const viewSel = el('select', { 'aria-label': 'Saved views', onchange: (e) => { if (e.target.value) go('#/findings' + views[e.target.value]); } },
    el('option', { value: '' }, 'Saved views…'), Object.keys(views).map(k => el('option', { value: k }, k)));
  const pages = Math.ceil(result.total / result.size);
  clear(view);
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Findings'), el('div', { class: 'muted' }, result.total + ' matching · priority is SecureTest\'s normalized urgency; source severity is preserved separately.')),
      el('div', { class: 'row' }, canContribute() ? el('button', { class: 'btn primary', onclick: () => reportFindingDialog() }, '+ Report finding') : null,
        viewSel, el('button', { class: 'btn', onclick: () => {
        const name = prompt('Name for this view');
        if (name) { views[name] = q(state); saveViews(views); toast('View saved', 'ok'); }
      } }, 'Save view'))),
    el('div', { class: 'card stack' },
      el('div', { class: 'filters' }, search, el('button', { class: 'btn', onclick: () => update({ q: search.value }) }, 'Search')),
      prChips,
      el('div', { class: 'filters' },
        sel('Status', 'status', [['', 'Open (default)'], ['OPEN', 'Open'], ['IN_PROGRESS', 'In progress'], ['SUPPRESSED', 'Suppressed'], ['ACCEPTED_RISK', 'Accepted risk'], ['FALSE_POSITIVE', 'False positive'], ['FIXED', 'Fixed']]),
        sel('Module', 'module', [['', 'All modules'], ...ST.modules.map(m => [m.id, m.name])]),
        sel('Sort', 'sort', [['', 'Priority'], ['newest', 'Newest'], ['oldest', 'Oldest'], ['module', 'Module'], ['file', 'File'], ['sourceSeverity', 'Source severity']]),
        el('label', { class: 'check' }, el('input', { type: 'checkbox', checked: state.includeClosed === 'true' ? true : null, onchange: (e) => update({ includeClosed: e.target.checked ? 'true' : '' }) }), 'Include closed'),
        state.source ? el('span', { class: 'tag' }, 'source: ' + state.source, ' ', linkBtn('✕', () => update({ source: '' }))) : null)),
    findingsTable(result.items),
    pages > 1 ? el('div', { class: 'row' }, el('button', { class: 'btn', disabled: result.page === 0 || null, onclick: () => update({ page: String(result.page - 1) }) }, '← Prev'),
      el('span', null, 'Page ' + (result.page + 1) + ' of ' + pages), el('button', { class: 'btn', disabled: result.page + 1 >= pages || null, onclick: () => update({ page: String(result.page + 1) }) }, 'Next →')) : null
  ]);
};

ST.pages.finding = async (view, id) => {
  const f = await guard(() => GET('/findings/' + id));
  if (!f) return;
  const [src, sets] = await Promise.all([guard(() => GET('/findings/' + id + '/source')), guard(() => GET('/remediations?kind=REMEDIATION'))]);
  const mine = (sets || []).filter(c => c.reference === f.id);
  const remBox = el('div', { class: 'stack' });
  const drawRem = (cs) => { clear(remBox); if (cs) remBox.appendChild(changeSetPanel(cs, () => ST.route())); };
  if (mine.length) drawRem(mine[0]);
  const dep = f.dependency;
  clear(view);
  append(view, [
    el('div', null, linkBtn('← Findings', () => history.length > 1 ? history.back() : go('#/findings'))),
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, f.title),
      el('div', { class: 'row' }, sevBadge(f.priority), el('span', { class: 'small muted' }, 'priority'), sevBadge(f.sourceSeverity, (f.sourceSeverityRaw || f.sourceSeverity)),
        el('span', { class: 'small muted' }, 'source severity'), stBadge(f.status), el('span', { class: 'tag' }, 'confidence ' + f.confidence.toLowerCase()),
        f.regression ? el('span', { class: 'badge st-FAIL' }, 'regression') : null, verificationBadge(f.verification), el('span', { class: 'mono small muted' }, f.id)))),
    el('div', { class: 'grid g2' },
      card('Details', kv([['Module', moduleName(f.moduleId)], ['Scanner / source', f.source + (f.sourceToolVersion ? ' (' + f.sourceToolVersion + ')' : '')], ['Rule', f.ruleId],
        ['Category', f.category], ['Asset', f.asset], ['Location', f.filePath ? f.filePath + ':' + f.lineStart + (f.lineEnd && f.lineEnd !== f.lineStart ? '-' + f.lineEnd : '') : null],
        ['Revision at scan', f.revision], ['First detected', fmt.date(f.firstDetected)], ['Last detected', fmt.date(f.lastDetected)], ['Occurrences', String(f.occurrences)],
        ['Also reported by', f.attributes.alsoReportedBy], ['Compliance', f.complianceTags.length ? el('span', null, f.complianceTags.map(t => el('span', { class: 'tag' }, t))) : null]])),
      card('Why this priority?', el('ol', { style: { margin: 0, paddingLeft: '18px' } }, (f.priorityRationale || []).map(r => el('li', null, r))),
        el('p', { class: 'small muted' }, ST.T.sevHelp[f.priority] || ''))),
    card('Description', el('p', { style: { whiteSpace: 'pre-wrap', margin: 0 } }, f.description || '—'), f.impact ? el('p', null, el('b', null, 'Impact: '), f.impact) : null),
    dep ? card('Dependency', kv([['Package', dep.packageName], ['Installed', dep.installedVersion], ['Fixed version', dep.fixedVersion || 'none published'],
      ['Advisory', [dep.advisoryId, ...(dep.aliases || [])].filter((v, i, a) => v && a.indexOf(v) === i).join(', ')], ['CVSS', dep.cvssScore ? dep.cvssScore + (dep.cvssVector ? ' (' + dep.cvssVector + ')' : '') : null],
      ['License', dep.license], ['Dependency path', (dep.dependencyPath || []).join(' → ')]])) : null,
    sourceCard(f, src),
    f.evidence ? card('Evidence (sanitized)', el('pre', null, f.evidence)) : null,
    f.attributes.screenshot && f.lastScanId ? card('Screenshot at failure', el('img', { src: ST.api + '/scans/' + encodeURIComponent(f.lastScanId) + '/artifacts/' + encodeURIComponent(f.attributes.screenshot),
      alt: 'Screenshot captured when the browser test failed', style: { maxWidth: '100%', border: '1px solid var(--border)', borderRadius: '8px' } })) : null,
    card('Recommended fix', el('p', { style: { whiteSpace: 'pre-wrap' } }, f.remediation || '—'),
      f.references.length ? el('ul', null, f.references.map(r => el('li', null, el('a', { href: r, target: '_blank', rel: 'noopener noreferrer' }, r)))) : null,
      el('div', { class: 'row' }, el('button', { class: 'btn primary', disabled: !can('REMEDIATE') || null, onclick: async () => {
        const r = await guard(() => POST('/remediations/preview', { findingId: f.id }));
        if (!r) return;
        if (!r.automated) { clear(remBox).appendChild(el('div', { class: 'alert info' }, r.reason)); return; }
        drawRem(r.changeSet);
        toast('Fix preview created: ' + r.changeSet.id, 'ok');
      } }, mine.length ? 'Regenerate fix preview' : 'Generate fix preview'),
        ST.me.policy.aiEnabled && f.filePath ? el('button', { class: 'btn', disabled: !can('REMEDIATE') || null, onclick: async () => {
          const ok = await confirmDialog('Ask AI for a fix', 'A redacted window of ' + f.filePath + ' (the flagged lines plus surrounding context, secrets removed) and the finding text will be sent to '
            + ST.me.policy.aiModel + '. The result is an untrusted suggestion: it is validated, shown as a diff, and an approver must apply it.', 'Send to AI');
          if (!ok) return;
          const r = await guard(() => POST('/remediations/ai-preview', { findingId: f.id }));
          if (!r) return;
          if (!r.automated) { clear(remBox).appendChild(el('div', { class: 'alert ' + (r.status === 'NO_CHANGE' ? 'info' : 'warn') }, el('b', null, r.status.replace('_', ' ').toLowerCase() + ': '), r.message)); return; }
          drawRem(r.changeSet);
          toast('AI fix preview created: ' + r.changeSet.id + ' (' + r.provenance.inputTokens + '/' + r.provenance.outputTokens + ' tokens)', 'ok');
        } }, '✦ Ask AI for a fix') : null,
        el('span', { class: 'small muted' }, ST.me.policy.aiEnabled ? 'Rules are deterministic; AI is opt-in per request. Nothing changes until you apply.' : 'Deterministic rules only (no AI); nothing changes until you apply.')),
      remBox),
    collabCards(f),
    workflowCard(f),
    card('History', el('ul', { class: 'timeline' }, (f.history || []).slice().reverse().map(h => el('li', null, el('b', null, fmt.date(h.at)), ' · ', h.actor, ' · ', h.action, ' — ', h.detail))))
  ]);
};

function sourceCard(f, src) {
  if (!src || (!src.available && !(f.snippet && f.snippet.length))) return f.filePath ? card('Code', el('p', { class: 'muted' }, src ? src.reason : 'Unavailable')) : null;
  const note = f.title;
  const showSnapshot = () => codeView(f.snippet, { severity: f.priority, note, noteLine: f.lineStart, label: 'Scan-time snippet' });
  const showCurrent = () => codeView(src.lines, { severity: f.priority, note, noteLine: f.lineStart, label: 'Current file' });
  const items = [];
  if (src.available && !src.stale) items.push({ label: 'Code (matches scanned revision)', render: showCurrent });
  if (f.snippet && f.snippet.length) items.push({ label: 'Scan-time snapshot', render: showSnapshot });
  if (src.available && src.stale) items.push({ label: 'Current file (changed since scan)', render: showCurrent });
  return card('Code — ' + f.filePath,
    src.stale ? el('div', { class: 'alert warn', style: { marginBottom: '8px' } }, src.warning) : null,
    el('div', { class: 'row small muted', style: { marginBottom: '6px' } }, 'Scanned revision: ', el('span', { class: 'mono' }, String(f.revision)),
      src.currentRevision ? ['· current: ', el('span', { class: 'mono' }, src.currentRevision)] : null,
      src.ideLink ? el('a', { href: src.ideLink }, 'Open in IDE') : null, src.repositoryLink ? el('a', { href: src.repositoryLink, target: '_blank', rel: 'noopener noreferrer' }, 'Open in repository') : null),
    tabs(items));
}

function workflowCard(f) {
  const owner = el('input', { type: 'text', value: f.owner || '', 'aria-label': 'Owner' });
  const due = el('input', { type: 'date', value: f.dueDate ? f.dueDate.slice(0, 10) : '', 'aria-label': 'Due date' });
  const status = el('select', { 'aria-label': 'Status' }, ['OPEN', 'IN_PROGRESS', 'FIXED'].map(s => el('option', { value: s, selected: f.status === s ? true : null }, s.replace('_', ' ').toLowerCase())));
  const note = el('input', { type: 'text', placeholder: 'Note (optional)', 'aria-label': 'Note' });
  const exType = el('select', { 'aria-label': 'Exception type' }, [['SUPPRESSED', 'Suppress'], ['ACCEPTED_RISK', 'Accept risk'], ['FALSE_POSITIVE', 'False positive']].map(([v, t]) => el('option', { value: v }, t)));
  const exReason = el('textarea', { placeholder: 'Reason (min 10 characters)', 'aria-label': 'Reason' });
  const exOwner = el('input', { type: 'text', placeholder: 'Exception owner', value: ST.me.name, 'aria-label': 'Exception owner' });
  const exExpiry = el('input', { type: 'date', 'aria-label': 'Expiry date', value: new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10) });
  const high = ['HIGH', 'CRITICAL'].includes(f.priority);
  return el('div', { class: 'grid g2' },
    card('Workflow', el('div', { class: 'form-grid' }, el('label', { class: 'field' }, 'Status', status), el('label', { class: 'field' }, 'Owner', owner), el('label', { class: 'field' }, 'Due date', due), el('label', { class: 'field' }, 'Note', note)),
      el('div', { class: 'row', style: { marginTop: '10px' } }, el('button', { class: 'btn primary', disabled: !can('REMEDIATE') || null, onclick: async () => {
        const body = { owner: owner.value, note: note.value || null, dueDate: due.value ? new Date(due.value + 'T00:00:00Z').toISOString() : null };
        if (status.value !== f.status && ['OPEN', 'IN_PROGRESS', 'FIXED'].includes(status.value)) body.status = status.value;
        if (await guard(() => PATCH('/findings/' + f.id, body))) { toast('Saved', 'ok'); ST.route(); }
      } }, 'Save'))),
    card('Governed exception', f.suppression ? el('div', { class: 'stack' },
      kv([['Type', f.suppression.resultingStatus], ['Reason', f.suppression.reason], ['Owner', f.suppression.owner], ['Expires', fmt.date(f.suppression.expiresAt)],
        ['Created by', f.suppression.createdBy], ['Approved by', f.suppression.approvedBy]]),
      el('button', { class: 'btn danger', disabled: !can('REMEDIATE') || null, onclick: async () => { if (await guard(() => DEL('/findings/' + f.id + '/suppressions'))) ST.route(); } }, 'Revoke exception'))
      : el('div', { class: 'stack' }, high ? el('div', { class: 'alert warn small' }, 'High/Critical: an approver (APPROVE permission) must create this exception.') : null,
        el('div', { class: 'form-grid' }, el('label', { class: 'field' }, 'Type', exType), el('label', { class: 'field' }, 'Owner', exOwner), el('label', { class: 'field' }, 'Expires', exExpiry)),
        el('label', { class: 'field' }, 'Reason', exReason),
        el('div', null, el('button', { class: 'btn', disabled: !can('REMEDIATE') || (high && !can('APPROVE')) || null, onclick: async () => {
          const r = await guard(() => POST('/findings/' + f.id + '/suppressions', { type: exType.value, reason: exReason.value, owner: exOwner.value,
            expiresAt: exExpiry.value ? new Date(exExpiry.value + 'T23:59:59Z').toISOString() : null }));
          if (r) { toast('Exception recorded', 'ok'); ST.route(); }
        } }, 'Create exception')))));
}

/* ================================================================== change set panel (remediation & migration) */
function changeSetPanel(cs, onChange) {
  const policyOff = !ST.me.policy.allowAutoRemediation;
  const needsApprover = cs.securitySensitive || cs.kind === 'MIGRATION';
  const branch = el('input', { type: 'checkbox', checked: true });
  const dirty = el('input', { type: 'checkbox' });
  const act = (label, path, opts = {}) => el('button', { class: 'btn ' + (opts.primary ? 'primary' : opts.danger ? 'danger' : ''), disabled: opts.disabled || null, title: opts.title || null, onclick: async () => {
    if (opts.confirm && !(await confirmDialog(label, opts.confirm, label, !!opts.danger))) return;
    const r = await guard(() => POST('/remediations/' + cs.id + '/' + path, opts.body ? opts.body() : undefined));
    if (r) { toast(label + ': ' + r.status, r.status === 'CONFLICT' || r.status === 'VALIDATION_FAILED' ? 'err' : 'ok'); onChange && onChange(r); }
  } }, label);
  const s = cs.status;
  return el('div', { class: 'card stack', style: { borderLeft: '4px solid var(--accent)' } },
    el('div', { class: 'row between' }, el('div', null, el('b', null, cs.title), el('div', { class: 'small muted mono' }, cs.id + ' · ' + cs.provenance)), stBadge(s)),
    cs.explanation ? el('p', { style: { margin: 0 } }, cs.explanation) : null,
    el('div', { class: 'row small' }, el('span', null, cs.files.length + ' file(s), +' + cs.files.reduce((a, f) => a + f.additions, 0) + ' −' + cs.files.reduce((a, f) => a + f.deletions, 0)),
      needsApprover ? el('span', { class: 'badge st-WARN' }, 'requires approver') : null, cs.gitBranch ? el('span', { class: 'tag' }, 'branch ' + cs.gitBranch) : null,
      cs.gitCommit ? el('span', { class: 'tag mono' }, 'commit ' + cs.gitCommit.slice(0, 10)) : null, el('span', { class: 'muted' }, 'baseline ' + String(cs.baselineRevision).slice(0, 12))),
    cs.conflicts && cs.conflicts.length ? el('div', { class: 'alert err' }, el('b', null, 'Conflicts — nothing was overwritten: '), el('ul', null, cs.conflicts.map(c => el('li', null, c)))) : null,
    el('details', { open: cs.files.length <= 6 }, el('summary', null, 'Diff preview'), el('div', { style: { marginTop: '8px' } },
      cs.files.map(f => el('div', { style: { marginBottom: '10px' } }, f.explanation ? el('div', { class: 'small muted', style: { marginBottom: '4px' } }, f.path + ': ' + f.explanation) : null, diffView(f.diff))))),
    cs.validation ? el('details', null, el('summary', null, 'Validation: ', stBadge(cs.validation.passed ? 'PASS' : 'FAIL'), ' ', cs.validation.command), el('pre', { style: { marginTop: '8px' } }, cs.validation.outputTail)) : null,
    policyOff && s === 'PREVIEW' ? el('div', { class: 'alert info small' }, 'Manual mode: applying changes is disabled by policy (securetest.security.allow-auto-remediation=false). Download the patch and apply it with git apply.') : null,
    s === 'PREVIEW' && !policyOff ? el('div', { class: 'row small' }, el('label', { class: 'check' }, branch, 'Create a dedicated git branch'), el('label', { class: 'check' }, dirty, 'Allow when files have uncommitted edits (backup snapshot)')) : null,
    el('div', { class: 'row' },
      el('button', { class: 'btn', onclick: () => download('/remediations/' + cs.id + '/patch') }, '⬇ Download patch'),
      s === 'PREVIEW' ? act('Apply', 'apply', { primary: true, disabled: policyOff || !can('REMEDIATE') || (needsApprover && !can('APPROVE')),
        title: policyOff ? 'Disabled by policy' : needsApprover && !can('APPROVE') ? 'Requires APPROVE permission' : null,
        confirm: 'A backup (rollback point) is created first, uncommitted work is never overwritten, and the change can be undone. Apply ' + cs.files.length + ' file change(s)?',
        body: () => ({ createBranch: branch.checked, allowDirtyWithSnapshot: dirty.checked }) }) : null,
      ['APPLIED', 'VALIDATED', 'VALIDATION_FAILED'].includes(s) ? act('Validate (build & tests)', 'validate', { disabled: !can('REMEDIATE') }) : null,
      ['APPLIED', 'VALIDATED'].includes(s) ? act('Commit', 'commit', { disabled: !can('APPROVE'), confirm: 'Create a git commit with these changes?' }) : null,
      ['APPLIED', 'VALIDATED', 'VALIDATION_FAILED', 'COMMITTED', 'CONFLICT'].includes(s) && cs.appliedAt ? act('Undo', 'undo', { danger: true, disabled: !can('REMEDIATE'),
        confirm: 'Revert this change? If files were edited after the change was applied, the undo stops and lists the conflicts.' }) : null),
    el('details', null, el('summary', null, 'Audit trail'), el('ul', { class: 'timeline', style: { marginTop: '6px' } }, cs.history.map(h => el('li', null, h)))));
}
