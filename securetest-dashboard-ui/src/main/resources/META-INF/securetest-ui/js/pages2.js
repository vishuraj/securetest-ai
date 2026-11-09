/* SecureTest AI dashboard — testing, reports, migration, compliance, integrations, settings, audit, help. */
'use strict';

/* ================================================================== testing panel */
ST.panels.testing = async (panel) => {
  const [scans, tc, sessions] = await Promise.all([guard(() => GET('/scans?module=testing&size=50')), guard(() => GET('/testing/cases')), guard(() => GET('/testing/sessions'))]);
  const items = scans ? scans.items : [];
  const sum = latestResult(items, 'testSummary');
  const cov = latestResult(items, 'coverage');
  const slow = latestResult(items, 'slowestTests');
  const apiRes = latestResult(items, 'apiResults');
  const nodes = [];
  if (sum || cov) {
    const s = sum ? sum.value : {};
    nodes.push(card('Automated test results',
      el('div', { class: 'grid gauto' }, sum ? [stat('Tests', fmt.num(s.tests), s.reportFiles + ' report files'), stat('Pass rate', fmt.num(s.passRate, '%'), s.passed + ' passed'),
        stat('Failures / errors', s.failures + ' / ' + s.errors, s.skipped + ' skipped'), stat('Flaky', fmt.num(s.flaky), 'failed then passed on rerun'), stat('Duration', fmt.num(s.durationSeconds, ' s'))] : null,
        cov ? [stat('Line coverage', fmt.num(cov.value.lineCoverage, '%'), 'JaCoCo'), stat('Branch coverage', fmt.num(cov.value.branchCoverage, '%'))] : null),
      sum ? el('div', { class: 'small muted' }, 'From scan ' + sum.job.id + ' · ' + fmt.date(sum.job.endedAt)) : null,
      cov && cov.value.packages.length ? el('details', null, el('summary', null, 'Coverage by package'), table([{ label: 'Package', key: 'package' }, { label: 'Line %', key: 'lineCoverage', num: true }], cov.value.packages)) : null,
      slow && slow.value.length ? el('details', null, el('summary', null, 'Slowest tests'), table([{ label: 'Class', key: 'class' }, { label: 'Test', key: 'name' }, { label: 'Status', key: 'status', render: r => stBadge(r.status === 'PASSED' ? 'PASS' : r.status) }, { label: 'Seconds', key: 'time', num: true }], slow.value)) : null));
  }
  const pw = latestResult(items, 'browserMatrix');
  if (pw) {
    const sum = pw.job.results.browserSummary || {};
    nodes.push(card('Browser matrix (Playwright)', el('div', { class: 'small muted', style: { marginBottom: '8px' } },
      'Scan ' + pw.job.id + ' · ' + fmt.date(pw.job.endedAt) + ' · ' + (sum.durationSeconds || 0) + ' s'),
      table([{ label: 'Browser', key: 'project' }, { label: 'Passed', key: 'passed', num: true }, { label: 'Failed', key: 'failed', num: true },
        { label: 'Flaky', key: 'flaky', num: true }, { label: 'Skipped', key: 'skipped', num: true },
        { label: 'Result', render: r => stBadge(r.failed ? 'FAIL' : r.flaky ? 'WARN' : 'PASS') }], pw.value)));
  }
  const devices = items.filter(j => j.status === 'COMPLETED' && j.results && j.results.device && j.results.testSummary);
  if (devices.length) {
    const latest = {};
    devices.forEach(j => { if (!latest[j.results.device]) latest[j.results.device] = j; });
    nodes.push(card('Device / browser matrix (Selenium, Appium)', table([{ label: 'Device', key: 'device' }, { label: 'Suite', key: 'suite' },
      { label: 'Tests', key: 'tests', num: true }, { label: 'Pass rate', key: 'passRate', num: true, render: r => fmt.num(r.passRate, '%') },
      { label: 'Failures', key: 'failures', num: true }, { label: 'Run', key: 'at', render: r => fmt.ago(r.at) }],
      Object.values(latest).map(j => ({ device: j.results.device, suite: j.results.suite || '', tests: j.results.testSummary.tests,
        passRate: j.results.testSummary.passRate, failures: j.results.testSummary.failures + j.results.testSummary.errors, at: j.endedAt })),
      { onRow: r => openScanDrawer(devices.find(j => j.results.device === r.device).id) })));
  }
  if (apiRes) nodes.push(card('API tests (OpenAPI)', table([{ label: 'Method', key: 'method' }, { label: 'Path', key: 'path' }, { label: 'Status', key: 'status', num: true },
    { label: 'ms', key: 'ms', num: true }, { label: 'Result', key: 'result', render: r => stBadge(r.result) }, { label: 'Problems', key: 'problems', render: r => r.problems.join('; ') }], apiRes.value)));
  nodes.push(manualTesting(tc, sessions || []));
  append(panel, nodes);
};

function manualTesting(tc, sessions) {
  const cases = tc ? tc.cases : [];
  const editCase = (c) => {
    const title = el('input', { type: 'text', value: c ? c.title : '' });
    const req = el('input', { type: 'text', value: c ? c.requirement || '' : '', placeholder: 'e.g. REQ-12 / user story' });
    const pre = el('textarea', null);
    pre.value = c ? c.preconditions || '' : '';
    const steps = el('textarea', { style: { minHeight: '120px' } });
    steps.value = c ? (c.steps || []).join('\n') : '';
    const exp = el('textarea', null);
    exp.value = c ? c.expected || '' : '';
    let m;
    m = modal(c ? 'Edit ' + c.id : 'New test case', [
      el('label', { class: 'field' }, 'Title *', title), el('label', { class: 'field' }, 'Requirement / traceability', req),
      el('label', { class: 'field' }, 'Preconditions (use synthetic or masked test data only)', pre), el('label', { class: 'field' }, 'Steps (one per line)', steps),
      el('label', { class: 'field' }, 'Expected result', exp)],
      [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), el('button', { class: 'btn primary', onclick: async () => {
        const r = await guard(() => POST('/testing/cases', { id: c ? c.id : null, title: title.value, requirement: req.value, preconditions: pre.value,
          steps: steps.value.split('\n').map(s => s.trim()).filter(Boolean), expected: exp.value }));
        if (r) { m.close(); ST.route(); }
      } }, 'Save')]);
  };
  const runCase = (c) => {
    const status = el('select', null, ['PASS', 'FAIL', 'BLOCKED'].map(s => el('option', { value: s }, s)));
    const notes = el('textarea', null);
    const evidence = el('input', { type: 'text', placeholder: 'Link to screenshot / ticket / log' });
    let m;
    m = modal('Execute ' + c.id + ': ' + c.title, [
      el('ol', null, (c.steps || []).map(s => el('li', null, s))), el('p', null, el('b', null, 'Expected: '), c.expected || '—'),
      el('label', { class: 'field' }, 'Result', status), el('label', { class: 'field' }, 'Notes', notes), el('label', { class: 'field' }, 'Evidence', evidence)],
      [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), el('button', { class: 'btn primary', onclick: async () => {
        if (await guard(() => POST('/testing/cases/' + c.id + '/executions', { status: status.value, notes: notes.value, evidence: evidence.value }))) { m.close(); ST.route(); }
      } }, 'Record result')]);
  };
  const newSession = () => {
    const charter = el('textarea', { placeholder: 'Explore <target> with <resources> to discover <information>' });
    let m;
    m = modal('New exploratory session', [el('label', { class: 'field' }, 'Charter', charter)], [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'),
      el('button', { class: 'btn primary', onclick: async () => { if (await guard(() => POST('/testing/sessions', { charter: charter.value }))) { m.close(); ST.route(); } } }, 'Start')]);
  };
  const editSession = (s) => {
    const notes = el('textarea', { style: { minHeight: '140px' } });
    notes.value = s.notes || '';
    const issues = el('textarea', null);
    issues.value = (s.issues || []).join('\n');
    const evidence = el('textarea', null);
    evidence.value = (s.evidence || []).join('\n');
    const end = el('input', { type: 'checkbox' });
    let m;
    m = modal('Session ' + s.id, [el('p', null, el('b', null, 'Charter: '), s.charter), el('label', { class: 'field' }, 'Notes', notes),
      el('label', { class: 'field' }, 'Issues found (one per line)', issues), el('label', { class: 'field' }, 'Evidence links (one per line)', evidence),
      s.endedAt ? null : el('label', { class: 'check' }, end, 'End session now')],
      [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), el('button', { class: 'btn primary', onclick: async () => {
        const body = { notes: notes.value, issues: issues.value.split('\n').filter(Boolean), evidence: evidence.value.split('\n').filter(Boolean) };
        if (end.checked) body.endedAt = new Date().toISOString();
        if (await guard(() => PUT('/testing/sessions/' + s.id, body))) { m.close(); ST.route(); }
      } }, 'Save')]);
  };
  return card('Manual and exploratory testing',
    tabs([
      { label: 'Test cases (' + cases.length + ')', render: () => el('div', { class: 'stack' },
        el('div', { class: 'row' }, el('button', { class: 'btn primary', disabled: !can('EXECUTE') || null, onclick: () => editCase(null) }, '+ New test case'),
          tc ? el('span', { class: 'small muted' }, Object.entries(tc.summary.byStatus).map(([k, v]) => k + ': ' + v).join(' · ')) : null),
        table([{ label: 'ID', key: 'id' }, { label: 'Title', key: 'title' }, { label: 'Requirement', key: 'requirement' }, { label: 'Status', key: 'status', render: r => stBadge(r.status === 'NOT_RUN' ? 'NOT_ASSESSED' : r.status) },
          { label: 'Last run', key: 'lastRunAt', render: r => r.lastRunAt ? fmt.ago(r.lastRunAt) + ' by ' + r.lastRunBy : '—' },
          { label: '', render: r => el('div', { class: 'row' }, el('button', { class: 'btn small', onclick: (e) => { e.stopPropagation(); runCase(r); } }, 'Execute'),
            el('button', { class: 'btn small', onclick: (e) => { e.stopPropagation(); editCase(r); } }, 'Edit')) }], cases, { empty: 'No manual test cases yet' })) },
      { label: 'Exploratory sessions (' + sessions.length + ')', render: () => el('div', { class: 'stack' },
        el('div', null, el('button', { class: 'btn primary', disabled: !can('EXECUTE') || null, onclick: newSession }, '+ New session')),
        table([{ label: 'ID', key: 'id' }, { label: 'Charter', key: 'charter' }, { label: 'Tester', key: 'tester' }, { label: 'Started', key: 'startedAt', render: r => fmt.date(r.startedAt) },
          { label: 'Ended', key: 'endedAt', render: r => r.endedAt ? fmt.date(r.endedAt) : stBadge('RUNNING') }, { label: 'Issues', key: 'issues', num: true, render: r => (r.issues || []).length }],
          sessions, { onRow: editSession, empty: 'No sessions yet' })) }
    ]));
}

/* ================================================================== scans list */
ST.pages.scans = async (view, _id, params) => {
  const page = +(params.page || 0);
  const r = await guard(() => GET('/scans' + q({ page, size: 50 })));
  if (!r) return;
  clear(view);
  append(view, [el('h1', null, 'Scans'), el('p', { class: 'muted' }, r.total + ' scans. Click a row for progress, log, results and approval.'), scansTable(r.items),
    r.total > 50 ? el('div', { class: 'row' }, el('button', { class: 'btn', disabled: page === 0 || null, onclick: () => go('#/scans?page=' + (page - 1)) }, '← Prev'),
      el('button', { class: 'btn', disabled: (page + 1) * 50 >= r.total || null, onclick: () => go('#/scans?page=' + (page + 1)) }, 'Next →')) : null]);
  every(5000, async () => { if (location.hash.startsWith('#/scans')) { const n = await GET('/scans' + q({ page, size: 50 })).catch(() => null); if (n && n.items.some(j => !['COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED'].includes(j.status))) ST.route(); } });
};

/* ================================================================== reports */
ST.pages.reports = async (view) => {
  const r = await guard(() => GET('/reports'));
  if (!r) return;
  const type = el('select', { id: 'rtype' }, Object.entries(r.types).map(([k, v]) => el('option', { value: k }, v)));
  const title = el('input', { type: 'text', placeholder: 'Optional custom title' });
  const min = el('select', null, [['INFO', 'All priorities'], ['LOW', 'Low and above'], ['MEDIUM', 'Medium and above'], ['HIGH', 'High and above'], ['CRITICAL', 'Critical only']].map(([v, t]) => el('option', { value: v }, t)));
  const closed = el('input', { type: 'checkbox' });
  const mods = el('select', { multiple: true, size: 5, 'aria-label': 'Modules (optional)' }, ST.modules.map(m => el('option', { value: m.id }, m.name)));
  const generate = async () => {
    const body = { type: type.value, title: title.value || null, minPriority: min.value, includeClosed: closed.checked, modules: [...mods.selectedOptions].map(o => o.value) };
    const rep = await guard(() => POST('/reports', body, { idempotencyKey: String(Date.now()) }));
    if (rep) { toast('Generating ' + rep.id + '…', 'ok'); ST.route(); }
  };
  const generating = r.reports.some(x => x.status === 'GENERATING');
  clear(view);
  append(view, [
    el('h1', null, 'Reports'),
    card('Generate a report', el('div', { class: 'form-grid' }, el('label', { class: 'field' }, 'Report type', type), el('label', { class: 'field' }, 'Title', title),
      el('label', { class: 'field' }, 'Minimum priority', min), el('label', { class: 'field' }, 'Modules (Ctrl/Cmd-click; empty = report default)', mods)),
      el('label', { class: 'check', style: { marginTop: '8px' } }, closed, 'Include closed / suppressed findings'),
      el('div', { class: 'row', style: { marginTop: '10px' } }, el('button', { class: 'btn primary', onclick: generate }, 'Generate'),
        el('span', { class: 'small muted' }, 'Reports are generated asynchronously as PDF, Excel (XLSX), CSV and JSON with report ID, snapshot version and SHA-256 checksum.'))),
    card('Generated reports', table([
      { label: 'Report', key: 'id', render: x => el('div', null, el('div', null, x.title), el('div', { class: 'small muted mono' }, x.id)) },
      { label: 'Type', key: 'type' }, { label: 'Status', key: 'status', render: x => x.status === 'FAILED' ? el('span', { title: x.error }, stBadge('FAILED')) : stBadge(x.status) },
      { label: 'Findings', key: 'findings', num: true }, { label: 'Requested', key: 'requestedAt', render: x => fmt.date(x.requestedAt) }, { label: 'By', key: 'generatedBy' },
      { label: 'Download', render: x => x.status === 'READY' ? el('div', { class: 'row' }, ['pdf', 'xlsx', 'csv', 'json'].map(f => el('button', { class: 'btn small', onclick: (e) => { e.stopPropagation(); download('/reports/' + x.id + '/download?format=' + f); } }, f.toUpperCase()))) : '—' }
    ], r.reports, { onRow: x => x.status === 'READY' && go('#/report/' + x.id), empty: 'No reports yet' }))
  ]);
  if (generating) every(2500, () => ST.route());
};

ST.pages.report = async (view, id) => {
  const meta = await guard(() => GET('/reports/' + id));
  if (!meta) return;
  const res = await fetch(ST.api + '/reports/' + id + '/data', { credentials: 'same-origin' });
  const d = await res.json();
  const filterBox = el('input', { type: 'search', placeholder: 'Filter findings…', 'aria-label': 'Filter report findings' });
  const tableBox = el('div');
  const drawTable = () => {
    const t = filterBox.value.toLowerCase();
    clear(tableBox).appendChild(findingsTable(d.findings.filter(f => !t || (f.title + ' ' + f.id + ' ' + (f.filePath || '') + ' ' + (f.asset || '')).toLowerCase().includes(t))));
  };
  filterBox.addEventListener('input', drawTable);
  clear(view);
  append(view, [
    linkBtn('← Reports', () => go('#/reports')),
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, d.title), el('div', { class: 'muted' }, d.organization + ' · ' + d.classification + ' · ' + d.reportId)),
      el('div', { class: 'row' }, ['pdf', 'xlsx', 'csv', 'json'].map(f => el('button', { class: 'btn' + (f === 'pdf' ? ' primary' : ''), onclick: () => download('/reports/' + id + '/download?format=' + f) }, '⬇ ' + f.toUpperCase())))),
    el('div', { class: 'grid g2' },
      card('Report metadata', kv([['Application', d.applicationName], ['Environment', d.environment], ['Generated', fmt.date(d.generatedAt)], ['Owner', d.owner], ['Revision', d.revision],
        ['Data snapshot', d.snapshotVersion], ['Integrity (SHA-256 of PDF)', el('span', { class: 'mono small' }, meta.checksum)], ...Object.entries(d.metadata)])),
      card('Executive summary', el('p', null, d.executiveSummary), sevChart(d.severityCounts), el('p', { class: 'small muted' }, d.scope))),
    d.recommendations.length ? card('Recommendations', el('ul', null, d.recommendations.map(x => el('li', null, x)))) : null,
    card('Findings (' + d.findings.length + ')', filterBox, el('div', { style: { marginTop: '8px' } }, tableBox)),
    ...d.tables.map(t => el('details', { class: 'card' }, el('summary', null, t.title + ' (' + t.rows.length + ')'),
      el('div', { style: { marginTop: '10px' } }, table(t.headers.map((h, i) => ({ label: h, key: String(i), render: r => r[i] })), t.rows.map(r => Object.assign([], r)))))),
    card('Limitations', el('ul', null, d.limitations.map(x => el('li', null, x))))
  ]);
  drawTable();
};

/* ================================================================== migration */
ST.pages.migration = async (view, id) => {
  const [runs, matrix] = await Promise.all([guard(() => GET('/migrations')), guard(() => GET('/migrations/matrix'))]);
  const mod = ST.modules.find(m => m.id === 'migration');
  clear(view);
  append(view, [el('h1', null, 'Migration & modernization'),
    el('p', { class: 'muted' }, 'Analysis never modifies files. Applying changes requires policy opt-in, an approver, a dedicated branch and a rollback point; undo detects later edits.')]);
  if (mod && !mod.enabled) {
    view.appendChild(el('div', { class: 'alert warn' }, 'The Migration module is disabled. ', can('CONFIGURE') ? linkBtn('Enable it', async () => { if (await toggleModule(mod, true) !== false) ST.route(); }) : 'Ask an administrator to enable it.'));
    return;
  }
  const run = id ? await guard(() => GET('/migrations/' + id)) : null;
  if (!run) {
    const inv = await guard(() => GET('/migrations/discover'));
    const java = el('select', null, matrix.javaTargets.map(j => el('option', { value: j, selected: j === 21 ? true : null }, 'Java ' + j)));
    const boot = el('select', null, matrix.bootTargets.map(b => el('option', { value: b }, 'Spring Boot ' + b)));
    append(view, [
      el('div', { class: 'steps' }, ['Discover', 'Select target', 'Assess', 'Plan', 'Preview', 'Apply', 'Validate', 'Commit / undo'].map((s, i) => el('span', { class: 'step' + (i < 1 ? ' done' : i === 1 ? ' active' : '') }, s))),
      inv ? card('1. Discovered project', el('div', { class: 'grid g2' },
        kv([['Workspace', inv.root], ['Languages', inv.languages.join(', ')], ['Java (detected)', inv.detectedJava], ['Spring Boot (detected)', inv.detectedSpringBoot],
          ['Namespace', inv.servletNamespace], ['Java files / tests', inv.totalJavaFiles + ' / ' + inv.totalTestFiles],
          ['Git', inv.gitRepository ? ((inv.gitHead ? (inv.gitBranch || 'detached') + ' @ ' + inv.gitHead.slice(0, 10) : 'no commits yet') + (inv.dirtyFiles.length ? ' · ' + inv.dirtyFiles.length + ' uncommitted file(s)' : ' · clean')) : 'not a git repository']]),
        el('div', null, table([{ label: 'Module', key: 'path', render: r => r.path || '(root)' }, { label: 'Build', key: 'buildTool' }, { label: 'Java', key: 'javaVersion' },
          { label: 'Boot', key: 'springBootVersion' }, { label: 'javax refs', key: 'javaxReferences', num: true }], inv.modules),
          Object.keys(inv.containerImages).length ? kv(Object.entries(inv.containerImages)) : null))) : null,
      card('2. Select target', el('div', { class: 'form-grid' }, el('label', { class: 'field' }, 'Java LTS', java), el('label', { class: 'field' }, 'Spring Boot', boot)),
        el('details', { style: { marginTop: '10px' } }, el('summary', null, 'Validated compatibility matrix'),
          table([{ label: 'Spring Boot line', key: 'line' }, { label: 'Java', render: r => r.minJava + '–' + r.maxJava }, { label: 'Namespace', key: 'servletNamespace' },
            { label: 'Latest patch', key: 'latestPatch' }, { label: 'OSS support', render: r => r.ossSupported ? 'yes' : 'ended' }], matrix.bootLines)),
        el('div', { style: { marginTop: '10px' } }, el('button', { class: 'btn primary', disabled: !can('EXECUTE') || null, onclick: async () => {
          const r = await guard(() => POST('/migrations/assess', { javaVersion: +java.value, springBootVersion: boot.value }));
          if (r) go('#/migration/' + r.id);
        } }, 'Assess (read-only)'))),
      runs && runs.length ? card('Previous migration runs', table([{ label: 'Run', key: 'id' }, { label: 'Status', key: 'status', render: r => stBadge(r.status) },
        { label: 'From', render: r => 'Java ' + r.sourceVersions.java + ' / Boot ' + r.sourceVersions.springBoot }, { label: 'To', render: r => 'Java ' + r.targetVersions.java + ' / Boot ' + r.targetVersions.springBoot },
        { label: 'Risk', render: r => r.assessment.riskLevel }, { label: 'Created', render: r => fmt.date(r.createdAt) }], runs, { onRow: r => go('#/migration/' + r.id) })) : null
    ]);
    return;
  }
  const a = run.assessment;
  const stepIndex = { ASSESSED: 2, UNSUPPORTED_TARGET: 2, PLANNED: 3, PREVIEWED: 4, APPLIED: 5, VALIDATED: 6, VALIDATION_FAILED: 6, COMMITTED: 7, UNDONE: 7, CONFLICT: 5 }[run.status] || 2;
  const cats = [...new Set(a.items.filter(i => i.autoFixable).map(i => i.category))];
  const catBoxes = cats.map(c => { const b = el('input', { type: 'checkbox', checked: c !== 'SPRING_SECURITY' ? true : null, value: c }); return { c, b }; });
  const cs = run.changeSetId ? await guard(() => GET('/remediations/' + run.changeSetId)) : null;
  const riskColor = { LOW: 'var(--ok)', MEDIUM: 'var(--med)', HIGH: 'var(--high)', 'VERY HIGH': 'var(--crit)' }[a.riskLevel];
  append(view, [
    linkBtn('← New assessment', () => go('#/migration')),
    el('div', { class: 'steps' }, ['Discover', 'Select target', 'Assess', 'Plan', 'Preview', 'Apply', 'Validate', 'Commit / undo'].map((s, i) => el('span', { class: 'step' + (i < stepIndex ? ' done' : i === stepIndex ? ' active' : '') }, s))),
    el('div', { class: 'grid g3' },
      card('Run ' + run.id, kv([['Status', stBadge(run.status)], ['From', 'Java ' + run.sourceVersions.java + ' · Boot ' + run.sourceVersions.springBoot + ' · ' + run.sourceVersions.namespace],
        ['To', 'Java ' + run.targetVersions.java + ' · Boot ' + run.targetVersions.springBoot], ['Baseline', el('span', { class: 'mono small' }, run.baselineRef)], ['Repository', run.repoRef]])),
      card('Risk', el('div', { class: 'gauge', style: { color: riskColor } }, a.riskScore + '/100'), el('div', null, stBadge(a.riskLevel === 'LOW' ? 'PASS' : a.riskLevel === 'MEDIUM' ? 'WARN' : 'FAIL'), ' ', a.riskLevel),
        el('ul', { class: 'small' }, a.riskFactors.map(f => el('li', null, f)))),
      card('Items', kv([['Total', String(a.items.length)], ['Automated', String(a.autoFixableCount)], ['Manual', String(a.manualCount)],
        ...Object.entries(a.countsByCategory).map(([k, v]) => [k.replace(/_/g, ' ').toLowerCase(), String(v)])]))),
    a.compatibilityErrors.length ? el('div', { class: 'alert err' }, el('b', null, 'Unsupported target: '), a.compatibilityErrors.join(' ')) : null,
    a.compatibilityWarnings.length ? el('div', { class: 'alert warn' }, a.compatibilityWarnings.map(w => el('div', null, w))) : null,
    card('3. Assessment (' + a.items.length + ' items)', table([{ label: 'Category', key: 'category' }, { label: 'Severity', key: 'severity' }, { label: 'File', key: 'file', render: r => el('span', { class: 'mono small' }, (r.file || '—') + (r.line ? ':' + r.line : '')) },
      { label: 'Change', key: 'message' }, { label: 'Automated', key: 'autoFixable', render: r => r.autoFixable ? stBadge('PASS') : el('span', { class: 'badge st-WARN', title: r.guidance }, 'manual') },
      { label: 'Guidance', key: 'guidance', render: r => el('span', { class: 'small muted' }, r.guidance || '') }], a.items.slice(0, 1000))),
    run.plan ? card('4. Plan', el('ol', { class: 'stack' }, run.plan.steps.map(s => el('li', null, el('b', null, s.title), ' ', el('span', { class: 'tag' }, s.complexity), s.automated ? el('span', { class: 'tag' }, 'automated') : el('span', { class: 'tag' }, 'manual'),
      el('div', { class: 'small' }, s.description), s.prerequisites.length ? el('div', { class: 'small muted' }, 'Prerequisites: ' + s.prerequisites.join(', ')) : null,
      s.affectedFiles.length ? el('details', null, el('summary', { class: 'small' }, s.affectedFiles.length + ' file(s)'), el('div', { class: 'mono small' }, s.affectedFiles.join('\n'))) : null,
      el('div', { class: 'small muted' }, 'Rollback: ' + s.rollback)))), el('p', { class: 'small muted' }, run.plan.rollbackStrategy))
      : el('div', null, el('button', { class: 'btn primary', disabled: !!a.compatibilityErrors.length || !can('EXECUTE') || null, onclick: async () => { if (await guard(() => POST('/migrations/' + run.id + '/plan'))) ST.route(); } }, 'Generate plan')),
    run.plan ? card('5. Preview changes', cats.length ? el('div', { class: 'stack' },
      el('div', { class: 'chips' }, catBoxes.map(({ c, b }) => el('label', { class: 'check tag' }, b, c.replace(/_/g, ' ').toLowerCase()))),
      el('p', { class: 'small muted' }, 'Spring Security changes are security-sensitive and unchecked by default.'),
      el('div', null, el('button', { class: 'btn primary', disabled: !can('REMEDIATE') || null, onclick: async () => {
        const r = await guard(() => POST('/migrations/' + run.id + '/preview', { categories: catBoxes.filter(x => x.b.checked).map(x => x.c) }));
        if (r) ST.route();
      } }, run.changeSetId ? 'Regenerate preview' : 'Generate per-file diff'))) : el('p', { class: 'muted' }, 'No automated changes are available; all items are manual.')) : null,
    cs ? card('6–8. Apply, validate, commit or undo', changeSetPanel(cs, () => ST.route())) : null,
    el('div', { class: 'row' }, el('button', { class: 'btn', onclick: async () => {
      const r = await guard(() => POST('/reports', { type: 'migration', migrationId: run.id, minPriority: 'INFO', includeClosed: true }));
      if (r) { toast('Migration report ' + r.id + ' is being generated', 'ok'); go('#/reports'); }
    } }, 'Generate migration report')),
    card('History', el('ul', { class: 'timeline' }, run.history.map(h => el('li', null, h))))
  ]);
};

/* ================================================================== compliance */
ST.pages.compliance = async (view) => {
  const c = await guard(() => GET('/compliance'));
  if (!c) return;
  const byFw = {};
  c.controls.forEach(x => (byFw[x.framework] = byFw[x.framework] || []).push(x));
  const markNa = async (x) => {
    const reason = el('textarea', { placeholder: 'Rationale (required when marking not applicable)' });
    let m;
    m = modal((x.status === 'NOT_APPLICABLE' ? 'Restore ' : 'Mark not applicable: ') + x.framework + ' ' + x.id, [el('p', null, x.title), x.status === 'NOT_APPLICABLE' ? null : el('label', { class: 'field' }, 'Rationale', reason)],
      [el('button', { class: 'btn', onclick: () => m.close() }, 'Cancel'), el('button', { class: 'btn primary', onclick: async () => {
        if (await guard(() => PUT('/compliance/applicability', { framework: x.framework, controlId: x.id, notApplicable: x.status !== 'NOT_APPLICABLE', reason: reason.value }))) { m.close(); ST.route(); }
      } }, 'Save')]);
  };
  clear(view);
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Compliance & governance')),
      el('button', { class: 'btn', disabled: !can('AUDIT') || null, onclick: () => download('/compliance/evidence-pack') }, '⬇ Evidence pack (ZIP)')),
    el('div', { class: 'alert warn' }, c.disclaimer),
    el('div', { class: 'grid gauto' }, Object.entries(c.frameworks).map(([fw, counts]) => el('div', { class: 'card tight' }, el('b', null, fw),
      el('div', { class: 'row small', style: { marginTop: '6px' } }, Object.entries(counts).map(([s, n]) => el('span', { class: 'badge st-' + s }, n + ' ' + s.replace(/_/g, ' ').toLowerCase())))))),
    ...Object.entries(byFw).map(([fw, list]) => el('details', { class: 'card', open: fw.startsWith('OWASP Top') ? true : null }, el('summary', null, fw),
      el('div', { style: { marginTop: '10px' } }, table([
        { label: 'Control', key: 'id' }, { label: 'Title', key: 'title' }, { label: 'Status', key: 'status', render: x => stBadge(x.status) },
        { label: 'Rationale', key: 'rationale', render: x => el('span', { class: 'small' }, x.rationale + (x.notApplicableReason ? ' — ' + x.notApplicableReason : '')) },
        { label: 'Findings', render: x => x.openFindings.length ? el('div', null, x.openFindings.slice(0, 5).map(id => el('a', { href: '#/finding/' + id, class: 'tag' }, id)), x.openFindings.length > 5 ? ' +' + (x.openFindings.length - 5) : '') : '—' },
        { label: 'Evidence', render: x => el('span', { class: 'small muted' }, x.evidenceScans.join('; ') || '—') },
        { label: '', render: x => can('APPROVE') ? el('button', { class: 'btn small', onclick: () => markNa(x) }, x.status === 'NOT_APPLICABLE' ? 'Restore' : 'N/A') : null }
      ], list))))
  ]);
};

/* ================================================================== integrations */
ST.pages.integrations = async (view) => {
  const i = await guard(() => GET('/integrations'));
  if (!i) return;
  clear(view);
  append(view, [
    el('h1', null, 'Integrations'),
    el('p', { class: 'muted' }, 'SecureTest does not bundle third-party scanners. Adapters drive tools you install (allowlisted commands), remote services you configure, or built-in safe checks.'),
    card('Adapters and checks', table([{ label: 'Name', key: 'name' }, { label: 'Module', key: 'module', render: r => moduleName(r.module) }, { label: 'Tool', key: 'tool' },
      { label: 'Execution', key: 'location', render: r => el('span', { class: 'small' }, ST.T.location[r.location]) }, { label: 'Mode', key: 'mode', render: r => modeBadge(r.mode) }], i.adapters)),
    el('div', { class: 'grid g2' },
      card('Installed tools', table([{ label: 'Tool', key: 't' }, { label: 'Installed', key: 'i', render: r => stBadge(r.i ? 'PASS' : 'NOT_ASSESSED') },
        { label: 'Allowlisted', key: 'a', render: r => stBadge(r.a ? 'PASS' : 'DISABLED') }], Object.entries(i.tools).map(([t, v]) => ({ t, i: v.installed, a: v.allowlisted }))),
        el('p', { class: 'small muted' }, 'Allow a tool with securetest.execution.allowed-commands[0]=trivy (etc.).')),
      card('Tested integration versions', kv(Object.entries(i.compatibilityMatrix)))),
    el('div', { class: 'grid g2' },
      card('Control plane (connected mode)', kv(Object.entries(i.controlPlane).map(([k, v]) => [k, String(v)]))),
      card('Notifications & event ingestion', el('h3', null, 'Webhooks'), i.webhooks.length ? table([{ label: 'Name', key: 'name' }, { label: 'Format', key: 'format' }, { label: 'Events', key: 'events', render: r => r.events.join(', ') }], i.webhooks)
        : el('p', { class: 'muted' }, 'None configured (securetest.notifications.webhooks).'),
        el('h3', { style: { marginTop: '10px' } }, 'Runtime alert ingestion'), kv([['Enabled', String(i.eventIngestion.enabled)], ['Endpoint', 'POST ' + i.eventIngestion.path], ['Header', i.eventIngestion.header], ['Formats', i.eventIngestion.formats.join(', ')]])))
  ]);
};

/* ================================================================== settings */
ST.pages.settings = async (view) => {
  const [s, compat, schedules, profiles, scanners] = await Promise.all([guard(() => GET('/settings')), guard(() => GET('/compatibility')), guard(() => GET('/schedules')), guard(() => GET('/profiles')), guard(() => GET('/scanners'))]);
  if (!s) return;
  const section = (title, obj) => el('details', { class: 'card' }, el('summary', null, title), el('pre', { style: { marginTop: '10px' } }, JSON.stringify(obj, null, 2)));
  const scannerSel = el('select', null, (scanners || []).map(x => el('option', { value: x.descriptor.id }, moduleName(x.descriptor.moduleId) + ' — ' + x.descriptor.name)));
  const profileSel = el('select', null, el('option', { value: '' }, '(defaults)'));
  const refreshProfiles = () => { clear(profileSel).appendChild(el('option', { value: '' }, '(defaults)')); (profiles || []).filter(p => p.scannerId === scannerSel.value).forEach(p => profileSel.appendChild(el('option', { value: p.name }, p.name))); };
  scannerSel.addEventListener('change', refreshProfiles);
  refreshProfiles();
  const cron = el('input', { type: 'text', value: '0 0 2 * * MON-FRI', 'aria-label': 'Cron expression' });
  clear(view);
  append(view, [
    el('h1', null, 'Settings'),
    el('p', { class: 'muted' }, 'Effective configuration (secrets are never shown). Change values in application.yml under the securetest prefix; module toggles can also be changed on each module page unless locked by policy.'),
    card('Your access', kv([['User', ST.me.name], ['Authentication', ST.me.authMethod], ['Roles', ST.me.roles.join(', ')], ['Permissions', ST.me.permissions.join(', ')]])),
    compat ? card('Compatibility diagnostics', table([{ label: 'Check', key: 'name' }, { label: 'Level', key: 'level', render: r => stBadge(r.level === 'OK' ? 'PASS' : r.level === 'INFO' ? 'INFO' : r.level) }, { label: 'Detail', key: 'detail' }], compat.checks)) : null,
    card('Scheduled scans',
      table([{ label: 'ID', key: 'id' }, { label: 'Scanner', key: 'scannerId' }, { label: 'Profile', key: 'profileName' }, { label: 'Cron', key: 'cron', render: r => el('span', { class: 'mono' }, r.cron) },
        { label: 'Next run', key: 'nextRun', render: r => fmt.date(r.nextRun) }, { label: 'Last', key: 'lastRun', render: r => r.lastRun ? fmt.ago(r.lastRun) + (r.lastError ? ' (' + r.lastError + ')' : '') : '—' },
        { label: 'Enabled', render: r => switchBtn(r.enabled, 'Toggle schedule', async (v) => !!(await guard(() => POST('/schedules/' + r.id + '/enabled?value=' + v))), !can('CONFIGURE')) },
        { label: '', render: r => el('button', { class: 'btn small danger', disabled: !can('CONFIGURE') || null, onclick: async () => { if (await confirmDialog('Delete schedule', 'Delete ' + r.id + '?', 'Delete', true)) { await guard(() => DEL('/schedules/' + r.id)); ST.route(); } } }, 'Delete') }],
        schedules || [], { empty: 'No schedules' }),
      el('div', { class: 'form-grid', style: { marginTop: '10px' } }, el('label', { class: 'field' }, 'Scanner', scannerSel), el('label', { class: 'field' }, 'Profile', profileSel),
        el('label', { class: 'field' }, 'Cron (sec min hour day month weekday)', cron)),
      el('div', { style: { marginTop: '8px' } }, el('button', { class: 'btn primary', disabled: !can('CONFIGURE') || null, onclick: async () => {
        if (await guard(() => POST('/schedules', { scannerId: scannerSel.value, profileName: profileSel.value || null, cron: cron.value }))) { toast('Schedule created', 'ok'); ST.route(); }
      } }, 'Add schedule'), el('span', { class: 'small muted' }, ' Schedules only run while their module is enabled; active scans need an approver to schedule.'))),
    card('Saved scan profiles', table([{ label: 'Scanner', key: 'scannerId' }, { label: 'Name', key: 'name' }, { label: 'Options', key: 'options', render: r => el('span', { class: 'small mono' }, JSON.stringify(r.options)) },
      { label: 'By', key: 'createdBy' }, { label: '', render: r => el('button', { class: 'btn small danger', disabled: !can('CONFIGURE') || null, onclick: async () => { await guard(() => DEL('/profiles/' + r.scannerId + '/' + encodeURIComponent(r.name))); ST.route(); } }, 'Delete') }],
      profiles || [], { empty: 'No saved profiles' })),
    section('Dashboard & authentication', s.dashboard), section('Modules', s.modules), section('Security policy', s.security), section('Execution', s.execution),
    section('Data & retention', s.data), section('Workspace', s.workspace), section('Telemetry', s.telemetry), section('Reports', s.reports),
    section('AI-assisted remediation', s.ai), section('E-mail notifications', s.email),
    section('Release gate & SLA policy', s.policy), section('Notifications', s.notifications), section('Control plane', s.controlPlane), section('Application', s.application),
    el('div', { class: 'row' }, el('a', { class: 'btn', href: ST.api + '/openapi.json', target: '_blank' }, 'OpenAPI document for this API'))
  ]);
};

/* ================================================================== audit */
ST.pages.audit = async (view, _id, params) => {
  if (!can('AUDIT')) { clear(view).appendChild(el('div', { class: 'alert warn' }, 'AUDIT permission is required.')); return; }
  const page = +(params.page || 0);
  const r = await guard(() => GET('/audit-events' + q({ actor: params.actor, action: params.action, target: params.target, page, size: 50 })));
  if (!r) return;
  const actor = el('input', { type: 'text', value: params.actor || '', placeholder: 'Actor' });
  const action = el('input', { type: 'text', value: params.action || '', placeholder: 'Action prefix (e.g. scan.)' });
  const target = el('input', { type: 'text', value: params.target || '', placeholder: 'Target' });
  const verifyBox = el('span');
  clear(view);
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Audit log'), el('div', { class: 'muted' }, 'Append-only and hash-chained: each event includes the hash of the previous one.')),
      el('div', { class: 'row' }, verifyBox, el('button', { class: 'btn', onclick: async () => {
        const v = await guard(() => GET('/audit-events/verify'));
        if (v) { clear(verifyBox).appendChild(v.valid ? el('span', { class: 'badge st-PASS' }, 'Chain valid (' + v.checked + ' events)') : el('span', { class: 'badge st-FAIL' }, 'Chain broken at #' + v.brokenAtSequence)); }
      } }, 'Verify integrity'))),
    el('div', { class: 'card filters' }, actor, action, target, el('button', { class: 'btn primary', onclick: () => go('#/audit' + q({ actor: actor.value, action: action.value, target: target.value })) }, 'Filter')),
    table([{ label: '#', key: 'sequence', num: true }, { label: 'Time', key: 'timestamp', render: e => fmt.date(e.timestamp) }, { label: 'Actor', key: 'actor' },
      { label: 'Action', key: 'action', render: e => el('span', { class: 'mono small' }, e.action) }, { label: 'Target', key: 'target' }, { label: 'Outcome', key: 'outcome', render: e => stBadge(e.outcome) },
      { label: 'Details', key: 'details', render: e => el('span', { class: 'small muted' }, Object.entries(e.details || {}).map(([k, v]) => k + '=' + v).join(', ')) },
      { label: 'Correlation', key: 'correlationId', render: e => el('span', { class: 'mono small muted' }, (e.correlationId || '').slice(0, 8)) }], r.items),
    el('div', { class: 'row' }, el('span', null, r.total + ' events'), el('button', { class: 'btn', disabled: page === 0 || null, onclick: () => go('#/audit' + q({ ...params, page: page - 1 })) }, '← Newer'),
      el('button', { class: 'btn', disabled: (page + 1) * 50 >= r.total || null, onclick: () => go('#/audit' + q({ ...params, page: page + 1 })) }, 'Older →'))
  ]);
};

/* ================================================================== help */
ST.pages.help = async (view) => {
  const gl = [['Starter', 'The single dependency that brings SecureTest auto-configuration and this dashboard.'], ['Auto-configuration', 'Conditional Spring Boot bean registration based on classpath, properties and environment.'],
    ['Control plane', 'Optional central service for inventory, policy, orchestration and reporting across applications.'], ['Worker', 'Isolated environment for heavy or intrusive scans.'],
    ['SAST', 'Static Application Security Testing — analysis of source code.'], ['DAST', 'Dynamic Application Security Testing — testing a running application.'],
    ['SCA', 'Software Composition Analysis — vulnerabilities and licenses in dependencies.'], ['SBOM', 'Software Bill of Materials (CycloneDX here).'],
    ['Finding', 'A normalized issue, vulnerability, defect, observation or compliance gap.'], ['Severity', 'Impact classification reported by the source tool (preserved).'],
    ['Priority', 'SecureTest urgency derived from severity and context; see "Why this priority?" on each finding.'], ['Feature toggle', 'Per-module switch; everything optional is OFF by default.'],
    ['Change set', 'A reviewable diff with a rollback point used for remediation and migration.'], ['Secret reference', 'env://NAME, prop://key, file:///path or secret://path — resolved at run time, never stored.']];
  clear(view);
  append(view, [el('h1', null, 'Help & glossary'),
    card('Getting started', el('ol', null,
      el('li', null, 'Enable a module with its toggle (Overview or the module page). Disabled modules do nothing.'),
      el('li', null, 'Open a check, click “Configure & run”. The dialog explains purpose, impact, credentials, permissions and runs a preflight.'),
      el('li', null, 'Passive checks run immediately. Active or resource-intensive checks need confirmation, and active scans need an approver.'),
      el('li', null, 'Review findings: priority, evidence, highlighted code and a recommended fix. Generate a fix preview to see the exact diff.'),
      el('li', null, 'Export reports (PDF/XLSX/CSV/JSON) and compliance evidence packs.'))),
    card('Priorities', table([{ label: 'Priority', render: r => sevBadge(r) }, { label: 'Meaning', render: r => ST.T.sevHelp[r] }], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])),
    card('Safety model', el('ul', null,
      el('li', null, 'The dashboard is loopback-only by default and disabled under production profiles unless explicitly enabled.'),
      el('li', null, 'Every network target must be on securetest.security.target-allowlist; cloud metadata endpoints are always refused.'),
      el('li', null, 'External tools run only if allowlisted (securetest.execution.allowed-commands), in separate processes with timeouts.'),
      el('li', null, 'Source changes are diff-first, need policy opt-in and approval, create a rollback point and can be undone.'),
      el('li', null, 'No AI service is used; recommendations are deterministic rules, so no code leaves this machine.'))),
    card('Glossary', kv(gl)),
    card('Keyboard', kv([['Tab / Shift+Tab', 'Move between controls'], ['Enter', 'Open the focused row or card'], ['Esc', 'Close dialogs']])),
    card('API', el('p', null, 'All dashboard data is available through the versioned REST API: ', el('a', { href: ST.api + '/openapi.json', target: '_blank' }, 'OpenAPI document'),
      '. Mutating calls require the header X-SecureTest-Request: 1. CI pipelines can call GET ', el('code', null, ST.api + '/gate'), ' for a release-gate decision.'))
  ]);
};
