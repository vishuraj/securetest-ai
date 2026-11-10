/* SecureTest AI dashboard — release readiness and sign-off. */
'use strict';

const CHECK_CLASS = { PASS: 'st-PASS', FAIL: 'st-FAIL', NOT_RUN: 'st-DISABLED', WAIVED: 'st-WARN' };

function releaseDialog() {
  const version = el('input', { type: 'text', placeholder: 'e.g. 2.4.0' });
  const name = el('input', { type: 'text', placeholder: 'Optional name' });
  const target = el('input', { type: 'date' });
  const items = el('textarea', { rows: 3, placeholder: 'Extra checklist items, one per line (e.g. Release notes reviewed)' });
  const engagement = el('input', { type: 'text', placeholder: 'Pentest engagement id (optional, e.g. E-0001)' });
  const submit = el('button', { class: 'btn primary', onclick: async () => {
    const r = await guard(() => POST('/releases', { version: version.value.trim(), name: name.value.trim() || null, targetDate: target.value || null,
      engagementId: engagement.value.trim() || null, items: lines(items.value) }));
    if (r) { clear(document.getElementById('modalRoot')); go('#/releases/' + r.release.id); }
  } }, 'Create release');
  const row = (l, n) => el('label', { class: 'field', style: { display: 'block' } }, l, n);
  modal('New release', [el('div', { class: 'stack' }, el('div', { class: 'grid g2' }, row('Version *', version), row('Target date', target)), row('Name', name),
    row('Pentest engagement', engagement), row('Checklist', items),
    el('p', { class: 'small muted' }, 'Required checks default to the release gate and critical vulnerabilities, plus tests and code quality when those modules are on.'))], [submit]);
}

ST.pages.releases = async (view, id) => {
  if (id) return ST.pages.release(view, id);
  const list = await guard(() => GET('/releases'));
  if (!list) return;
  clear(view);
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Releases'),
      el('div', { class: 'muted' }, 'Quality and security readiness for each release, with waivers and role-based sign-off.')),
      can('CONFIGURE') ? el('button', { class: 'btn primary', onclick: releaseDialog }, '+ New release') : null),
    card(null, table([
      { label: 'Release', sort: x => x.release.version, render: x => el('div', null, el('b', null, x.release.version), el('div', { class: 'small muted' }, x.release.id + (x.release.name ? ' · ' + x.release.name : ''))) },
      { label: 'Status', sort: x => x.release.status, render: x => stBadge(x.release.status) },
      { label: 'Ready', render: x => x.readiness.ready ? stBadge('PASS') : el('span', { class: 'badge st-FAIL', title: x.readiness.blockers.join('\n') }, x.readiness.blockers.length + ' blocker(s)') },
      { label: 'Sign-offs', render: x => (x.release.requiredSignoffs.length - x.readiness.missingSignoffs.length) + ' / ' + x.release.requiredSignoffs.length },
      { label: 'Target', render: x => x.release.targetDate || '—' }
    ], list, { onRow: x => go('#/releases/' + x.release.id), empty: 'No releases yet' }))
  ]);
};

ST.pages.release = async (view, id) => {
  const data = await guard(() => GET('/releases/' + encodeURIComponent(id)));
  if (!data) return;
  const r = data.release, ready = data.readiness;
  const draft = r.status === 'DRAFT';
  const post = (path, body) => async () => { const res = await guard(() => POST('/releases/' + encodeURIComponent(r.id) + path, body ? body() : {})); if (res) ST.route(); };
  clear(view);
  append(view, [
    el('div', null, linkBtn('← Releases', () => go('#/releases'))),
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Release ' + r.version),
      el('div', { class: 'row' }, stBadge(r.status), el('span', { class: 'mono small muted' }, r.id), r.name ? el('span', null, r.name) : null,
        r.targetDate ? el('span', { class: 'small muted' }, 'target ' + r.targetDate) : null)),
      el('div', { class: 'row' },
        el('button', { class: 'btn', onclick: async () => {
          const rep = await guard(() => POST('/reports', { type: 'release', releaseId: r.id }));
          if (rep) go('#/report/' + rep.id);
        } }, 'Readiness report'),
        r.status === 'APPROVED' && can('APPROVE') ? el('button', { class: 'btn primary', onclick: post('/released') }, 'Mark released') : null,
        r.status === 'REJECTED' && can('CONFIGURE') ? el('button', { class: 'btn', onclick: post('/reopen') }, 'Reopen') : null)),
    draft ? el('div', { class: 'alert ' + (ready.ready ? 'ok' : 'warn') }, ready.ready ? 'Ready for sign-off.' : el('span', null, el('b', null, 'Blocked: '), ready.blockers.join(' · '))) : null,
    card(r.approvedChecks ? 'Checks (frozen at approval)' : 'Checks', table([
      { label: 'Check', render: c => el('div', null, c.title, c.required ? el('span', { class: 'tag', style: { marginLeft: '6px' } }, 'required') : null) },
      { label: 'Result', render: c => el('span', { class: 'badge ' + (CHECK_CLASS[c.state] || 'st-INFO') }, c.state.replace('_', ' ').toLowerCase()) },
      { label: 'Detail', render: c => el('span', { class: 'small' }, c.detail) },
      { label: '', render: c => draft && can('APPROVE') && c.state !== 'PASS' && c.state !== 'WAIVED' ? linkBtn('Waive', post('/checks/' + c.id + '/waiver', () => ({ reason: prompt('Why is it acceptable to release with "' + c.title + '" ' + c.state.toLowerCase() + '?') || '' }))) : null }
    ], ready.checks)),
    r.items.length ? card('Checklist', el('div', { class: 'stack' }, r.items.map(i => el('label', { class: 'check' },
      el('input', { type: 'checkbox', checked: i.done ? true : null, disabled: !draft || !can('EXECUTE') || null, onchange: async (e) => {
        const res = await guard(() => PUT('/releases/' + encodeURIComponent(r.id) + '/items/' + i.id, { done: e.target.checked }));
        if (res) ST.route();
      } }), i.title, i.by ? el('span', { class: 'small muted' }, ' · ' + i.by + ' ' + fmt.ago(i.at)) : null)))) : null,
    card('Sign-off', table([
      { label: 'Role', render: role => el('b', null, role) },
      { label: 'Decision', render: role => { const s = r.signoffs.find(x => x.role === role); return s ? stBadge(s.decision === 'APPROVE' ? 'PASS' : 'FAIL') : el('span', { class: 'muted' }, 'pending'); } },
      { label: 'By', render: role => { const s = r.signoffs.find(x => x.role === role); return s ? s.user + ' · ' + fmt.date(s.at) + (s.comment ? ' — ' + s.comment : '') : '—'; } },
      { label: '', render: role => draft && (ST.me.roles.includes(role) || ST.me.roles.includes('ADMIN')) ? el('span', { class: 'row' },
          el('button', { class: 'btn small primary', disabled: !ready.ready || null, onclick: post('/signoffs', () => ({ role, decision: 'APPROVE', comment: prompt('Comment (optional)') || null })) }, 'Approve'),
          el('button', { class: 'btn small', onclick: post('/signoffs', () => ({ role, decision: 'REJECT', comment: prompt('Why reject?') || null })) }, 'Reject')) : null }
    ], r.requiredSignoffs))
  ]);
};
