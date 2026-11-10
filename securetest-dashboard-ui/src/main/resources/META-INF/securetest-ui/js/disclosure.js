/* SecureTest AI dashboard — vulnerability disclosure program: triage of external researchers' reports. */
'use strict';

ST.pages.disclosures = async (view, id) => {
  const data = await guard(() => GET('/disclosures'));
  if (!data) return;
  clear(view);
  if (!data.enabled && !data.reports.length) {
    append(view, [el('h1', null, 'Vulnerability reports'), el('div', { class: 'alert info' },
      'The vulnerability disclosure program is off. Set securetest.disclosure.enabled=true (and securetest.disclosure.contact) to publish ',
      el('code', null, '/.well-known/security.txt'), ' and a public report form for security researchers. Reports then arrive here for triage.')]);
    return;
  }
  const open = (r) => {
    const severity = el('select', { 'aria-label': 'Severity' }, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => el('option', { value: s, selected: s === 'MEDIUM' ? true : null }, ST.T.severity[s])));
    const module = el('select', { 'aria-label': 'Module' }, ST.modules.map(m => el('option', { value: m.id, selected: m.id === 'api-security' ? true : null }, m.name)));
    const note = el('textarea', { rows: 2, placeholder: 'Note to the team (and to the researcher, if you reply by e-mail)' });
    const decide = (decision) => el('button', { class: 'btn' + (decision === 'ACCEPTED' ? ' primary' : ''), disabled: !can('REMEDIATE') || null, onclick: async () => {
      const res = await guard(() => POST('/disclosures/' + encodeURIComponent(r.id) + '/triage', { decision, note: note.value || null, severity: severity.value, moduleId: module.value }));
      if (res) { clear(document.getElementById('modalRoot')); toast(r.id + ': ' + decision.toLowerCase().replace('_', ' '), 'ok'); if (res.findingId) go('#/finding/' + res.findingId); else ST.route(); }
    } }, { ACCEPTED: 'Accept → finding', REJECTED: 'Reject', DUPLICATE: 'Duplicate', NEEDS_INFO: 'Needs info', OUT_OF_SCOPE: 'Out of scope' }[decision]);
    modal(r.id + ' · ' + r.title, [el('div', { class: 'stack' },
      kv([['Received', fmt.date(r.receivedAt)], ['Status', stBadge(r.status)], ['Asset', r.asset], ['Reporter', [r.reporterName, r.reporterEmail].filter(Boolean).join(' · ') || 'anonymous'],
        ['Credit', r.publicCredit ? 'may be credited by name' : 'no public credit'], r.findingId ? ['Finding', linkBtn(r.findingId, () => go('#/finding/' + r.findingId))] : null]),
      el('h3', null, 'Description'), el('pre', { style: { whiteSpace: 'pre-wrap' } }, r.description || '—'),
      r.stepsToReproduce ? [el('h3', null, 'Steps to reproduce'), el('pre', { style: { whiteSpace: 'pre-wrap' } }, r.stepsToReproduce)] : null,
      r.impact ? [el('h3', null, 'Impact'), el('p', null, r.impact)] : null,
      el('p', { class: 'small muted' }, 'This text comes from outside your organisation. Treat links and attachments with care.'),
      el('div', { class: 'grid g2' }, el('label', { class: 'field' }, 'Severity', severity), el('label', { class: 'field' }, 'Module', module)), note)],
      [decide('ACCEPTED'), decide('NEEDS_INFO'), decide('DUPLICATE'), decide('OUT_OF_SCOPE'), decide('REJECTED')], { width: '760px' });
  };
  const fresh = data.reports.filter(r => r.status === 'NEW').length;
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Vulnerability reports'),
      el('div', { class: 'muted' }, fresh + ' new · reports from external researchers through ', el('code', null, ST.base + '/disclose'), ' and ',
        el('code', null, '/.well-known/security.txt')))),
    card(null, table([
      { label: 'Report', sort: r => r.id, render: r => el('div', null, el('b', null, r.title), el('div', { class: 'small muted' }, r.id + (r.asset ? ' · ' + r.asset : ''))) },
      { label: 'Status', sort: r => r.status, render: r => stBadge(r.status) },
      { label: 'Reporter', render: r => r.reporterName || r.reporterEmail || el('span', { class: 'muted' }, 'anonymous') },
      { label: 'Received', sort: r => r.receivedAt, render: r => fmt.ago(r.receivedAt) },
      { label: 'Finding', render: r => r.findingId ? linkBtn(r.findingId, () => go('#/finding/' + r.findingId)) : '—' }
    ], data.reports, { onRow: open, empty: 'No reports yet' }))
  ]);
  if (id) { const r = data.reports.find(x => x.id === id); if (r) open(r); }
};
