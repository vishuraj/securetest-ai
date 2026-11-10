/* SecureTest AI dashboard — collaboration on findings: manual (tester) findings, retest, comments, evidence and issues. */
'use strict';

const VERIFY_LABEL = {
  PENDING: 'Retest running', AWAITING_TESTER: 'Waiting for a tester', VERIFIED_FIXED: 'Verified fixed',
  STILL_PRESENT: 'Still present', INCONCLUSIVE: 'Retest inconclusive'
};
const VERIFY_CLASS = { PENDING: 'st-RUNNING', AWAITING_TESTER: 'st-AWAITING_APPROVAL', VERIFIED_FIXED: 'st-PASS', STILL_PRESENT: 'st-FAIL', INCONCLUSIVE: 'st-WARN' };

function verificationBadge(v) {
  if (!v || !v.state) return null;
  return el('span', { class: 'badge ' + (VERIFY_CLASS[v.state] || 'st-INFO'), title: v.note || '' }, VERIFY_LABEL[v.state] || v.state);
}

function canContribute() { return can('EXECUTE') || can('REMEDIATE'); }

/** Cards added to the finding page. */
function collabCards(f) {
  return [
    f.stepsToReproduce ? card('Steps to reproduce', el('pre', { style: { whiteSpace: 'pre-wrap' } }, f.stepsToReproduce)) : null,
    retestCard(f),
    attachmentsCard(f),
    issuesCard(f),
    commentsCard(f)
  ];
}

function retestCard(f) {
  const v = f.verification;
  const manual = f.source === 'manual';
  const box = el('div', { class: 'stack' });
  const verdict = (fixed) => async () => {
    const note = prompt(fixed ? 'How was the fix verified? (optional)' : 'What did you observe? (optional)') || '';
    const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/verification', { fixed, note }));
    if (r) { toast(fixed ? 'Marked verified fixed' : 'Marked still present', 'ok'); ST.route(); }
  };
  append(box, [
    el('p', { class: 'small muted', style: { margin: 0 } }, manual
      ? 'A tester re-checks this finding and records whether the fix works.'
      : 'Retest runs the scanner that found this again. If it no longer detects the issue, the finding is marked verified fixed.'),
    v ? kv([['Status', verificationBadge(v)], ['Requested', (v.requestedBy || '') + ' · ' + fmt.date(v.requestedAt)],
      v.jobId ? ['Retest scan', linkBtn(v.jobId, () => go('#/scans'))] : null,
      v.completedAt ? ['Completed', (v.verifiedBy || '') + ' · ' + fmt.date(v.completedAt)] : null, v.note ? ['Note', v.note] : null]) : null,
    el('div', { class: 'row' },
      el('button', { class: 'btn primary', disabled: !can('EXECUTE') || (v && v.state === 'PENDING') || null, onclick: async () => {
        let confirmed = false;
        if (!manual) confirmed = await confirmDialog('Retest', 'Run ' + f.source + ' again to check whether this finding is fixed? Active scanners may need approval.', 'Retest');
        if (!manual && !confirmed) return;
        const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/retest', { confirmed }));
        if (r) { toast(r.mode === 'scan' ? 'Retest scan started' : 'Retest requested', 'ok'); ST.route(); }
      } }, 'Retest'),
      el('button', { class: 'btn', disabled: !can('EXECUTE') || null, onclick: verdict(true) }, 'Mark verified fixed'),
      el('button', { class: 'btn', disabled: !can('EXECUTE') || null, onclick: verdict(false) }, 'Still present'))
  ]);
  return card('Retest', box);
}

function attachmentsCard(f) {
  const list = el('div', { class: 'stack' });
  (f.attachments || []).forEach(a => {
    const url = ST.api + '/findings/' + encodeURIComponent(f.id) + '/attachments/' + encodeURIComponent(a.id);
    list.appendChild(el('div', null,
      a.contentType.startsWith('image/') ? el('a', { href: url, target: '_blank', rel: 'noopener' },
        el('img', { src: url, alt: a.name, style: { maxWidth: '320px', maxHeight: '200px', border: '1px solid var(--border)', borderRadius: '6px', display: 'block' } })) : null,
      el('a', { href: url, target: '_blank', rel: 'noopener' }, a.name), el('span', { class: 'small muted' }, ' · ' + Math.round(a.size / 1024) + ' KB · ' + a.uploadedBy + ' · ' + fmt.ago(a.uploadedAt))));
  });
  const input = el('input', { type: 'file', accept: 'image/png,image/jpeg,image/gif,image/webp,application/pdf,text/plain,application/json,.har', 'aria-label': 'Attach evidence' });
  input.addEventListener('change', async () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { toast('Attachments are limited to 5 MB', 'err'); return; }
    const data = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = rej; r.readAsDataURL(file); });
    const type = file.name.endsWith('.har') ? 'application/json' : (file.type || 'text/plain');
    const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/attachments', { name: file.name, contentType: type, dataBase64: data }));
    if (r) { toast('Attached ' + file.name, 'ok'); ST.route(); }
  });
  return card('Evidence attachments', (f.attachments || []).length ? list : el('p', { class: 'muted small' }, 'Screenshots, request/response captures (HAR), logs or PDFs.'),
    canContribute() ? el('div', { class: 'row', style: { marginTop: '8px' } }, input) : null);
}

function issuesCard(f) {
  const box = el('div', { class: 'stack' });
  const links = Object.values(f.issues || {});
  links.forEach(l => box.appendChild(el('div', { class: 'row' }, el('b', null, l.tracker === 'jira' ? 'Jira' : 'GitHub'),
    el('a', { href: l.url, target: '_blank', rel: 'noopener noreferrer' }, l.key), stBadge((l.state || '').toUpperCase()),
    el('span', { class: 'small muted' }, l.checkedAt ? 'checked ' + fmt.ago(l.checkedAt) : 'created ' + fmt.ago(l.createdAt)),
    linkBtn('Refresh', async () => { const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/issues/' + l.tracker + '/refresh', {})); if (r) ST.route(); }))));
  const buttons = el('div', { class: 'row' });
  box.appendChild(buttons);
  guard(() => GET('/integrations/issue-trackers')).then(trackers => {
    (trackers || []).filter(t => !(f.issues || {})[t.id]).forEach(t => buttons.appendChild(el('button', { class: 'btn', disabled: !canContribute() || null, onclick: async () => {
      const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/issues', { tracker: t.id }));
      if (r) { toast('Issue created in ' + t.name, 'ok'); ST.route(); }
    } }, 'Create ' + t.name + ' issue (' + t.target + ')')));
    if (!(trackers || []).length && !links.length) buttons.appendChild(el('span', { class: 'small muted' },
      'Configure securetest.integrations.jira or .github to create issues from findings.'));
  });
  return card('Issues', box);
}

function commentsCard(f) {
  const text = el('textarea', { rows: 3, placeholder: 'Add a comment for developers, testers or reviewers…', 'aria-label': 'Comment', style: { width: '100%' } });
  return card('Comments (' + (f.comments || []).length + ')',
    el('ul', { class: 'timeline' }, (f.comments || []).map(c => el('li', null, el('b', null, c.author), ' · ', el('span', { class: 'small muted' }, fmt.date(c.at)),
      el('div', { style: { whiteSpace: 'pre-wrap' } }, c.text)))),
    canContribute() ? el('div', { class: 'stack' }, text, el('div', null, el('button', { class: 'btn', onclick: async () => {
      if (!text.value.trim()) return;
      const r = await guard(() => POST('/findings/' + encodeURIComponent(f.id) + '/comments', { text: text.value }));
      if (r) ST.route();
    } }, 'Comment'))) : null);
}

/** "Report finding" dialog: a tester's manual finding (pentest / exploratory testing). */
function reportFindingDialog(defaults = {}) {
  const fields = {
    title: el('input', { type: 'text', required: true, maxlength: 300 }),
    severity: el('select', null, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => el('option', { value: s, selected: s === 'MEDIUM' ? true : null }, ST.T.severity[s]))),
    moduleId: el('select', null, ST.modules.map(m => el('option', { value: m.id, selected: m.id === (defaults.moduleId || 'api-security') ? true : null }, m.name))),
    category: el('input', { type: 'text', placeholder: 'e.g. Broken access control' }),
    cwe: el('input', { type: 'text', placeholder: 'e.g. CWE-639' }),
    asset: el('input', { type: 'text', placeholder: 'URL, endpoint, screen or component' }),
    description: el('textarea', { rows: 3 }),
    stepsToReproduce: el('textarea', { rows: 4, placeholder: '1. …\n2. …' }),
    impact: el('textarea', { rows: 2 }),
    remediation: el('textarea', { rows: 2 }),
    evidence: el('textarea', { rows: 3, placeholder: 'Request/response excerpt (secrets are redacted)' })
  };
  const row = (label, n) => el('label', { class: 'field', style: { display: 'block' } }, label, n);
  const body = el('div', { class: 'stack' },
    row('Title *', fields.title), el('div', { class: 'grid g2' }, row('Severity', fields.severity), row('Module', fields.moduleId)),
    el('div', { class: 'grid g2' }, row('Category', fields.category), row('CWE', fields.cwe)), row('Affected asset', fields.asset),
    row('Description', fields.description), row('Steps to reproduce', fields.stepsToReproduce), row('Impact', fields.impact),
    row('Recommended fix', fields.remediation), row('Evidence', fields.evidence));
  const submit = el('button', { class: 'btn primary', onclick: async () => {
    if (!fields.title.value.trim()) { toast('Title is required', 'err'); return; }
    const payload = Object.fromEntries(Object.entries(fields).map(([k, n]) => [k, n.value.trim() || null]));
    if (defaults.engagementId) payload.engagementId = defaults.engagementId;
    const r = await guard(() => POST('/findings', payload));
    if (r) { clear(document.getElementById('modalRoot')); toast('Reported ' + r.id, 'ok'); if (defaults.after) defaults.after(r); else go('#/finding/' + r.id); }
  } }, 'Report finding');
  modal('Report a finding', [body], [submit]);
}
