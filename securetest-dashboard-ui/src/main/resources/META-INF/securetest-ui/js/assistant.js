/* SecureTest AI dashboard — security assistant (opt-in AI chat about this application's findings). */
'use strict';

ST.chat = ST.chat || { history: [], findingId: null };

/** Renders an answer safely: fenced code blocks become <pre>, everything else is text (never HTML). */
function renderAnswer(text) {
  const box = el('div', { class: 'stack', style: { gap: '6px' } });
  const parts = String(text || '').split(/```[a-zA-Z0-9_-]*\n?/);
  parts.forEach((p, i) => {
    if (!p.trim()) return;
    box.appendChild(i % 2 ? el('pre', null, p.replace(/\n$/, '')) : el('div', { style: { whiteSpace: 'pre-wrap' } }, p.trim()));
  });
  return box;
}

function aiEnabled() { return !!(ST.me && ST.me.policy && ST.me.policy.aiEnabled); }

ST.pages.assistant = async (view, _id, params) => {
  if (params.finding && params.finding !== ST.chat.findingId) { ST.chat = { history: [], findingId: params.finding }; }
  clear(view);
  if (!aiEnabled()) {
    append(view, [el('h1', null, 'Security assistant'), el('div', { class: 'alert info' },
      'The assistant answers questions about your findings using Claude. It is off: set securetest.ai.enabled=true and ',
      'securetest.ai.data-processing-approved=true (plus an API key) to turn it on. Findings are redacted before they are sent.')]);
    return;
  }
  const log = el('div', { class: 'stack', role: 'log', 'aria-live': 'polite' });
  const input = el('textarea', { rows: 3, placeholder: ST.chat.findingId ? 'Ask about ' + ST.chat.findingId + '…' : 'e.g. What should we fix first before the release?', 'aria-label': 'Question', style: { width: '100%' } });
  const send = el('button', { class: 'btn primary' }, 'Ask');
  const draw = () => {
    clear(log);
    if (!ST.chat.history.length) log.appendChild(el('p', { class: 'muted' }, ST.chat.findingId
      ? 'Ask how to fix ' + ST.chat.findingId + ', whether it is a false positive, or how to test it.'
      : 'Ask what the findings mean, what to fix first, or how to fix a specific one.'));
    ST.chat.history.forEach(t => log.appendChild(el('div', { class: 'card tight', style: t.role === 'user' ? { background: 'var(--accent-soft)' } : null },
      el('div', { class: 'small muted' }, t.role === 'user' ? ST.me.name : 'Assistant' + (t.meta ? ' · ' + t.meta : '')),
      t.role === 'user' ? el('div', { style: { whiteSpace: 'pre-wrap' } }, t.text) : renderAnswer(t.text))));
  };
  const ask = async () => {
    const message = input.value.trim();
    if (!message) return;
    send.disabled = true;
    const history = ST.chat.history.map(t => ({ role: t.role, text: t.text }));
    ST.chat.history.push({ role: 'user', text: message });
    input.value = '';
    draw();
    log.appendChild(el('p', { class: 'muted' }, 'Thinking…'));
    const r = await guard(() => POST('/assistant', { message, history, findingId: ST.chat.findingId }));
    send.disabled = false;
    if (!r) { ST.chat.history.pop(); draw(); return; }
    if (r.status === 'OK' || r.status === 'TRUNCATED') {
      ST.chat.history.push({ role: 'assistant', text: r.answer + (r.status === 'TRUNCATED' ? '\n\n(answer cut off)' : ''),
        meta: r.provenance.model + ' · ' + r.provenance.outputTokens + ' tokens' });
    } else {
      ST.chat.history.pop();
      toast(r.message || r.status, 'err', 8000);
    }
    draw();
  };
  send.addEventListener('click', ask);
  input.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) ask(); });
  append(view, [
    el('div', { class: 'page-head' }, el('div', { class: 'grow' }, el('h1', null, 'Security assistant'),
      el('div', { class: 'muted' }, 'Answers come from your findings (redacted) and Claude. They are suggestions: check them, and verify fixes with Retest.')),
      el('div', { class: 'row' },
        ST.chat.findingId ? el('span', { class: 'tag' }, 'about ', linkBtn(ST.chat.findingId, () => go('#/finding/' + ST.chat.findingId))) : null,
        el('button', { class: 'btn', onclick: () => { ST.chat = { history: [], findingId: null }; go('#/assistant'); ST.route(); } }, 'New conversation'))),
    card(null, log, el('div', { class: 'stack', style: { marginTop: '12px' } }, input, el('div', { class: 'row' }, send, el('span', { class: 'small muted' }, 'Ctrl+Enter to send'))))
  ]);
  draw();
  input.focus();
};
