// cg-researcher local UI. No dependencies, no inline script, no HTML-string sinks:
// every server or model string is rendered with textContent.
'use strict';

const $ = (s, r = document) => r.querySelector(s);
// f32 settings arrive widened to f64 (0.30000001...); show 2 decimals.
const r2 = (x) => (typeof x === 'number' ? Math.round(x * 100) / 100 : x);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const TOKEN_KEY = 'cg-researcher-session';
let status = null;
let extDefaults = {};
const FAMILY = { anthropic: /^claude/i, xai: /^grok/i };
let busy = false;
// Client-side pre-checks only; the server enforces its own limits.
let limits = { max_bytes: 10 * 1024 * 1024, max_per_turn: 4 };

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}

function token() { return sessionStorage.getItem(TOKEN_KEY); }

function lock(reason) {
  sessionStorage.removeItem(TOKEN_KEY);
  document.body.classList.add('locked');
  $$('[data-panel]').forEach(p => { p.hidden = true; });
  $('#lockedTitle').textContent = reason === 'expired' ? 'Session ended' : 'Not paired';
  $('#lockedWhy').textContent = reason === 'expired'
    ? 'The server no longer recognizes this session (it restarted or the session expired).'
    : '';
  $('#locked').hidden = false;
}

class ApiError extends Error {}

async function api(path, body) {
  const t = token();
  if (!t) { lock(); throw new ApiError('not paired'); }
  const opts = { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: 'Bearer ' + t }, cache: 'no-store' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(path, opts);
  } catch (_) {
    throw new ApiError('Cannot reach the cg-researcher server. Is `cg-researcher serve` (or the app) still running?');
  }
  if (r.status === 401) { lock('expired'); throw new ApiError('session expired'); }
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  return { status: r.status, data };
}

const why = (r) => (r.data && r.data.error) || ('HTTP ' + r.status);
const errText = (e) => String((e && e.message) || e);

// Wrap an async UI handler so failures surface in `out` (or are dropped when the
// page has locked) instead of becoming unhandled rejections.
function guard(fn, out) {
  return async (...args) => {
    try {
      await fn(...args);
    } catch (e) {
      if (document.body.classList.contains('locked')) return;
      const o = typeof out === 'function' ? out() : out && $(out);
      if (o) { o.textContent = errText(e); o.className = 'bad'; }
    }
  };
}

function say(sel, text, kind = 'muted') {
  const o = $(sel);
  o.textContent = text;
  o.className = kind;
}

// Pairing: `cg-researcher ui` opens /#p=<single-use code>. Exchange it for a
// session token, then scrub it from the URL and history entry.
async function pair() {
  const m = location.hash.match(/^#p=([0-9a-f]{64})$/);
  history.replaceState(null, '', location.pathname);
  if (!m) return !!token();
  try {
    const r = await fetch('/api/session', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pair: m[1] }), cache: 'no-store',
    });
    if (!r.ok) return false;
    const d = await r.json();
    sessionStorage.setItem(TOKEN_KEY, d.session);
    return true;
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------------ tabs
function showTab(name) {
  if (document.body.classList.contains('locked')) return;
  $$('.tabs button').forEach(b => {
    const on = b.dataset.tab === name;
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  });
  $$('[data-panel]').forEach(p => { p.hidden = p.id !== 'tab-' + name; });
  if (name === 'chat') $('#q').focus();
  else guard(refresh, '#tab-' + name + ' [role=status]')();
}

function onTabKey(e) {
  const tabs = $$('.tabs button');
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  let j = null;
  if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
  if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
  if (e.key === 'Home') j = 0;
  if (e.key === 'End') j = tabs.length - 1;
  if (j === null) return;
  e.preventDefault();
  tabs[j].focus();
  showTab(tabs[j].dataset.tab);
}

// ------------------------------------------------------------ chat
let pendingFiles = [];

function readB64(file) {
  return new Promise((ok, bad) => {
    const fr = new FileReader();
    fr.onload = () => ok(String(fr.result).split(',', 2)[1] || '');
    fr.onerror = () => bad(fr.error);
    fr.readAsDataURL(file);
  });
}

function addMsg(kind, text) {
  $('#empty').hidden = true;
  const m = el('div', { class: 'msg ' + kind });
  m.append(el('div', { class: 'body' }, text));
  $('#log').append(m);
  m.scrollIntoView({ block: 'end' });
  return m;
}

function meta(r) {
  const box = el('div', { class: 'meta' });
  const model = r.answer_model || 'paused';
  box.append(el('span', { class: 'tag' + (model.startsWith('external') ? ' ext' : '') }, model));
  if (r.tainted) box.append(el('span', { class: 'tag warn', title: 'Turn contained untrusted content' }, 'tainted'));
  if (r.blocked) box.append(el('span', { class: 'tag warn' }, 'blocked'));
  if (r.sources && r.sources.length) {
    const ul = el('ul', { class: 'chips', 'aria-label': 'Sources' });
    for (const src of r.sources) ul.append(el('li', { title: src }, src));
    box.append(ul);
  }
  if (r.tools && r.tools.length) box.append(el('span', {}, 'tools: ' + r.tools.map(t => t.tool + ':' + t.decision).join(', ')));
  if (r.path && r.path.length) {
    const d = el('details', { class: 'path' });
    d.append(el('summary', {}, 'route (' + r.path.length + ' steps)'), el('span', {}, r.path.join(' → ')));
    box.append(d);
  }
  return box;
}

function copyButton(text) {
  const b = el('button', { type: 'button', class: 'ghost small copy', 'aria-label': 'Copy answer' }, 'Copy');
  b.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      b.textContent = 'Copied';
    } catch (_) {
      b.textContent = 'Copy failed';
    }
    setTimeout(() => { b.textContent = 'Copy'; }, 1500);
  });
  return b;
}

function setBusy(on) {
  busy = on;
  const btn = $('#chatForm button[type=submit]');
  btn.disabled = on;
  btn.textContent = on ? 'Working…' : 'Send';
  $('#log').setAttribute('aria-busy', String(on));
}

async function send(payload, label) {
  if (busy) return;
  setBusy(true);
  const bubble = addMsg('bot pending', 'Thinking…');
  const body = $('.body', bubble);
  const t0 = Date.now();
  const tick = setInterval(() => { body.textContent = 'Thinking… ' + Math.round((Date.now() - t0) / 1000) + 's'; }, 1000);
  try {
    const r = await api('/query', payload);
    clearInterval(tick);
    bubble.classList.remove('pending');
    if (r.status !== 200) {
      bubble.classList.add('error');
      body.textContent = 'Error: ' + why(r);
      return;
    }
    const data = r.data;
    body.textContent = data.answer;
    const actions = el('div', { class: 'actions' }, copyButton(data.answer || ''));
    bubble.append(meta(data), actions);
    if (data.needs_confirm) {
      const who = data.external_label || label || 'the external model';
      const row = el('div', { class: 'confirm' });
      const yes = el('button', { class: 'primary', type: 'button' }, 'Ask ' + who);
      const no = el('button', { type: 'button' }, 'Answer locally');
      yes.addEventListener('click', () => { if (busy) return; row.remove(); send({ ...payload, confirm_online: true }); });
      no.addEventListener('click', () => { if (busy) return; row.remove(); send({ ...payload, confirm_online: false }); });
      row.append(yes, no);
      bubble.append(row);
    }
    bubble.scrollIntoView({ block: 'nearest' });
  } catch (e) {
    bubble.classList.remove('pending');
    bubble.classList.add('error');
    body.textContent = errText(e);
  } finally {
    clearInterval(tick);
    setBusy(false);
  }
}

function setFiles(list) {
  const all = Array.from(list);
  const over = all.filter(f => f.size > limits.max_bytes).map(f => f.name);
  const ok = all.filter(f => f.size <= limits.max_bytes);
  pendingFiles = ok.slice(0, limits.max_per_turn);
  const notes = [];
  if (ok.length > limits.max_per_turn) notes.push('only the first ' + limits.max_per_turn + ' files are attached');
  if (over.length) notes.push('skipped (over ' + Math.round(limits.max_bytes / 1048576) + ' MB): ' + over.join(', '));
  const fl = $('#fileList');
  fl.textContent = pendingFiles.map(f => f.name).join(', ') + (notes.length ? ' — ' + notes.join('; ') : '');
  fl.className = 'files ' + (notes.length ? 'warn' : 'muted');
}

async function onChat(ev) {
  ev.preventDefault();
  if (busy) return;
  const q = $('#q').value.trim();
  if (!q) return;
  const route = $('input[name=route]:checked').value;
  const attachments = [];
  try {
    for (const f of pendingFiles) attachments.push({ name: f.name, data_base64: await readB64(f) });
  } catch (e) {
    say('#fileList', 'Could not read attachment: ' + errText(e), 'files bad');
    return;
  }
  const payload = { query: q, attachments };
  if (route === 'local') payload.confirm_online = false;
  if (route === 'external') payload.prefer_external = true;
  addMsg('user', q + (attachments.length ? '\n[' + attachments.map(a => a.name).join(', ') + ']' : ''));
  $('#q').value = '';
  pendingFiles = [];
  $('#files').value = '';
  say('#fileList', '', 'files muted');
  await send(payload);
}

function newChat() {
  if (busy) return;
  $$('#log .msg').forEach(m => m.remove());
  $('#empty').hidden = false;
  $('#q').focus();
}

// ------------------------------------------------------------ settings
async function saveSettings(set, msgSel, okText) {
  say(msgSel, 'Applying…');
  let r = await api('/api/settings', { set });
  if (r.status === 409) {
    const list = (r.data.relaxations || []).join('\n• ');
    if (!window.confirm('This loosens policy:\n• ' + list + '\n\nIt will be recorded in the audit log. Continue?')) {
      say(msgSel, 'Cancelled.');
      return false;
    }
    r = await api('/api/settings', { set, ack_relax: true });
  }
  if (r.status !== 200) { say(msgSel, 'Refused: ' + why(r), 'bad'); return false; }
  say(msgSel, okText, 'ok');
  await refresh();
  return true;
}

function num(id) { const v = $(id).value; return v === '' ? undefined : Number(v); }

function onSwitch() {
  const set = {
    'llm.model': $('#localModel').value.trim(),
    'llm.vision_model': $('#visionModel').value.trim(),
    'app.mode': $('#mode').value,
    'external.enabled': $('#extEnabled').checked,
    'external.provider': $('#provider').value,
    'external.model': $('#extModel').value.trim(),
    'external.xai_region': $('#xaiRegion').value,
  };
  const mt = num('#localMax'); if (mt !== undefined) set['llm.max_tokens'] = Math.trunc(mt);
  const tp = num('#localTemp'); if (tp !== undefined) set['llm.temperature'] = tp;
  return saveSettings(set, '#modelsMsg', 'Applied and autotuned.');
}

const RULE_BOOLS = ['send_local_context', 'allow_attachment_text', 'allow_images', 'allow_telegram'];
const RULE_INTS = ['max_calls_per_hour', 'max_calls_per_day', 'max_output_tokens', 'max_outbound_chars'];

function onRules() {
  const set = {};
  for (const k of RULE_BOOLS) set['external.rules.' + k] = $('#r_' + k).checked;
  for (const k of RULE_INTS) { const v = num('#r_' + k); if (v !== undefined) set['external.rules.' + k] = Math.trunc(v); }
  const t = num('#r_temperature'); if (t !== undefined) set['external.rules.temperature'] = t;
  return saveSettings(set, '#rulesMsg', 'Rules saved.');
}

async function withButton(btn, fn) {
  btn.disabled = true;
  try { await fn(); } finally { btn.disabled = false; }
}

async function onRetune(ev) {
  await withButton(ev.currentTarget, async () => {
    say('#modelsMsg', 'Probing…');
    const r = await api('/api/autotune', {});
    if (r.status === 200) say('#modelsMsg', 'Autotune complete.', 'ok');
    else say('#modelsMsg', 'Autotune failed: ' + why(r), 'bad');
    await refresh();
  });
}

// Switching provider must not leave the other vendor's model id behind
// (e.g. xAI + claude-*), which would only fail later at call time.
function onProvider() {
  const p = $('#provider').value;
  const model = $('#extModel').value.trim();
  const other = Object.keys(FAMILY).find(k => k !== p && FAMILY[k].test(model));
  if ((!model || other) && extDefaults[p]) $('#extModel').value = extDefaults[p];
  if (status && status.external.provider !== p) fillList('#extList', extDefaults[p] ? [extDefaults[p]] : []);
  syncProviderFields();
}

function syncProviderFields() {
  const xai = $('#provider').value === 'xai';
  $('#xaiRegion').disabled = !xai;
  $('#xaiRegion').closest('label').classList.toggle('off', !xai);
}

// ------------------------------------------------------------ keys
async function onKey(ev) {
  ev.preventDefault();
  const form = ev.currentTarget;
  const input = $('input', form);
  const key = input.value;
  input.value = ''; // never keep it in the DOM
  const r = await api('/api/keys', { provider: form.dataset.provider, key });
  if (r.status === 200) say('#keysMsg', 'Saved to ' + r.data.backend + '.', 'ok');
  else say('#keysMsg', 'Refused: ' + why(r), 'bad');
  await refresh();
}

async function onKeyDelete(ev) {
  const form = ev.currentTarget.closest('form');
  if (!window.confirm('Delete the stored ' + form.dataset.provider + ' key?')) return;
  const r = await api('/api/keys/delete', { provider: form.dataset.provider });
  if (r.status === 200) say('#keysMsg', 'Deleted' + (r.data.external_disabled ? '; external fallback disabled.' : '.'), 'ok');
  else say('#keysMsg', 'Failed: ' + why(r), 'bad');
  await refresh();
}

// ------------------------------------------------------------ render
function dl(target, pairs) {
  const d = $(target);
  d.replaceChildren();
  for (const [k, v] of pairs) d.append(el('dt', {}, k), el('dd', {}, v === undefined || v === null ? '—' : String(v)));
}

function tuneRows(p, t) {
  if (!p || !t) return [['status', 'not tuned yet (enable external and switch)']];
  return [['model', p.provider + ' / ' + p.model], ['source', p.source], ['context', p.context_tokens + ' tokens'],
    ['max output', t.max_tokens], ['temperature', r2(t.temperature)], ['top_k', t.top_k],
    ['context budget', t.context_chars + ' chars'], ['tools', t.tools ? 'yes' : 'no'], ['vision', t.vision ? 'yes' : 'no']];
}

function fillList(id, items) {
  const l = $(id);
  l.replaceChildren(...items.map(x => el('option', { value: x })));
}

async function refresh() {
  const { status: code, data } = await api('/api/status');
  if (code !== 200) return;
  status = data;
  if (data.attachments) limits = data.attachments;
  const ext = data.external;
  const pill = $('#modePill');
  pill.textContent = data.mode + (ext.built ? ' · ' + ext.provider : '');
  pill.classList.toggle('hybrid', data.mode === 'hybrid');
  $('#extRouteName').textContent = ext.built ? 'Ask ' + (ext.provider === 'anthropic' ? 'Claude' : 'Grok') : 'External (off)';
  const extRadio = $('#extRouteLabel input');
  extRadio.disabled = !ext.built;
  $('#extRouteLabel').classList.toggle('off', !ext.built);
  if (!ext.built && extRadio.checked) $('input[name=route][value=auto]').checked = true;
  if (data.corpus_dir) $('#corpusDir').textContent = data.corpus_dir;
  $('#chatHint').textContent = data.indexed_chunks
    ? data.indexed_chunks + (data.indexed_chunks === 1 ? ' chunk' : ' chunks') + ' indexed' + (data.local.healthy ? '' : ' · local model unreachable')
    : 'Corpus not indexed yet: add files, then Status → Reindex corpus';
  $('#chatHint').className = (data.indexed_chunks && data.local.healthy) ? 'muted' : 'warn';

  if (document.activeElement?.closest('#tab-models') == null) {
    $('#localModel').value = data.local.model;
    $('#visionModel').value = data.local.vision_model;
    $('#localMax').value = data.local.tuning.max_tokens;
    $('#localTemp').value = r2(data.local.tuning.temperature);
    $('#mode').value = data.mode;
    $('#extEnabled').checked = ext.enabled;
    $('#provider').value = ext.provider;
    $('#extModel').value = ext.model;
    $('#xaiRegion').value = ext.xai_region;
  }
  dl('#localTune', tuneRows(data.local.profile, data.local.tuning));
  dl('#extTune', tuneRows(ext.profile, ext.tuning));

  if (document.activeElement?.closest('#tab-rules') == null) {
    for (const k of RULE_BOOLS) $('#r_' + k).checked = !!ext.rules[k];
    for (const k of RULE_INTS) $('#r_' + k).value = ext.rules[k];
    $('#r_temperature').value = r2(ext.rules.temperature);
  }

  for (const form of $$('#tab-keys form')) {
    const on = !!ext.keys[form.dataset.provider];
    const s = $('[data-state]', form);
    s.textContent = on ? 'configured' : 'not configured';
    s.className = 'state ' + (on ? 'on' : 'off');
  }

  dl('#health', [['local server', data.local.healthy ? 'reachable' : 'unreachable'], ['endpoint', data.local.base_url],
    ['indexed chunks', data.indexed_chunks], ['corpus folder', data.corpus_dir],
    ['external client', ext.built ? ext.label : 'not constructed'],
    ['HTTP can approve writes', data.http_can_approve_writes ? 'yes' : 'no']]);
  dl('#budget', [['last hour', ext.budget_used.last_hour + ' / ' + ext.rules.max_calls_per_hour],
    ['last 24h', ext.budget_used.last_day + ' / ' + ext.rules.max_calls_per_day], ['resets', 'on restart (in-memory)']]);
  const tools = data.tools || [];
  $('#tools').replaceChildren(...(tools.length
    ? tools.map(t => el('li', { class: t.write ? 'w' : '', title: t.write ? 'write: needs CLI confirmation' : 'read' }, t.name))
    : [el('li', { class: 'none' }, 'No tools enabled. Enable connectors in cg.toml and restart.')]));
  const edges = data.graph_edges || (data.graph || []).map(n => ({ node: n, to: [] }));
  const visible = (to) => (to || []).filter(n => n !== '__end__');
  $('#graph').replaceChildren(...edges.map(e => el('li', {},
    el('span', { class: 'node' }, e.node),
    el('span', { class: 'muted' }, visible(e.to).length ? ' → ' + visible(e.to).join(' | ') : ' (end)'))));

  syncProviderFields();
  const m = await api('/api/models');
  if (m.status === 200) {
    extDefaults = m.data.external_defaults || {};
    fillList('#localList', m.data.local || []);
    fillList('#extList', (m.data.external && m.data.external.length) ? m.data.external : Object.values(m.data.external_defaults || {}));
  }
}

async function onVerify(ev) {
  await withButton(ev.currentTarget, async () => {
    say('#verifyMsg', 'Verifying…');
    const r = await api('/api/audit/verify');
    if (r.status === 200 && r.data.ok) say('#verifyMsg', 'Chain OK: ' + r.data.records + ' records', 'ok');
    else say('#verifyMsg', 'Chain check FAILED: ' + why(r), 'bad');
  });
}

async function onReindex(ev) {
  await withButton(ev.currentTarget, async () => {
    say('#verifyMsg', 'Reindexing…');
    const r = await api('/api/reindex', {});
    if (r.status === 200) {
      say('#verifyMsg', 'Indexed ' + r.data.files + ' files → ' + r.data.chunks + ' chunks (' + r.data.embedded + ' embedded)', 'ok');
    } else {
      say('#verifyMsg', 'Reindex failed: ' + why(r), 'bad');
    }
    await refresh();
  });
}

// ------------------------------------------------------------ boot
document.addEventListener('DOMContentLoaded', async () => {
  $$('.tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  $('.tabs').addEventListener('keydown', onTabKey);
  $('#chatForm').addEventListener('submit', guard(onChat, () => $('#fileList')));
  $('#q').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      if (!busy) $('#chatForm').requestSubmit();
    }
  });
  $$('.ex').forEach(b => b.addEventListener('click', () => { $('#q').value = b.textContent; $('#q').focus(); }));
  $('#newChat').addEventListener('click', newChat);
  $('#files').addEventListener('change', e => setFiles(e.target.files));
  $('#provider').addEventListener('change', onProvider);
  $('#switchBtn').addEventListener('click', guard(onSwitch, '#modelsMsg'));
  $('#retuneBtn').addEventListener('click', guard(onRetune, '#modelsMsg'));
  $('#rulesBtn').addEventListener('click', guard(onRules, '#rulesMsg'));
  $$('#tab-keys form').forEach(f => {
    f.addEventListener('submit', guard(onKey, '#keysMsg'));
    $('[data-del]', f).addEventListener('click', guard(onKeyDelete, '#keysMsg'));
  });
  $('#refreshBtn').addEventListener('click', guard(refresh, '#verifyMsg'));
  $('#reindexBtn').addEventListener('click', guard(onReindex, '#verifyMsg'));
  $('#verifyBtn').addEventListener('click', guard(onVerify, '#verifyMsg'));
  if (!(await pair())) { lock(); return; }
  document.body.classList.remove('locked');
  $('#locked').hidden = true;
  showTab('chat');
  guard(refresh, '#chatHint')();
});
