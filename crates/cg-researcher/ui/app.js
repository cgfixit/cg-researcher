// cg-researcher local UI. No dependencies, no inline script, no HTML-string sinks:
// every server or model string is rendered with textContent.
'use strict';

const $ = (s, r = document) => r.querySelector(s);
// f32 settings arrive widened to f64 (0.30000001...); show 2 decimals.
const r2 = (x) => (typeof x === 'number' ? Math.round(x * 100) / 100 : x);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const TOKEN_KEY = 'cg-researcher-session';
let status = null;

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

function lock() {
  sessionStorage.removeItem(TOKEN_KEY);
  $$('[data-panel]').forEach(p => { p.hidden = true; });
  $('#locked').hidden = false;
}

async function api(path, body) {
  const t = token();
  if (!t) { lock(); throw new Error('not paired'); }
  const opts = { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: 'Bearer ' + t }, cache: 'no-store' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401) { lock(); throw new Error('session expired'); }
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  return { status: r.status, data };
}

// Pairing: `cg-researcher ui` opens /#p=<single-use code>. Exchange it for a
// session token, then scrub it from the URL and history entry.
async function pair() {
  const m = location.hash.match(/^#p=([0-9a-f]{64})$/);
  history.replaceState(null, '', location.pathname);
  if (!m) return !!token();
  const r = await fetch('/api/session', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pair: m[1] }), cache: 'no-store',
  });
  if (!r.ok) return false;
  const d = await r.json();
  sessionStorage.setItem(TOKEN_KEY, d.session);
  return true;
}

// ------------------------------------------------------------ tabs
function showTab(name) {
  $$('.tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  $$('[data-panel]').forEach(p => { p.hidden = p.id !== 'tab-' + name; });
  if (name !== 'chat') refresh();
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
  const m = el('div', { class: 'msg ' + kind }, text);
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
  if (r.sources && r.sources.length) box.append(el('span', {}, 'sources: ' + r.sources.join(', ')));
  if (r.tools && r.tools.length) box.append(el('span', {}, 'tools: ' + r.tools.map(t => t.tool + ':' + t.decision).join(', ')));
  if (r.path) box.append(el('span', {}, r.path.join(' → ')));
  return box;
}

async function send(payload, label) {
  const btn = $('#chatForm button[type=submit]');
  btn.disabled = true;
  const bubble = addMsg('bot', '…');
  try {
    const { status: code, data } = await api('/query', payload);
    if (code !== 200) { bubble.textContent = 'Error ' + code + ': ' + (data.error || 'request failed'); return; }
    bubble.textContent = data.answer;
    bubble.append(meta(data));
    if (data.needs_confirm) {
      const who = data.external_label || label || 'the external model';
      const row = el('div', { class: 'confirm' });
      const yes = el('button', { class: 'primary', type: 'button' }, 'Ask ' + who);
      const no = el('button', { type: 'button' }, 'Answer locally');
      yes.addEventListener('click', () => { row.remove(); send({ ...payload, confirm_online: true }); });
      no.addEventListener('click', () => { row.remove(); send({ ...payload, confirm_online: false }); });
      row.append(yes, no);
      bubble.append(row);
    }
  } catch (e) {
    bubble.textContent = String(e.message || e);
  } finally {
    btn.disabled = false;
  }
}

async function onChat(ev) {
  ev.preventDefault();
  const q = $('#q').value.trim();
  if (!q) return;
  const route = $('input[name=route]:checked').value;
  const attachments = [];
  for (const f of pendingFiles) attachments.push({ name: f.name, data_base64: await readB64(f) });
  const payload = { query: q, attachments };
  if (route === 'local') payload.confirm_online = false;
  if (route === 'external') payload.prefer_external = true;
  addMsg('user', q + (attachments.length ? '\n[' + attachments.map(a => a.name).join(', ') + ']' : ''));
  $('#q').value = '';
  pendingFiles = [];
  $('#files').value = '';
  $('#fileList').textContent = '';
  send(payload);
}

// ------------------------------------------------------------ settings
async function saveSettings(set, msgEl) {
  msgEl.textContent = 'Applying…';
  let r = await api('/api/settings', { set });
  if (r.status === 409) {
    const list = (r.data.relaxations || []).join('\n• ');
    if (!window.confirm('This loosens policy:\n• ' + list + '\n\nIt will be recorded in the audit log. Continue?')) {
      msgEl.textContent = 'Cancelled.';
      return false;
    }
    r = await api('/api/settings', { set, ack_relax: true });
  }
  if (r.status !== 200) { msgEl.textContent = 'Refused: ' + (r.data.error || r.status); return false; }
  msgEl.textContent = 'Applied and autotuned.';
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
  saveSettings(set, $('#modelsMsg'));
}

const RULE_BOOLS = ['send_local_context', 'allow_attachment_text', 'allow_images', 'allow_telegram'];
const RULE_INTS = ['max_calls_per_hour', 'max_calls_per_day', 'max_output_tokens', 'max_outbound_chars'];

function onRules() {
  const set = {};
  for (const k of RULE_BOOLS) set['external.rules.' + k] = $('#r_' + k).checked;
  for (const k of RULE_INTS) { const v = num('#r_' + k); if (v !== undefined) set['external.rules.' + k] = Math.trunc(v); }
  const t = num('#r_temperature'); if (t !== undefined) set['external.rules.temperature'] = t;
  saveSettings(set, $('#rulesMsg'));
}

async function onRetune() {
  $('#modelsMsg').textContent = 'Probing…';
  const r = await api('/api/autotune', {});
  $('#modelsMsg').textContent = r.status === 200 ? 'Autotune complete.' : 'Autotune failed: ' + (r.data.error || r.status);
  refresh();
}

// ------------------------------------------------------------ keys
async function onKey(ev) {
  ev.preventDefault();
  const form = ev.currentTarget;
  const input = $('input', form);
  const key = input.value;
  input.value = ''; // never keep it in the DOM
  const r = await api('/api/keys', { provider: form.dataset.provider, key });
  $('#keysMsg').textContent = r.status === 200 ? 'Saved to ' + r.data.backend + '.' : 'Refused: ' + (r.data.error || r.status);
  refresh();
}

async function onKeyDelete(ev) {
  const form = ev.currentTarget.closest('form');
  if (!window.confirm('Delete the stored ' + form.dataset.provider + ' key?')) return;
  const r = await api('/api/keys/delete', { provider: form.dataset.provider });
  $('#keysMsg').textContent = r.status === 200 ? 'Deleted' + (r.data.external_disabled ? '; external fallback disabled.' : '.') : 'Failed: ' + (r.data.error || r.status);
  refresh();
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
  const ext = data.external;
  const pill = $('#modePill');
  pill.textContent = data.mode + (ext.built ? ' · ' + ext.provider : '');
  pill.classList.toggle('hybrid', data.mode === 'hybrid');
  $('#extRouteName').textContent = ext.built ? 'Ask ' + (ext.provider === 'anthropic' ? 'Claude' : 'Grok') : 'External (off)';
  $('#extRouteLabel input').disabled = !ext.built;

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
    ['indexed chunks', data.indexed_chunks], ['external client', ext.built ? ext.label : 'not constructed'],
    ['HTTP can approve writes', data.http_can_approve_writes ? 'yes' : 'no']]);
  dl('#budget', [['last hour', ext.budget_used.last_hour + ' / ' + ext.rules.max_calls_per_hour],
    ['last 24h', ext.budget_used.last_day + ' / ' + ext.rules.max_calls_per_day], ['resets', 'on restart (in-memory)']]);
  $('#tools').replaceChildren(...data.tools.map(t => el('li', { class: t.write ? 'w' : '', title: t.write ? 'write: needs CLI confirmation' : 'read' }, t.name)));
  $('#graph').textContent = data.graph.join(' · ');

  const m = await api('/api/models');
  if (m.status === 200) {
    fillList('#localList', m.data.local || []);
    fillList('#extList', (m.data.external && m.data.external.length) ? m.data.external : Object.values(m.data.external_defaults || {}));
  }
}

async function onVerify() {
  const r = await api('/api/audit/verify');
  const out = $('#verifyMsg');
  out.textContent = r.data.ok ? 'Chain OK: ' + r.data.records + ' records' : 'FAILED: ' + r.data.error;
  out.className = r.data.ok ? 'ok' : 'bad';
}

// ------------------------------------------------------------ boot
document.addEventListener('DOMContentLoaded', async () => {
  $$('.tabs button').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
  $('#chatForm').addEventListener('submit', onChat);
  $('#q').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#chatForm').requestSubmit(); }
  });
  $('#files').addEventListener('change', e => {
    pendingFiles = Array.from(e.target.files).slice(0, 4);
    $('#fileList').textContent = pendingFiles.map(f => f.name).join(', ');
  });
  $('#switchBtn').addEventListener('click', onSwitch);
  $('#retuneBtn').addEventListener('click', onRetune);
  $('#rulesBtn').addEventListener('click', onRules);
  $$('#tab-keys form').forEach(f => {
    f.addEventListener('submit', onKey);
    $('[data-del]', f).addEventListener('click', onKeyDelete);
  });
  $('#refreshBtn').addEventListener('click', refresh);
  $('#verifyBtn').addEventListener('click', onVerify);
  if (!(await pair())) { lock(); return; }
  $('#locked').hidden = true;
  showTab('chat');
  refresh().catch(() => {});
});
