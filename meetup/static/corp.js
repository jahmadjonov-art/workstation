/* Huddle Corp front end. Plain JavaScript, no build step. Encryption lives in crypto.js. */
window.__appLoaded = true;
const $ = (s, r = document) => r.querySelector(s);
const app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------- storage, API, routing guard ---------- */
const mem = new Map();  // when the browser blocks localStorage (private mode, embedded frames)
const store = {
  get: k => { try { return localStorage.getItem(k); } catch { return mem.get(k) ?? null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { mem.set(k, v); } },
  del: k => { try { localStorage.removeItem(k); } catch { mem.delete(k); } },
};
class Stale extends Error {}  // a page load that finished after you had already moved on
let routeSeq = 0;
const token = () => store.get('corp_token');
async function api(path, opts = {}) {
  const seq = routeSeq, isGet = !opts.method || opts.method === 'GET';
  const headers = { 'Content-Type': 'application/json' };
  if (token()) headers.Authorization = 'Bearer ' + token();
  let r;
  try { r = await fetch('/api/corp' + path, { headers, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined }); }
  catch { throw new Error("Can't reach the Huddle Corp server. Check your connection and try again."); }
  if (isGet && seq !== routeSeq) throw new Stale();
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : 'Something went wrong'); }
  return r.json();
}

/* ---------- state ---------- */
let me = null;          // { user, workspaces }
let W = null;           // the open workspace: members, my scopes, my key grants
let wid = null;
const scopeKeys = new Map();  // "scope:epoch" -> { raw, key }
const myPriv = () => { const s = me && store.get('corp_priv_' + me.user.id); return s ? JSON.parse(s) : null; };
const roleRank = { member: 1, manager: 2, admin: 3, owner: 4 };
const can = role => !!W && roleRank[W.me.role] >= roleRank[role];
const member = id => W?.members.find(m => m.id === id);
const nameOf = id => member(id)?.name || 'Former member';

/* ---------- small UI helpers ---------- */
const toast = (m, action) => {
  const t = $('#toast'); t.textContent = m;
  if (action) { const b = document.createElement('button'); b.textContent = action.label; b.onclick = () => { t.classList.remove('show'); action.fn(); }; t.append(' ', b); }
  t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), action ? 7000 : 2800);
};
const colors = ['#2f7f8f', '#a8741a', '#4f8a4b', '#b04a3c', '#6b5fa8', '#3d6fa8'];
const avatar = (u, cls = '') => `<span class="avatar ${cls}" style="background:${colors[(u?.id || 0) % colors.length]}" title="${esc(u?.name || '')}">${esc((u?.name || '?').trim()[0] || '?').toUpperCase()}</span>`;
const ago = iso => { const s = (Date.now() - new Date(iso)) / 1000; return s < 60 ? 'now' : s < 3600 ? Math.floor(s / 60) + 'm' : s < 86400 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 86400) + 'd'; };
const fmtDay = d => new Date(d.length === 10 ? d + 'T12:00' : d).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
const fmtDT = d => new Date(d).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => { const x = new Date(d + 'T12:00'); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };
const loading = '<div class="loading">Loading…</div>';
const lockSvg = '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
let timers = [];
const poll = (fn, ms) => timers.push(setInterval(() => document.hidden || fn().catch(() => {}), ms));

function dialog(html, { onOpen } = {}) {
  const d = document.createElement('dialog');
  d.innerHTML = `<form method="dialog">${html}</form>`;
  document.body.appendChild(d);
  d.addEventListener('close', () => d.remove());
  d.showModal(); onOpen?.(d);
  return d;
}
const confirmDialog = ({ title, text, ok = 'Continue', danger = false }) => new Promise(resolve => {
  const d = dialog(`<h3>${esc(title)}</h3><p class="sub">${esc(text)}</p><div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn ${danger ? 'danger' : ''}" value="yes">${esc(ok)}</button></div>`);
  d.addEventListener('close', () => resolve(d.returnValue === 'yes'));
});
const moreMenu = items => `<details class="more"><summary aria-label="More options">&middot;&middot;&middot;</summary><div>${items.map(i => `<button class="${i.danger ? 'danger' : ''}" data-act="${i.act}" data-id="${esc(i.id ?? '')}">${i.label}</button>`).join('')}</div></details>`;

/* ---------- keys: opening grants, handing keys to teammates, rotating after someone leaves ---------- */
const aadFor = (scopeId, kind, parentId) => enc.encode(`${wid}|${scopeId}|${kind}|${parentId || 0}`);
const scopeById = id => W.scopes.find(s => s.id === id);
const keyFor = (scopeId, epoch) => scopeKeys.get(`${scopeId}:${epoch}`);
const wsScope = () => W.scopes.find(s => s.kind === 'workspace');
const hasAccess = () => !!(wsScope() && keyFor(wsScope().id, wsScope().epoch));

async function openGrants() {
  for (const g of W.grants) {
    const id = `${g.scope_id}:${g.epoch}`;
    if (scopeKeys.has(id)) continue;
    try { const raw = await unwrapKey(myPriv(), W.granter_keys[g.granter_id], g.wrapped); scopeKeys.set(id, { raw, key: await aesKey(raw, ['encrypt', 'decrypt']) }); } catch {}
  }
}
async function loadWorkspace(id) {
  wid = id; store.set('corp_wid', String(id));
  W = await api(`/w/${id}`);
  await openGrants();
  return W;
}
const reloadW = () => loadWorkspace(wid);

/* any teammate who holds a key shares it with people who are waiting for it, with no admin action needed */
async function autoGrant() {
  if (!W || !myPriv()) return;
  const pending = await api(`/w/${wid}/pending`);
  const groups = new Map();
  for (const p of pending) { const k = `${p.scope_id}:${p.epoch}`; if (scopeKeys.has(k)) (groups.get(k) || groups.set(k, []).get(k)).push(p); }
  for (const [k, list] of groups) {
    const [scope, epoch] = k.split(':').map(Number), { raw } = scopeKeys.get(k);
    const grants = await Promise.all(list.map(async p => ({ user_id: p.user_id, wrapped: await wrapKey(myPriv(), p.public_key, raw) })));
    await api(`/w/${wid}/scopes/${scope}/grants`, { method: 'POST', body: { epoch, grants } });
  }
}
/* someone left a group: make a new key for what is said from now on and give it to everyone who is left */
async function autoRotate() {
  if (!W || !myPriv()) return;
  for (const s of W.scopes.filter(s => s.rotation_needed && keyFor(s.id, s.epoch))) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const grants = await Promise.all(s.member_ids.map(async id => ({ user_id: id, wrapped: await wrapKey(myPriv(), member(id)?.public_key || me.user.public_key, raw) })));
    try { await api(`/w/${wid}/scopes/${s.id}/rotate`, { method: 'POST', body: { epoch: s.epoch + 1, grants } }); } catch {}
    await reloadW();
  }
}
async function keepKeysFlowing() { try { await reloadW(); await autoRotate(); await autoGrant(); } catch (e) { if (!(e instanceof Stale)) throw e; } }

/* ---------- encrypted items ---------- */
async function sealFor(scopeId, kind, parentId, data) {
  const s = scopeById(scopeId), k = s && keyFor(s.id, s.epoch);
  if (!k) throw new Error('You do not have the key for that yet. A teammate will unlock it for you shortly.');
  return { ...(await sealJson(k.key, data, aadFor(scopeId, kind, parentId))), epoch: s.epoch };
}
async function createItem({ kind, scope_id, parent_id = null, meta = {}, data }, retried = false) {
  const sealed = await sealFor(scope_id, kind, parent_id, data);
  try { return (await api(`/w/${wid}/items`, { method: 'POST', body: { kind, scope_id, parent_id, meta, ...sealed } })).id; }
  catch (e) { if (e.message === 'stale_epoch' && !retried) { await reloadW(); return createItem({ kind, scope_id, parent_id, meta, data }, true); } throw e; }
}
async function editItem(item, data, meta) {
  const body = {};
  if (data) Object.assign(body, await sealFor(item.scope_id, item.kind, item.parent_id, data));
  if (meta) body.meta = meta;
  try { await api(`/w/${wid}/items/${item.id}`, { method: 'PUT', body }); }
  catch (e) { if (e.message === 'stale_epoch') { await reloadW(); return editItem(item, data, meta); } throw e; }
}
async function openItem(it) {
  const k = keyFor(it.scope_id, it.epoch);
  if (!k) return { _locked: true };
  try { return await openJson(k.key, it.iv, it.ct, aadFor(it.scope_id, it.kind, it.parent_id)); } catch { return { _locked: true }; }
}
async function listItems(kind, parentId = 0, afterId = 0) {
  const items = await api(`/w/${wid}/items?kind=${kind}&parent_id=${parentId}&after_id=${afterId}`);
  return Promise.all(items.map(async it => ({ ...it, data: await openItem(it) })));
}
/* "who can see this": the whole company, or one of my private groups */
const scopeLabel = s => s.kind === 'workspace' ? `Everyone at ${W.name}` : 'Private: ' + s.member_ids.map(nameOf).join(', ');
const scopePicker = (id, selected) => `<select id="${id}">${W.scopes.filter(s => keyFor(s.id, s.epoch)).map(s => `<option value="${s.id}" ${s.id === selected ? 'selected' : ''}>${esc(scopeLabel(s))}</option>`).join('')}</select>`;
const scopeMembers = scopeId => (scopeById(scopeId)?.member_ids || []).map(member).filter(Boolean);

/* ---------- layout ---------- */
const NAV = [['#/', 'Home'], ['#/chat', 'Chat'], ['#/tasks', 'Tasks'], ['#/workflows', 'Workflows'], ['#/pages', 'Pages'], ['#/events', 'Events'], ['#/incentives', 'Incentives'], ['#/people', 'People']];
function shell(main) {
  if (!me || !W) return `<div class="solo">${main}</div>`;
  return `<div class="cshell"><nav class="side" aria-label="Workspace">${NAV.map(([h, l]) => `<a href="${h}" data-nav="${h}">${l}</a>`).join('')}
    ${can('admin') ? '<a href="#/settings" data-nav="#/settings">Settings</a>' : '<a href="#/settings" data-nav="#/settings">Account</a>'}</nav><section class="cmain">${main}</section></div>`;
}
function renderTop() {
  const el = $('#me');
  if (!me) { el.innerHTML = '<a class="btn small ghost" href="#/login">Log in</a> <a class="btn small" href="#/new">Create a workspace</a>'; $('#wsname').textContent = ''; return; }
  $('#wsname').innerHTML = me.workspaces.length > 1
    ? `<select id="wsswitch" aria-label="Workspace">${me.workspaces.map(w => `<option value="${w.id}" ${w.id === wid ? 'selected' : ''}>${esc(w.name)}</option>`).join('')}</select>`
    : esc(W?.name || '');
  $('#wsswitch')?.addEventListener('change', async ev => { await loadWorkspace(+ev.target.value); renderTop(); location.hash = '#/'; route(); });
  el.innerHTML = `<details class="more usermenu"><summary>${avatar(me.user)}<span>${esc(me.user.name.split(' ')[0])}</span></summary><div>
    <a href="#/settings">Account</a><a href="#/new">New workspace</a><button data-act="signout">Sign out</button></div></details>`;
}
function renderBanner() {
  const el = $('#banner'); if (!el || window.__DEMO) return;
  const show = me && myPriv() && !store.get('corp_saved_' + me.user.id);
  el.innerHTML = show ? '<div class="banner">Save your login file. It holds your private encryption key: without it, nobody (including us) can recover your messages. <button class="btn small" data-act="save-login">Save it</button></div>' : '';
}
function downloadLoginFile() {
  const blob = new Blob([JSON.stringify({ huddle_corp: 1, user_id: me.user.id, token: token(), private_key: myPriv(), workspace_id: wid })], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `huddle-corp-login-${me.user.name.split(' ')[0].toLowerCase()}.json`; a.click();
  store.set('corp_saved_' + me.user.id, '1'); renderBanner();
}

/* ---------- account screens ---------- */
async function loadMe() {
  me = null;
  if (token()) { try { me = await api('/me'); } catch (e) { if (/sign in/i.test(e.message)) store.del('corp_token'); } }
  if (me) {
    const want = +store.get('corp_wid') || me.workspaces[0]?.id;
    const pick = me.workspaces.find(w => w.id === want) || me.workspaces[0];
    if (pick) { try { await loadWorkspace(pick.id); } catch {} }
    else { W = null; wid = null; }
  }
  renderTop(); renderBanner();
}
async function startSession(tok, userId, priv) {
  store.set('corp_token', tok); store.set('corp_priv_' + userId, JSON.stringify(priv));
  await loadMe();
}
function welcome() {
  app.innerHTML = `<div class="hero"><div class="wrap-s"><h1>A private workspace for your company.</h1>
    <p>Chat, tasks, workflows, pages, events and incentives in one place, end-to-end encrypted in your team's browsers. Huddle can't read it, and neither can anyone who breaks into our servers.</p>
    <p><a class="btn big-btn" href="#/new">Create your company workspace</a> <a class="btn ghost big-btn" href="#/login">Log in</a></p>
    <p class="sub">Joining a team? Open the invite link your admin sent you.</p></div></div>
    <div class="cards">
      <div class="card"><h3>Encrypted by default</h3><p>Messages, tasks, pages and plans are encrypted before they leave the browser. Removing someone changes the keys, so they can't read what comes next.</p></div>
      <div class="card"><h3>Roles that make sense</h3><p>Owners, admins, managers and members. Private groups for leadership or HR keep their content from everyone else, cryptographically.</p></div>
      <div class="card"><h3>Onboarding in one click</h3><p>Turn a checklist into a workflow. Start it for a new hire and every step becomes a task with an owner and a due date.</p></div>
      <div class="card"><h3>Separate from Huddle</h3><p>Huddle Corp has its own accounts and its own data. Nothing from the social side of Huddle appears here.</p></div></div>`;
}

async function newWorkspace() {
  const existing = !!me;
  app.innerHTML = shell(`<div class="box form"><h2>${existing ? 'Create another workspace' : 'Create your company workspace'}</h2>
    <p class="sub">You will be its owner. Your content is encrypted in this browser with keys only you and your teammates hold.</p>
    <label>Company name</label><input id="co" maxlength="80" placeholder="Northwind Labs">
    ${existing ? '' : `<label>Your name</label><input id="nm" maxlength="60" autocomplete="name"><label>Your job title <small>(optional)</small></label><input id="jt" maxlength="60" placeholder="CEO, Head of People…">`}
    <div class="hp" aria-hidden="true"><label>Website</label><input id="hp" tabindex="-1" autocomplete="off"></div>
    <label class="check"><input type="checkbox" id="auth"> <span>I am allowed to create this workspace for my company.</span></label>
    <p><button class="btn big" id="go">Create workspace</button></p><p class="sub" id="status"></p>
    ${existing ? '' : '<p class="sub">Already have an account? <a href="#/login">Log in</a></p>'}</div>`);
  $('#go').onclick = async () => {
    const company = $('#co').value.trim(), status = t => $('#status').textContent = t;
    if (company.length < 2 || (!existing && !$('#nm').value.trim())) return toast('Please add the company name and your name');
    if (!$('#auth').checked) return toast('Please confirm you are allowed to create this workspace');
    $('#go').disabled = true;
    try {
      let keys, r;
      if (!existing) {
        status('Creating your encryption keys…'); keys = await genKeys();
        status('Quick check that you are human…'); const ch = await api('/pow');
        const counter = await solvePow(ch.challenge, ch.bits);
        r = await api('/signup', { method: 'POST', body: { name: $('#nm').value, title: $('#jt').value, company, authorized: true, website: $('#hp').value, public_key: keys.pub, pow: { challenge: ch.challenge, counter } } });
        await startSession(r.token, r.user_id, keys.priv);
      } else {
        status('Creating your workspace…');
        r = await api('/workspaces', { method: 'POST', body: { company, authorized: true } });
      }
      status('Setting up your workspace…');
      await loadWorkspace(r.workspace_id);
      await seedWorkspace(r.scope_id);
      await loadMe(); toast('Your workspace is ready'); location.hash = '#/';
    } catch (e) { $('#go').disabled = false; status(''); toast(e.message); }
  };
}
/* the founder's browser makes the workspace key and the first encrypted content */
async function seedWorkspace(scopeId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  await api(`/w/${wid}/scopes/${scopeId}/grants`, { method: 'POST', body: { epoch: 1, grants: [{ user_id: me.user.id, wrapped: await wrapKey(myPriv(), me.user.public_key, raw) }] } });
  await reloadW();
  const general = await createItem({ kind: 'channel', scope_id: scopeId, data: { name: 'general', topic: 'Company-wide announcements and chat' } });
  await createItem({ kind: 'message', scope_id: scopeId, parent_id: general, data: { text: `Welcome to ${W.name}! This chat is end-to-end encrypted. Only people in this workspace can read it.` } });
  await createItem({ kind: 'page', scope_id: scopeId, meta: { pinned: true }, data: { title: `Welcome to ${W.name}`, body: `# Our company page\n\nThis is where we keep what everyone should know.\n\n## Start here\n- Say hello in the #general channel\n- Check your tasks on the Tasks board\n- Read the handbook pages\n\n## How we work\nEdit this page to describe your mission, values and how your teams work together.` } });
  await createItem({ kind: 'workflow', scope_id: scopeId, data: ONBOARDING });
}
const ONBOARDING = { name: 'New hire onboarding', description: 'Everything a new teammate needs in their first weeks.', steps: [
  { title: 'Set up laptop and accounts', notes: 'Email, chat, password manager, VPN.', who: 'admin', days: 0 },
  { title: 'Welcome meeting with the team', notes: 'Introductions and how the team works.', who: 'manager', days: 1 },
  { title: 'Read the company pages', notes: 'Company page, handbook and policies.', who: 'subject', days: 3 },
  { title: 'Complete payroll and benefits forms', notes: '', who: 'subject', days: 5 },
  { title: 'First goals agreed with manager', notes: 'Three goals for the first 90 days.', who: 'manager', days: 14 },
  { title: '30-day check-in', notes: 'What is working, what is not.', who: 'manager', days: 30 } ] };

async function loginPage() {
  app.innerHTML = `<div class="solo"><div class="box form"><h2>Log in</h2><p class="sub">Huddle Corp has no passwords. Choose the login file you saved. It restores your account and the key that opens your workspace.</p>
    <input type="file" id="restore" accept="application/json,.json"><p class="sub" id="status"></p><p class="sub">New here? <a href="#/new">Create a workspace</a></p></div></div>`;
  $('#restore').addEventListener('change', async ev => {
    try {
      const f = JSON.parse(await ev.target.files[0].text());
      if (!f.huddle_corp || !f.token || !f.user_id || !f.private_key) throw new Error();
      if (f.workspace_id) store.set('corp_wid', String(f.workspace_id));
      await startSession(f.token, f.user_id, f.private_key);
      if (!me) throw new Error();
      store.set('corp_saved_' + me.user.id, '1'); renderBanner(); toast('Welcome back, ' + me.user.name.split(' ')[0]); location.hash = '#/';
    } catch { store.del('corp_token'); $('#status').textContent = 'That file did not work. Use the Huddle Corp login file you downloaded.'; }
  });
}

async function joinPage(tokenStr) {
  let inv;
  try { inv = await api('/invites/peek', { method: 'POST', body: { token: tokenStr } }); }
  catch (e) { app.innerHTML = `<div class="solo"><div class="box"><h2>This invite isn't valid</h2><p class="sub">${esc(e.message)}</p></div></div>`; return; }
  if (me) {  // already have an account: just add this workspace
    app.innerHTML = `<div class="solo"><div class="box form"><h2>Join ${esc(inv.workspace)}</h2><p class="sub">You will join as ${esc(inv.role)}, signed in as ${esc(me.user.name)}.</p><p><button class="btn big" id="go">Join workspace</button></p></div></div>`;
    $('#go').onclick = async () => { try { const r = await api('/invites/accept', { method: 'POST', body: { token: tokenStr } }); await loadMe(); await loadWorkspace(r.workspace_id); renderTop(); toast('You have joined'); location.hash = '#/'; } catch (e) { toast(e.message); } };
    return;
  }
  app.innerHTML = `<div class="solo"><div class="box form"><h2>Join ${esc(inv.workspace)}</h2><p class="sub">You are invited as ${esc(inv.role)}. Your keys are created in this browser.</p>
    <label>Your name</label><input id="nm" maxlength="60" autocomplete="name"><label>Job title <small>(optional)</small></label><input id="jt" maxlength="60">
    <div class="hp" aria-hidden="true"><label>Website</label><input id="hp" tabindex="-1" autocomplete="off"></div>
    <p><button class="btn big" id="go">Join ${esc(inv.workspace)}</button></p><p class="sub" id="status"></p></div></div>`;
  $('#go').onclick = async () => {
    if (!$('#nm').value.trim()) return toast('Please add your name');
    $('#go').disabled = true; const status = t => $('#status').textContent = t;
    try {
      status('Creating your encryption keys…'); const keys = await genKeys();
      status('Quick check that you are human…'); const ch = await api('/pow'); const counter = await solvePow(ch.challenge, ch.bits);
      const r = await api('/join', { method: 'POST', body: { token: tokenStr, name: $('#nm').value, title: $('#jt').value, website: $('#hp').value, public_key: keys.pub, pow: { challenge: ch.challenge, counter } } });
      await startSession(r.token, r.user_id, keys.priv);
      toast(`Welcome to ${W?.name || inv.workspace}`); location.hash = '#/';
    } catch (e) { $('#go').disabled = false; status(''); toast(e.message); }
  };
}

/* a new member is in, but a teammate's browser still has to hand them the workspace key */
function waitingPage() {
  app.innerHTML = shell(`<div class="box gate"><h2>Almost there</h2><p>You are in ${esc(W.name)}. A teammate's browser has to unlock the encrypted workspace for you. That happens automatically when someone with access is online.</p>
    <p class="sub">Nobody needs to do anything. This page checks every few seconds.</p><p><span class="spinner"></span></p></div>`);
  poll(async () => { await keepKeysFlowing(); if (hasAccess()) route(); }, 4000);
}

/* ---------- home ---------- */
const kindOf = (list, k) => list.filter(i => i.kind === k);
async function home() {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const [pages, tasks, events, runs, workflows] = await Promise.all(['page', 'task', 'event', 'run', 'workflow'].map(k => listItems(k)));
  const pinned = pages.find(p => p.meta.pinned && !p.data._locked) || pages.find(p => !p.data._locked);
  const mine = tasks.filter(t => t.meta.assignee_id === me.user.id && t.meta.status !== 'done' && !t.data._locked).sort((a, b) => (a.meta.due || '9') < (b.meta.due || '9') ? -1 : 1).slice(0, 6);
  const upcoming = events.filter(e => e.meta.starts >= new Date().toISOString().slice(0, 16)).sort((a, b) => a.meta.starts < b.meta.starts ? -1 : 1).slice(0, 4);
  const hires = W.members.filter(m => m.new_hire);
  const active = runs.filter(r => r.meta.status === 'active' && !r.data._locked);
  const progress = r => { const ts = tasks.filter(t => t.meta.run_id === r.id); return { done: ts.filter(t => t.meta.status === 'done').length, total: ts.length }; };
  app.innerHTML = shell(`<div class="titlebar"><div><h1>${esc(W.name)}</h1><div class="sub">${lockSvg} End-to-end encrypted &middot; you are ${W.me.role === 'owner' ? 'the owner' : 'a ' + W.me.role}</div></div></div>
    <div class="cols2"><div>
      <div class="box"><div class="boxhead"><h3>Company page</h3>${can('manager') && pinned ? `<a class="linkbtn" href="#/pages/${pinned.id}">Edit</a>` : ''}</div>
        ${pinned ? `<div class="doc">${renderDoc(pinned.data.body)}</div>` : '<div class="empty">No company page yet. Managers can write one under Pages.</div>'}</div>
      <div class="box"><div class="boxhead"><h3>Workflows in progress</h3><a class="linkbtn" href="#/workflows">All workflows</a></div>
        ${active.map(r => { const p = progress(r); return `<div class="rowi"><div class="grow"><b>${esc(r.data.name)}</b><div class="bar"><i style="width:${p.total ? Math.round(p.done / p.total * 100) : 0}%"></i></div></div><small>${p.done}/${p.total} done</small></div>`; }).join('') || '<div class="empty small">Nothing running. Start one from Workflows.</div>'}</div>
    </div><div>
      <div class="box"><div class="boxhead"><h3>My tasks</h3><a class="linkbtn" href="#/tasks">Board</a></div>
        ${mine.map(t => `<a class="rowi link" href="#/tasks"><span class="dot p${t.meta.priority}"></span><div class="grow"><b>${esc(t.data.title)}</b>${t.meta.due ? `<small class="${t.meta.due < today() ? 'late' : ''}">Due ${fmtDay(t.meta.due)}</small>` : ''}</div><small>${esc(t.meta.status)}</small></a>`).join('') || '<div class="empty small">Nothing assigned to you.</div>'}</div>
      <div class="box"><div class="boxhead"><h3>Coming up</h3><a class="linkbtn" href="#/events">Events</a></div>
        ${upcoming.map(e => `<a class="rowi link" href="#/events"><div class="grow"><b>${esc(e.data.title)}</b><small>${fmtDT(e.meta.starts)}${e.data.where ? ' &middot; ' + esc(e.data.where) : ''}</small></div></a>`).join('') || '<div class="empty small">No events scheduled.</div>'}</div>
      ${hires.length ? `<div class="box"><div class="boxhead"><h3>New hires</h3><a class="linkbtn" href="#/people">People</a></div>${hires.map(m => `<div class="rowi">${avatar(m)}<div class="grow"><b>${esc(m.name)}</b><small>${esc(m.title || 'Joined')} &middot; started ${m.start_date ? fmtDay(m.start_date) : 'recently'}</small></div>${can('manager') && workflows.length ? `<button class="btn small ghost" data-act="onboard" data-id="${m.id}">Start onboarding</button>` : ''}</div>`).join('')}</div>` : ''}
    </div></div>`);
}

/* a tiny, safe text format for pages: # heading, ## subheading, - bullets, **bold**, blank line = new paragraph */
function renderDoc(src) {
  const inline = t => esc(t).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
  const out = []; let list = false;
  for (const line of String(src || '').split('\n')) {
    if (/^- /.test(line)) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${inline(line.slice(2))}</li>`); continue; }
    if (list) { out.push('</ul>'); list = false; }
    if (/^## /.test(line)) out.push(`<h3>${inline(line.slice(3))}</h3>`);
    else if (/^# /.test(line)) out.push(`<h2>${inline(line.slice(2))}</h2>`);
    else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  if (list) out.push('</ul>');
  return out.join('');
}

/* ---------- chat ---------- */
async function channelList() {
  const chans = (await listItems('channel')).filter(c => !c.data._locked && !c.meta.archived);
  const withScope = chans.map(c => ({ ...c, scope: scopeById(c.scope_id) }));
  const dmName = c => { const other = c.scope.member_ids.find(i => i !== me.user.id); return nameOf(other ?? me.user.id); };
  return {
    channels: withScope.filter(c => !c.data.dm),
    dms: withScope.filter(c => c.data.dm).map(c => ({ ...c, label: dmName(c) })),
  };
}
async function chat(idStr) {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const { channels, dms } = await channelList();
  const current = channels.concat(dms).find(c => c.id === +idStr) || channels[0];
  const side = `<div class="chanlist"><div class="boxhead"><h3>Channels</h3><button class="linkbtn" data-act="new-channel">+ New</button></div>
    ${channels.map(c => `<a href="#/chat/${c.id}" class="${current?.id === c.id ? 'on' : ''}"># ${esc(c.data.name)}${c.scope.kind === 'private' ? ' ' + lockSvg : ''}</a>`).join('')}
    <div class="boxhead"><h3>Direct messages</h3></div>${dms.map(c => `<a href="#/chat/${c.id}" class="${current?.id === c.id ? 'on' : ''}">${esc(c.label)}</a>`).join('') || '<div class="sub pad">Message someone from the People page.</div>'}</div>`;
  if (!current) { app.innerHTML = shell(`<div class="chatwrap">${side}<div class="chatmain"><div class="empty">No channels yet. Create the first one.</div></div></div>`); return; }
  const title = current.data.dm ? current.label : '# ' + current.data.name;
  app.innerHTML = shell(`<div class="chatwrap">${side}<div class="chatmain"><div class="boxhead"><div><h3>${esc(title)}</h3><small>${lockSvg} ${current.scope.kind === 'private' ? 'Private: ' + current.scope.member_ids.map(nameOf).join(', ') : 'Everyone at ' + esc(W.name)}${current.data.topic ? ' &middot; ' + esc(current.data.topic) : ''}</small></div>
      ${!current.data.dm && (current.created_by === me.user.id || can('admin')) ? moreMenu([{ act: 'archive-channel', id: current.id, label: 'Archive channel', danger: true }]) : ''}</div>
    <div id="msgs" class="msgs"></div>
    <div class="composer"><textarea id="mt" rows="1" maxlength="4000" placeholder="Message ${esc(title)}"></textarea><button class="btn" id="ms">Send</button></div></div></div>`);
  let last = 0, drawn = new Set();
  const draw = async () => {
    const msgs = await listItems('message', current.id, 0);
    if (msgs.length === drawn.size && msgs.every(m => drawn.has(m.id))) return;
    const box = $('#msgs'); if (!box) return;
    const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    drawn = new Set(msgs.map(m => m.id));
    box.innerHTML = msgs.map(m => `<div class="msg"><div class="who">${avatar(member(m.created_by) || { name: '?' })}</div><div class="what"><b>${esc(nameOf(m.created_by))}</b> <small>${ago(m.created)}</small>${m.created_by === me.user.id || can('admin') ? moreMenu([{ act: 'del-item', id: m.id, label: 'Delete', danger: true }]) : ''}<div class="txt">${m.data._locked ? '<i class="sub">Encrypted with a key you do not have</i>' : esc(m.data.text).replace(/\n/g, '<br>')}</div></div></div>`).join('') || '<div class="empty">No messages yet. Say hello.</div>';
    if (atEnd || !last) box.scrollTop = box.scrollHeight; last = msgs.at(-1)?.id || 0;
  };
  await draw(); poll(draw, 4000);
  // new channels, direct messages and freshly granted keys appear without a refresh
  const sig = () => channels.concat(dms).map(c => c.id).join(',');
  const before = sig();
  poll(async () => { await reloadW(); const l = await channelList(); if (l.channels.concat(l.dms).map(c => c.id).join(',') !== before) route(); }, 8000);
  const send = async () => {
    const text = $('#mt').value.trim(); if (!text) return; $('#mt').value = '';
    try { await createItem({ kind: 'message', scope_id: current.scope_id, parent_id: current.id, data: { text } }); await draw(); } catch (e) { $('#mt').value = text; toast(e.message); }
  };
  $('#ms').onclick = send; $('#mt').onkeydown = k => { if (k.key === 'Enter' && !k.shiftKey) { k.preventDefault(); send(); } }; $('#mt').focus();
}
function newChannelDialog() {
  const others = W.members.filter(m => m.id !== me.user.id);
  const d = dialog(`<h3>New channel</h3><label>Name</label><input id="cn" maxlength="40" placeholder="design-reviews">
    <label>Who can see it?</label>
    <label class="choice"><input type="radio" name="vis" value="all" checked><span><b>Everyone at ${esc(W.name)}</b></span></label>
    <label class="choice"><input type="radio" name="vis" value="private"><span><b>Only people I choose</b><small>It gets its own encryption key. Everyone else in the company, and Huddle, can't read it.</small></span></label>
    <div id="who" class="picklist hidden">${others.map(m => `<label><input type="checkbox" value="${m.id}"> ${esc(m.name)} <small>${esc(m.title)}</small></label>`).join('') || '<small>Invite teammates first.</small>'}</div>
    <div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="mk" value="yes">Create</button></div>`, {
    onOpen: d => d.querySelectorAll('input[name=vis]').forEach(r => r.onchange = () => $('#who').classList.toggle('hidden', d.querySelector('input[name=vis]:checked').value !== 'private')),
  });
  d.querySelector('#mk').onclick = async ev => {
    ev.preventDefault();
    const name = d.querySelector('#cn').value.trim().toLowerCase().replace(/\s+/g, '-'); if (!name) return toast('Give the channel a name');
    try {
      let scope = wsScope().id;
      if (d.querySelector('input[name=vis]:checked').value === 'private') {
        const ids = [...d.querySelectorAll('#who input:checked')].map(i => +i.value); if (!ids.length) return toast('Choose at least one person');
        scope = await makePrivateScope(ids);
      }
      const id = await createItem({ kind: 'channel', scope_id: scope, data: { name } });
      d.close(); location.hash = '#/chat/' + id;
    } catch (e) { toast(e.message); }
  };
}
/* a private group: its own key, handed only to the people in it */
async function makePrivateScope(ids) {
  const all = [...new Set([me.user.id, ...ids])];
  const r = await api(`/w/${wid}/scopes`, { method: 'POST', body: { member_ids: all } });
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const grants = await Promise.all(all.map(async id => ({ user_id: id, wrapped: await wrapKey(myPriv(), id === me.user.id ? me.user.public_key : member(id).public_key, raw) })));
  await api(`/w/${wid}/scopes/${r.id}/grants`, { method: 'POST', body: { epoch: 1, grants } });
  await reloadW(); return r.id;
}
async function openDm(userId) {
  const { dms } = await channelList();
  const existing = dms.find(c => c.scope.member_ids.length === 2 && c.scope.member_ids.includes(userId));
  if (existing) return (location.hash = '#/chat/' + existing.id);
  const scope = await makePrivateScope([userId]);
  const id = await createItem({ kind: 'channel', scope_id: scope, data: { name: 'dm', dm: true } });
  location.hash = '#/chat/' + id;
}

/* ---------- tasks ---------- */
const STATUS = [['todo', 'To do'], ['doing', 'In progress'], ['blocked', 'Blocked'], ['done', 'Done']];
const PRIORITY = { 1: 'High', 2: 'Normal', 3: 'Low' };
let taskFilter = 'mine';
async function tasks() {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const [items, runs] = await Promise.all([listItems('task'), listItems('run')]);
  const all = items.filter(t => !t.data._locked);
  const shown = taskFilter === 'mine' ? all.filter(t => t.meta.assignee_id === me.user.id) : all;
  const runName = id => runs.find(r => r.id === id)?.data.name;
  const card = t => `<div class="tcard" data-act="open-task" data-id="${t.id}"><div class="ttitle">${esc(t.data.title)}</div>
    <div class="tmeta"><span class="dot p${t.meta.priority}" title="${PRIORITY[t.meta.priority]} priority"></span>${t.meta.due ? `<small class="${t.meta.due < today() && t.meta.status !== 'done' ? 'late' : ''}">${fmtDay(t.meta.due)}</small>` : ''}
    ${t.meta.assignee_id ? `<span class="who2">${avatar(member(t.meta.assignee_id) || { name: '?' })}</span>` : '<small>Unassigned</small>'}</div>${t.meta.run_id && runName(t.meta.run_id) ? `<small class="runtag">${esc(runName(t.meta.run_id))}</small>` : ''}</div>`;
  app.innerHTML = shell(`<div class="titlebar"><h1>Tasks</h1><div class="row"><div class="seg"><button class="${taskFilter === 'mine' ? 'on' : ''}" data-act="tfilter" data-id="mine">Mine</button><button class="${taskFilter === 'all' ? 'on' : ''}" data-act="tfilter" data-id="all">Everyone</button></div><button class="btn" data-act="new-task">New task</button></div></div>
    <div class="board">${STATUS.map(([k, l]) => { const col = shown.filter(t => t.meta.status === k).sort((a, b) => (a.meta.due || '9') < (b.meta.due || '9') ? -1 : 1);
      return `<div class="col"><div class="colhead">${l} <span class="count">${col.length}</span></div>${col.map(card).join('') || '<div class="colempty">Nothing here</div>'}</div>`; }).join('')}</div>`);
  window.__tasks = all;
}
function taskDialog(existing) {
  const scopeId = existing?.scope_id ?? wsScope().id;
  const d = dialog(`<h3>${existing ? 'Edit task' : 'New task'}</h3><label>Title</label><input id="tt" maxlength="140" value="${esc(existing?.data.title || '')}">
    <label>Details</label><textarea id="tn" rows="3" maxlength="3000">${esc(existing?.data.notes || '')}</textarea>
    <div class="grid2"><div><label>Assigned to</label><select id="ta"></select></div><div><label>Due</label><input type="date" id="td" value="${existing?.meta.due || ''}"></div>
    <div><label>Priority</label><select id="tp">${[1, 2, 3].map(p => `<option value="${p}" ${(existing?.meta.priority || 2) === p ? 'selected' : ''}>${PRIORITY[p]}</option>`).join('')}</select></div>
    <div><label>Who can see it</label>${existing ? `<div class="sub">${esc(scopeLabel(scopeById(scopeId)))}</div>` : scopePicker('ts', scopeId)}</div></div>
    <div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="tsave" value="yes">${existing ? 'Save' : 'Create task'}</button></div>`, {
    onOpen: d => {
      const fill = () => { const sid = existing ? scopeId : +d.querySelector('#ts').value; d.querySelector('#ta').innerHTML = '<option value="">Unassigned</option>' + scopeMembers(sid).map(m => `<option value="${m.id}" ${existing?.meta.assignee_id === m.id ? 'selected' : ''}>${esc(m.name)}</option>`).join(''); };
      fill(); d.querySelector('#ts')?.addEventListener('change', fill);
    },
  });
  d.querySelector('#tsave').onclick = async ev => {
    ev.preventDefault();
    const title = d.querySelector('#tt').value.trim(); if (!title) return toast('Give the task a title');
    const meta = { assignee_id: +d.querySelector('#ta').value || null, due: d.querySelector('#td').value || null, priority: +d.querySelector('#tp').value };
    try {
      if (existing) { await editItem(existing, { title, notes: d.querySelector('#tn').value }, meta); }
      else await createItem({ kind: 'task', scope_id: +d.querySelector('#ts').value, meta: { ...meta, status: 'todo' }, data: { title, notes: d.querySelector('#tn').value } });
      d.close(); toast(existing ? 'Task saved' : 'Task created'); route();
    } catch (e) { toast(e.message); }
  };
}
async function taskDetail(id) {
  const t = (window.__tasks || []).find(x => x.id === id); if (!t) return;
  const editable = t.created_by === me.user.id || can('manager'), mover = editable || t.meta.assignee_id === me.user.id;
  const d = dialog(`<div class="row between"><h3>${esc(t.data.title)}</h3><button class="linkbtn" value="x">Close</button></div>
    <div class="sub">Created by ${esc(nameOf(t.created_by))} &middot; ${ago(t.created)} ago &middot; ${esc(scopeLabel(scopeById(t.scope_id)))}</div>
    ${t.data.notes ? `<p class="pre">${esc(t.data.notes)}</p>` : ''}
    <div class="tmeta big"><span>${t.meta.assignee_id ? avatar(member(t.meta.assignee_id) || { name: '?' }) + ' ' + esc(nameOf(t.meta.assignee_id)) : 'Unassigned'}</span><span>${t.meta.due ? 'Due ' + fmtDay(t.meta.due) : 'No due date'}</span><span>${PRIORITY[t.meta.priority]} priority</span></div>
    ${mover ? `<div class="seg wide">${STATUS.map(([k, l]) => `<button class="${t.meta.status === k ? 'on' : ''}" data-s="${k}" value="x">${l}</button>`).join('')}</div>` : `<div class="sub">Status: ${t.meta.status}</div>`}
    <h4>Comments</h4><div id="tcm" class="comments">${loading}</div>
    <div class="composer"><input id="tcn" maxlength="2000" placeholder="Add a comment"><button class="btn" id="tcs" type="button">Send</button></div>
    <div class="row end">${editable ? '<button class="btn ghost" id="tedit" type="button">Edit</button><button class="btn ghost danger-text" id="tdel" type="button">Delete</button>' : ''}</div>`);
  d.querySelectorAll('[data-s]').forEach(b => b.onclick = async ev => { ev.preventDefault(); try { await editItem(t, null, { status: b.dataset.s }); d.close(); route(); } catch (e) { toast(e.message); } });
  const draw = async () => { const cs = await listItems('message', t.id); if (!d.isConnected) return; d.querySelector('#tcm').innerHTML = cs.map(c => `<div class="cm"><b>${esc(nameOf(c.created_by))}</b> <small>${ago(c.created)}</small><div>${c.data._locked ? '<i class="sub">Locked</i>' : esc(c.data.text)}</div></div>`).join('') || '<div class="sub">No comments yet.</div>'; };
  draw();
  d.querySelector('#tcs').onclick = async () => { const text = d.querySelector('#tcn').value.trim(); if (!text) return; d.querySelector('#tcn').value = ''; try { await createItem({ kind: 'message', scope_id: t.scope_id, parent_id: t.id, data: { text } }); draw(); } catch (e) { toast(e.message); } };
  d.querySelector('#tcn').onkeydown = k => { if (k.key === 'Enter') { k.preventDefault(); d.querySelector('#tcs').click(); } };
  d.querySelector('#tedit')?.addEventListener('click', () => { d.close(); taskDialog(t); });
  d.querySelector('#tdel')?.addEventListener('click', async () => { if (await confirmDialog({ title: 'Delete this task?', text: 'It disappears for everyone, including its comments.', ok: 'Delete', danger: true })) { await api(`/w/${wid}/items/${t.id}`, { method: 'DELETE' }); d.close(); toast('Task deleted'); route(); } });
}

/* ---------- workflows: a checklist you can run for a person or a project ---------- */
async function workflows() {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const [wfs, runs, tasksList] = await Promise.all([listItems('workflow'), listItems('run'), listItems('task')]);
  const flows = wfs.filter(w => !w.data._locked);
  const prog = r => { const ts = tasksList.filter(t => t.meta.run_id === r.id && !t.data._locked); return { done: ts.filter(t => t.meta.status === 'done').length, total: ts.length }; };
  window.__flows = flows;
  app.innerHTML = shell(`<div class="titlebar"><div><h1>Workflows</h1><div class="sub">Turn a checklist into tasks with owners and due dates.</div></div>${can('admin') ? '<button class="btn" data-act="new-workflow">New workflow</button>' : ''}</div>
    <div class="box"><div class="boxhead"><h3>Templates</h3></div>${flows.map(w => `<div class="rowi"><div class="grow"><b>${esc(w.data.name)}</b><small>${esc(w.data.description || '')} ${w.data.steps.length} step${w.data.steps.length === 1 ? '' : 's'}</small></div>
      ${can('manager') ? `<button class="btn small" data-act="run-workflow" data-id="${w.id}">Run</button>` : ''}${can('admin') ? `<button class="btn small ghost" data-act="edit-workflow" data-id="${w.id}">Edit</button>` : ''}</div>`).join('') || '<div class="empty">No workflows yet.</div>'}</div>
    <div class="box"><div class="boxhead"><h3>What is going on</h3></div>${runs.filter(r => !r.data._locked).reverse().map(r => { const p = prog(r); const done = r.meta.status === 'done' || (p.total && p.done === p.total);
      return `<div class="rowi"><div class="grow"><b>${esc(r.data.name)}</b> ${done ? '<span class="tag ok">Complete</span>' : '<span class="tag">Active</span>'}<div class="bar"><i style="width:${p.total ? Math.round(p.done / p.total * 100) : 0}%"></i></div><small>${p.done} of ${p.total} steps done${r.data.startDate ? ' &middot; started ' + fmtDay(r.data.startDate) : ''}</small></div>
      ${can('manager') ? moreMenu([...(r.meta.status !== 'done' ? [{ act: 'finish-run', id: r.id, label: 'Mark complete' }] : []), { act: 'del-item', id: r.id, label: 'Delete', danger: true }]) : ''}</div>`; }).join('') || '<div class="empty">Nothing is running. Press Run on a template.</div>'}</div>`);
}
function workflowEditor(existing) {
  const steps = existing ? existing.data.steps.map(s => ({ ...s })) : [{ title: '', notes: '', who: 'subject', days: 0 }];
  const d = dialog(`<h3>${existing ? 'Edit workflow' : 'New workflow'}</h3><label>Name</label><input id="wn" maxlength="80" value="${esc(existing?.data.name || '')}">
    <label>What is it for?</label><input id="wd" maxlength="200" value="${esc(existing?.data.description || '')}"><h4>Steps</h4><div id="steps"></div>
    <button class="linkbtn" type="button" id="addstep">+ Add a step</button><div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="wsave" value="yes">Save workflow</button></div>`);
  const draw = () => {
    d.querySelector('#steps').innerHTML = steps.map((s, i) => `<div class="stepRow"><input data-f="title" data-i="${i}" placeholder="Step ${i + 1}" value="${esc(s.title)}"><select data-f="who" data-i="${i}">${[['subject', 'The person'], ['manager', 'Their manager'], ['admin', 'An admin'], ['creator', 'Whoever runs it']].map(([k, l]) => `<option value="${k}" ${s.who === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <label class="days">day <input type="number" min="0" max="365" data-f="days" data-i="${i}" value="${s.days}"></label><button type="button" class="linkbtn danger-text" data-del="${i}">Remove</button></div>`).join('');
    d.querySelectorAll('[data-f]').forEach(el => el.oninput = () => { steps[+el.dataset.i][el.dataset.f] = el.dataset.f === 'days' ? +el.value || 0 : el.value; });
    d.querySelectorAll('[data-del]').forEach(b => b.onclick = () => { steps.splice(+b.dataset.del, 1); draw(); });
  };
  draw(); d.querySelector('#addstep').onclick = () => { steps.push({ title: '', notes: '', who: 'subject', days: 0 }); draw(); };
  d.querySelector('#wsave').onclick = async ev => {
    ev.preventDefault();
    const clean = steps.filter(s => s.title.trim()).map(s => ({ ...s, title: s.title.trim() }));
    if (!d.querySelector('#wn').value.trim() || !clean.length) return toast('Add a name and at least one step');
    const data = { name: d.querySelector('#wn').value.trim(), description: d.querySelector('#wd').value.trim(), steps: clean };
    try { existing ? await editItem(existing, data) : await createItem({ kind: 'workflow', scope_id: wsScope().id, data }); d.close(); toast('Workflow saved'); route(); } catch (e) { toast(e.message); }
  };
}
/* running a workflow makes one task per step, assigned and dated, all encrypted, in a single request */
function runDialog(wf, subjectId) {
  const people = W.members;
  const d = dialog(`<h3>Run: ${esc(wf.data.name)}</h3><label>Who is it for?</label><select id="rs">${people.map(m => `<option value="${m.id}" ${m.id === subjectId ? 'selected' : ''}>${esc(m.name)}${m.new_hire ? ' (new hire)' : ''}</option>`).join('')}</select>
    <div class="grid2"><div><label>Their manager</label><select id="rm">${people.filter(m => roleRank[m.role] >= 2).map(m => `<option value="${m.id}">${esc(m.name)}</option>`).join('') || `<option value="${me.user.id}">${esc(me.user.name)}</option>`}</select></div><div><label>Starts</label><input type="date" id="rd" value="${today()}"></div></div>
    <p class="sub">${wf.data.steps.length} task${wf.data.steps.length === 1 ? '' : 's'} will be created with owners and due dates.</p><div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="rgo" value="yes">Start</button></div>`);
  d.querySelector('#rgo').onclick = async ev => {
    ev.preventDefault();
    const subject = +d.querySelector('#rs').value, manager = +d.querySelector('#rm').value, start = d.querySelector('#rd').value || today(), scope = wsScope().id;
    const admin = W.members.find(m => roleRank[m.role] >= 3)?.id || me.user.id;
    const who = w => ({ subject, manager, admin, creator: me.user.id }[w] || subject);
    try {
      const runId = (await api(`/w/${wid}/items/batch`, { method: 'POST', body: { items: [{ kind: 'run', scope_id: scope, meta: { workflow_id: wf.id, subject_id: subject }, ...(await sealFor(scope, 'run', null, { name: `${wf.data.name}: ${nameOf(subject)}`, startDate: start })) }] } })).ids[0];
      const items = [];
      for (const s of wf.data.steps) items.push({ kind: 'task', scope_id: scope, meta: { status: 'todo', assignee_id: who(s.who), due: addDays(start, s.days), priority: 2, run_id: runId }, ...(await sealFor(scope, 'task', null, { title: s.title, notes: s.notes || '' })) });
      await api(`/w/${wid}/items/batch`, { method: 'POST', body: { items } });
      d.close(); toast(`Started. ${items.length} tasks created.`); route();
    } catch (e) { toast(e.message); }
  };
}

/* ---------- pages ---------- */
async function pages(idStr) {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const list = (await listItems('page')).filter(p => !p.data._locked).sort((a, b) => b.meta.pinned - a.meta.pinned || (a.data.title < b.data.title ? -1 : 1));
  const cur = idStr === 'new' ? null : list.find(p => p.id === +idStr) || (idStr ? null : list[0]);
  const editing = idStr === 'new' || (location.hash.endsWith('/edit') && cur);
  const side = `<div class="chanlist"><div class="boxhead"><h3>Pages</h3>${can('manager') ? '<a class="linkbtn" href="#/pages/new">+ New</a>' : ''}</div>${list.map(p => `<a href="#/pages/${p.id}" class="${cur?.id === p.id ? 'on' : ''}">${p.meta.pinned ? '&#9733; ' : ''}${esc(p.data.title)}</a>`).join('') || '<div class="sub pad">No pages yet.</div>'}</div>`;
  if (editing) {
    app.innerHTML = shell(`<div class="chatwrap">${side}<div class="chatmain pad2"><h2>${cur ? 'Edit page' : 'New page'}</h2><label>Title</label><input id="pt" maxlength="120" value="${esc(cur?.data.title || '')}">
      <label>Content <small># heading, ## subheading, - bullet, **bold**</small></label><textarea id="pb" rows="16" maxlength="20000">${esc(cur?.data.body || '')}</textarea>
      ${cur ? '' : `<label>Who can see it</label>${scopePicker('ps', wsScope().id)}`}
      <label class="check"><input type="checkbox" id="pp" ${cur?.meta.pinned ? 'checked' : ''}> <span>Pin to the Home page</span></label>
      <div class="row end"><a class="btn ghost" href="#/pages/${cur?.id || ''}">Cancel</a><button class="btn" id="psave">Save page</button></div></div></div>`);
    $('#psave').onclick = async () => {
      const title = $('#pt').value.trim(); if (!title) return toast('Give the page a title');
      const data = { title, body: $('#pb').value }, meta = { pinned: $('#pp').checked };
      try { if (cur) { await editItem(cur, data, meta); location.hash = '#/pages/' + cur.id; } else { const id = await createItem({ kind: 'page', scope_id: +$('#ps').value, meta, data }); location.hash = '#/pages/' + id; } toast('Page saved'); } catch (e) { toast(e.message); }
    };
    return;
  }
  app.innerHTML = shell(`<div class="chatwrap">${side}<div class="chatmain pad2">${cur ? `<div class="titlebar"><div><h1>${esc(cur.data.title)}</h1><div class="sub">${lockSvg} ${esc(scopeLabel(scopeById(cur.scope_id)))} &middot; updated ${ago(cur.updated)} ago</div></div>${can('manager') ? `<div class="row"><a class="btn ghost" href="#/pages/${cur.id}/edit">Edit</a>${moreMenu([{ act: 'del-item', id: cur.id, label: 'Delete page', danger: true }])}</div>` : ''}</div><div class="doc">${renderDoc(cur.data.body)}</div>` : '<div class="empty">Select a page, or ask a manager to write one.</div>'}</div></div>`);
}

/* ---------- events ---------- */
async function events() {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const evs = (await listItems('event')).filter(e => !e.data._locked).sort((a, b) => a.meta.starts < b.meta.starts ? -1 : 1);
  const nowStr = new Date().toISOString().slice(0, 16), upcoming = evs.filter(e => e.meta.starts >= nowStr), past = evs.filter(e => e.meta.starts < nowStr).reverse();
  const card = e => { const mine = e.rsvps.find(r => r.user_id === me.user.id)?.status, going = e.rsvps.filter(r => r.status === 'yes');
    return `<div class="box ev"><div class="evdate"><b>${new Date(e.meta.starts).toLocaleDateString([], { month: 'short' })}</b><i>${new Date(e.meta.starts).getDate()}</i></div><div class="grow"><div class="row between"><h3>${esc(e.data.title)}</h3>${can('manager') ? moreMenu([{ act: 'del-item', id: e.id, label: 'Cancel event', danger: true }]) : ''}</div>
      <div class="sub">${fmtDT(e.meta.starts)}${e.data.where ? ' &middot; ' + esc(e.data.where) : ''} &middot; ${esc(scopeLabel(scopeById(e.scope_id)))}</div>${e.data.notes ? `<p class="pre">${esc(e.data.notes)}</p>` : ''}
      <div class="row wrapx">${['yes', 'maybe', 'no'].map(s => `<button class="btn small ${mine === s ? '' : 'ghost'}" data-act="rsvp" data-id="${e.id}:${s}">${{ yes: 'Going', maybe: 'Maybe', no: "Can't go" }[s]}</button>`).join('')}<small class="going">${going.length} going${going.length ? ': ' + going.slice(0, 5).map(r => esc(nameOf(r.user_id).split(' ')[0])).join(', ') + (going.length > 5 ? '…' : '') : ''}</small></div></div></div>`; };
  app.innerHTML = shell(`<div class="titlebar"><h1>Events</h1>${can('manager') ? '<button class="btn" data-act="new-event">New event</button>' : ''}</div>${upcoming.map(card).join('') || '<div class="box"><div class="empty">No upcoming events.</div></div>'}${past.length ? `<h4 class="sect">Past events</h4>${past.slice(0, 5).map(card).join('')}` : ''}`);
}
function eventDialog() {
  const start = new Date(Date.now() + 7 * 864e5); start.setHours(10, 0, 0, 0); const dv = new Date(start - start.getTimezoneOffset() * 6e4).toISOString().slice(0, 16);
  const d = dialog(`<h3>New event</h3><label>Title</label><input id="et" maxlength="120" placeholder="Quarterly all-hands"><label>Details</label><textarea id="en" rows="3" maxlength="2000"></textarea>
    <div class="grid2"><div><label>Starts</label><input type="datetime-local" id="es" value="${dv}"></div><div><label>Where</label><input id="ew" maxlength="120" placeholder="Room 4 or a video link"></div></div>
    <label>Who is invited</label>${scopePicker('esc', wsScope().id)}<div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="esave" value="yes">Create event</button></div>`);
  d.querySelector('#esave').onclick = async ev => {
    ev.preventDefault();
    const title = d.querySelector('#et').value.trim(); if (!title) return toast('Give the event a title');
    try { await createItem({ kind: 'event', scope_id: +d.querySelector('#esc').value, meta: { starts: d.querySelector('#es').value }, data: { title, notes: d.querySelector('#en').value, where: d.querySelector('#ew').value } }); d.close(); toast('Event created'); route(); } catch (e) { toast(e.message); }
  };
}

/* ---------- incentives ---------- */
async function incentives() {
  if (!hasAccess()) return waitingPage();
  app.innerHTML = shell(loading);
  const list = (await listItems('incentive')).filter(i => !i.data._locked).reverse(); window.__inc = list;
  const card = i => `<div class="box"><div class="row between"><div><h3>${esc(i.data.title)} ${i.meta.status === 'closed' ? '<span class="tag">Closed</span>' : '<span class="tag ok">Open</span>'}</h3><div class="reward">${esc(i.data.reward)}</div></div>
    ${can('admin') ? moreMenu([{ act: 'edit-incentive', id: i.id, label: 'Edit' }, { act: 'toggle-incentive', id: i.id, label: i.meta.status === 'closed' ? 'Reopen' : 'Close' }, { act: 'del-item', id: i.id, label: 'Delete', danger: true }]) : ''}</div>
    ${i.data.how ? `<h4>How to earn it</h4><p class="pre">${esc(i.data.how)}</p>` : ''}${i.meta.ends ? `<small>Ends ${fmtDay(i.meta.ends)}</small>` : ''}</div>`;
  app.innerHTML = shell(`<div class="titlebar"><div><h1>Incentives</h1><div class="sub">Programs and rewards for the whole team.</div></div>${can('admin') ? '<button class="btn" data-act="new-incentive">New program</button>' : ''}</div>${list.map(card).join('') || '<div class="box"><div class="empty">No incentive programs yet.</div></div>'}`);
}
function incentiveDialog(existing) {
  const d = dialog(`<h3>${existing ? 'Edit program' : 'New incentive program'}</h3><label>Name</label><input id="in" maxlength="100" value="${esc(existing?.data.title || '')}" placeholder="Referral bonus">
    <label>The reward</label><input id="ir" maxlength="200" value="${esc(existing?.data.reward || '')}" placeholder="$1,000 when your referral stays 90 days">
    <label>How people earn it</label><textarea id="ih" rows="4" maxlength="3000">${esc(existing?.data.how || '')}</textarea><label>Ends <small>(optional)</small></label><input type="date" id="ie" value="${existing?.meta.ends || ''}">
    <div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="isave" value="yes">Save</button></div>`);
  d.querySelector('#isave').onclick = async ev => {
    ev.preventDefault();
    const title = d.querySelector('#in').value.trim(); if (!title) return toast('Give the program a name');
    const data = { title, reward: d.querySelector('#ir').value, how: d.querySelector('#ih').value }, ends = d.querySelector('#ie').value || null;
    try { existing ? await editItem(existing, data, { ends }) : await createItem({ kind: 'incentive', scope_id: wsScope().id, meta: { ends }, data }); d.close(); toast('Saved'); route(); } catch (e) { toast(e.message); }
  };
}

/* ---------- people ---------- */
async function people() {
  if (!hasAccess()) return waitingPage();
  await reloadW();
  const fps = await Promise.all(W.members.map(m => fingerprint(m.public_key)));
  const invites = can('admin') ? await api(`/w/${wid}/invites`) : [];
  const roleSel = m => can('admin') && m.id !== me.user.id && m.role !== 'owner' && (W.me.role === 'owner' || roleRank[m.role] < roleRank[W.me.role])
    ? `<select data-act="set-role" data-id="${m.id}">${['member', 'manager', 'admin'].filter(r => W.me.role === 'owner' || roleRank[r] < roleRank[W.me.role]).map(r => `<option ${m.role === r ? 'selected' : ''}>${r}</option>`).join('')}</select>` : `<span class="role">${m.role}</span>`;
  app.innerHTML = shell(`<div class="titlebar"><div><h1>People</h1><div class="sub">${W.members.length} in ${esc(W.name)}</div></div>${can('admin') ? '<button class="btn" data-act="new-invite">Invite people</button>' : ''}</div>
    <div class="box">${W.members.map((m, i) => `<div class="rowi person">${avatar(m, 'lg')}<div class="grow"><b>${esc(m.name)}</b> ${m.id === me.user.id ? '<small>(you)</small>' : ''} ${m.new_hire ? `<span class="tag">New hire${m.start_date ? ' &middot; ' + fmtDay(m.start_date) : ''}</span>` : ''}<div class="sub">${esc(m.title || 'No title yet')}</div>
      <div class="fp" title="If this code matches what they see on their People page, nobody has swapped their key.">${lockSvg} ${fps[i]}</div></div>
      <div class="row end2">${roleSel(m)}${m.id !== me.user.id ? `<button class="btn small ghost" data-act="dm" data-id="${m.id}">Message</button>` : '<button class="btn small ghost" data-act="edit-title" data-id="' + m.id + '">Edit title</button>'}
      ${can('admin') && m.id !== me.user.id && m.role !== 'owner' ? moreMenu([{ act: 'edit-title', id: m.id, label: 'Edit title' }, { act: 'toggle-hire', id: m.id, label: m.new_hire ? 'Not a new hire' : 'Mark as new hire' }, ...(can('manager') ? [{ act: 'onboard', id: m.id, label: 'Start onboarding' }] : []), { act: 'remove-member', id: m.id, label: 'Remove from workspace', danger: true }]) : ''}</div></div>`).join('')}</div>
    ${can('admin') ? `<div class="box"><div class="boxhead"><h3>Invite links</h3></div>${invites.map(v => `<div class="rowi"><div class="grow"><b>${esc(v.role)}</b> ${v.revoked ? '<span class="tag">Revoked</span>' : v.uses >= v.max_uses ? '<span class="tag">Used up</span>' : v.expires < new Date().toISOString() ? '<span class="tag">Expired</span>' : '<span class="tag ok">Active</span>'}<small>${v.uses}/${v.max_uses} used &middot; expires ${fmtDay(v.expires.slice(0, 10))}${v.new_hire ? '' : ' &middot; not new hires'}</small></div>${!v.revoked ? `<button class="btn small ghost" data-act="revoke-invite" data-id="${v.id}">Revoke</button>` : ''}</div>`).join('') || '<div class="empty small">No invite links yet. Links are shown once, when you create them.</div>'}</div>` : ''}`);
}
function inviteDialog() {
  const roles = W.me.role === 'owner' ? ['member', 'manager', 'admin'] : ['member', 'manager'].filter(r => roleRank[r] < roleRank[W.me.role]);
  const d = dialog(`<h3>Invite people</h3><p class="sub">Create a link and send it however you like. Whoever opens it can join with the role you pick.</p>
    <div class="grid2"><div><label>Role</label><select id="ivr">${roles.map(r => `<option>${r}</option>`).join('')}</select></div><div><label>Can be used</label><select id="ivu">${[1, 5, 25, 100].map(n => `<option value="${n}" ${n === 5 ? 'selected' : ''}>${n} time${n > 1 ? 's' : ''}</option>`).join('')}</select></div>
    <div><label>Expires in</label><select id="ivd">${[1, 7, 14, 30].map(n => `<option value="${n}" ${n === 7 ? 'selected' : ''}>${n} day${n > 1 ? 's' : ''}</option>`).join('')}</select></div><div><label>Label <small>(optional)</small></label><input id="ivl" maxlength="60" placeholder="Design team"></div></div>
    <label class="check"><input type="checkbox" id="ivn" checked> <span>They are new hires (shows a badge and offers onboarding)</span></label><div id="ivout"></div>
    <div class="row end"><button class="btn ghost" value="no">Close</button><button class="btn" id="ivgo" value="x" type="button">Create link</button></div>`);
  d.querySelector('#ivgo').onclick = async () => {
    try {
      const r = await api(`/w/${wid}/invites`, { method: 'POST', body: { role: d.querySelector('#ivr').value, max_uses: +d.querySelector('#ivu').value, days: +d.querySelector('#ivd').value, label: d.querySelector('#ivl').value, new_hire: d.querySelector('#ivn').checked } });
      const link = `${location.origin}/corp#/join/${r.token}`;
      d.querySelector('#ivout').innerHTML = `<div class="invitebox"><input readonly id="ivlink" value="${esc(link)}"><button class="btn small" type="button" id="ivcopy">Copy</button></div><small>This link is shown once. Anyone who has it can join, so share it privately.</small>`;
      d.querySelector('#ivcopy').onclick = async () => { const el = d.querySelector('#ivlink'); el.select(); try { await navigator.clipboard.writeText(link); toast('Link copied'); } catch { toast('Press Ctrl+C to copy the link'); } };
      d.querySelector('#ivgo').remove();
    } catch (e) { toast(e.message); }
  };
}

/* ---------- settings ---------- */
async function settings() {
  await reloadW();
  const log = can('admin') ? await api(`/w/${wid}/audit`) : [];
  const names = { workspace_created: 'Workspace created', member_joined: 'Someone joined', member_removed: 'Someone was removed', member_left: 'Someone left', role_changed: 'A role changed', invite_created: 'An invite link was created', invite_revoked: 'An invite link was revoked', key_rotated: 'Encryption key renewed', workspace_renamed: 'Workspace renamed', new_hire_flag: 'New-hire flag changed', private_group_created: 'A private group was created', private_group_member_added: 'Someone was added to a private group', private_group_member_removed: 'Someone was removed from a private group' };
  app.innerHTML = shell(`<div class="titlebar"><h1>${can('admin') ? 'Settings' : 'Account'}</h1></div>
    <div class="box"><div class="boxhead"><h3>Your profile</h3></div><div class="setrow"><div class="grid2"><div><label>Name</label><input id="sn" maxlength="60" value="${esc(me.user.name)}"></div><div><label>Job title</label><input id="st" maxlength="60" value="${esc(me.user.title)}"></div></div><button class="btn small" data-act="save-profile">Save</button></div>
      <div class="setrow"><div><b>Login file</b><div class="sub">Holds your private key. Keep it somewhere safe: without it, nobody (including us) can recover your messages.</div></div><button class="btn small ghost" data-act="save-login">Download</button></div></div>
    ${can('admin') ? `<div class="box"><div class="boxhead"><h3>Workspace</h3></div><div class="setrow"><div class="grow"><label>Company name</label><input id="wn" maxlength="80" value="${esc(W.name)}"></div><button class="btn small" data-act="rename-ws">Save</button></div></div>` : ''}
    <div class="box"><div class="boxhead"><h3>How your data is protected</h3></div><div class="explain"><p><b>Encrypted in your browser:</b> messages, task titles and details, comments, pages, workflows, events, incentives. Huddle's servers only store scrambled data.</p>
      <p><b>Visible to the server:</b> who is in the workspace and their roles, task status, assignee and due date, event times, and when things were created. This is what lets the app work.</p>
      <p><b>Not possible:</b> Huddle can't reset a lost key or search your content, and admins can't read private groups they aren't in. Search happens in your browser.</p>
      <p><b>When someone leaves:</b> their access ends right away and the keys are renewed, so they can't read anything new.</p></div></div>
    ${can('admin') ? `<div class="box"><div class="boxhead"><h3>Activity log</h3></div>${log.map(e => `<div class="rowi"><div class="grow">${esc(names[e.action] || e.action)}<small>${e.actor_id ? esc(nameOf(e.actor_id)) : ''} &middot; ${ago(e.created)} ago</small></div></div>`).join('') || '<div class="empty small">Nothing yet.</div>'}<div class="sub pad">The log records actions, never content.</div></div>` : ''}
    <div class="box"><div class="boxhead"><h3>Danger zone</h3></div>${W.me.role !== 'owner' ? '<div class="setrow"><div><b>Leave this workspace</b><div class="sub">You lose access to its content. An admin can invite you back.</div></div><button class="btn small danger" data-act="leave-ws">Leave</button></div>' : '<div class="setrow"><div><b>Delete this workspace</b><div class="sub">Permanently erases everything in it for everyone. This can\'t be undone.</div></div><button class="btn small danger" data-act="delete-ws">Delete workspace</button></div>'}</div>`);
}

/* ---------- actions ---------- */
document.addEventListener('click', async e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const { act, id } = el.dataset;
  el.closest('details')?.removeAttribute('open');
  if (act === 'set-role') return;  // handled on change
  try {
    if (act === 'signout') { store.del('corp_token'); me = null; W = null; scopeKeys.clear(); renderTop(); renderBanner(); toast('Signed out. Use your login file to get back in.'); location.hash = '#/'; route();
    } else if (act === 'save-login') { downloadLoginFile(); toast('Saved. Keep that file somewhere private.');
    } else if (act === 'new-channel') newChannelDialog();
    else if (act === 'archive-channel') { await editItem({ id: +id, scope_id: 0, kind: 'channel', parent_id: null }, null, { archived: true }); toast('Channel archived'); location.hash = '#/chat'; route();
    } else if (act === 'dm') await openDm(+id);
    else if (act === 'del-item') { if (await confirmDialog({ title: 'Delete this?', text: 'It disappears for everyone.', ok: 'Delete', danger: true })) { await api(`/w/${wid}/items/${id}`, { method: 'DELETE' }); toast('Deleted'); if (location.hash.startsWith('#/pages/')) location.hash = '#/pages'; route(); }
    } else if (act === 'tfilter') { taskFilter = id; route();
    } else if (act === 'new-task') taskDialog();
    else if (act === 'open-task') taskDetail(+id);
    else if (act === 'new-workflow') workflowEditor();
    else if (act === 'edit-workflow') workflowEditor(window.__flows.find(w => w.id === +id));
    else if (act === 'run-workflow') runDialog(window.__flows.find(w => w.id === +id));
    else if (act === 'finish-run') { await api(`/w/${wid}/items/${id}`, { method: 'PUT', body: { meta: { status: 'done' } } }); toast('Marked complete'); route();
    } else if (act === 'onboard') {
      const flows = (await listItems('workflow')).filter(w => !w.data._locked); window.__flows = flows;
      const wf = flows.find(w => /onboard/i.test(w.data.name)) || flows[0]; if (!wf) return toast('Create an onboarding workflow first'); runDialog(wf, +id);
    } else if (act === 'new-event') eventDialog();
    else if (act === 'rsvp') { const [i, s] = id.split(':'); await api(`/w/${wid}/items/${i}/rsvp`, { method: 'PUT', body: { status: s } }); route();
    } else if (act === 'new-incentive') incentiveDialog();
    else if (act === 'edit-incentive') incentiveDialog(window.__inc.find(i => i.id === +id));
    else if (act === 'toggle-incentive') { const i = window.__inc.find(x => x.id === +id); await editItem(i, null, { status: i.meta.status === 'closed' ? 'active' : 'closed' }); route();
    } else if (act === 'new-invite') inviteDialog();
    else if (act === 'revoke-invite') { await api(`/w/${wid}/invites/${id}`, { method: 'DELETE' }); toast('Invite revoked'); route();
    } else if (act === 'toggle-hire') { const m = member(+id); await api(`/w/${wid}/members/${id}`, { method: 'PUT', body: { new_hire: !m.new_hire, start_date: m.new_hire ? null : today() } }); route();
    } else if (act === 'edit-title') {
      const m = member(+id), d = dialog(`<h3>Job title</h3><input id="tt2" maxlength="60" value="${esc(m.title)}"><div class="row end"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="tt2s" value="yes">Save</button></div>`);
      d.querySelector('#tt2s').onclick = async ev => { ev.preventDefault(); try { await api(`/w/${wid}/members/${id}`, { method: 'PUT', body: { title: d.querySelector('#tt2').value } }); d.close(); route(); } catch (err) { toast(err.message); } };
    } else if (act === 'remove-member') {
      const m = member(+id);
      if (await confirmDialog({ title: `Remove ${m.name}?`, text: 'They lose access right away, and the encryption keys are renewed so they cannot read anything new.', ok: 'Remove', danger: true })) { await api(`/w/${wid}/members/${id}`, { method: 'DELETE' }); await reloadW(); await autoRotate(); toast(`${m.name} was removed`); route(); }
    } else if (act === 'save-profile') { await api('/me', { method: 'PUT', body: { name: $('#sn').value, title: $('#st').value } }); await loadMe(); toast('Saved'); route();
    } else if (act === 'rename-ws') { await api(`/w/${wid}`, { method: 'PUT', body: { name: $('#wn').value } }); await loadMe(); toast('Saved'); route();
    } else if (act === 'leave-ws') {
      if (await confirmDialog({ title: 'Leave this workspace?', text: 'You will lose access to its content.', ok: 'Leave', danger: true })) { await api(`/w/${wid}/members/${me.user.id}`, { method: 'DELETE' }); store.del('corp_wid'); await loadMe(); toast('You left the workspace'); location.hash = '#/'; route(); }
    } else if (act === 'delete-ws') {
      if (await confirmDialog({ title: `Delete ${W.name}?`, text: 'Everything in it is erased for everyone. This cannot be undone.', ok: 'Delete workspace', danger: true })) { await api(`/w/${wid}`, { method: 'DELETE' }); store.del('corp_wid'); await loadMe(); toast('Workspace deleted'); location.hash = '#/'; route(); }
    }
  } catch (err) { if (!(err instanceof Stale)) toast(err.message); }
});
document.addEventListener('change', async e => {
  const el = e.target.closest('[data-act="set-role"]'); if (!el) return;
  try { await api(`/w/${wid}/members/${el.dataset.id}`, { method: 'PUT', body: { role: el.value } }); toast('Role updated'); route(); } catch (err) { toast(err.message); route(); }
});

/* ---------- routing ---------- */
const routes = [
  [/^#\/join\/(.+)/, joinPage, false], [/^#\/new/, newWorkspace, false], [/^#\/login/, loginPage, false],
  [/^#\/chat(?:\/(\d+))?/, chat, true], [/^#\/tasks/, tasks, true], [/^#\/workflows/, workflows, true],
  [/^#\/pages(?:\/(new|\d+))?/, pages, true], [/^#\/events/, events, true], [/^#\/incentives/, incentives, true],
  [/^#\/people/, people, true], [/^#\/settings/, settings, true],
];
async function route() {
  const h = location.hash || '#/'; const seq = ++routeSeq;
  timers.forEach(clearInterval); timers = []; window.scrollTo({ top: 0 });
  const fail = e => { if (!(e instanceof Stale)) app.innerHTML = shell(`<div class="box"><div class="empty">${esc(e.message)}</div></div>`); };
  for (const [re, fn, needs] of routes) {
    const m = h.match(re); if (!m) continue;
    if (needs && !me) return welcome();
    if (needs && !W) { app.innerHTML = '<div class="solo"><div class="box"><h2>No workspace yet</h2><p><a class="btn" href="#/new">Create one</a></p></div></div>'; return; }
    await Promise.resolve().then(() => fn(m[1])).catch(fail);
    if (seq === routeSeq) document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === navFor(h)));
    return;
  }
  if (!me) return welcome();
  try { await home(); } catch (e) { fail(e); }
  if (seq === routeSeq) document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === '#/'));
}
const navFor = h => (NAV.map(n => n[0]).concat('#/settings').filter(p => p !== '#/').find(p => h.startsWith(p))) || '#/';
addEventListener('hashchange', route);
setInterval(() => document.hidden || !W || keepKeysFlowing().catch(() => {}), 12000);  // hand out and renew keys in the background
(async () => {
  try { await loadMe(); } catch { app.innerHTML = '<div class="solo"><div class="box form"><h2>Can\'t connect to Huddle Corp</h2><p>Check your connection, then try again.</p><p><button class="btn" id="retry">Try again</button></p></div></div>'; $('#retry').onclick = () => location.reload(); return; }
  if (W) { try { await keepKeysFlowing(); } catch {} }
  route();
})();
