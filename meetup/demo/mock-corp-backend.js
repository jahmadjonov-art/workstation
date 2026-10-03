/* Demo-only stand-in for corp.py. It runs inside the browser tab and answers the same /api/corp requests, so the
   real Huddle Corp front end (static/corp.js) runs unchanged. Nothing is saved: reload to start over.
   The pretend teammates have real encryption keys. They unwrap and use workspace keys exactly as a real browser
   would, so everything you see is genuinely encrypted in this page. Needs crypto.js loaded first. */
(() => {
  const nowIso = () => new Date().toISOString().slice(0, 19) + 'Z';
  const DAY = 864e5, HOUR = 36e5;
  const RANK = { member: 1, manager: 2, admin: 3, owner: 4 };
  const KINDS = new Set(['channel', 'message', 'task', 'page', 'workflow', 'run', 'event', 'incentive']);
  const MIN_ROLE = { channel: 'member', message: 'member', task: 'member', page: 'manager', event: 'manager', run: 'manager', workflow: 'admin', incentive: 'admin' };
  const STATUSES = new Set(['todo', 'doing', 'blocked', 'done']);
  const DATE_RE = /^\d{4}-\d{2}-\d{2}$/, DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
  const rnd = n => b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[^a-z0-9]/gi, '');
  const db = { users: [], workspaces: [], members: [], invites: [], scopes: [], sm: [], grants: [], items: [], rsvps: [], audit: [], tokens: {}, ids: { user: 0, ws: 0, scope: 0, item: 0, invite: 0, audit: 0 } };
  const nid = k => ++db.ids[k];
  const bots = {};  // seeded teammates: user id -> private key (JWK), so they can read and write encrypted content
  class HttpError extends Error { constructor(status, detail) { super(detail); this.status = status; this.detail = detail; } }
  const fail = (s, d) => { throw new HttpError(s, d); };

  const user = id => db.users.find(u => u.id === id);
  const pubU = u => ({ id: u.id, name: u.name, title: u.title, public_key: u.public_key });
  const mem = (wid, uid) => db.members.find(m => m.workspace_id === wid && m.user_id === uid);
  const needMember = (wid, uid) => mem(wid, uid) || fail(404, 'Workspace not found');
  const needRole = (m, r) => { if (RANK[m.role] < RANK[r]) fail(403, `This needs the ${r} role`); };
  const inScope = (sid, uid) => db.sm.some(x => x.scope_id === sid && x.user_id === uid);
  const holds = (sid, epoch, uid) => db.grants.some(g => g.scope_id === sid && g.epoch === epoch && g.user_id === uid);
  const audit = (wid, actor, action, detail = '') => db.audit.push({ id: nid('audit'), workspace_id: wid, actor_id: actor, action, detail, created: nowIso() });
  const wsScope = wid => db.scopes.find(s => s.workspace_id === wid && s.kind === 'workspace');
  const newUser = (name, title, public_key) => { const token = rnd(32), u = { id: nid('user'), name: name.trim(), title: (title || '').trim(), public_key, deleted: false }; db.users.push(u); db.tokens[token] = u.id; return [u, token]; };
  const addMember = (wid, uid, role, title, newHire) => { db.members.push({ workspace_id: wid, user_id: uid, role, title: title || '', start_date: newHire ? nowIso().slice(0, 10) : null, new_hire: !!newHire, joined: nowIso() }); db.sm.push({ scope_id: wsScope(wid).id, user_id: uid }); };
  const membersOf = sid => db.sm.filter(x => x.scope_id === sid).map(x => x.user_id);
  const dropFromScope = (sid, uid) => { db.sm = db.sm.filter(x => !(x.scope_id === sid && x.user_id === uid)); if (membersOf(sid).length) db.scopes.find(s => s.id === sid).rotation_needed = true; };

  /* ---------- the same sealing and wrapping the browser app does ---------- */
  const aad = (wid, scope, kind, parent) => enc.encode(`${wid}|${scope}|${kind}|${parent || 0}`);
  const scopeKeys = new Map();  // "scope:epoch" -> CryptoKey, learned by the pretend teammates by opening their own grants
  async function botKey(botId, scopeId, epoch) {
    const id = `${scopeId}:${epoch}:${botId}`;
    if (scopeKeys.has(id)) return scopeKeys.get(id);
    const g = db.grants.find(x => x.scope_id === scopeId && x.epoch === epoch && x.user_id === botId); if (!g) return null;
    const raw = await unwrapKey(bots[botId], user(g.granter_id).public_key, g.wrapped);
    const k = await aesKey(raw, ['encrypt', 'decrypt']); scopeKeys.set(id, k); return k;
  }
  async function botPut(botId, wid, scopeId, kind, data, { parent = null, meta = {}, when } = {}) {
    const s = db.scopes.find(x => x.id === scopeId), k = await botKey(botId, scopeId, s.epoch);
    const sealed = await sealJson(k, data, aad(wid, scopeId, kind, parent));
    const it = { id: nid('item'), workspace_id: wid, scope_id: scopeId, kind, parent_id: parent, meta: cleanMeta(scopeId, kind, meta), iv: sealed.iv, ct: sealed.ct, epoch: s.epoch, created_by: botId, created: when || nowIso(), updated: when || nowIso(), deleted: false };
    db.items.push(it); return it;
  }

  /* ---------- plaintext metadata, validated like the real server ---------- */
  function cleanMeta(scopeId, kind, meta) {
    const date = v => { if (v != null && !(typeof v === 'string' && DATE_RE.test(v))) fail(400, 'Use dates like 2026-01-15'); return v ?? null; };
    const person = v => { if (v == null) return null; if (!Number.isInteger(v) || !inScope(scopeId, v)) fail(400, "That person can't see this item. Pick someone from its group."); return v; };
    if (kind === 'task') { const st = meta.status ?? 'todo'; if (!STATUSES.has(st)) fail(400, 'Unknown status'); return { status: st, assignee_id: person(meta.assignee_id), due: date(meta.due), priority: [1, 2, 3].includes(meta.priority) ? meta.priority : 2, run_id: Number.isInteger(meta.run_id) ? meta.run_id : null }; }
    if (kind === 'run') return { workflow_id: Number.isInteger(meta.workflow_id) ? meta.workflow_id : null, subject_id: person(meta.subject_id), status: meta.status === 'done' ? 'done' : 'active' };
    if (kind === 'event') { if (typeof meta.starts !== 'string' || !DT_RE.test(meta.starts)) fail(400, 'Choose when the event starts'); return { starts: meta.starts, ends: typeof meta.ends === 'string' && DT_RE.test(meta.ends) ? meta.ends : null }; }
    if (kind === 'incentive') return { status: meta.status === 'closed' ? 'closed' : 'active', ends: date(meta.ends) };
    if (kind === 'page') return { pinned: !!meta.pinned };
    if (kind === 'channel') return { archived: !!meta.archived };
    return {};
  }

  /* ---------- the pretend company: Northwind Labs ---------- */
  let NW = null;  // { wid, scope, owner, ... }
  const ready = (async () => {
    const people = [['Priya Raman', 'Chief Executive', 'owner', false], ['Marcus Webb', 'Head of Engineering', 'manager', false], ['Jo Alvarez', 'People & Culture', 'admin', false], ['Lena Fischer', 'Product Designer', 'member', true], ['Sam Idowu', 'Customer Success', 'member', false]];
    const ids = [];
    for (const [name, title] of people) { const k = await genKeys(); const [u] = newUser(name, title, k.pub); bots[u.id] = k.priv; ids.push(u.id); }
    const [priya, marcus, jo, lena, sam] = ids;
    const wid = nid('ws'); db.workspaces.push({ id: wid, name: 'Northwind Labs', owner_id: priya, created: nowIso() });
    const sid = nid('scope'); db.scopes.push({ id: sid, workspace_id: wid, kind: 'workspace', epoch: 1, rotation_needed: false, created_by: priya, created: nowIso() });
    people.forEach(([n, t, role, hire], i) => addMember(wid, ids[i], role, t, hire));
    const wsRaw = crypto.getRandomValues(new Uint8Array(32));
    for (const id of ids) db.grants.push({ scope_id: sid, epoch: 1, user_id: id, granter_id: priya, wrapped: await wrapKey(bots[priya], user(id).public_key, wsRaw), created: nowIso() });
    NW = { wid, sid, priya, marcus, jo, lena, sam, wsRaw };
    const ago = h => new Date(Date.now() - h * HOUR).toISOString().slice(0, 19) + 'Z';
    const put = (by, kind, data, o = {}) => botPut(by, wid, o.scope || sid, kind, data, o);

    // channels and conversation
    const general = await put(priya, 'channel', { name: 'general', topic: 'Company-wide announcements and chat' });
    const product = await put(marcus, 'channel', { name: 'product-launch', topic: 'Everything about the Q4 launch' });
    const random = await put(sam, 'channel', { name: 'watercooler', topic: 'Off-topic and good news' });
    await put(priya, 'message', { text: 'Welcome to Northwind Labs on Huddle Corp. This space is end-to-end encrypted, so what we say here stays here.' }, { parent: general.id, when: ago(30) });
    await put(jo, 'message', { text: 'Reminder: the all-hands is next week. Questions for Priya can go in this channel.' }, { parent: general.id, when: ago(22) });
    await put(marcus, 'message', { text: 'Design review for the new dashboard is done. Lena, great work on the empty states.' }, { parent: product.id, when: ago(20) });
    await put(lena, 'message', { text: 'Thanks! Happy to walk anyone through the Figma file.' }, { parent: product.id, when: ago(19) });
    await put(sam, 'message', { text: 'Friday lunch is on the company. Vote for tacos or ramen below.' }, { parent: random.id, when: ago(6) });

    // a private group: leadership. Not everyone in the company can read it.
    const lsid = nid('scope'); db.scopes.push({ id: lsid, workspace_id: wid, kind: 'private', epoch: 1, rotation_needed: false, created_by: priya, created: nowIso() });
    const lraw = crypto.getRandomValues(new Uint8Array(32));
    for (const id of [priya, marcus, jo]) { db.sm.push({ scope_id: lsid, user_id: id }); db.grants.push({ scope_id: lsid, epoch: 1, user_id: id, granter_id: priya, wrapped: await wrapKey(bots[priya], user(id).public_key, lraw), created: nowIso() }); }
    const lead = await put(priya, 'channel', { name: 'leadership' }, { scope: lsid });
    await put(priya, 'message', { text: 'Salary bands for next year are attached. Please keep this between us until the announcement.' }, { scope: lsid, parent: lead.id, when: ago(4) });
    audit(wid, priya, 'private_group_created', `scope=${lsid} members=3`);

    // pages
    await put(priya, 'page', { title: 'Welcome to Northwind Labs', body: '# Our company page\n\nWe build calm software for small teams.\n\n## What we value\n- **Clarity** over cleverness\n- **Kindness** in every review\n- **Ownership**: if you see it, you own it\n\n## Where to start\n- Say hello in #general\n- Read the handbook\n- Check your tasks on the board' }, { meta: { pinned: true } });
    await put(jo, 'page', { title: 'Employee handbook', body: '# Handbook\n\n## Working hours\nWe work flexibly. Core hours are 10:00 to 15:00.\n\n## Time off\n- 25 days of paid leave\n- Request leave from your manager at least two weeks ahead\n\n## Equipment\nEvery new hire gets a laptop and a monitor.' });
    await put(jo, 'page', { title: 'Expense policy', body: '# Expenses\n\n- Keep receipts for **everything**\n- Submit within 30 days\n- Anything over $500 needs manager approval' });

    // workflows: a template and a run that is already underway
    const onboarding = { name: 'New hire onboarding', description: 'Everything a new teammate needs in their first weeks.', steps: [
      { title: 'Set up laptop and accounts', notes: 'Email, chat, password manager, VPN.', who: 'admin', days: 0 }, { title: 'Welcome meeting with the team', notes: 'Introductions and how the team works.', who: 'manager', days: 1 },
      { title: 'Read the company pages', notes: 'Company page, handbook and policies.', who: 'subject', days: 3 }, { title: 'Complete payroll and benefits forms', notes: '', who: 'subject', days: 5 },
      { title: 'First goals agreed with manager', notes: 'Three goals for the first 90 days.', who: 'manager', days: 14 }, { title: '30-day check-in', notes: 'What is working, what is not.', who: 'manager', days: 30 }] };
    const wf = await put(jo, 'workflow', onboarding);
    await put(jo, 'workflow', { name: 'Expense approval', description: 'For purchases over $500.', steps: [{ title: 'Submit the receipt and a short reason', notes: '', who: 'subject', days: 0 }, { title: 'Manager review', notes: '', who: 'manager', days: 2 }, { title: 'Finance reimburses', notes: '', who: 'admin', days: 7 }] });
    const start = new Date(Date.now() - 12 * DAY).toISOString().slice(0, 10), addD = (d, n) => new Date(new Date(d + 'T12:00').getTime() + n * DAY).toISOString().slice(0, 10);
    const run = await put(jo, 'run', { name: 'New hire onboarding: Lena Fischer', startDate: start }, { meta: { workflow_id: wf.id, subject_id: lena } });
    const who = w => ({ subject: lena, manager: marcus, admin: jo }[w]);
    for (const [i, s] of onboarding.steps.entries()) await put(jo, 'task', { title: s.title, notes: s.notes }, { meta: { status: i < 3 ? 'done' : i === 3 ? 'doing' : 'todo', assignee_id: who(s.who), due: addD(start, s.days), priority: 2, run_id: run.id } });

    // a few standalone tasks
    await put(marcus, 'task', { title: 'Finalize the Q4 launch checklist', notes: 'Marketing, support and engineering sign-offs.' }, { meta: { status: 'doing', assignee_id: marcus, due: addD(nowIso().slice(0, 10), 4), priority: 1 } });
    await put(sam, 'task', { title: 'Collect customer quotes for the launch page', notes: 'Three quotes, with permission.' }, { meta: { status: 'todo', assignee_id: sam, due: addD(nowIso().slice(0, 10), 9), priority: 2 } });
    await put(lena, 'task', { title: 'Export dashboard icons for engineering', notes: '' }, { meta: { status: 'blocked', assignee_id: lena, due: addD(nowIso().slice(0, 10), 2), priority: 2 } });

    // events and incentives
    const d = n => { const x = new Date(Date.now() + n * DAY); x.setHours(10, 0, 0, 0); return new Date(x - x.getTimezoneOffset() * 6e4).toISOString().slice(0, 16); };
    const ev1 = await put(jo, 'event', { title: 'Quarterly all-hands', notes: 'Results, roadmap and open Q&A with Priya.', where: 'Main room and video link' }, { meta: { starts: d(7) } });
    await put(jo, 'event', { title: 'Team offsite: planning day', notes: 'Bring ideas for next year.', where: 'The Barn, Hill Country' }, { meta: { starts: d(24) } });
    for (const [u, st] of [[priya, 'yes'], [marcus, 'yes'], [lena, 'maybe']]) db.rsvps.push({ item_id: ev1.id, user_id: u, status: st });
    await put(jo, 'incentive', { title: 'Referral bonus', reward: '$1,000 when your referral stays 90 days', how: 'Refer someone who joins and stays for three months. Tell People & Culture when you make the introduction.' }, { meta: {} });
    await put(priya, 'incentive', { title: 'Launch spot awards', reward: 'A $250 award for standout work on the Q4 launch', how: 'Managers nominate people who went above and beyond. Awards are announced at the all-hands.' }, { meta: { ends: d(7).slice(0, 10) } });
    audit(wid, priya, 'workspace_created');
  })();

  /* ---------- pretend teammates answer in the real encrypted channels ---------- */
  const LINES = ['Good point. Let me think about that and get back to you.', 'Thanks for flagging. I will add it to the launch checklist.', 'Agreed. Can we talk about it at the all-hands?', 'On it. I will update the task today.', 'Nice, that helps a lot.', 'Let us loop in Jo on this.'];
  async function maybeReply(item) {
    if (item.kind !== 'message' || bots[item.created_by]) return;
    const parent = db.items.find(i => i.id === item.parent_id); if (!parent || parent.kind !== 'channel') return;
    const others = membersOf(item.scope_id).filter(id => bots[id] && id !== item.created_by); if (!others.length) return;
    const dm = membersOf(item.scope_id).length === 2, pick = others[item.id % others.length];
    setTimeout(() => botPut(pick, item.workspace_id, item.scope_id, 'message', { text: dm ? 'Thanks for the message. I will get back to you shortly.' : LINES[item.id % LINES.length] }, { parent: item.parent_id }).catch(() => {}), 2500);
  }

  /* ---------- routes ---------- */
  const routes = [];
  const R = (method, path, fn, auth = true) => routes.push({ method, re: new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, auth });
  const itemDict = it => ({ id: it.id, kind: it.kind, scope_id: it.scope_id, parent_id: it.parent_id, meta: it.meta, iv: it.iv, ct: it.ct, epoch: it.epoch, created_by: it.created_by, created: it.created, updated: it.updated,
    ...(it.kind === 'event' ? { rsvps: db.rsvps.filter(r => r.item_id === it.id).map(r => ({ user_id: r.user_id, status: r.status })) } : {}) });
  const memberDict = m => ({ ...pubU(user(m.user_id)), title: m.title, role: m.role, start_date: m.start_date, new_hire: m.new_hire, joined: m.joined });
  const validWrap = w => typeof w === 'string' && w.split('.').length === 2 && w.split('.').every(p => p && /^[A-Za-z0-9+/]+={0,2}$/.test(p));
  const okB64 = s => typeof s === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(s);

  R('GET', '/pow', () => ({ challenge: 'demo.' + rnd(8), bits: 10 }), false);
  R('POST', '/signup', ({ body: b }) => {
    if (b.website) fail(400, 'Could not create account');
    if (!b.authorized) fail(400, 'Please confirm you are allowed to create this workspace');
    if (!b.company || b.company.trim().length < 2) fail(422, 'Please add the company name');
    const [u, token] = newUser(b.name, b.title, b.public_key);
    const wid = nid('ws'); db.workspaces.push({ id: wid, name: b.company.trim(), owner_id: u.id, created: nowIso() });
    const sid = nid('scope'); db.scopes.push({ id: sid, workspace_id: wid, kind: 'workspace', epoch: 1, rotation_needed: false, created_by: u.id, created: nowIso() });
    db.members.push({ workspace_id: wid, user_id: u.id, role: 'owner', title: (b.title || '').trim(), start_date: null, new_hire: false, joined: nowIso() }); db.sm.push({ scope_id: sid, user_id: u.id });
    audit(wid, u.id, 'workspace_created'); return { token, user_id: u.id, workspace_id: wid, scope_id: sid };
  }, false);
  R('POST', '/workspaces', ({ me, body: b }) => {
    if (!b.authorized) fail(400, 'Please confirm you are allowed to create this workspace');
    const wid = nid('ws'); db.workspaces.push({ id: wid, name: b.company.trim(), owner_id: me.id, created: nowIso() });
    const sid = nid('scope'); db.scopes.push({ id: sid, workspace_id: wid, kind: 'workspace', epoch: 1, rotation_needed: false, created_by: me.id, created: nowIso() });
    db.members.push({ workspace_id: wid, user_id: me.id, role: 'owner', title: me.title, start_date: null, new_hire: false, joined: nowIso() }); db.sm.push({ scope_id: sid, user_id: me.id });
    audit(wid, me.id, 'workspace_created'); return { workspace_id: wid, scope_id: sid };
  });
  /* demo only: jump into the pretend company as an admin, with the workspace key handed over by its owner */
  R('POST', '/demo-join', async ({ body: b }) => {
    await ready;
    const [u, token] = newUser(b.name, b.title, b.public_key);
    addMember(NW.wid, u.id, 'admin', b.title, false);
    db.grants.push({ scope_id: NW.sid, epoch: 1, user_id: u.id, granter_id: NW.priya, wrapped: await wrapKey(bots[NW.priya], u.public_key, NW.wsRaw), created: nowIso() });
    audit(NW.wid, u.id, 'member_joined', 'role=admin');
    // Marcus sends a direct message and hands over two tasks
    const sid = nid('scope'); db.scopes.push({ id: sid, workspace_id: NW.wid, kind: 'private', epoch: 1, rotation_needed: false, created_by: NW.marcus, created: nowIso() });
    const raw = crypto.getRandomValues(new Uint8Array(32));
    for (const id of [NW.marcus, u.id]) { db.sm.push({ scope_id: sid, user_id: id }); db.grants.push({ scope_id: sid, epoch: 1, user_id: id, granter_id: NW.marcus, wrapped: await wrapKey(bots[NW.marcus], user(id).public_key, raw), created: nowIso() }); }
    const dm = await botPut(NW.marcus, NW.wid, sid, 'channel', { name: 'dm', dm: true });
    await botPut(NW.marcus, NW.wid, sid, 'message', { text: `Hi ${u.name.split(' ')[0]}, welcome to the team! I have assigned you a couple of tasks to get started.` }, { parent: dm.id });
    const due = n => new Date(Date.now() + n * DAY).toISOString().slice(0, 10);
    await botPut(NW.marcus, NW.wid, NW.sid, 'task', { title: 'Review the Q4 launch checklist', notes: 'Add anything that is missing from the support side.' }, { meta: { status: 'todo', assignee_id: u.id, due: due(3), priority: 1 } });
    await botPut(NW.jo, NW.wid, NW.sid, 'task', { title: 'Meet your onboarding buddy', notes: 'Fifteen minutes with Sam.' }, { meta: { status: 'todo', assignee_id: u.id, due: due(5), priority: 2 } });
    return { token, user_id: u.id, workspace_id: NW.wid };
  }, false);
  R('GET', '/me', ({ me }) => ({ user: pubU(me), workspaces: db.members.filter(m => m.user_id === me.id).map(m => ({ id: m.workspace_id, name: db.workspaces.find(w => w.id === m.workspace_id).name, role: m.role, title: m.title })) }));
  R('PUT', '/me', ({ me, body: b }) => { me.name = (b.name || '').trim() || me.name; me.title = (b.title || '').trim(); db.members.filter(m => m.user_id === me.id).forEach(m => { m.title = me.title; }); return { ok: true }; });
  R('DELETE', '/me', ({ me }) => {
    if (db.members.some(m => m.user_id === me.id && m.role === 'owner')) fail(400, 'You own a workspace. Delete it first, or ask to hand it over.');
    db.scopes.filter(s => inScope(s.id, me.id)).forEach(s => dropFromScope(s.id, me.id)); db.members = db.members.filter(m => m.user_id !== me.id);
    Object.keys(db.tokens).forEach(t => { if (db.tokens[t] === me.id) delete db.tokens[t]; }); Object.assign(me, { name: 'Former member', title: '', deleted: true }); return { ok: true };
  });

  R('POST', '/w/:wid/invites', ({ params, me, body: b }) => {
    const wid = +params.wid, m = needMember(wid, me.id); needRole(m, 'admin');
    if (!['member', 'manager', 'admin'].includes(b.role || 'member')) fail(400, 'Choose member, manager or admin');
    if (RANK[b.role || 'member'] >= RANK[m.role] && m.role !== 'owner') fail(403, 'You can only invite people to roles below your own');
    const token = rnd(24), inv = { id: nid('invite'), workspace_id: wid, token, role: b.role || 'member', label: b.label || '', created: nowIso(), expires: new Date(Date.now() + (b.days || 7) * DAY).toISOString().slice(0, 19) + 'Z', max_uses: b.max_uses || 5, uses: 0, revoked: false, new_hire: b.new_hire !== false };
    db.invites.push(inv); audit(wid, me.id, 'invite_created', `role=${inv.role}`); return { id: inv.id, token, role: inv.role, expires: inv.expires };
  });
  R('GET', '/w/:wid/invites', ({ params, me }) => { needRole(needMember(+params.wid, me.id), 'admin'); return db.invites.filter(i => i.workspace_id === +params.wid).reverse().map(({ token, ...i }) => i); });
  R('DELETE', '/w/:wid/invites/:iid', ({ params, me }) => { needRole(needMember(+params.wid, me.id), 'admin'); const i = db.invites.find(x => x.id === +params.iid); if (i) i.revoked = true; return { ok: true }; });
  const liveInvite = t => { const i = db.invites.find(x => x.token === t); if (!i || i.revoked || i.uses >= i.max_uses || i.expires < nowIso()) fail(404, "This invite link isn't valid any more. Ask your admin for a new one."); return i; };
  R('POST', '/invites/peek', ({ body: b }) => { const i = liveInvite(b.token); return { workspace: db.workspaces.find(w => w.id === i.workspace_id).name, role: i.role }; }, false);
  R('POST', '/join', ({ body: b }) => {
    if (b.website) fail(400, 'Could not create account'); const i = liveInvite(b.token), [u, token] = newUser(b.name, b.title, b.public_key);
    addMember(i.workspace_id, u.id, i.role, b.title, i.new_hire); i.uses++; audit(i.workspace_id, u.id, 'member_joined', `role=${i.role}`); return { token, user_id: u.id, workspace_id: i.workspace_id };
  }, false);
  R('POST', '/invites/accept', ({ body: b, me }) => { const i = liveInvite(b.token); if (!mem(i.workspace_id, me.id)) { addMember(i.workspace_id, me.id, i.role, me.title, i.new_hire); i.uses++; } return { workspace_id: i.workspace_id }; });

  R('GET', '/w/:wid', ({ params, me }) => {
    const wid = +params.wid, m = needMember(wid, me.id), w = db.workspaces.find(x => x.id === wid);
    const scopes = db.scopes.filter(s => s.workspace_id === wid && inScope(s.id, me.id)).map(s => ({ id: s.id, kind: s.kind, epoch: s.epoch, rotation_needed: s.rotation_needed, created_by: s.created_by, member_ids: membersOf(s.id) }));
    const grants = db.grants.filter(g => g.user_id === me.id && scopes.some(s => s.id === g.scope_id)).map(({ scope_id, epoch, granter_id, wrapped }) => ({ scope_id, epoch, granter_id, wrapped }));
    const granter_keys = {}; grants.forEach(g => { granter_keys[g.granter_id] = user(g.granter_id).public_key; });
    return { id: w.id, name: w.name, created: w.created, me: { id: me.id, role: m.role }, members: db.members.filter(x => x.workspace_id === wid).map(memberDict), scopes, grants, granter_keys };
  });
  R('PUT', '/w/:wid', ({ params, me, body: b }) => { needRole(needMember(+params.wid, me.id), 'admin'); db.workspaces.find(w => w.id === +params.wid).name = (b.name || '').trim(); audit(+params.wid, me.id, 'workspace_renamed'); return { ok: true }; });
  R('DELETE', '/w/:wid', ({ params, me }) => {
    const wid = +params.wid; needRole(needMember(wid, me.id), 'owner'); const sids = db.scopes.filter(s => s.workspace_id === wid).map(s => s.id);
    db.grants = db.grants.filter(g => !sids.includes(g.scope_id)); db.sm = db.sm.filter(x => !sids.includes(x.scope_id)); db.rsvps = db.rsvps.filter(r => !db.items.some(i => i.id === r.item_id && i.workspace_id === wid));
    db.items = db.items.filter(i => i.workspace_id !== wid); db.scopes = db.scopes.filter(s => s.workspace_id !== wid); db.invites = db.invites.filter(i => i.workspace_id !== wid);
    db.members = db.members.filter(m => m.workspace_id !== wid); db.audit = db.audit.filter(a => a.workspace_id !== wid); db.workspaces = db.workspaces.filter(w => w.id !== wid); return { ok: true };
  });
  R('PUT', '/w/:wid/members/:uid', ({ params, me, body: b }) => {
    const wid = +params.wid, uid = +params.uid, mm = needMember(wid, me.id), t = mem(wid, uid) || fail(404, 'Person not found'), own = uid === me.id;
    if (!own) needRole(mm, 'admin'); else if ((b.role != null || b.new_hire != null) && RANK[mm.role] < RANK.admin) fail(403, 'Only an admin can change that');
    if (b.role != null) {
      if (!['member', 'manager', 'admin'].includes(b.role)) fail(400, 'Choose member, manager or admin'); if (t.role === 'owner' || own) fail(403, "You can't change that person's role");
      if (mm.role !== 'owner' && (RANK[t.role] >= RANK[mm.role] || RANK[b.role] >= RANK[mm.role])) fail(403, 'Only the owner can manage admins');
      t.role = b.role; audit(wid, me.id, 'role_changed', `user=${uid} role=${b.role}`);
    }
    if (b.title != null) t.title = b.title.trim();
    if (b.new_hire != null) { t.new_hire = !!b.new_hire; if (b.start_date) t.start_date = b.start_date; audit(wid, me.id, 'new_hire_flag', `user=${uid}`); }
    return { ok: true };
  });
  R('DELETE', '/w/:wid/members/:uid', ({ params, me }) => {
    const wid = +params.wid, uid = +params.uid, mm = needMember(wid, me.id), t = mem(wid, uid) || fail(404, 'Person not found');
    if (t.role === 'owner') fail(403, "The owner can't be removed. Delete the workspace instead.");
    if (uid !== me.id) { needRole(mm, 'admin'); if (mm.role !== 'owner' && RANK[t.role] >= RANK[mm.role]) fail(403, 'Only the owner can remove admins'); }
    db.scopes.filter(s => s.workspace_id === wid).forEach(s => dropFromScope(s.id, uid)); db.members = db.members.filter(m => !(m.workspace_id === wid && m.user_id === uid));
    audit(wid, me.id, uid !== me.id ? 'member_removed' : 'member_left', `user=${uid}`); return { ok: true };
  });

  R('POST', '/w/:wid/scopes', ({ params, me, body: b }) => {
    const wid = +params.wid; needMember(wid, me.id); const ids = [...new Set([...(b.member_ids || []), me.id])];
    ids.forEach(i => { if (!mem(wid, i)) fail(400, 'Everyone in a private group must belong to this workspace'); });
    const sid = nid('scope'); db.scopes.push({ id: sid, workspace_id: wid, kind: 'private', epoch: 1, rotation_needed: false, created_by: me.id, created: nowIso() }); ids.forEach(i => db.sm.push({ scope_id: sid, user_id: i }));
    audit(wid, me.id, 'private_group_created', `scope=${sid} members=${ids.length}`); return { id: sid, epoch: 1 };
  });
  const scopeOf = (wid, sid) => db.scopes.find(s => s.id === +sid && s.workspace_id === +wid) || fail(404, 'Not found');
  R('POST', '/w/:wid/scopes/:sid/grants', ({ params, me, body: b }) => {
    const wid = +params.wid; needMember(wid, me.id); const s = scopeOf(wid, params.sid);
    if (!inScope(s.id, me.id) || b.epoch < 1 || b.epoch > s.epoch) fail(404, 'Not found');
    const firstEver = !db.grants.some(g => g.scope_id === s.id && g.epoch === b.epoch);
    if (!(holds(s.id, b.epoch, me.id) || (firstEver && b.epoch === 1 && s.created_by === me.id))) fail(403, "You don't hold this key yet, so you can't share it");
    let n = 0; for (const g of b.grants || []) { if (!inScope(s.id, g.user_id) || !validWrap(g.wrapped) || holds(s.id, b.epoch, g.user_id)) continue; db.grants.push({ scope_id: s.id, epoch: b.epoch, user_id: g.user_id, granter_id: me.id, wrapped: g.wrapped, created: nowIso() }); n++; }
    return { granted: n };
  });
  R('GET', '/w/:wid/pending', ({ params, me }) => {
    const wid = +params.wid; needMember(wid, me.id); const out = [];
    db.scopes.filter(s => s.workspace_id === wid && inScope(s.id, me.id)).forEach(s => {
      const epochs = db.grants.filter(g => g.scope_id === s.id && g.user_id === me.id).map(g => g.epoch);
      membersOf(s.id).filter(id => id !== me.id).forEach(id => epochs.forEach(e => { if (!holds(s.id, e, id)) out.push({ scope_id: s.id, epoch: e, user_id: id, public_key: user(id).public_key }); }));
    });
    return out;
  });
  R('POST', '/w/:wid/scopes/:sid/rotate', ({ params, me, body: b }) => {
    const wid = +params.wid; needMember(wid, me.id); const s = scopeOf(wid, params.sid);
    if (!inScope(s.id, me.id) || !holds(s.id, s.epoch, me.id)) fail(403, "You don't hold this key");
    if (b.epoch !== s.epoch + 1) fail(409, 'stale_epoch');
    const want = membersOf(s.id).sort().join(), got = (b.grants || []).map(g => g.user_id).sort().join();
    if (want !== got) fail(400, 'The new key must be shared with exactly the people who are in this group now');
    for (const g of b.grants) { if (!validWrap(g.wrapped)) fail(400, 'Malformed key'); db.grants = db.grants.filter(x => !(x.scope_id === s.id && x.epoch === b.epoch && x.user_id === g.user_id)); db.grants.push({ scope_id: s.id, epoch: b.epoch, user_id: g.user_id, granter_id: me.id, wrapped: g.wrapped, created: nowIso() }); }
    s.epoch = b.epoch; s.rotation_needed = false; audit(wid, me.id, 'key_rotated', `scope=${s.id} epoch=${b.epoch}`); return { epoch: b.epoch };
  });

  function createItem(wid, me, m, b) {
    if (!KINDS.has(b.kind)) fail(400, 'Unknown item type'); needRole(m, MIN_ROLE[b.kind]);
    const s = scopeOf(wid, b.scope_id); if (!inScope(s.id, me.id)) fail(404, 'Not found'); if (b.epoch !== s.epoch) fail(409, 'stale_epoch');
    if (!okB64(b.iv) || !okB64(b.ct) || !b.ct) fail(400, 'Malformed content');
    if (b.kind === 'message') { const p = db.items.find(i => i.id === b.parent_id && i.workspace_id === wid && i.scope_id === s.id && !i.deleted); if (!p || !['channel', 'task'].includes(p.kind)) fail(400, 'Messages belong in a channel or on a task'); }
    else if (b.parent_id != null) fail(400, 'Only messages can have a parent');
    const it = { id: nid('item'), workspace_id: wid, scope_id: s.id, kind: b.kind, parent_id: b.parent_id ?? null, meta: cleanMeta(s.id, b.kind, b.meta || {}), iv: b.iv, ct: b.ct, epoch: b.epoch, created_by: me.id, created: nowIso(), updated: nowIso(), deleted: false };
    db.items.push(it); if (!['message', 'task'].includes(b.kind)) audit(wid, me.id, `${b.kind}_created`, `item=${it.id}`);
    maybeReply(it); return it.id;
  }
  R('POST', '/w/:wid/items', ({ params, me, body: b }) => ({ id: createItem(+params.wid, me, needMember(+params.wid, me.id), b) }));
  R('POST', '/w/:wid/items/batch', ({ params, me, body: b }) => { const m = needMember(+params.wid, me.id); return { ids: (b.items || []).map(i => createItem(+params.wid, me, m, i)) }; });
  R('GET', '/w/:wid/items', ({ params, me, q }) => {
    const wid = +params.wid; needMember(wid, me.id); const kind = q.get('kind'), parent = +q.get('parent_id') || 0, after = +q.get('after_id') || 0;
    return db.items.filter(i => i.workspace_id === wid && !i.deleted && i.id > after && inScope(i.scope_id, me.id) && (!kind || i.kind === kind) && (!parent || i.parent_id === parent)).map(itemDict);
  });
  const ownItem = (wid, iid, me) => { const r = db.items.find(i => i.id === +iid && i.workspace_id === wid && !i.deleted); if (!r || !inScope(r.scope_id, me.id)) fail(404, 'Not found'); return r; };
  R('PUT', '/w/:wid/items/:iid', ({ params, me, body: b }) => {
    const wid = +params.wid, m = needMember(wid, me.id), r = ownItem(wid, params.iid, me), mine = r.created_by === me.id, boss = RANK[m.role] >= RANK.manager, assignee = r.kind === 'task' && r.meta.assignee_id === me.id;
    if (b.iv != null || b.ct != null) {
      if (!(mine || boss) || b.iv == null || b.ct == null || b.epoch == null) fail(403, "You can't edit this");
      if (b.epoch !== scopeOf(wid, r.scope_id).epoch) fail(409, 'stale_epoch'); if (!okB64(b.iv) || !okB64(b.ct) || !b.ct) fail(400, 'Malformed content');
      Object.assign(r, { iv: b.iv, ct: b.ct, epoch: b.epoch, updated: nowIso() });
    }
    if (b.meta != null) {
      if (!(mine || boss || assignee) || (r.kind === 'workflow' && RANK[m.role] < RANK.admin)) fail(403, "You can't change this");
      const merged = cleanMeta(r.scope_id, r.kind, { ...r.meta, ...b.meta });
      if (r.kind === 'task' && assignee && !(mine || boss)) Object.assign(merged, { assignee_id: r.meta.assignee_id, due: r.meta.due, priority: r.meta.priority });
      r.meta = merged; r.updated = nowIso();
    }
    return { ok: true };
  });
  R('DELETE', '/w/:wid/items/:iid', ({ params, me }) => {
    const wid = +params.wid, m = needMember(wid, me.id), r = ownItem(wid, params.iid, me);
    if (r.created_by !== me.id && RANK[m.role] < RANK[r.kind !== 'message' ? 'manager' : 'admin']) fail(403, "You can't delete this");
    [r, ...db.items.filter(i => i.parent_id === r.id)].forEach(i => { i.deleted = true; i.iv = ''; i.ct = ''; db.rsvps = db.rsvps.filter(x => x.item_id !== i.id); });
    if (!['message', 'task'].includes(r.kind)) audit(wid, me.id, `${r.kind}_deleted`, `item=${r.id}`); return { ok: true };
  });
  R('PUT', '/w/:wid/items/:iid/rsvp', ({ params, me, body: b }) => {
    if (!['yes', 'no', 'maybe'].includes(b.status)) fail(400, 'Choose yes, no or maybe'); const wid = +params.wid; needMember(wid, me.id); const r = ownItem(wid, params.iid, me);
    if (r.kind !== 'event') fail(400, "That isn't an event"); db.rsvps = db.rsvps.filter(x => !(x.item_id === r.id && x.user_id === me.id)); db.rsvps.push({ item_id: r.id, user_id: me.id, status: b.status }); return { ok: true };
  });
  R('GET', '/w/:wid/audit', ({ params, me }) => { needRole(needMember(+params.wid, me.id), 'admin'); return db.audit.filter(a => a.workspace_id === +params.wid).slice(-200).reverse(); });

  /* ---------- fetch shim (only /api/corp/…; everything else passes through) ---------- */
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = async (input, init = {}) => {
    const raw = typeof input === 'string' ? input : input.url;
    if (!raw.startsWith('/api/corp/')) return realFetch ? realFetch(input, init) : Promise.reject(new TypeError('offline'));
    const url = new URL(raw, 'http://demo.invalid'), path = url.pathname.slice('/api/corp'.length), method = (init.method || 'GET').toUpperCase();
    const auth = new Headers(init.headers || {}).get('authorization') || '', uid = auth.startsWith('Bearer ') ? db.tokens[auth.slice(7)] : null, me = uid ? user(uid) : null;
    await ready;
    for (const r of routes) {
      if (r.method !== method) continue; const m = path.match(r.re); if (!m) continue;
      try { if (r.auth && !me) fail(401, 'Please sign in'); return json(await r.fn({ params: m.groups || {}, q: url.searchParams, body: init.body ? JSON.parse(init.body) : {}, me })); }
      catch (e) { if (e instanceof HttpError) return json({ detail: e.detail }, e.status); console.error(e); return json({ detail: 'Something went wrong' }, 500); }
    }
    return json({ detail: 'Not found' }, 404);
  };
})();
