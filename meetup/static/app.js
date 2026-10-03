const $ = (s, r = document) => r.querySelector(s);
const app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let meta = { categories: [], looking_for: [] };
let me = null;

const store = {
  get: k => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch {} },
  del: k => { try { localStorage.removeItem(k); } catch {} },
};
const token = () => store.get('huddle_token');
const api = async (path, opts = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (token()) headers.Authorization = 'Bearer ' + token();
  const r = await fetch('/api' + path, { headers, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : 'Something went wrong'); }
  return r.json();
};

/* ---------- end-to-end encryption (WebCrypto) ----------
   Each account has an ECDH P-256 key pair made in this browser. The private key never leaves it.
   A conversation key is derived from my private key + their public key, then used with AES-GCM.
   The server only ever sees ciphertext. */
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const subtle = crypto.subtle;
async function genKeys() {
  const kp = await subtle.generateKey(ECDH, true, ['deriveBits']);
  return { pub: await subtle.exportKey('jwk', kp.publicKey), priv: await subtle.exportKey('jwk', kp.privateKey) };
}
const privJwk = () => { const s = me && store.get('huddle_priv_' + me.id); return s ? JSON.parse(s) : null; };
const pubOnly = j => ({ kty: j.kty, crv: j.crv, x: j.x, y: j.y });
async function convoKey(otherPub) {
  const priv = privJwk();
  if (!priv) throw new Error('This browser does not have your encryption key. Restore your account file.');
  const mine = await subtle.importKey('jwk', priv, ECDH, false, ['deriveBits']);
  const theirs = await subtle.importKey('jwk', pubOnly(otherPub), ECDH, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirs }, mine, 256));
}
const aes = (raw, usage) => subtle.importKey('raw', raw, 'AES-GCM', false, [usage]);
async function encrypt(raw, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, await aes(raw, 'encrypt'), new TextEncoder().encode(text));
  return { iv: b64(iv), ciphertext: b64(ct) };
}
async function decrypt(raw, m) {
  try { return new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(m.iv) }, await aes(raw, 'decrypt'), unb64(m.ciphertext))); }
  catch { return '[could not decrypt this message]'; }
}
async function safetyNumber(otherPub) {
  const keys = [pubOnly(privJwk()), pubOnly(otherPub)].map(k => k.x + k.y).sort().join('|');
  const h = [...new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(keys)))].map(x => x.toString(16).padStart(2, '0')).join('');
  return h.slice(0, 30).match(/.{5}/g).join(' ');
}
/* proof of work: a few seconds of compute at sign-up. Trivial for a person, costly at bot scale */
async function solvePow(challenge, bits, onProgress) {
  const enc = new TextEncoder();
  for (let i = 0; ; i++) {
    const d = new Uint8Array(await subtle.digest('SHA-256', enc.encode(challenge + ':' + i)));
    let zeros = 0; for (const byte of d) { if (byte === 0) zeros += 8; else { zeros += Math.clz32(byte) - 24; break; } }
    if (zeros >= bits) return String(i);
    if (i % 4000 === 0) { onProgress?.(i); await new Promise(r => setTimeout(r)); }
  }
}
function downloadAccountFile() {
  const blob = new Blob([JSON.stringify({ huddle: 1, user_id: me.id, token: token(), private_key: privJwk() })], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `huddle-login-${me.name.split(' ')[0].toLowerCase()}.json`; a.click();
  store.set('huddle_saved_' + me.id, '1'); renderBanner();
}
const REASONS = { child_safety: 'A child may be at risk', harassment: 'Harassment or abuse', spam: 'Spam or a fake account', scam: 'Scam or fraud', other: 'Something else' };
function reportDialog({ title, note, onSubmit }) {
  const d = document.createElement('dialog');
  d.innerHTML = `<form method="dialog"><h3>${esc(title)}</h3><p class="muted">${esc(note)}</p>
    <label>Reason</label><select id="rr">${Object.entries(REASONS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}</select>
    <label>Details <small>(optional)</small></label><textarea id="rd" rows="3" maxlength="1000"></textarea>
    <div class="row" style="margin-top:14px"><button class="btn ghost" value="cancel">Cancel</button><button class="btn" id="rs" value="ok">Send report</button></div></form>`;
  document.body.appendChild(d);
  d.querySelector('#rs').onclick = async e => { e.preventDefault(); try { await onSubmit(d.querySelector('#rr').value, d.querySelector('#rd').value); toast('Thanks. Our safety team will review this.'); } catch (err) { toast(err.message); } d.close(); };
  d.addEventListener('close', () => d.remove()); d.showModal();
}
const toast = (m, action) => {
  const t = $('#toast'); t.textContent = m;
  if (action) { const b = document.createElement('button'); b.textContent = action.label; b.onclick = () => { t.classList.remove('show'); action.fn(); }; t.append(' ', b); }
  t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), action ? 7000 : 2800);
};
const colors = ['#ff5a4e', '#0f9d8a', '#7c5cff', '#e6a100', '#2b7de9', '#d6409f'];
const avatar = (u, cls = '') => `<span class="avatar ${cls}" style="background:${colors[u.id % colors.length]}" title="${esc(u.name)}">${esc(u.name.trim()[0] || '?').toUpperCase()}</span>`;
const fmt = iso => new Date(iso).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const ago = iso => { const s = (Date.now() - new Date(iso)) / 1000; return s < 60 ? 'just now' : s < 3600 ? Math.floor(s / 60) + 'm ago' : s < 86400 ? Math.floor(s / 3600) + 'h ago' : Math.floor(s / 86400) + 'd ago'; };
const chips = (xs, cls = '') => xs.map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join('');
const host = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
const SUGGESTED = ['Hiking', 'Coffee', 'Board games', 'Running', 'Photography', 'Cooking', 'Books', 'Live music', 'Python', 'Startups', 'Yoga', 'Travel', 'Languages', 'Art', 'Cycling', 'Movies'];

let timers = [];
const poll = (fn, ms) => timers.push(setInterval(() => document.hidden || fn().catch(() => {}), ms));
let dmCtx = null;

async function loadMe() {
  me = null;
  if (token()) { try { me = await api('/me'); } catch (e) { if (/sign in|suspended/.test(e.message)) store.del('huddle_token'); } }
  $('#me').innerHTML = me
    ? `<details class="more usermenu"><summary>${avatar(me)}<span>${esc(me.name.split(' ')[0])}</span></summary><div>
        <a href="#/user/${me.id}">My profile</a><a href="#/settings">Settings</a><button data-act="signout">Sign out</button></div></details>`
    : `<a class="btn ghost" href="#/login">Log in</a> <a class="btn" href="#/join">Join free</a>`;
  renderBanner();
}
function renderBanner() {
  const el = $('#banner'); if (!el) return;
  const show = me && !store.get('huddle_saved_' + me.id) && privJwk();
  el.innerHTML = show ? `<div class="banner">💾 <span>Save your login file so you never lose your account or messages.</span> <button class="btn" data-act="save-login">Save it</button></div>` : '';
}
const needMe = () => { if (!me) { toast('Join free to do that. It takes a minute.'); location.hash = '#/join'; return false; } return true; };

const moreMenu = items => `<details class="more"><summary aria-label="More options">⋯</summary><div>${items.map(i =>
  `<button class="${i.danger ? 'danger' : ''}" data-act="${i.act}" data-id="${esc(i.id)}" data-kind="${i.kind || ''}" data-name="${esc(i.name || '')}">${i.label}</button>`).join('')}</div></details>`;
const personMenu = (u, extra = []) => me && me.id !== u.id ? moreMenu([...extra, { act: 'report', kind: 'user', id: u.id, name: u.name, label: 'Report' }, { act: 'block', id: u.id, name: u.name, label: `Block ${esc(u.name.split(' ')[0])}`, danger: true }]) : '';

const REPORT_INFO = {
  dm: ['Report this conversation', 'Messages are private, so this shares up to 100 recent messages (decrypted by you) with our safety team. Your other conversations stay private.'],
  user: ['Report this person', 'Their profile will be shared with our safety team. Your private messages are not shared.'],
  post: ['Report this post', 'The post and who wrote it will be shared with our safety team.'],
  reply: ['Report this reply', 'The reply and who wrote it will be shared with our safety team.'],
  event_message: ['Report this message', 'The message and who sent it will be shared with our safety team.'],
  event: ['Report this event', 'The event will be shared with our safety team.'],
};

async function blockUser(id, name) {
  await api('/blocks/' + id, { method: 'PUT' });
  toast(`Blocked ${name.split(' ')[0]}. They can't see you or message you.`, { label: 'Undo', fn: async () => { await api('/blocks/' + id, { method: 'DELETE' }); toast('Unblocked'); route(); } });
  if (location.hash.startsWith('#/dm/')) location.hash = '#/inbox'; else route();
}

document.addEventListener('click', async e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const { act, id, kind, name } = el.dataset;
  el.closest('details')?.removeAttribute('open');
  try {
    if (act === 'signout') {
      store.del('huddle_token'); await loadMe(); toast('Signed out. Use your login file to get back in.'); location.hash = '#/';
    } else if (act === 'save-login') { downloadAccountFile(); toast('Saved. Keep that file somewhere private.');
    } else if (act === 'block') { await blockUser(id, name);
    } else if (act === 'report') {
      const [title, note] = REPORT_INFO[kind];
      reportDialog({ title, note, onSubmit: (reason, details) => api('/reports', { method: 'POST', body: { kind, target_id: +id, reason, details, ...(kind === 'dm' ? { key: b64(dmCtx.raw) } : {}) } }) });
    } else if (act === 'del-post') { await api('/posts/' + id, { method: 'DELETE' }); toast('Post deleted'); location.hash.startsWith('#/post/') ? (location.hash = '#/feed') : route();
    } else if (act === 'del-reply') { await api('/replies/' + id, { method: 'DELETE' }); route();
    } else if (act === 'tag') { feedTag = id; location.hash = '#/feed'; route();
    } else if (act === 'unblock') { await api('/blocks/' + id, { method: 'DELETE' }); toast('Unblocked'); route();
    }
  } catch (err) { toast(err.message); }
});

/* ---------- views ---------- */
async function home() {
  app.innerHTML = `
  ${me ? `<div class="row between"><h1>Events for you</h1><a class="btn" href="#/create">+ Host an event</a></div>` : `
  <div class="hero"><h1>Find your people, not just an event.</h1>
  <p>Meet people near you who share your interests. See who's going, say hello easily, and share what you're into. Open to everyone, 18+.</p>
  <p><a class="btn" href="#/join">Join free</a> <span class="muted">No password, no email. Or just look around.</span></p></div>`}
  <div class="filters">
    <input id="q" placeholder="Search events, interests, places">
    <select id="cat"><option value="">All categories</option>${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
    <input id="city" placeholder="City" value="${esc(me?.city || '')}">
    ${me ? `<select id="sort"><option value="match">Best for me</option><option value="soon">Soonest</option></select>` : ''}
  </div>
  <div id="list" class="grid"></div>`;
  const run = async () => {
    const p = new URLSearchParams({ q: $('#q').value, category: $('#cat').value, city: $('#city').value, sort: $('#sort')?.value || 'soon' });
    const evs = await api('/events?' + p);
    $('#list').innerHTML = evs.length ? evs.map(eventCard).join('') : '<div class="empty" style="grid-column:1/-1">No events match. Try clearing the city filter, or <a href="#/create">host one</a>.</div>';
  };
  let t; ['q', 'city'].forEach(i => $('#' + i).oninput = () => { clearTimeout(t); t = setTimeout(run, 250); });
  ['cat', 'sort'].forEach(i => $('#' + i) && ($('#' + i).onchange = run));
  if (me) $('#sort').value = 'match';
  run();
}

const eventCard = e => `
<a class="card" href="#/event/${e.id}">
  <div class="when">${fmt(e.starts)}</div>
  <h3>${esc(e.title)}</h3>
  <div class="muted">${esc(e.venue)}, ${esc(e.city)}</div>
  <div class="chips"><span class="chip warm">${esc(e.category)}</span>${e.vibe ? `<span class="chip plain">${esc(e.vibe)}</span>` : ''}</div>
  <div class="avatars">${e.attendees.map(a => avatar(a)).join('')}<span class="muted" style="margin-left:10px;font-size:.85rem">${e.attendee_count} going · ${e.spots_left} spots left</span></div>
  ${me && e.people_like_you ? `<div class="match">${e.people_like_you} ${e.people_like_you === 1 ? 'person shares' : 'people share'} your interests</div>` : ''}
</a>`;

async function eventPage(id) {
  const e = await api(`/events/${id}`);
  const full = e.spots_left === 0 && !e.going;
  app.innerHTML = `
  <a href="#/" class="muted">&larr; All events</a>
  <div class="cols"><div>
    <div class="when">${fmt(e.starts)}</div><h1>${esc(e.title)}</h1>
    <p class="muted">${esc(e.venue)}, ${esc(e.city)} · Hosted by <a href="#/user/${e.host.id}">${esc(e.host.name)}</a></p>
    <div class="chips"><span class="chip warm">${esc(e.category)}</span>${e.vibe ? `<span class="chip plain">${esc(e.vibe)}</span>` : ''}${chips(e.tags)}</div>
    <p style="white-space:pre-wrap">${esc(e.description)}</p>
    <div class="row" style="align-items:center"><button class="btn" id="rsvp" ${full ? 'disabled' : ''}>${e.going ? '✓ Going, tap to cancel' : full ? 'Event is full' : 'Count me in'}</button>
    ${me && me.id !== e.host.id ? moreMenu([{ act: 'report', kind: 'event', id: e.id, label: 'Report this event' }]) : ''}</div>
    <h2>Chat</h2>
    <p class="muted" style="margin-top:-6px"><small>Event chat is public to attendees and watched by our safety team. For private chats, tap Message on a person.</small></p>
    <div class="panel">
      ${e.messages.map(m => `<div class="msg"><div class="row between"><b><a href="#/user/${m.user.id}">${esc(m.user.name)}</a></b>${personMenu(m.user, [{ act: 'report', kind: 'event_message', id: m.id, label: 'Report message' }])}</div>${esc(m.body)}</div>`).join('') || '<div class="muted">Nobody has said anything yet. Break the ice!</div>'}
      ${e.going ? `<div class="row" style="margin-top:12px"><input id="msg" maxlength="1000" placeholder="Say hi to the group"><button class="btn" id="send">Send</button></div>
      <p class="muted" style="margin:12px 0 4px">Need a starter? Tap one:</p>${e.icebreakers.map(i => `<button class="ice">${esc(i)}</button>`).join('')}`
      : '<p class="muted" style="margin-top:12px">Count yourself in to join the chat.</p>'}
    </div>
  </div>
  <aside><div class="panel"><h3>Who's going (${e.attendee_count}/${e.capacity})</h3>
    ${e.attendees.map(a => `<div class="person">${avatar(a)}<div class="info"><a class="name" href="#/user/${a.id}">${esc(a.name)}</a> <small>${esc(a.pronouns)}</small>
      ${a.shared?.length ? `<div class="chips" style="margin-top:4px">${chips(a.shared)}</div><small>in common with you</small>` : `<div class="muted" style="font-size:.85rem">${esc(a.interests.slice(0, 3).join(', '))}</div>`}</div>
      ${e.going && me && a.id !== me.id && a.public_key ? `<a class="btn small" href="#/dm/${a.id}">Message</a>` : ''}</div>`).join('')}
  </div></aside></div>`;
  $('#rsvp').onclick = async () => {
    if (!needMe()) return;
    try {
      if (e.going) await api(`/events/${id}/rsvp`, { method: 'DELETE' });
      else { await api(`/events/${id}/rsvp`, { method: 'POST' }); toast("You're in! Say hi in the chat, or message someone."); }
      eventPage(id);
    } catch (err) { toast(err.message); }
  };
  if (e.going) {
    const send = async () => { const b = $('#msg').value.trim(); if (!b) return; try { await api(`/events/${id}/messages`, { method: 'POST', body: { body: b } }); eventPage(id); } catch (err) { toast(err.message); } };
    $('#send').onclick = send; $('#msg').onkeydown = k => k.key === 'Enter' && send();
    document.querySelectorAll('.ice').forEach(b => b.onclick = () => { $('#msg').value = b.textContent; $('#msg').focus(); });
  }
}

/* ---- feed: share news and interests ---- */
let feedScope = null, feedTag = '';
const postCard = (p, full = false) => `
<article class="card post">
  <div class="row between"><div class="row" style="align-items:center">${avatar(p.author)}<div><a class="name" href="#/user/${p.author.id}"><b>${esc(p.author.name)}</b></a><br><small class="muted">${esc(p.city)} · ${ago(p.created)}</small></div></div>
  ${me ? moreMenu(p.mine ? [{ act: 'del-post', id: p.id, label: 'Delete post', danger: true }] : [{ act: 'report', kind: 'post', id: p.id, label: 'Report post' }, { act: 'block', id: p.author.id, name: p.author.name, label: `Block ${esc(p.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
  <p class="postbody">${esc(p.body)}</p>
  ${p.url ? `<a class="link" href="${esc(p.url)}" target="_blank" rel="nofollow noopener noreferrer ugc">🔗 ${esc(host(p.url))}</a>` : ''}
  <div class="chips">${p.tags.map(t => `<button class="chip ${p.match?.includes(t) ? '' : 'plain'}" data-act="tag" data-id="${esc(t)}">${esc(t)}</button>`).join('')}</div>
  ${full ? '' : `<a class="muted" href="#/post/${p.id}">💬 ${p.reply_count ? p.reply_count + (p.reply_count === 1 ? ' reply' : ' replies') : 'Reply'}</a>`}
</article>`;

async function feed() {
  if (!feedScope) feedScope = me ? 'foryou' : 'all';
  const sel = new Set();
  app.innerHTML = `<h1>Feed</h1><p class="muted" style="margin-top:-4px">News, finds and thoughts from people near you and with your interests.</p>
  ${me ? `<div class="panel composer"><textarea id="pb" rows="2" maxlength="500" placeholder="Share some news, a find, or something you're into…"></textarea>
    <div id="pl" class="hidden"><input id="pu" placeholder="Paste a link (https://…)" maxlength="300"></div>
    ${me.interests.length ? `<div class="chips" id="pt"><small class="muted" style="align-self:center">Tag:</small>${me.interests.slice(0, 8).map(t => `<button type="button" class="chip plain" data-t="${esc(t)}">${esc(t)}</button>`).join('')}</div>` : ''}
    <div class="row between" style="margin-top:10px"><button class="linkbtn" id="addlink" type="button">+ Add a link</button><button class="btn" id="post">Post</button></div></div>` : `<div class="panel"><a href="#/join" class="btn">Join free</a> <span class="muted">to share and reply.</span></div>`}
  <div class="pills">${[['foryou', 'For you'], ['near', 'Near me'], ['all', 'Everyone']].filter(([k]) => me || k === 'all').map(([k, l]) => `<button class="pill ${feedScope === k ? 'on' : ''}" data-s="${k}">${l}</button>`).join('')}
    ${feedTag ? `<button class="pill on" id="cleartag">#${esc(feedTag)} ×</button>` : ''}</div>
  <div id="posts" class="stack"></div>`;
  document.querySelectorAll('.pill[data-s]').forEach(b => b.onclick = () => { feedScope = b.dataset.s; feed(); });
  $('#cleartag')?.addEventListener('click', () => { feedTag = ''; feed(); });
  if (me) {
    $('#addlink').onclick = () => { $('#pl').classList.toggle('hidden'); $('#pu').focus(); };
    document.querySelectorAll('#pt [data-t]').forEach(b => b.onclick = () => { const t = b.dataset.t; if (sel.has(t)) sel.delete(t); else if (sel.size < 3) sel.add(t); b.classList.toggle('plain', !sel.has(t)); });
    $('#post').onclick = async () => {
      const body = $('#pb').value.trim(); if (!body) return toast('Write something first');
      try { await api('/posts', { method: 'POST', body: { body, url: $('#pu').value, tags: [...sel] } }); toast('Posted'); feed(); } catch (err) { toast(err.message); }
    };
  }
  const posts = await api(`/posts?scope=${feedScope}&tag=${encodeURIComponent(feedTag)}`);
  $('#posts').innerHTML = posts.map(p => postCard(p)).join('') || `<div class="empty">Nothing here yet. ${feedScope === 'near' ? 'Try “Everyone”, or ' : ''}be the first to share something!</div>`;
}

async function postPage(id) {
  const p = await api('/posts/' + id);
  app.innerHTML = `<a href="#/feed" class="muted">&larr; Feed</a><div style="margin-top:8px">${postCard(p, true)}</div>
  <h2>${p.replies.length ? 'Replies' : 'No replies yet'}</h2><div class="stack">
  ${p.replies.map(r => `<div class="panel"><div class="row between"><div class="row" style="align-items:center">${avatar(r.author)}<div><a class="name" href="#/user/${r.author.id}"><b>${esc(r.author.name)}</b></a> <small class="muted">${ago(r.created)}</small></div></div>
    ${me ? moreMenu(r.mine ? [{ act: 'del-reply', id: r.id, label: 'Delete', danger: true }] : [{ act: 'report', kind: 'reply', id: r.id, label: 'Report reply' }, { act: 'block', id: r.author.id, name: r.author.name, label: `Block ${esc(r.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
    <p class="postbody" style="margin-bottom:0">${esc(r.body)}</p></div>`).join('')}
  </div>
  ${me ? `<div class="row" style="margin-top:14px"><input id="rb" maxlength="500" placeholder="Write a reply"><button class="btn" id="rs">Reply</button></div>` : '<p><a href="#/join" class="btn">Join free</a> <span class="muted">to reply.</span></p>'}`;
  if (me) {
    const send = async () => { const b = $('#rb').value.trim(); if (!b) return; try { await api(`/posts/${id}/replies`, { method: 'POST', body: { body: b } }); postPage(id); } catch (err) { toast(err.message); } };
    $('#rs').onclick = send; $('#rb').onkeydown = k => k.key === 'Enter' && send();
  }
}

async function people() {
  if (!needMe()) return;
  const list = await api('/me/matches');
  app.innerHTML = `<h1>People you may click with</h1><p class="muted" style="margin-top:-4px">Based on your interests, where you live, and what you're looking for.</p>
  <div class="grid">${list.map(u => `<div class="card"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div class="grow"><a href="#/user/${u.id}"><h3>${esc(u.name)}</h3></a><small class="muted">${esc(u.city)} ${esc(u.pronouns)}</small></div></div>
    <div class="chips">${chips(u.shared)}</div>
    ${u.shared_goals.length ? `<small>Both looking for: ${esc(u.shared_goals.join(', '))}</small>` : ''}
    ${u.events_in_common ? `<small>${u.events_in_common} event${u.events_in_common > 1 ? 's' : ''} in common</small>` : ''}
    <div class="row" style="margin-top:4px">${u.can_message ? `<a class="btn small" href="#/dm/${u.id}">Message</a>` : u.public_key ? `<a class="btn small ghost" href="#/user/${u.id}">See profile</a>` : '<small class="muted">Sample profile</small>'}</div></div>`).join('') || '<div class="empty">Add some interests to your profile to see people.</div>'}</div>`;
}

async function userPage(id) {
  const u = await api(`/users/${id}`);
  const mine = me && me.id === u.id;
  app.innerHTML = `<div class="panel"><div class="row between"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><h1 style="margin:0">${esc(u.name)}</h1><span class="muted">${esc(u.city)} ${u.pronouns ? '· ' + esc(u.pronouns) : ''}</span></div></div>${personMenu(u)}</div>
  <p>${esc(u.bio) || '<span class="muted">No bio yet.</span>'}</p>
  <div class="chips">${chips(u.interests, '')}</div>
  ${u.looking_for.length ? `<p class="muted">Looking for: ${esc(u.looking_for.join(', '))}</p>` : ''}
  ${u.shared?.length ? `<div class="match">You both like: ${esc(u.shared.join(', '))}</div>` : ''}
  ${u.shared_events?.length ? `<p class="muted">You're both going to: ${esc(u.shared_events.join(', '))}</p>` : ''}
  <p>${mine ? '<a class="btn ghost" href="#/join?edit=1">Edit profile</a> <a class="btn ghost" href="#/settings">Settings</a>'
    : u.can_message ? `<a class="btn" href="#/dm/${u.id}">Message ${esc(u.name.split(' ')[0])}</a>`
    : !u.public_key ? '<span class="muted">Sample profile (no messaging)</span>'
    : u.blocked ? `<button class="btn ghost" data-act="unblock" data-id="${u.id}">Unblock</button>`
    : me ? '<span class="muted">You can chat once you\'re both going to the same event. <a href="#/">Find one</a></span>' : '<a class="btn" href="#/join">Join free to message</a>'}</p></div>
  <h2>Upcoming events</h2><div class="panel">${u.events.map(e => `<div class="msg"><a href="#/event/${e.id}">${esc(e.title)}</a> <small>${fmt(e.starts)}</small></div>`).join('') || '<span class="muted">Nothing yet.</span>'}</div>`;
}

function interestPicker(initial) {
  const sel = [...initial];
  const draw = () => {
    const all = [...new Set([...SUGGESTED, ...sel])];
    $('#ints').innerHTML = all.map(t => `<button type="button" class="chip ${sel.some(x => x.toLowerCase() === t.toLowerCase()) ? 'sel' : 'plain'}" data-t="${esc(t)}">${esc(t)}</button>`).join('');
    document.querySelectorAll('#ints .chip').forEach(b => b.onclick = () => { const i = sel.findIndex(x => x.toLowerCase() === b.dataset.t.toLowerCase()); i >= 0 ? sel.splice(i, 1) : sel.length < 12 && sel.push(b.dataset.t); draw(); });
  };
  const add = () => { const v = $('#i').value.trim(); if (v && !sel.some(x => x.toLowerCase() === v.toLowerCase())) sel.push(v); $('#i').value = ''; draw(); };
  $('#i').onkeydown = k => { if (k.key === 'Enter' || k.key === ',') { k.preventDefault(); add(); } };
  draw();
  return () => { add(); return sel; };
}

async function join() {
  const editing = location.hash.includes('edit=1') && me;
  if (me && !editing) { location.hash = '#/'; return; }
  const lf = new Set(editing ? me.looking_for : []);
  app.innerHTML = `<div class="panel narrow"><h1>${editing ? 'Edit your profile' : 'Join Huddle'}</h1>
  ${editing ? '' : '<p class="muted" style="margin-top:0">Free. No password, no email. Takes under a minute. For adults 18+.</p>'}
  <label>First name</label><input id="n" maxlength="60" autocomplete="given-name" value="${esc(editing ? me.name : '')}">
  <label>City</label><input id="c" autocomplete="address-level2" placeholder="Where do you live?" value="${esc(editing ? me.city : '')}">
  ${editing ? '' : '<label>Birthday <small>(only to confirm you\'re 18+. Never stored.)</small></label><input id="dob" type="date" autocomplete="bday">'}
  <div class="hp" aria-hidden="true"><label>Website</label><input id="hp" tabindex="-1" autocomplete="off"></div>
  <label>What are you into? <small>(tap a few)</small></label>
  <div class="chips" id="ints"></div><input id="i" placeholder="Add your own and press Enter" style="margin-top:8px">
  <details class="opt" ${editing ? 'open' : ''}><summary>Add more about you (optional)</summary>
    <label>Short bio</label><textarea id="b" rows="3" maxlength="400">${esc(editing ? me.bio : '')}</textarea>
    <label>Pronouns</label><input id="p" placeholder="she/her, he/him, they/them, anything" value="${esc(editing ? me.pronouns : '')}">
    <label>I'm looking for</label><div class="chips" id="lf">${meta.looking_for.map(x => `<button type="button" class="chip ${lf.has(x) ? 'sel' : 'plain'}" data-v="${esc(x)}">${esc(x)}</button>`).join('')}</div>
  </details>
  <p><button class="btn big" id="save">${editing ? 'Save' : 'Create my account'}</button></p><p class="muted" id="status"></p>
  ${editing ? '' : '<p class="muted">Already a member? <a href="#/login">Log in</a></p>'}</div>`;
  const getInterests = interestPicker(editing ? me.interests : []);
  document.querySelectorAll('#lf .chip').forEach(b => b.onclick = () => { lf.has(b.dataset.v) ? lf.delete(b.dataset.v) : lf.add(b.dataset.v); b.classList.toggle('sel'); b.classList.toggle('plain'); });
  $('#save').onclick = async () => {
    const profile = { name: $('#n').value, city: $('#c').value, pronouns: $('#p').value, bio: $('#b').value, interests: getInterests(), looking_for: [...lf] };
    const status = t => $('#status').textContent = t;
    if (!profile.name.trim() || profile.city.trim().length < 2) return toast('Please add your name and city');
    try {
      if (editing) { await api('/me', { method: 'PUT', body: profile }); await loadMe(); toast('Saved'); location.hash = '#/user/' + me.id; return; }
      if (!$('#dob').value) return toast('Please add your birthday');
      $('#save').disabled = true;
      status('Setting up your private keys…');
      const keys = await genKeys();
      status('Quick check that you\'re human…');
      const ch = await api('/pow');
      const counter = await solvePow(ch.challenge, ch.bits);
      const r = await api('/signup', { method: 'POST', body: { ...profile, birth_date: $('#dob').value, website: $('#hp').value, public_key: pubOnly(keys.pub), pow: { challenge: ch.challenge, counter } } });
      store.set('huddle_token', r.token); store.set('huddle_priv_' + r.user.id, JSON.stringify(keys.priv));
      await loadMe(); toast(`Welcome, ${me.name.split(' ')[0]}! Here are events for you.`); location.hash = '#/';
    } catch (e) { $('#save').disabled = false; status(''); toast(e.message || 'Please check your details'); }
  };
}

function login() {
  if (me) { location.hash = '#/'; return; }
  app.innerHTML = `<div class="panel narrow"><h1>Log in</h1>
  <p class="muted">Huddle has no passwords. Choose the login file you saved when you joined. It restores your account and your private messages on this device.</p>
  <input type="file" id="restore" accept="application/json,.json"><p class="muted" id="status"></p>
  <p class="muted">New here? <a href="#/join">Join free</a></p></div>`;
  $('#restore').addEventListener('change', async ev => {
    try {
      const f = JSON.parse(await ev.target.files[0].text());
      if (!f.huddle || !f.token || !f.user_id) throw new Error();
      store.set('huddle_token', f.token); if (f.private_key) store.set('huddle_priv_' + f.user_id, JSON.stringify(f.private_key));
      await loadMe(); if (!me) throw new Error(); store.set('huddle_saved_' + me.id, '1'); renderBanner();
      toast('Welcome back, ' + me.name.split(' ')[0]); location.hash = '#/';
    } catch { store.del('huddle_token'); $('#status').textContent = 'That file didn\'t work. Make sure it\'s the Huddle login file you downloaded.'; }
  });
}

async function settings() {
  if (!needMe()) return;
  const blocked = await api('/blocks');
  app.innerHTML = `<h1>Settings</h1><div class="stack">
  <div class="panel"><h3>Your profile</h3><p class="muted">Update your name, city, interests and bio.</p><a class="btn ghost" href="#/join?edit=1">Edit profile</a></div>
  <div class="panel"><h3>Your login file</h3><p class="muted">Huddle has no password. This file is how you log back in and read your private messages on a new device. Keep it somewhere private.</p><button class="btn ghost" data-act="save-login">Download login file</button></div>
  <div class="panel"><h3>Blocked people</h3>${blocked.map(u => `<div class="person">${avatar(u)}<div class="info"><b>${esc(u.name)}</b></div><button class="btn small ghost" data-act="unblock" data-id="${u.id}">Unblock</button></div>`).join('') || '<p class="muted">You haven\'t blocked anyone.</p>'}</div>
  <div class="panel"><h3>Delete my account</h3><p class="muted">Permanently removes your profile, messages, posts, RSVPs and any events you host. This can't be undone. (Safety reports involving your account may be kept so abuse can be investigated.)</p><button class="btn danger" id="del">Delete my account</button></div></div>`;
  $('#del').onclick = () => {
    const d = document.createElement('dialog');
    d.innerHTML = `<form method="dialog"><h3>Delete your account?</h3><p class="muted">This permanently deletes everything and can't be undone.</p>
      <div class="row" style="margin-top:14px"><button class="btn ghost" value="cancel">Keep my account</button><button class="btn danger" id="yes" value="ok">Yes, delete it</button></div></form>`;
    document.body.appendChild(d); d.addEventListener('close', () => d.remove()); d.showModal();
    d.querySelector('#yes').onclick = async ev => {
      ev.preventDefault();
      try {
        await api('/me', { method: 'DELETE' });
        const id = me.id; store.del('huddle_token'); store.del('huddle_priv_' + id); store.del('huddle_saved_' + id);
        d.close(); await loadMe(); toast('Your account has been deleted.'); location.hash = '#/';
      } catch (err) { toast(err.message); d.close(); }
    };
  };
}

function create() {
  if (!needMe()) return;
  const d = new Date(Date.now() + 7 * 864e5); d.setMinutes(0); const dv = new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16);
  app.innerHTML = `<div class="panel narrow"><h1>Host an event</h1>
  <label>Title</label><input id="t" placeholder="Sunrise walk, board game night…"><label>Category</label><select id="cat">${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
  <label>What's it about?</label><textarea id="d" rows="4" placeholder="Who is it for? What will you do? Say that newcomers and solo attendees are welcome."></textarea>
  <label>Venue <small>(please use a public place)</small></label><input id="v"><label>City</label><input id="c" value="${esc(me.city)}">
  <label>Starts</label><input id="s" type="datetime-local" value="${dv}"><label>Capacity</label><input id="cap" type="number" min="2" max="500" value="15">
  <details class="opt"><summary>More options</summary><label>Vibe <small>(e.g. "Chill & beginner-friendly")</small></label><input id="vibe">
  <label>Topic tags <small>(comma separated)</small></label><input id="tags" placeholder="Hiking, Coffee"></details>
  <p><button class="btn big" id="go">Publish event</button></p></div>`;
  $('#go').onclick = async () => {
    try {
      const r = await api('/events', { method: 'POST', body: { title: $('#t').value, category: $('#cat').value, description: $('#d').value, venue: $('#v').value, city: $('#c').value, starts: $('#s').value, capacity: +$('#cap').value, vibe: $('#vibe').value, tags: $('#tags').value.split(',').map(x => x.trim()).filter(Boolean) } });
      toast('Event published'); location.hash = '#/event/' + r.id;
    } catch (e) { toast(/too fast|account|limit|day/i.test(e.message) ? e.message : 'Please fill in the title, a short description, venue and city'); }
  };
}

async function inbox() {
  if (!needMe()) return;
  app.innerHTML = '<h1>Messages</h1><p class="muted" style="margin-top:-4px">🔒 Private. Only you and the other person can read these.</p><div class="panel" id="threads"></div>';
  let last = '';
  const load = async () => {
    const th = await api('/inbox');
    const key = th.map(t => t.user.id + ':' + t.created).join();
    if (key === last) return; last = key;
    const rows = await Promise.all(th.map(async t => {
      let preview = '🔒 Encrypted message';
      try { preview = await decrypt(await convoKey(t.user.public_key), t); } catch {}
      return `<a class="person thread" href="#/dm/${t.user.id}">${avatar(t.user)}<div class="info"><b>${esc(t.user.name)}</b> <small class="muted">${ago(t.created)}</small><br><span class="muted">${t.mine ? 'You: ' : ''}${esc(preview.slice(0, 100))}</span></div></a>`;
    }));
    $('#threads').innerHTML = rows.join('') || '<div class="empty">No messages yet.<br>Count yourself in to an event, then tap <b>Message</b> next to someone you\'d like to meet.</div>';
  };
  await load(); poll(load, 6000);
}

async function dm(other) {
  if (!needMe()) return;
  const u = await api('/users/' + other);
  if (!u.public_key) { app.innerHTML = '<div class="empty">This sample profile can\'t receive messages.</div>'; return; }
  const raw = await convoKey(u.public_key);
  dmCtx = { id: +other, raw };
  const sn = await safetyNumber(u.public_key);
  app.innerHTML = `<div class="row between"><a href="#/inbox" class="muted">&larr; Messages</a>${personMenu(u, [{ act: 'report', kind: 'dm', id: u.id, label: 'Report conversation' }])}</div>
  <div class="row" style="align-items:center;margin:8px 0"><a href="#/user/${u.id}">${avatar(u, 'lg')}</a><div><h1 style="margin:0"><a href="#/user/${u.id}">${esc(u.name)}</a></h1><small class="muted">🔒 Private. <span title="If this matches on their screen, no one is in the middle.">Safety number: <code>${sn}</code></span></small></div></div>
  ${u.shared?.length ? `<div class="match">Conversation starter: you both like ${esc(u.shared.join(', '))}</div>` : ''}
  <div class="panel chat"><div id="bubbles"></div>
  ${u.can_message ? `<div class="row" style="margin-top:12px"><input id="m" maxlength="1500" placeholder="Write a message" autofocus><button class="btn" id="s">Send</button></div>`
    : '<p class="muted" style="margin-bottom:0">You can chat once you\'re both going to the same event.</p>'}</div>`;
  let lastKey = '';
  const load = async () => {
    const msgs = await api(`/dm/${other}`);
    const k = msgs.length + ':' + (msgs.at(-1)?.id || 0); if (k === lastKey) return; lastKey = k;
    const plain = await Promise.all(msgs.map(m => decrypt(raw, m)));
    const box = $('#bubbles'); if (!box) return;
    box.innerHTML = msgs.map((m, i) => `<div class="bubble ${m.from_id === me.id ? 'mine' : ''}">${esc(plain[i])}</div>`).join('') || '<div class="muted">Say hello 👋</div>';
    box.scrollTop = box.scrollHeight;
  };
  await load(); poll(load, 4000);
  if (u.can_message) {
    const send = async () => {
      const b = $('#m').value.trim(); if (!b) return;
      $('#m').value = '';
      try { await api('/dm', { method: 'POST', body: { to_id: +other, ...(await encrypt(raw, b)) } }); await load(); } catch (e) { $('#m').value = b; toast(e.message); }
    };
    $('#s').onclick = send; $('#m').onkeydown = k => k.key === 'Enter' && send(); $('#m').focus();
  }
}

const routes = [
  [/^#\/event\/(\d+)/, eventPage], [/^#\/user\/(\d+)/, userPage], [/^#\/dm\/(\d+)/, dm], [/^#\/post\/(\d+)/, postPage],
  [/^#\/feed/, feed], [/^#\/people/, people], [/^#\/join/, join], [/^#\/login/, login], [/^#\/settings/, settings],
  [/^#\/create/, create], [/^#\/inbox/, inbox],
];
async function route() {
  const h = location.hash || '#/';
  timers.forEach(clearInterval); timers = [];
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === h || (a.getAttribute('href') === '#/inbox' && h.startsWith('#/dm/'))));
  for (const [re, fn] of routes) { const m = h.match(re); if (m) { window.scrollTo(0, 0); return fn(m[1]).catch(e => app.innerHTML = `<div class="empty">${esc(e.message)}</div>`); } }
  window.scrollTo(0, 0); home().catch(e => app.innerHTML = `<div class="empty">${esc(e.message)}</div>`);
}
addEventListener('hashchange', route);
(async () => { meta = await api('/meta'); await loadMe(); route(); })();
