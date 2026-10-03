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
const colors = ['#4a9ad4', '#c98a1b', '#6aa356', '#cf5b46', '#8271bd', '#3c8a8a'];
const avatar = (u, cls = '') => `<span class="avatar ${cls}" style="background:${colors[u.id % colors.length]}" title="${esc(u.name)}">${esc(u.name.trim()[0] || '?').toUpperCase()}</span>`;
const lockIcon = '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
const fmtTime = iso => new Date(iso).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const fmtDay = iso => new Date(iso).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
const fmt = iso => `${fmtDay(iso)}, ${fmtTime(iso)}`;
const ago = iso => { const s = (Date.now() - new Date(iso)) / 1000; return s < 60 ? 'now' : s < 3600 ? Math.floor(s / 60) + 'm' : s < 86400 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 86400) + 'd'; };
const host = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
const hashtag = t => `<button class="hash" data-act="tag" data-id="${esc(t)}">#${esc(t.replace(/\s+/g, ''))}</button>`;
const hashtags = xs => xs.length ? `<div class="tags">${xs.map(hashtag).join(' ')}</div>` : '';
const plainTags = xs => xs.map(t => `<span class="hash static">#${esc(t.replace(/\s+/g, ''))}</span>`).join(' ');
const dateBlock = (iso, cls = '') => { const d = new Date(iso); return `<span class="cal ${cls}"><b>${d.toLocaleDateString([], { month: 'short' })}</b><i>${d.getDate()}</i></span>`; };
const SUGGESTED = ['Hiking', 'Coffee', 'Board games', 'Running', 'Photography', 'Cooking', 'Books', 'Live music', 'Python', 'Startups', 'Yoga', 'Travel', 'Languages', 'Art', 'Cycling', 'Movies'];
const loading = '<div class="loading">Loading…</div>';

let timers = [];
const poll = (fn, ms) => timers.push(setInterval(() => document.hidden || fn().catch(() => {}), ms));
let dmCtx = null, searchQ = '', feedScope = null, feedTag = '';

async function loadMe() {
  me = null;
  if (token()) { try { me = await api('/me'); } catch (e) { if (/sign in|suspended/.test(e.message)) store.del('huddle_token'); } }
  $('#me').innerHTML = me
    ? `<details class="more usermenu"><summary>${avatar(me)}<span>${esc(me.name.split(' ')[0])}</span></summary><div>
        <a href="#/user/${me.id}">My profile</a><a href="#/settings">Settings</a><button data-act="signout">Sign out</button></div></details>`
    : `<a class="btn small ghost" href="#/login">Log in</a> <a class="btn small" href="#/join">Join free</a>`;
  renderBanner(); refreshBadge();
}
async function refreshBadge() {
  const b = $('#mbadge'); if (!b) return;
  try { const n = me ? (await api('/me/counts')).requests : 0; b.textContent = n || ''; } catch { b.textContent = ''; }
}
setInterval(() => document.hidden || refreshBadge(), 30000);
function renderBanner() {
  const el = $('#banner'); if (!el) return;
  const show = me && !store.get('huddle_saved_' + me.id) && privJwk();
  el.innerHTML = show ? `<div class="banner">Save your login file so you never lose your account or messages. <button class="btn small" data-act="save-login">Save it</button></div>` : '';
}
const needMe = () => { if (!me) { toast('Join free to do that. It takes a minute.'); location.hash = '#/join'; return false; } return true; };

const moreMenu = items => `<details class="more"><summary aria-label="More options">&middot;&middot;&middot;</summary><div>${items.map(i =>
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
  const el = e.target.closest('[data-act]');
  if (!el) {  // whole timeline row is clickable, except links, buttons and menus inside it
    const row = e.target.closest('[data-href]');
    if (row && !e.target.closest('a,button,details,input,textarea,select')) location.hash = row.dataset.href;
    return;
  }
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
    } else if (act === 'del-post') { await api('/posts/' + id, { method: 'DELETE' }); toast('Post deleted'); location.hash.startsWith('#/post/') ? (location.hash = '#/') : route();
    } else if (act === 'del-reply') { await api('/replies/' + id, { method: 'DELETE' }); route();
    } else if (act === 'tag') { feedTag = id; if (location.hash === '#/' || location.hash === '') route(); else location.hash = '#/';
    } else if (act === 'accept-req') { await api(`/requests/${id}/accept`, { method: 'POST' }); toast('Accepted. You can chat now.'); refreshBadge(); route();
    } else if (act === 'decline-req') { await api(`/requests/${id}/decline`, { method: 'POST' }); toast("Declined. They won't be told."); refreshBadge(); route();
    } else if (act === 'unblock') { await api('/blocks/' + id, { method: 'DELETE' }); toast('Unblocked'); route();
    }
  } catch (err) { toast(err.message); }
});

/* ---------- layout: left column, centre, right column ---------- */
const leftCol = () => me ? `
  <div class="box profile"><a class="who" href="#/user/${me.id}">${avatar(me, 'lg')}<span><b>${esc(me.name)}</b><small>${esc(me.city)}</small></span></a>
    <div class="stats"><a href="#/user/${me.id}"><b>${me.stats?.posts ?? 0}</b>Posts</a><a href="#/events"><b>${me.stats?.events ?? 0}</b>Events</a><a href="#/join?edit=1"><b>${me.interests.length}</b>Interests</a></div></div>
  ${me.interests.length ? `<div class="box"><h4>Your interests</h4><div class="tags">${me.interests.slice(0, 10).map(hashtag).join(' ')}</div><a class="more-link" href="#/join?edit=1">Edit</a></div>` : ''}`
  : `<div class="box"><h4>New to Huddle?</h4><p class="sub" style="margin:6px 0 12px">Meet people near you who share your interests. Free. No password, no email.</p><a class="btn" href="#/join">Join free</a> <a class="btn ghost" href="#/login">Log in</a></div>`;
const rightCol = () => `
  ${me ? '<div class="box" id="w-people"><h4>People you may like</h4><div class="loading">Loading…</div></div>' : ''}
  <div class="box" id="w-events"><h4>Happening nearby</h4><div class="loading">Loading…</div></div>
  <div class="box" id="w-trends"><h4>Interests people are posting about</h4><div class="loading">Loading…</div></div>
  <p class="fine">18+ only. See something wrong? Report it from the menu on any post, message or profile.</p>`;
const shell = (main, { right = false, solo = false } = {}) => solo ? `<div class="solo">${main}</div>`
  : `<div class="shell ${right ? 'has-right' : ''}"><aside class="left">${leftCol()}</aside><section class="main">${main}</section>${right ? `<aside class="right">${rightCol()}</aside>` : ''}</div>`;

async function fillWidgets() {
  const q = async (id, fn) => { const el = $('#' + id); if (!el) return; try { const html = await fn(); if ($('#' + id)) $('#' + id).innerHTML = html; } catch { $('#' + id)?.remove(); } };
  q('w-people', async () => {
    const ms = (await api('/me/matches')).slice(0, 3);
    return `<h4>People you may like</h4>${ms.map(u => `<div class="mini">${avatar(u)}<div class="grow"><a class="nm" href="#/user/${u.id}">${esc(u.name)}</a><small>${u.shared.length ? 'Likes ' + esc(u.shared.slice(0, 2).join(', ')) : esc(u.city)}</small></div>
      ${u.can_message ? `<a class="btn small ghost" href="#/dm/${u.id}">${u.chat === 'accepted' ? 'Chat' : u.chat === 'request_out' ? 'Sent' : 'Message'}</a>` : ''}</div>`).join('') || '<p class="sub">Add interests to see people.</p>'}<a class="more-link" href="#/people">View all</a>`;
  });
  q('w-events', async () => {
    const evs = (await api('/events?sort=' + (me ? 'match' : 'soon') + (me?.city ? '&city=' + encodeURIComponent(me.city) : ''))).slice(0, 4);
    return `<h4>Happening nearby</h4>${evs.map(e => `<div class="mini">${dateBlock(e.starts, 'sm')}<div class="grow"><a class="nm" href="#/event/${e.id}">${esc(e.title)}</a><small>${fmtTime(e.starts)} · ${e.attendee_count} going</small></div></div>`).join('') || '<p class="sub">No events yet.</p>'}<a class="more-link" href="#/events">All events</a>`;
  });
  q('w-trends', async () => {
    const counts = {};
    (await api('/posts?scope=all')).forEach(p => p.tags.forEach(t => counts[t] = (counts[t] || 0) + 1));
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    return `<h4>Interests people are posting about</h4>${top.map(([t, n]) => `<div class="trend">${hashtag(t)}<small>${n} post${n > 1 ? 's' : ''}</small></div>`).join('') || '<p class="sub">Nothing yet.</p>'}`;
  });
}

/* ---------- home: compose + timeline ---------- */
const postRow = (p, full = false) => `
<article class="tw" ${full ? '' : `data-href="#/post/${p.id}"`}>
  <a href="#/user/${p.author.id}">${avatar(p.author, 'lg')}</a>
  <div class="body">
    <div class="head"><span><a class="nm" href="#/user/${p.author.id}">${esc(p.author.name)}</a> <small>${esc(p.city)} &middot; ${ago(p.created)}</small></span>
    ${me ? moreMenu(p.mine ? [{ act: 'del-post', id: p.id, label: 'Delete post', danger: true }] : [{ act: 'report', kind: 'post', id: p.id, label: 'Report post' }, { act: 'block', id: p.author.id, name: p.author.name, label: `Block ${esc(p.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
    <div class="txt">${esc(p.body)}</div>
    ${p.url ? `<a class="ext" href="${esc(p.url)}" target="_blank" rel="nofollow noopener noreferrer ugc">${esc(host(p.url))} &#8599;</a>` : ''}
    ${hashtags(p.tags)}
    ${full ? '' : `<div class="acts"><a href="#/post/${p.id}">Reply${p.reply_count ? ' (' + p.reply_count + ')' : ''}</a></div>`}
  </div>
</article>`;

async function home() {
  if (!feedScope) feedScope = me ? 'foryou' : 'all';
  const sel = new Set();
  const compose = me ? `<div class="box compose">${avatar(me, 'lg')}<div class="grow"><textarea id="pb" rows="2" maxlength="500" placeholder="Share something with people nearby…"></textarea>
      <input id="pu" class="hidden" placeholder="Paste a link (https://…)" maxlength="300">
      ${me.interests.length ? `<div class="tags" id="pt"><small>Tag:</small> ${me.interests.slice(0, 8).map(t => `<button type="button" class="hash opt" data-t="${esc(t)}">#${esc(t.replace(/\s+/g, ''))}</button>`).join(' ')}</div>` : ''}
      <div class="row between" style="margin-top:8px"><button class="linkbtn" id="addlink" type="button">Add a link</button><span class="row" style="align-items:center"><span class="counter" id="cnt">500</span><button class="btn" id="post">Post</button></span></div></div></div>`
    : `<div class="box intro"><h2>See what's happening near you.</h2><p>Huddle is a place to share news and interests, find events, and meet people nearby who like the same things.</p><a class="btn" href="#/join">Join free</a> <span class="sub">or just look around below.</span></div>`;
  const tabs = [['foryou', 'For you'], ['near', 'Near me'], ['all', 'Everyone']].filter(([k]) => me || k === 'all');
  app.innerHTML = shell(`${compose}
    <div class="box"><div class="tabs">${tabs.map(([k, l]) => `<a href="#/" class="${feedScope === k ? 'on' : ''}" data-s="${k}">${l}</a>`).join('')}</div>
    ${feedTag ? `<div class="filterbar">Showing posts tagged <b>#${esc(feedTag.replace(/\s+/g, ''))}</b> <button class="linkbtn" id="cleartag">Clear</button></div>` : ''}
    <div id="posts" class="list">${loading}</div></div>`, { right: true });
  document.querySelectorAll('.tabs a').forEach(a => a.onclick = ev => { ev.preventDefault(); feedScope = a.dataset.s; home(); });
  $('#cleartag')?.addEventListener('click', () => { feedTag = ''; home(); });
  if (me) {
    $('#addlink').onclick = () => { $('#pu').classList.toggle('hidden'); $('#pu').focus(); };
    $('#pb').oninput = () => { const n = 500 - $('#pb').value.length; $('#cnt').textContent = n; $('#cnt').classList.toggle('low', n < 40); };
    document.querySelectorAll('#pt [data-t]').forEach(b => b.onclick = () => { const t = b.dataset.t; if (sel.has(t)) sel.delete(t); else if (sel.size < 3) sel.add(t); b.classList.toggle('on', sel.has(t)); });
    $('#post').onclick = async () => {
      const body = $('#pb').value.trim(); if (!body) return toast('Write something first');
      try { await api('/posts', { method: 'POST', body: { body, url: $('#pu').value, tags: [...sel] } }); toast('Posted'); me = await api('/me'); home(); } catch (err) { toast(err.message); }
    };
  }
  fillWidgets();
  const posts = await api(`/posts?scope=${feedScope}&tag=${encodeURIComponent(feedTag)}`);
  $('#posts').innerHTML = posts.map(p => postRow(p)).join('') || `<div class="empty">Nothing here yet. ${feedScope === 'near' ? 'Try “Everyone”, or ' : ''}be the first to share something.</div>`;
}

async function postPage(id) {
  const p = await api('/posts/' + id);
  app.innerHTML = shell(`<p class="back"><a href="#/">&larr; Home</a></p><div class="box">${postRow(p, true)}</div>
  <div class="box"><div class="boxhead"><h3>${p.replies.length ? `Replies (${p.replies.length})` : 'No replies yet'}</h3></div>
  <div class="list">${p.replies.map(r => `<article class="tw"><a href="#/user/${r.author.id}">${avatar(r.author, 'lg')}</a><div class="body"><div class="head"><span><a class="nm" href="#/user/${r.author.id}">${esc(r.author.name)}</a> <small>${ago(r.created)}</small></span>
    ${me ? moreMenu(r.mine ? [{ act: 'del-reply', id: r.id, label: 'Delete', danger: true }] : [{ act: 'report', kind: 'reply', id: r.id, label: 'Report reply' }, { act: 'block', id: r.author.id, name: r.author.name, label: `Block ${esc(r.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
    <div class="txt">${esc(r.body)}</div></div></article>`).join('')}</div>
  ${me ? `<div class="replybar row"><input id="rb" maxlength="500" placeholder="Write a reply"><button class="btn" id="rs">Reply</button></div>` : '<div class="replybar"><a href="#/join" class="btn">Join free</a> <span class="sub">to reply.</span></div>'}</div>`);
  if (me) {
    const send = async () => { const b = $('#rb').value.trim(); if (!b) return; try { await api(`/posts/${id}/replies`, { method: 'POST', body: { body: b } }); postPage(id); } catch (err) { toast(err.message); } };
    $('#rs').onclick = send; $('#rb').onkeydown = k => k.key === 'Enter' && send();
  }
}

/* ---------- events ---------- */
const eventRow = e => `
<a class="ev" href="#/event/${e.id}">${dateBlock(e.starts)}
  <div class="grow"><b class="nm">${esc(e.title)}</b><small>${fmtDay(e.starts)}, ${fmtTime(e.starts)} &middot; ${esc(e.venue)}, ${esc(e.city)}</small>
    <div class="tags"><span class="hash static">#${esc(e.category.replace(/[^A-Za-z]+/g, ''))}</span>${e.vibe ? ` <span class="vibe">${esc(e.vibe)}</span>` : ''}</div></div>
  <div class="meta"><div class="avatars">${e.attendees.slice(0, 4).map(a => avatar(a)).join('')}</div><small>${e.attendee_count} going &middot; ${e.spots_left} left</small>
    ${me && e.people_like_you ? `<small class="hl">${e.people_like_you} share your interests</small>` : ''}</div>
</a>`;

async function events() {
  app.innerHTML = shell(`<div class="box"><div class="boxhead"><h2>Events</h2>${me ? '<a class="btn small" href="#/create">Host an event</a>' : ''}</div>
  <div class="filters">
    <input id="q" placeholder="Search events, interests, places" value="${esc(searchQ)}">
    <select id="cat"><option value="">All categories</option>${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
    <input id="city" placeholder="City" value="${esc(me?.city || '')}">
    ${me ? `<select id="sort"><option value="match">Best for me</option><option value="soon">Soonest</option></select>` : ''}
  </div><div id="list" class="list">${loading}</div></div>`);
  const run = async () => {
    const p = new URLSearchParams({ q: $('#q').value, category: $('#cat').value, city: $('#city').value, sort: $('#sort')?.value || 'soon' });
    const evs = await api('/events?' + p);
    if ($('#list')) $('#list').innerHTML = evs.length ? evs.map(eventRow).join('') : '<div class="empty">No events match. Try clearing the city filter, or <a href="#/create">host one</a>.</div>';
  };
  let t; ['q', 'city'].forEach(i => $('#' + i).oninput = () => { clearTimeout(t); t = setTimeout(run, 250); });
  ['cat', 'sort'].forEach(i => $('#' + i) && ($('#' + i).onchange = run));
  if (me) $('#sort').value = 'match';
  await run();
}

async function eventPage(id) {
  const e = await api(`/events/${id}`);
  const full = e.spots_left === 0 && !e.going;
  app.innerHTML = shell(`<p class="back"><a href="#/events">&larr; All events</a></p>
  <div class="box event"><div class="row" style="gap:14px">${dateBlock(e.starts, 'big')}<div class="grow"><div class="row between"><h2 style="margin:0">${esc(e.title)}</h2>${me && me.id !== e.host.id ? moreMenu([{ act: 'report', kind: 'event', id: e.id, label: 'Report this event' }]) : ''}</div>
    <div class="sub">${fmt(e.starts)} &middot; ${esc(e.venue)}, ${esc(e.city)}</div><div class="sub">Hosted by <a href="#/user/${e.host.id}">${esc(e.host.name)}</a></div></div></div>
    <p class="desc">${esc(e.description)}</p>
    <div class="tags">${plainTags([e.category, ...e.tags])}${e.vibe ? ` <span class="vibe">${esc(e.vibe)}</span>` : ''}</div>
    <p style="margin-bottom:0"><button class="btn ${e.going ? 'ghost' : ''}" id="rsvp" ${full ? 'disabled' : ''}>${e.going ? 'Going &#10003; (tap to cancel)' : full ? 'Event is full' : 'Count me in'}</button></p></div>
  <div class="box"><div class="boxhead"><h3>Who's going (${e.attendee_count}/${e.capacity})</h3></div><div class="list">
    ${e.attendees.map(a => `<div class="row-item">${avatar(a, 'lg')}<div class="grow"><a class="nm" href="#/user/${a.id}">${esc(a.name)}</a> <small>${esc(a.pronouns)}</small>
      <div class="sub">${a.shared?.length ? 'In common: ' + plainTags(a.shared) : esc(a.interests.slice(0, 3).join(', '))}</div></div>
      ${me && a.id !== me.id && a.public_key ? `<a class="btn small ghost" href="#/dm/${a.id}">Message</a>` : ''}</div>`).join('')}</div></div>
  <div class="box"><div class="boxhead"><h3>Chat</h3><small>Public to attendees and watched by our safety team</small></div><div class="list">
    ${e.messages.map(m => `<article class="tw"><a href="#/user/${m.user.id}">${avatar(m.user, 'lg')}</a><div class="body"><div class="head"><span><a class="nm" href="#/user/${m.user.id}">${esc(m.user.name)}</a> <small>${ago(m.created)}</small></span>${personMenu(m.user, [{ act: 'report', kind: 'event_message', id: m.id, label: 'Report message' }])}</div><div class="txt">${esc(m.body)}</div></div></article>`).join('') || '<div class="empty">Nobody has said anything yet.</div>'}</div>
    ${e.going ? `<div class="replybar"><div class="row"><input id="msg" maxlength="1000" placeholder="Say hi to the group"><button class="btn" id="send">Send</button></div>
      <div class="starters"><small>Need a starter?</small> ${e.icebreakers.map(i => `<button class="ice">${esc(i)}</button>`).join('')}</div></div>` : '<div class="replybar sub">Count yourself in to join the chat.</div>'}</div>`);
  $('#rsvp').onclick = async () => {
    if (!needMe()) return;
    try {
      if (e.going) await api(`/events/${id}/rsvp`, { method: 'DELETE' });
      else { await api(`/events/${id}/rsvp`, { method: 'POST' }); toast("You're in! Say hi in the chat, or message someone."); }
      me = await api('/me'); eventPage(id);
    } catch (err) { toast(err.message); }
  };
  if (e.going) {
    const send = async () => { const b = $('#msg').value.trim(); if (!b) return; try { await api(`/events/${id}/messages`, { method: 'POST', body: { body: b } }); eventPage(id); } catch (err) { toast(err.message); } };
    $('#send').onclick = send; $('#msg').onkeydown = k => k.key === 'Enter' && send();
    document.querySelectorAll('.ice').forEach(b => b.onclick = () => { $('#msg').value = b.textContent; $('#msg').focus(); });
  }
}

/* ---------- people ---------- */
async function people() {
  if (!needMe()) return;
  const list = await api('/me/matches');
  app.innerHTML = shell(`<div class="box"><div class="boxhead"><h2>People you may like</h2></div><p class="sub pad">Based on your interests, where you live, and what you're looking for.</p><div class="list">
  ${list.map(u => `<div class="row-item">${avatar(u, 'lg')}<div class="grow"><a class="nm" href="#/user/${u.id}">${esc(u.name)}</a> <small>${esc(u.city)} ${esc(u.pronouns)}</small>
    <div class="sub">${u.shared.length ? 'In common: ' + plainTags(u.shared) : ''}${u.shared_goals.length ? ` &middot; Both looking for ${esc(u.shared_goals.join(', ').toLowerCase())}` : ''}${u.events_in_common ? ` &middot; ${u.events_in_common} event${u.events_in_common > 1 ? 's' : ''} in common` : ''}</div></div>
    ${u.chat === 'accepted' ? `<a class="btn small" href="#/dm/${u.id}">Open chat</a>` : u.chat === 'request_out' ? `<a class="btn small ghost" href="#/dm/${u.id}">Request sent</a>` : u.chat === 'request_in' ? `<a class="btn small" href="#/dm/${u.id}">Respond</a>` : u.can_message ? `<a class="btn small ghost" href="#/dm/${u.id}">Message</a>` : '<small>Sample profile</small>'}</div>`).join('') || '<div class="empty">Add some interests to your profile to see people.</div>'}</div></div>`);
}

async function userPage(id) {
  const [u, posts] = await Promise.all([api(`/users/${id}`), api(`/users/${id}/posts`)]);
  const mine = me && me.id === u.id;
  const action = mine ? '<a class="btn ghost" href="#/join?edit=1">Edit profile</a>'
    : u.chat === 'request_in' ? `<a class="btn" href="#/dm/${u.id}">Respond to request</a>`
    : u.chat === 'request_out' ? `<a class="btn ghost" href="#/dm/${u.id}">Request sent</a>`
    : u.can_message ? `<a class="btn" href="#/dm/${u.id}">Message</a>`
    : u.blocked ? `<button class="btn ghost" data-act="unblock" data-id="${u.id}">Unblock</button>`
    : !u.public_key ? '<small>Sample profile</small>' : me ? '<small>Messaging isn\'t available</small>' : '<a class="btn" href="#/join">Join free to message</a>';
  app.innerHTML = shell(`<div class="box pbox"><div class="pbanner"></div><div class="phead">${avatar(u, 'xl')}<div class="row" style="align-items:center">${action}${personMenu(u)}</div></div>
    <div class="pinfo"><h2>${esc(u.name)}</h2><div class="sub">${esc(u.city)}${u.pronouns ? ' &middot; ' + esc(u.pronouns) : ''}</div>
    ${u.bio ? `<p>${esc(u.bio)}</p>` : ''}<div class="tags">${plainTags(u.interests)}</div>
    ${u.looking_for.length ? `<p class="sub">Looking for: ${esc(u.looking_for.join(', ').toLowerCase())}</p>` : ''}
    ${u.shared?.length ? `<p class="hl">You both like ${esc(u.shared.join(', '))}</p>` : ''}
    ${u.shared_events?.length ? `<p class="sub">You're both going to ${esc(u.shared_events.join(', '))}</p>` : ''}</div></div>
  <div class="box"><div class="boxhead"><h3>Posts</h3></div><div class="list">${posts.map(p => postRow(p)).join('') || '<div class="empty">No posts yet.</div>'}</div></div>
  <div class="box"><div class="boxhead"><h3>Upcoming events</h3></div><div class="list">${u.events.map(e => `<a class="ev" href="#/event/${e.id}">${dateBlock(e.starts, 'sm')}<div class="grow"><b class="nm">${esc(e.title)}</b><small>${fmt(e.starts)}</small></div></a>`).join('') || '<div class="empty">Nothing yet.</div>'}</div></div>`);
}

/* ---------- join, login, settings, host ---------- */
function interestPicker(initial) {
  const sel = [...initial];
  const draw = () => {
    const all = [...new Set([...SUGGESTED, ...sel])];
    $('#ints').innerHTML = all.map(t => `<button type="button" class="hash opt ${sel.some(x => x.toLowerCase() === t.toLowerCase()) ? 'on' : ''}" data-t="${esc(t)}">#${esc(t.replace(/\s+/g, ''))}</button>`).join(' ');
    document.querySelectorAll('#ints .hash').forEach(b => b.onclick = () => { const i = sel.findIndex(x => x.toLowerCase() === b.dataset.t.toLowerCase()); i >= 0 ? sel.splice(i, 1) : sel.length < 12 && sel.push(b.dataset.t); draw(); });
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
  const form = `<div class="box form"><h2>${editing ? 'Edit your profile' : 'Join Huddle'}</h2>
  ${editing ? '' : '<p class="sub">Free. No password, no email. Takes under a minute. For adults 18+.</p>'}
  <label>First name</label><input id="n" maxlength="60" autocomplete="given-name" value="${esc(editing ? me.name : '')}">
  <label>City</label><input id="c" autocomplete="address-level2" placeholder="Where do you live?" value="${esc(editing ? me.city : '')}">
  ${editing ? '' : '<label>Birthday <small>(only to confirm you\'re 18+. Never stored.)</small></label><input id="dob" type="date" autocomplete="bday">'}
  <div class="hp" aria-hidden="true"><label>Website</label><input id="hp" tabindex="-1" autocomplete="off"></div>
  <label>What are you into? <small>(tap a few)</small></label>
  <div class="tags" id="ints"></div><input id="i" placeholder="Add your own and press Enter" style="margin-top:8px">
  <details class="opt" ${editing ? 'open' : ''}><summary>Add more about you (optional)</summary>
    <label>Short bio</label><textarea id="b" rows="3" maxlength="400">${esc(editing ? me.bio : '')}</textarea>
    <label>Pronouns</label><input id="p" placeholder="she/her, he/him, they/them, anything" value="${esc(editing ? me.pronouns : '')}">
    <label>I'm looking for</label><div class="tags" id="lf">${meta.looking_for.map(x => `<button type="button" class="hash opt ${lf.has(x) ? 'on' : ''}" data-v="${esc(x)}">${esc(x)}</button>`).join(' ')}</div>
  </details>
  <p><button class="btn big" id="save">${editing ? 'Save' : 'Create my account'}</button></p><p class="sub" id="status"></p>
  ${editing ? '' : '<p class="sub">Already a member? <a href="#/login">Log in</a></p>'}</div>`;
  app.innerHTML = editing ? shell(form) : shell(form, { solo: true });
  const getInterests = interestPicker(editing ? me.interests : []);
  document.querySelectorAll('#lf .hash').forEach(b => b.onclick = () => { lf.has(b.dataset.v) ? lf.delete(b.dataset.v) : lf.add(b.dataset.v); b.classList.toggle('on'); });
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
      await loadMe(); toast(`Welcome, ${me.name.split(' ')[0]}!`); location.hash = '#/';
    } catch (e) { $('#save').disabled = false; status(''); toast(e.message || 'Please check your details'); }
  };
}

function login() {
  if (me) { location.hash = '#/'; return; }
  app.innerHTML = shell(`<div class="box form"><h2>Log in</h2>
  <p class="sub">Huddle has no passwords. Choose the login file you saved when you joined. It restores your account and your private messages on this device.</p>
  <input type="file" id="restore" accept="application/json,.json"><p class="sub" id="status"></p>
  <p class="sub">New here? <a href="#/join">Join free</a></p></div>`, { solo: true });
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
  app.innerHTML = shell(`<div class="box"><div class="boxhead"><h2>Settings</h2></div>
  <div class="setting"><div><b>Your profile</b><div class="sub">Update your name, city, interests and bio.</div></div><a class="btn small ghost" href="#/join?edit=1">Edit profile</a></div>
  <div class="setting"><div><b>Login file</b><div class="sub">Huddle has no password. This file is how you log back in and read your private messages on a new device. Keep it private.</div></div><button class="btn small ghost" data-act="save-login">Download</button></div>
  <div class="setting col"><b>Blocked people</b>${blocked.map(u => `<div class="row-item">${avatar(u)}<div class="grow nm">${esc(u.name)}</div><button class="btn small ghost" data-act="unblock" data-id="${u.id}">Unblock</button></div>`).join('') || '<div class="sub">You haven\'t blocked anyone.</div>'}</div>
  <div class="setting"><div><b>Delete my account</b><div class="sub">Permanently removes your profile, messages, posts, RSVPs and any events you host. This can't be undone. (Safety reports involving your account may be kept so abuse can be investigated.)</div></div><button class="btn small danger" id="del">Delete account</button></div></div>`);
  $('#del').onclick = () => {
    const d = document.createElement('dialog');
    d.innerHTML = `<form method="dialog"><h3>Delete your account?</h3><p class="sub">This permanently deletes everything and can't be undone.</p>
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
  app.innerHTML = shell(`<div class="box form"><h2>Host an event</h2>
  <label>Title</label><input id="t" placeholder="Sunrise walk, board game night…"><label>Category</label><select id="cat">${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
  <label>What's it about?</label><textarea id="d" rows="4" placeholder="Who is it for? What will you do? Say that newcomers and solo attendees are welcome."></textarea>
  <label>Venue <small>(please use a public place)</small></label><input id="v"><label>City</label><input id="c" value="${esc(me.city)}">
  <label>Starts</label><input id="s" type="datetime-local" value="${dv}"><label>Capacity</label><input id="cap" type="number" min="2" max="500" value="15">
  <details class="opt"><summary>More options</summary><label>Vibe <small>(e.g. "Chill & beginner-friendly")</small></label><input id="vibe">
  <label>Topic tags <small>(comma separated)</small></label><input id="tags" placeholder="Hiking, Coffee"></details>
  <p><button class="btn big" id="go">Publish event</button></p></div>`);
  $('#go').onclick = async () => {
    try {
      const r = await api('/events', { method: 'POST', body: { title: $('#t').value, category: $('#cat').value, description: $('#d').value, venue: $('#v').value, city: $('#c').value, starts: $('#s').value, capacity: +$('#cap').value, vibe: $('#vibe').value, tags: $('#tags').value.split(',').map(x => x.trim()).filter(Boolean) } });
      toast('Event published'); location.hash = '#/event/' + r.id;
    } catch (e) { toast(/too fast|account|limit|day/i.test(e.message) ? e.message : 'Please fill in the title, a short description, venue and city'); }
  };
}

/* ---------- messages ---------- */
async function inbox() {
  if (!needMe()) return;
  app.innerHTML = shell(`<div class="box"><div class="boxhead"><h2>Messages</h2><small>${lockIcon} Private. Only you and the other person can read these.</small></div><div id="reqs"></div><div class="list" id="threads">${loading}</div></div>`);
  let last = '';
  const load = async () => {
    const th = await api('/inbox');
    const key = th.map(t => `${t.user.id}:${t.created}:${t.status}`).join();
    if (key === last) return; last = key;
    const items = await Promise.all(th.map(async t => {
      let preview = 'Encrypted message';
      try { preview = await decrypt(await convoKey(t.user.public_key), t); } catch {}
      return { t, preview };
    }));
    const reqs = items.filter(i => i.t.status === 'request_in'), rest = items.filter(i => i.t.status !== 'request_in');
    $('#reqs').innerHTML = reqs.length ? `<div class="reqhead">Message requests (${reqs.length})</div>${reqs.map(({ t, preview }) => {
      const common = t.user.interests.filter(i => me.interests.some(m => m.toLowerCase() === i.toLowerCase()));
      return `<div class="request"><div class="row">${avatar(t.user, 'lg')}<div class="grow"><a class="nm" href="#/user/${t.user.id}">${esc(t.user.name)}</a> <small>${esc(t.user.city)} &middot; ${ago(t.created)}</small>
        ${common.length ? `<div class="sub">In common: ${plainTags(common)}</div>` : ''}<div class="quote">${esc(preview.slice(0, 280))}</div>
        <div class="row" style="align-items:center"><button class="btn small" data-act="accept-req" data-id="${t.user.id}">Accept</button><button class="btn small ghost" data-act="decline-req" data-id="${t.user.id}">Decline</button>
        ${moreMenu([{ act: 'block', id: t.user.id, name: t.user.name, label: `Block ${esc(t.user.name.split(' ')[0])}`, danger: true }])}</div></div></div></div>`; }).join('')}` : '';
    $('#threads').innerHTML = rest.map(({ t, preview }) => `<a class="row-item thread" href="#/dm/${t.user.id}">${avatar(t.user, 'lg')}<div class="grow"><b class="nm">${esc(t.user.name)}</b> <small>${ago(t.created)}</small><div class="sub">${t.status === 'request_out' ? '<span class="tag">Request sent</span> ' : t.mine ? 'You: ' : ''}${esc(preview.slice(0, 100))}</div></div></a>`).join('')
      || (reqs.length ? '<div class="empty">Accept a request to start chatting.</div>' : '<div class="empty">No messages yet.<br>Tap <b>Message</b> on someone\'s profile to send a request.</div>');
    refreshBadge();
  };
  await load(); poll(load, 6000);
}

async function dm(other) {
  if (!needMe()) return;
  timers.forEach(clearInterval); timers = [];
  const u = await api('/users/' + other);
  if (!u.public_key) { app.innerHTML = shell('<div class="empty">This sample profile can\'t receive messages.</div>'); return; }
  const raw = await convoKey(u.public_key);
  dmCtx = { id: +other, raw };
  const sn = await safetyNumber(u.public_key);
  const first = esc(u.name.split(' ')[0]);
  const bottom = {
    none: `<p class="hint">${first} will get a message request. You can keep chatting once they accept.</p><div class="row"><input id="m" maxlength="1500" placeholder="Introduce yourself…"><button class="btn" id="s">Send request</button></div>`,
    accepted: `<div class="row"><input id="m" maxlength="1500" placeholder="Write a message"><button class="btn" id="s">Send</button></div>`,
    request_out: `<p class="hint" style="margin:0">Request sent. You can keep chatting once ${first} accepts.</p>`,
    request_in: `<p class="hint">${first} would like to chat. Accept to reply, or decline and they won't be told.</p><div class="row"><button class="btn" id="acc">Accept</button><button class="btn ghost" id="dec">Decline</button></div>`,
    unavailable: `<p class="hint" style="margin:0">This person can't be messaged right now.</p>`,
  }[u.chat || 'none'];
  app.innerHTML = shell(`<p class="back"><a href="#/inbox">&larr; Messages</a></p>
  <div class="box"><div class="boxhead"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><a class="nm" href="#/user/${u.id}" style="font-size:1.1rem">${esc(u.name)}</a><div class="sub">${lockIcon} Private &middot; <span title="If this matches on their screen, no one is in the middle.">Safety number <code>${sn}</code></span></div></div></div>${personMenu(u, [{ act: 'report', kind: 'dm', id: u.id, label: 'Report conversation' }])}</div>
  ${u.shared?.length ? `<div class="starter">You both like ${esc(u.shared.join(', '))}. A good place to start.</div>` : ''}
  <div class="chat"><div id="bubbles"></div><div class="composer-bar">${bottom}</div></div></div>`);
  let seen = 0, lastId = 0;
  const load = async () => {
    const msgs = await api(`/dm/${other}`);
    const id = msgs.at(-1)?.id || 0; if (msgs.length === seen && id === lastId) return;
    const box = $('#bubbles'); if (!box) return;
    const fresh = msgs.slice(seen); const plain = await Promise.all(fresh.map(m => decrypt(raw, m)));
    if (!seen) box.innerHTML = '';
    box.insertAdjacentHTML('beforeend', fresh.map((m, i) => `<div class="bubble ${m.from_id === me.id ? 'mine' : ''}">${esc(plain[i])}<small>${fmtTime(m.created)}</small></div>`).join(''));
    if (!msgs.length) box.innerHTML = `<div class="sub" style="padding:6px 2px">${u.chat === 'none' ? `Say hello to ${first}.` : 'No messages yet.'}</div>`;
    seen = msgs.length; lastId = id; box.scrollTop = box.scrollHeight;
  };
  await load();
  if (u.chat !== 'unavailable') {
    poll(load, 4000);
    poll(async () => { const now = (await api('/users/' + other)).chat || 'none'; if (now !== (u.chat || 'none')) dm(other); }, 5000);
  }
  if ($('#m')) {
    const send = async () => {
      const b = $('#m').value.trim(); if (!b) return;
      $('#m').value = '';
      try { await api('/dm', { method: 'POST', body: { to_id: +other, ...(await encrypt(raw, b)) } }); if (u.chat === 'none') { toast(`Request sent to ${u.name.split(' ')[0]}`); dm(other); } else await load(); }
      catch (e) { $('#m').value = b; toast(e.message); }
    };
    $('#s').onclick = send; $('#m').onkeydown = k => k.key === 'Enter' && send(); $('#m').focus();
  }
  $('#acc')?.addEventListener('click', async () => { await api(`/requests/${other}/accept`, { method: 'POST' }); toast('Accepted. Say hello!'); refreshBadge(); dm(other); });
  $('#dec')?.addEventListener('click', async () => { await api(`/requests/${other}/decline`, { method: 'POST' }); toast("Declined. They won't be told."); refreshBadge(); location.hash = '#/inbox'; });
}

/* ---------- routing ---------- */
const routes = [
  [/^#\/event\/(\d+)/, eventPage], [/^#\/events/, events], [/^#\/user\/(\d+)/, userPage], [/^#\/dm\/(\d+)/, dm], [/^#\/post\/(\d+)/, postPage],
  [/^#\/people/, people], [/^#\/join/, join], [/^#\/login/, login], [/^#\/settings/, settings], [/^#\/create/, create], [/^#\/inbox/, inbox],
];
async function route() {
  const h = location.hash || '#/';
  timers.forEach(clearInterval); timers = [];
  const group = /^#\/(events?|create)/.test(h) ? '#/events' : /^#\/(inbox|dm)/.test(h) ? '#/inbox' : /^#\/people/.test(h) ? '#/people' : /^#\/(user|join|login|settings)/.test(h) ? '' : '#/';
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === group));
  window.scrollTo({ top: 0 });
  if (me) { try { me = await api('/me'); } catch {} }  // keep profile-card counts fresh
  const fail = e => app.innerHTML = shell(`<div class="empty">${esc(e.message)}</div>`);
  for (const [re, fn] of routes) { const m = h.match(re); if (m) return fn(m[1]).catch(fail); }
  return home().catch(fail);
}
addEventListener('hashchange', route);
$('#search').addEventListener('submit', e => { e.preventDefault(); searchQ = $('#search input').value.trim(); location.hash === '#/events' ? route() : (location.hash = '#/events'); });
(async () => { meta = await api('/meta'); await loadMe(); route(); })();
