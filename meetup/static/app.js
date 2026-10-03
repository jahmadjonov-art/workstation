const $ = (s, r = document) => r.querySelector(s);
const app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let meta = { categories: [], looking_for: [] };
let me = null;

const mem = new Map();  // used when the browser blocks localStorage (private mode, embedded frames)
const store = {
  get: k => { try { return localStorage.getItem(k); } catch { return mem.get(k) ?? null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { mem.set(k, v); } },
  del: k => { try { localStorage.removeItem(k); } catch { mem.delete(k); } },
};
const token = () => store.get('huddle_token');
class Stale extends Error {}  // thrown when a page load finishes after you have already moved to another page
let routeSeq = 0;
const api = async (path, opts = {}) => {
  const seq = routeSeq, isGet = !opts.method || opts.method === 'GET';
  const headers = { 'Content-Type': 'application/json' };
  if (token()) headers.Authorization = 'Bearer ' + token();
  let r;
  try { r = await fetch('/api' + path, { headers, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined }); }
  catch { throw new Error("Can't reach the Huddle server. Check your connection and try again."); }
  if (isGet && seq !== routeSeq) throw new Stale();
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
  try { const n = me ? (await api('/me/counts')).requests : 0; b.textContent = n || ''; } catch (e) { if (!(e instanceof Stale)) b.textContent = ''; }
}
setInterval(() => document.hidden || refreshBadge(), 30000);
function renderBanner() {
  const el = $('#banner'); if (!el || window.__DEMO) return;
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
  group: ['Report this group', 'The group, its description and who started it will be shared with our safety team. Use this if a group is labelled open but is really 18+.'],
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
    if (row && !e.target.closest('a,button,details,input,textarea,select,video')) location.hash = row.dataset.href;
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
    } else if (act === 'like') {
      if (!needMe()) return;
      const r = await api(`/posts/${id}/like`, { method: el.classList.contains('on') ? 'DELETE' : 'PUT' });
      el.classList.toggle('on', r.liked); el.textContent = `${r.liked ? 'Liked' : 'Like'}${r.like_count ? ' · ' + r.like_count : ''}`;
    } else if (act === 'repost') { if (needMe()) repostDialog(id);
    } else if (act === 'zoom') {
      const d = document.createElement('dialog'); d.className = 'lightbox';
      d.innerHTML = `<form method="dialog"><img src="${esc(el.dataset.src)}" alt="Photo"><button class="btn ghost small" value="close">Close</button></form>`;
      document.body.appendChild(d); d.addEventListener('close', () => d.remove()); d.showModal();
    } else if (act === 'reveal') { el.closest('.media').classList.remove('blur'); el.remove();
    } else if (act === 'join-group') {
      if (!needMe()) return;
      if (kind === '1' && !(await confirmDialog({ title: 'This is an 18+ group', text: 'It is for 18+ activities and topics. Join anyway?', ok: 'Join group' }))) return;
      await api(`/groups/${id}/join`, { method: 'POST' }); toast('Joined the group'); route();
    } else if (act === 'leave-group') { await api(`/groups/${id}/join`, { method: 'DELETE' }); toast('You left the group'); route();
    } else if (act === 'delete-group') {
      if (await confirmDialog({ title: 'Delete this group?', text: 'This removes the group and all of its posts and photos for everyone. It cannot be undone.', ok: 'Delete group', danger: true })) { await api('/groups/' + id, { method: 'DELETE' }); toast('Group deleted'); location.hash = '#/groups'; }
    } else if (act === 'remove-member') { await api(`/groups/${kind}/members/${id}`, { method: 'DELETE' }); toast('Removed from the group'); route();
    } else if (act === 'group-remove-post') { await api(`/groups/${kind}/posts/${id}`, { method: 'DELETE' }); toast('Post removed'); route();
    } else if (act === 'mature-on') {
      if (await confirmDialog({ title: 'Turn on 18+ groups?', text: 'You will be able to find and join groups for 18+ activities. They stay separate from the rest of Huddle, and you can turn this off any time in Settings.', ok: 'Turn on' })) {
        await api('/me/prefs', { method: 'PUT', body: { show_mature: true } }); me = await api('/me'); toast('18+ groups are on'); route();
      }
    } else if (act === 'mature-off') { await api('/me/prefs', { method: 'PUT', body: { show_mature: false } }); me = await api('/me'); toast('18+ groups are hidden again'); route();
    } else if (act === 'accept-req') { await api(`/requests/${id}/accept`, { method: 'POST' }); toast('Accepted. You can chat now.'); refreshBadge(); route();
    } else if (act === 'decline-req') { await api(`/requests/${id}/decline`, { method: 'POST' }); toast("Declined. They won't be told."); refreshBadge(); route();
    } else if (act === 'unblock') { await api('/blocks/' + id, { method: 'DELETE' }); toast('Unblocked'); route();
    }
  } catch (err) { if (!(err instanceof Stale)) toast(err.message); }
});

/* ---------- layout: left column, centre, right column ---------- */
const leftCol = () => me ? `
  <div class="box profile"><a class="who" href="#/user/${me.id}">${avatar(me, 'lg')}<span><b>${esc(me.name)}</b><small>${esc(me.city)}</small></span></a>
    <div class="stats"><a href="#/user/${me.id}"><b>${me.stats?.posts ?? 0}</b>Posts</a><a href="#/events"><b>${me.stats?.events ?? 0}</b>Events</a><a href="#/join?edit=1"><b>${me.interests.length}</b>Interests</a></div></div>
  <div class="box" id="w-mygroups"><h4>Your groups</h4><div class="loading">Loading…</div></div>
  ${me.interests.length ? `<div class="box"><h4>Your interests</h4><div class="tags">${me.interests.slice(0, 10).map(hashtag).join(' ')}</div><a class="more-link" href="#/join?edit=1">Edit</a></div>` : ''}`
  : `<div class="box"><h4>New to Huddle?</h4><p class="sub" style="margin:6px 0 12px">Meet people near you who share your interests. Free. No password, no email.</p><a class="btn" href="#/join">Join free</a> <a class="btn ghost" href="#/login">Log in</a></div>`;
const rightCol = () => `
  ${me ? '<div class="box" id="w-people"><h4>People you may like</h4><div class="loading">Loading…</div></div>' : ''}
  <div class="box" id="w-groups"><h4>Groups you might like</h4><div class="loading">Loading…</div></div>
  <div class="box" id="w-events"><h4>Happening nearby</h4><div class="loading">Loading…</div></div>
  <div class="box" id="w-trends"><h4>Interests people are posting about</h4><div class="loading">Loading…</div></div>
  <p class="fine">18+ only. See something wrong? Report it from the menu on any post, message or profile.</p>`;
function shell(main, { right = false, solo = false } = {}) {
  if (solo) return `<div class="solo">${main}</div>`;
  setTimeout(fillWidgets, 0);  // fills the sidebar boxes once this markup is on the page
  return `<div class="shell ${right ? 'has-right' : ''}"><aside class="left">${leftCol()}</aside><section class="main">${main}</section>${right ? `<aside class="right">${rightCol()}</aside>` : ''}</div>`;
}

async function fillWidgets() {
  const q = async (id, fn) => { const el = $('#' + id); if (!el) return; try { const html = await fn(); if ($('#' + id)) $('#' + id).innerHTML = html; } catch (e) { if (!(e instanceof Stale)) $('#' + id)?.remove(); } };
  q('w-people', async () => {
    const ms = (await api('/me/matches')).slice(0, 3);
    return `<h4>People you may like</h4>${ms.map(u => `<div class="mini">${avatar(u)}<div class="grow"><a class="nm" href="#/user/${u.id}">${esc(u.name)}</a><small>${u.shared.length ? 'Likes ' + esc(u.shared.slice(0, 2).join(', ')) : esc(u.city)}</small></div>
      ${u.can_message ? `<a class="btn small ghost" href="#/dm/${u.id}">${u.chat === 'accepted' ? 'Chat' : u.chat === 'request_out' ? 'Sent' : 'Message'}</a>` : ''}</div>`).join('') || '<p class="sub">Add interests to see people.</p>'}<a class="more-link" href="#/people">View all</a>`;
  });
  q('w-mygroups', async () => {
    const gs = await api('/groups?scope=mine');
    return `<h4>Your groups</h4>${gs.slice(0, 6).map(g => `<a class="mini grp-mini" href="#/group/${g.id}">${groupAv(g)}<div class="grow"><span class="nm">${esc(g.name)}</span><small>${g.member_count} member${g.member_count === 1 ? '' : 's'}</small></div></a>`).join('') || '<p class="sub">Join a group to see it here.</p>'}<a class="more-link" href="#/groups">${gs.length ? 'All groups' : 'Find groups'}</a>`;
  });
  q('w-groups', async () => {
    const gs = (await api('/groups?scope=discover')).filter(g => !g.joined).slice(0, 3);
    return `<h4>Groups you might like</h4>${gs.map(g => `<div class="mini">${groupAv(g)}<div class="grow"><a class="nm" href="#/group/${g.id}">${esc(g.name)}</a><small>${g.member_count} member${g.member_count === 1 ? '' : 's'}</small></div><button class="btn small ghost" data-act="join-group" data-id="${g.id}" data-kind="0">Join</button></div>`).join('') || '<p class="sub">No suggestions right now.</p>'}<a class="more-link" href="#/groups">Browse groups</a>`;
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

/* ---------- posts: photos, videos, likes, comments, reposts ---------- */
const confirmDialog = ({ title, text, ok = 'Continue', danger = false }) => new Promise(resolve => {
  const d = document.createElement('dialog');
  d.innerHTML = `<form method="dialog"><h3>${esc(title)}</h3><p class="sub">${esc(text)}</p>
    <div class="row" style="margin-top:14px"><button class="btn ghost" value="no">Cancel</button><button class="btn ${danger ? 'danger' : ''}" value="yes">${esc(ok)}</button></div></form>`;
  document.body.appendChild(d);
  d.addEventListener('close', () => { resolve(d.returnValue === 'yes'); d.remove(); });
  d.showModal();
});

async function uploadMedia(file) {
  const fd = new FormData(); fd.append('file', file);
  let r;
  try { r = await fetch('/api/media', { method: 'POST', headers: { Authorization: 'Bearer ' + token() }, body: fd }); }
  catch { throw new Error("Can't reach the Huddle server. Check your connection and try again."); }
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : 'That upload did not work'); }
  return r.json();
}

const mediaGrid = (media, blur = false) => !media.length ? '' : `<div class="media n${media.length} ${blur ? 'blur' : ''}">${media.map(m => m.kind === 'video'
  ? `<video src="${esc(m.url)}" controls preload="metadata" playsinline></video>`
  : `<button type="button" class="mimg" data-act="zoom" data-src="${esc(m.url)}" aria-label="View photo"><img src="${esc(m.url)}" alt="Photo" loading="lazy"></button>`).join('')}
  ${blur ? '<button type="button" class="reveal" data-act="reveal">Tap to show</button>' : ''}</div>`;

const likeLabel = p => `${p.liked ? 'Liked' : 'Like'}${p.like_count ? ' · ' + p.like_count : ''}`;
const postActs = p => `<div class="acts">
  <button type="button" class="act ${p.liked ? 'on' : ''}" data-act="like" data-id="${p.id}">${likeLabel(p)}</button>
  <a class="act" href="#/post/${p.id}">Comment${p.reply_count ? ' · ' + p.reply_count : ''}</a>
  ${p.group?.mature ? '' : `<button type="button" class="act ${p.reposted ? 'on' : ''}" data-act="repost" data-id="${p.id}" ${p.reposted || p.mine ? 'disabled' : ''}>${p.reposted ? 'Reposted' : 'Repost'}${p.repost_count ? ' · ' + p.repost_count : ''}</button>`}
</div>`;

const pill18 = '<span class="pill18" title="For 18+ activities">18+</span>';
const embedPost = o => `<div class="embed" data-href="#/post/${o.id}"><div class="head"><span><a class="nm" href="#/user/${o.author.id}">${esc(o.author.name)}</a> <small>${esc(o.city)} &middot; ${ago(o.created)}</small></span></div>
  ${o.body ? `<div class="txt">${esc(o.body)}</div>` : ''}${mediaGrid(o.media)}${hashtags(o.tags)}</div>`;

const postRow = (p, full = false, ownerOfGroup = null) => `
<article class="tw" ${full ? '' : `data-href="#/post/${p.id}"`}>
  <a href="#/user/${p.author.id}">${avatar(p.author, 'lg')}</a>
  <div class="body">
    <div class="head"><span><a class="nm" href="#/user/${p.author.id}">${esc(p.author.name)}</a> <small>${esc(p.city)} &middot; ${ago(p.created)}${p.repost ? ' &middot; reposted' : ''}</small>
      ${p.group ? `<small>in <a href="#/group/${p.group.id}">${esc(p.group.name)}</a></small> ${p.group.mature ? pill18 : ''}` : ''}</span>
    ${me ? moreMenu(p.mine ? [{ act: 'del-post', id: p.id, label: 'Delete post', danger: true }] : [
      { act: 'report', kind: 'post', id: p.id, label: 'Report post' },
      ...(ownerOfGroup ? [{ act: 'group-remove-post', id: p.id, kind: ownerOfGroup, label: 'Remove from group', danger: true }] : []),
      { act: 'block', id: p.author.id, name: p.author.name, label: `Block ${esc(p.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
    ${p.body ? `<div class="txt">${esc(p.body)}</div>` : ''}
    ${p.url ? `<a class="ext" href="${esc(p.url)}" target="_blank" rel="nofollow noopener noreferrer ugc">${esc(host(p.url))} &#8599;</a>` : ''}
    ${p.repost ? embedPost(p.repost) : ''}
    ${mediaGrid(p.media, !!p.group?.mature)}
    ${hashtags(p.tags)}
    ${postActs(p)}
  </div>
</article>`;

function composer({ placeholder = 'Share something with people nearby…', groupId = null, groups = [] } = {}) {
  return `<div class="box compose">${avatar(me, 'lg')}<div class="grow"><textarea id="pb" rows="2" maxlength="500" placeholder="${esc(placeholder)}"></textarea>
    <div id="pv" class="previews"></div>
    <input id="pu" class="hidden" placeholder="Paste a link (https://…)" maxlength="300">
    ${!groupId && me.interests.length ? `<div class="tags" id="pt"><small>Tag:</small> ${me.interests.slice(0, 8).map(t => `<button type="button" class="hash opt" data-t="${esc(t)}">#${esc(t.replace(/\s+/g, ''))}</button>`).join(' ')}</div>` : ''}
    <div class="row between wrapx" style="margin-top:8px"><span class="row" style="align-items:center;flex-wrap:wrap"><button class="linkbtn" id="addphoto" type="button">Photo or video</button><button class="linkbtn" id="addlink" type="button">Add a link</button>
      ${!groupId && groups.length ? `<select id="pg" class="mini-select" aria-label="Post to"><option value="">Post to everyone</option>${groups.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join('')}</select>` : ''}</span>
      <span class="row" style="align-items:center"><span class="counter" id="cnt">500</span><button class="btn" id="post">Post</button></span></div>
    <input type="file" id="pf" accept="image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm" multiple hidden></div></div>`;
}

function wireComposer({ groupId = null, onPosted }) {
  const sel = new Set(); const items = [];  // items: { id, kind, url, busy }
  const draw = () => {
    $('#pv').innerHTML = items.map((it, i) => `<span class="pv">${it.kind === 'video' ? `<video src="${it.url}#t=0.1" muted preload="metadata"></video>` : `<img src="${it.url}" alt="">`}${it.busy ? '<i>Uploading…</i>' : ''}<button type="button" data-i="${i}" aria-label="Remove">&times;</button></span>`).join('');
    document.querySelectorAll('#pv button').forEach(b => b.onclick = () => { const [it] = items.splice(+b.dataset.i, 1); draw(); if (it.id) api('/media/' + it.id, { method: 'DELETE' }).catch(() => {}); });
  };
  $('#addphoto').onclick = () => $('#pf').click();
  $('#addlink').onclick = () => { $('#pu').classList.toggle('hidden'); $('#pu').focus(); };
  $('#pb').oninput = () => { const n = 500 - $('#pb').value.length; $('#cnt').textContent = n; $('#cnt').classList.toggle('low', n < 40); };
  document.querySelectorAll('#pt [data-t]').forEach(b => b.onclick = () => { const t = b.dataset.t; if (sel.has(t)) sel.delete(t); else if (sel.size < 3) sel.add(t); b.classList.toggle('on', sel.has(t)); });
  $('#pf').onchange = async ev => {
    for (const f of [...ev.target.files]) {
      const video = f.type.startsWith('video/');
      if (video ? f.size > 40e6 : f.size > 8e6) { toast(video ? 'Videos can be up to 40 MB' : 'Photos can be up to 8 MB'); continue; }
      if (items.length >= 4 || items.some(i => i.kind === 'video') || (video && items.length)) { toast('Add up to 4 photos, or 1 video'); continue; }
      const it = { kind: video ? 'video' : 'image', url: URL.createObjectURL(f), busy: true }; items.push(it); draw();
      try { it.id = (await uploadMedia(f)).id; } catch (e) { items.splice(items.indexOf(it), 1); toast(e.message); }
      it.busy = false; draw();
    }
    ev.target.value = '';
  };
  $('#post').onclick = async () => {
    if (items.some(i => i.busy)) return toast('Still uploading…');
    const body = $('#pb').value.trim();
    if (!body && !items.length) return toast('Write something or add a photo first');
    try {
      await api('/posts', { method: 'POST', body: { body, url: $('#pu').value, tags: [...sel], group_id: groupId || (+$('#pg')?.value || null), media: items.map(i => i.id) } });
      toast('Posted'); me = await api('/me'); onPosted();
    } catch (err) { toast(err.message); }
  };
}

function repostDialog(id) {
  const d = document.createElement('dialog');
  d.innerHTML = `<form method="dialog"><h3>Repost to your profile</h3><p class="sub">Share this with the people who follow what you post. You can add a comment.</p>
    <textarea id="rpc" rows="2" maxlength="300" placeholder="Add a comment (optional)"></textarea>
    <div class="row" style="margin-top:14px"><button class="btn ghost" value="no">Cancel</button><button class="btn" id="rpgo" value="yes">Repost</button></div></form>`;
  document.body.appendChild(d); d.addEventListener('close', () => d.remove()); d.showModal();
  d.querySelector('#rpgo').onclick = async ev => {
    ev.preventDefault();
    try { await api(`/posts/${id}/repost`, { method: 'POST', body: { body: d.querySelector('#rpc').value } }); toast('Reposted to your profile'); d.close(); route(); }
    catch (err) { toast(err.message); d.close(); }
  };
}

async function home() {
  if (!feedScope) feedScope = me ? 'foryou' : 'all';
  const myGroups = me ? await api('/groups?scope=mine').catch(() => []) : [];
  const compose = me ? composer({ groups: myGroups })
    : `<div class="box intro"><h2>See what's happening near you.</h2><p>Huddle is a place to share photos, news and interests, join groups, find events, and meet people nearby who like the same things.</p><a class="btn" href="#/join">Join free</a> <span class="sub">or just look around below.</span></div>`;
  const tabs = [['foryou', 'For you'], ['near', 'Near me'], ['all', 'Everyone']].filter(([k]) => me || k === 'all');
  app.innerHTML = shell(`${compose}
    <div class="box"><div class="tabs">${tabs.map(([k, l]) => `<a href="#/" class="${feedScope === k ? 'on' : ''}" data-s="${k}">${l}</a>`).join('')}</div>
    ${feedTag ? `<div class="filterbar">Showing posts tagged <b>#${esc(feedTag.replace(/\s+/g, ''))}</b> <button class="linkbtn" id="cleartag">Clear</button></div>` : ''}
    <div id="posts" class="list">${loading}</div></div>`, { right: true });
  document.querySelectorAll('.tabs a').forEach(a => a.onclick = ev => { ev.preventDefault(); feedScope = a.dataset.s; home(); });
  $('#cleartag')?.addEventListener('click', () => { feedTag = ''; home(); });
  if (me) wireComposer({ onPosted: home });
  const posts = await api(`/posts?scope=${feedScope}&tag=${encodeURIComponent(feedTag)}`);
  $('#posts').innerHTML = posts.map(p => postRow(p)).join('') || `<div class="empty">Nothing here yet. ${feedScope === 'near' ? 'Try “Everyone”, or ' : ''}be the first to share something.</div>`;
}

async function postPage(id) {
  const p = await api('/posts/' + id);
  app.innerHTML = shell(`<p class="back"><a href="#/">&larr; Home</a></p><div class="box flush">${postRow(p, true)}</div>
  <div class="box"><div class="boxhead"><h3>${p.replies.length ? `Comments (${p.replies.length})` : 'No comments yet'}</h3></div>
  <div class="list">${p.replies.map(r => `<article class="tw"><a href="#/user/${r.author.id}">${avatar(r.author, 'lg')}</a><div class="body"><div class="head"><span><a class="nm" href="#/user/${r.author.id}">${esc(r.author.name)}</a> <small>${ago(r.created)}</small></span>
    ${me ? moreMenu(r.mine ? [{ act: 'del-reply', id: r.id, label: 'Delete', danger: true }] : [{ act: 'report', kind: 'reply', id: r.id, label: 'Report comment' }, { act: 'block', id: r.author.id, name: r.author.name, label: `Block ${esc(r.author.name.split(' ')[0])}`, danger: true }]) : ''}</div>
    <div class="txt">${esc(r.body)}</div></div></article>`).join('')}</div>
  ${me ? `<div class="replybar row"><input id="rb" maxlength="500" placeholder="Write a comment"><button class="btn" id="rs">Comment</button></div>` : '<div class="replybar"><a href="#/join" class="btn">Join free</a> <span class="sub">to comment.</span></div>'}</div>`);
  if (me) {
    const send = async () => { const b = $('#rb').value.trim(); if (!b) return; try { await api(`/posts/${id}/replies`, { method: 'POST', body: { body: b } }); postPage(id); } catch (err) { toast(err.message); } };
    $('#rs').onclick = send; $('#rb').onkeydown = k => k.key === 'Enter' && send();
  }
}

/* ---------- groups, including the separate 18+ side ---------- */
let groupTab = null;
const groupAv = g => `<span class="gav" style="background:${colors[g.id % colors.length]}">${esc(g.name.trim()[0].toUpperCase())}</span>`;
const groupRow = g => `<div class="row-item grp" data-href="#/group/${g.id}">${groupAv(g)}<div class="grow"><a class="nm" href="#/group/${g.id}">${esc(g.name)}</a> ${g.mature ? pill18 : ''}
    <small style="display:block">${g.member_count} member${g.member_count === 1 ? '' : 's'}${g.city ? ' &middot; ' + esc(g.city) : ''}</small>
    ${g.description ? `<div class="sub clip">${esc(g.description)}</div>` : ''}${g.tags.length ? `<div class="tags">${plainTags(g.tags)}</div>` : ''}</div>
  ${g.joined ? `<a class="btn small ghost" href="#/group/${g.id}">Joined</a>` : `<button class="btn small" data-act="join-group" data-id="${g.id}" data-kind="${g.mature ? 1 : 0}">Join</button>`}</div>`;

async function groups() {
  if (!groupTab || (groupTab === 'mine' && !me) || (groupTab === 'mature' && !me?.show_mature)) groupTab = me ? 'mine' : 'discover';
  const tabs = [...(me ? [['mine', 'Your groups']] : []), ['discover', 'Discover'], ...(me?.show_mature ? [['mature', '18+ side']] : [])];
  app.innerHTML = shell(`<div class="box"><div class="boxhead"><h2>Groups</h2><a class="btn small" href="#/groups/new">Create a group</a></div>
    <div class="tabs flat">${tabs.map(([k, l]) => `<a href="#/groups" class="${groupTab === k ? 'on' : ''}" data-t="${k}">${l}</a>`).join('')}</div>
    ${groupTab === 'mature' ? '<div class="starter dark">You are on the 18+ side. These groups are hidden from everyone who has not turned this on.</div>' : ''}
    <div class="filters"><input id="gq" placeholder="Search groups" aria-label="Search groups"></div><div id="glist" class="list">${loading}</div></div>
    ${me && !me.show_mature ? '<div class="box"><small>Looking for 18+ groups? They are kept on a separate side of Huddle that is off by default. <a href="#/settings">Turn it on in Settings</a>.</small></div>' : ''}`);
  document.querySelectorAll('.tabs a').forEach(a => a.onclick = ev => { ev.preventDefault(); groupTab = a.dataset.t; groups(); });
  const run = async () => {
    const list = await api(`/groups?scope=${groupTab}&q=${encodeURIComponent($('#gq').value)}`);
    $('#glist').innerHTML = list.map(groupRow).join('') || `<div class="empty">${groupTab === 'mine' ? 'You have not joined any groups yet. Try <a href="#/groups" id="goDiscover">Discover</a> or start your own.' : 'No groups match.'}</div>`;
    $('#goDiscover')?.addEventListener('click', ev => { ev.preventDefault(); groupTab = 'discover'; groups(); });
  };
  let t; $('#gq').oninput = () => { clearTimeout(t); t = setTimeout(run, 250); };
  await run();
}

function createGroup() {
  if (!needMe()) return;
  app.innerHTML = shell(`<div class="box form"><h2>Create a group</h2>
    <label>Group name</label><input id="gn" maxlength="60" placeholder="Austin Trail Runners">
    <label>What is it about?</label><textarea id="gd" rows="3" maxlength="500" placeholder="Who is it for and what will members do together?"></textarea>
    <label>City <small>(optional)</small></label><input id="gc" value="${esc(me.city)}">
    <label>Topics <small>(comma separated)</small></label><input id="gt" placeholder="Running, Hiking">
    <fieldset class="ask"><legend>Is this an 18+ activities group?</legend>
      <label class="choice"><input type="radio" name="mature" value="0"><span><b>No. Anyone on Huddle can join.</b><small>It appears in the group directory, in search and in the main feed.</small></span></label>
      <label class="choice"><input type="radio" name="mature" value="1"><span><b>Yes. It is for 18+ activities.</b><small>For adult topics such as nightlife or drinking. It is kept on a separate side of Huddle, out of the main feed, search and directory, and only people who turned on 18+ groups can find it.</small></span></label>
      <p class="sub">Sexually explicit content is not allowed anywhere on Huddle, including 18+ groups.</p></fieldset>
    <p><button class="btn big" id="gcreate" disabled>Create group</button></p></div>`);
  document.querySelectorAll('input[name=mature]').forEach(r => r.onchange = () => { $('#gcreate').disabled = false; });
  $('#gcreate').onclick = async () => {
    const mature = document.querySelector('input[name=mature]:checked')?.value === '1';
    if (mature && !me.show_mature) {
      if (!(await confirmDialog({ title: 'Turn on 18+ groups?', text: 'To create an 18+ group you need the 18+ side switched on for your account. These groups stay separate from the rest of Huddle, and you can turn this off any time in Settings.', ok: 'Turn on and continue' }))) return;
      await api('/me/prefs', { method: 'PUT', body: { show_mature: true } }); me = await api('/me');
    }
    try {
      const r = await api('/groups', { method: 'POST', body: { name: $('#gn').value, description: $('#gd').value, city: $('#gc').value, tags: $('#gt').value.split(',').map(x => x.trim()).filter(Boolean), mature } });
      toast('Group created'); location.hash = '#/group/' + r.id;
    } catch (e) { toast(/at least 3|short|string_too/i.test(e.message) ? 'Please give the group a name of at least 3 letters' : e.message); }
  };
}

async function groupPage(id) {
  let g;
  try { g = await api('/groups/' + id); }
  catch (e) {
    if (e.message !== 'mature_hidden') throw e;
    app.innerHTML = shell(`<p class="back"><a href="#/groups">&larr; Groups</a></p><div class="box gate"><h2>This group is for 18+ activities</h2>
      <p>18+ groups are kept on a separate side of Huddle that is off by default.</p>
      ${me ? '<p><button class="btn" data-act="mature-on">Turn on 18+ groups</button></p>' : '<p><a class="btn" href="#/join">Join free</a> <a class="btn ghost" href="#/login">Log in</a></p>'}</div>`);
    return;
  }
  const posts = await api(`/groups/${id}/posts`);
  const owner = g.role === 'owner';
  app.innerHTML = shell(`<p class="back"><a href="#/groups">&larr; Groups</a></p>
  <div class="box pbox"><div class="gbanner ${g.mature ? 'dark' : ''}"></div><div class="ghead">${groupAv(g)}<div class="grow"><h2>${esc(g.name)} ${g.mature ? pill18 : ''}</h2><div class="sub">${g.member_count} member${g.member_count === 1 ? '' : 's'}${g.city ? ' &middot; ' + esc(g.city) : ''} &middot; started by <a href="#/user/${g.owner.id}">${esc(g.owner.name)}</a></div></div>
    <div class="row" style="align-items:center">${g.joined ? (owner ? '' : '<button class="btn ghost" data-act="leave-group" data-id="' + g.id + '">Leave</button>') : `<button class="btn" data-act="join-group" data-id="${g.id}" data-kind="${g.mature ? 1 : 0}">Join group</button>`}
    ${me ? moreMenu([{ act: 'report', kind: 'group', id: g.id, label: 'Report group' }, ...(owner ? [{ act: 'delete-group', id: g.id, label: 'Delete group', danger: true }] : [])]) : ''}</div></div>
    <div class="pinfo">${g.description ? `<p>${esc(g.description)}</p>` : ''}<div class="tags">${plainTags(g.tags)}</div>
    ${g.mature ? '<p class="sub">An 18+ group. Not shown in the main feed or on profiles. Sexually explicit content is not allowed.</p>' : ''}</div></div>
  ${g.joined ? composer({ placeholder: `Share something with ${g.name}…`, groupId: g.id }) : ''}
  <div class="box"><div class="boxhead"><h3>Posts</h3></div><div id="gposts" class="list">${posts.map(p => postRow(p, false, owner ? g.id : null)).join('') || '<div class="empty">No posts yet. ' + (g.joined ? 'Start the conversation.' : 'Join to post.') + '</div>'}</div></div>
  <div class="box"><div class="boxhead"><h3>Members</h3></div><div class="list">${g.members.map(m => `<div class="row-item">${avatar(m, 'lg')}<div class="grow"><a class="nm" href="#/user/${m.id}">${esc(m.name)}</a> ${m.id === g.owner.id ? '<span class="tag">Owner</span>' : ''}<div class="sub">${esc(m.city)}</div></div>
    ${owner && m.id !== me.id ? moreMenu([{ act: 'remove-member', id: m.id, kind: g.id, label: 'Remove from group', danger: true }]) : ''}</div>`).join('')}</div></div>`);
  if (g.joined) wireComposer({ groupId: g.id, onPosted: () => groupPage(id) });
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
  ${posts.some(p => p.media.length) ? `<div class="box"><div class="boxhead"><h3>Photos &amp; videos</h3></div><div class="mgrid">${posts.flatMap(p => p.media.map(m => ({ m, pid: p.id }))).slice(0, 9).map(({ m, pid }) => `<a href="#/post/${pid}">${m.kind === 'video' ? `<video src="${esc(m.url)}#t=0.1" muted preload="metadata"></video>` : `<img src="${esc(m.url)}" alt="Photo" loading="lazy">`}</a>`).join('')}</div></div>` : ''}
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
  <div class="setting"><div><b>18+ groups: ${me.show_mature ? 'on' : 'off'}</b><div class="sub">Groups for 18+ activities are kept on a separate side of Huddle and stay hidden unless you turn this on. Sexually explicit content is not allowed anywhere on Huddle.</div></div><button class="btn small ${me.show_mature ? 'ghost' : ''}" data-act="${me.show_mature ? 'mature-off' : 'mature-on'}">${me.show_mature ? 'Turn off' : 'Turn on'}</button></div>
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
  [/^#\/groups\/new/, createGroup], [/^#\/groups/, groups], [/^#\/group\/(\d+)/, groupPage],
  [/^#\/people/, people], [/^#\/join/, join], [/^#\/login/, login], [/^#\/settings/, settings], [/^#\/create/, create], [/^#\/inbox/, inbox],
];
async function route() {
  const h = location.hash || '#/';
  const seq = ++routeSeq;
  timers.forEach(clearInterval); timers = [];
  const group = /^#\/groups?(\/|$)/.test(h) ? '#/groups' : /^#\/(events?|create)/.test(h) ? '#/events' : /^#\/(inbox|dm)/.test(h) ? '#/inbox' : /^#\/people/.test(h) ? '#/people' : /^#\/(user|join|login|settings)/.test(h) ? '' : '#/';
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === group));
  window.scrollTo({ top: 0 });
  if (me) { try { me = await api('/me'); } catch {} }  // keep profile-card counts fresh
  if (seq !== routeSeq) return;  // you already clicked somewhere else
  const fail = e => { if (!(e instanceof Stale)) app.innerHTML = shell(`<div class="empty">${esc(e.message)}</div>`); };
  for (const [re, fn] of routes) { const m = h.match(re); if (m) return Promise.resolve().then(() => fn(m[1])).catch(fail); }
  return home().catch(fail);
}
addEventListener('hashchange', route);
$('#search').addEventListener('submit', e => { e.preventDefault(); searchQ = $('#search input').value.trim(); location.hash === '#/events' ? route() : (location.hash = '#/events'); });
(async () => {
  try { meta = await api('/meta'); }
  catch {
    const asFile = location.protocol === 'file:';
    app.innerHTML = `<div class="solo"><div class="box form"><h2>Can't connect to the Huddle server</h2>
      <p>${asFile ? 'This page was opened as a file, but Huddle needs its server running to sign you in and load events.' : 'The Huddle server isn\'t responding right now.'}</p>
      <p class="sub">${asFile ? 'Start the server (<code>uvicorn server:app</code> in the <code>meetup</code> folder), then open <code>http://localhost:8000</code> in your browser.' : 'Check your connection, then try again.'}</p>
      <p><button class="btn" id="retry">Try again</button></p></div></div>`;
    $('#retry').onclick = () => location.reload();
    return;
  }
  await loadMe(); route();
})();
