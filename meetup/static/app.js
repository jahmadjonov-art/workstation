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
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `huddle-account-${me.name.split(' ')[0].toLowerCase()}.json`; a.click();
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
const toast = m => { const t = $('#toast'); t.textContent = m; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2600); };
const colors = ['#ff5a4e', '#0f9d8a', '#7c5cff', '#e6a100', '#2b7de9', '#d6409f'];
const avatar = (u, cls = '') => `<span class="avatar ${cls}" style="background:${colors[u.id % colors.length]}" title="${esc(u.name)}">${esc(u.name.trim()[0] || '?').toUpperCase()}</span>`;
const fmt = iso => new Date(iso).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const chips = (xs, cls = '') => xs.map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join('');

async function loadMe() {
  me = null;
  if (token()) { try { me = await api('/me'); } catch (e) { if (/sign in|suspended/.test(e.message)) store.del('huddle_token'); } }
  $('#me').innerHTML = me
    ? `<span class="meprof">${avatar(me)}<a href="#/user/${me.id}">${esc(me.name.split(' ')[0])}</a><button class="btn ghost" id="out">Sign out</button></span>`
    : `<a class="btn" href="#/join">Join</a>`;
  if (me) $('#out').onclick = async () => {
    if (!confirm('Sign out? Keep your account file: it is the only way back in and the only way to read your messages.')) return;
    store.del('huddle_token'); await loadMe(); location.hash = '#/';
  };
}
const needMe = () => { if (!me) { toast('Create a profile first'); location.hash = '#/join'; return false; } return true; };

/* ---------- views ---------- */
async function home() {
  app.innerHTML = `
  <div class="hero"><h1>Find your people, not just an event.</h1>
  <p>Huddle shows you who's going, what you have in common, and gives everyone an easy way to say hello. Open to everyone, solo newcomers especially.</p></div>
  <div class="filters">
    <input id="q" placeholder="Search events, interests, places">
    <select id="cat"><option value="">All categories</option>${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
    <input id="city" placeholder="City">
    ${me ? `<select id="sort"><option value="match">Best for me</option><option value="soon">Soonest</option></select>` : ''}
  </div>
  <div id="list" class="grid"></div>`;
  const run = async () => {
    const p = new URLSearchParams({ q: $('#q').value, category: $('#cat').value, city: $('#city').value, sort: $('#sort')?.value || 'soon' });
    const evs = await api('/events?' + p);
    $('#list').innerHTML = evs.length ? evs.map(eventCard).join('') : '<div class="empty" style="grid-column:1/-1">No events match. Try fewer filters, or <a href="#/create">host one</a>.</div>';
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
    <button class="btn" id="rsvp" ${full ? 'disabled' : ''}>${e.going ? 'Going, tap to cancel' : full ? 'Event is full' : 'Count me in'}</button>
    ${me && me.id !== e.host.id ? '<button class="linkbtn" id="rep-event">Report this event</button>' : ''}
    <h2>Conversation</h2>
    <p class="muted" style="margin-top:-6px"><small>Event chats are public to attendees and reviewed by our safety team. For private conversations, use end-to-end encrypted messages.</small></p>
    <div class="panel">
      ${e.messages.map(m => `<div class="msg"><b><a href="#/user/${m.user.id}">${esc(m.user.name)}</a></b>${me && me.id !== m.user.id ? ` <button class="linkbtn rep-msg" data-id="${m.id}">Report</button>` : ''}<br>${esc(m.body)}</div>`).join('') || '<div class="muted">Nobody has said anything yet. Break the ice!</div>'}
      ${e.going ? `<div class="row" style="margin-top:12px"><input id="msg" maxlength="1000" placeholder="Say hi to the group"><button class="btn" id="send">Send</button></div>
      <p class="muted" style="margin:12px 0 4px">Need a starter? Tap one:</p>${e.icebreakers.map(i => `<button class="ice">${esc(i)}</button>`).join('')}`
      : '<p class="muted" style="margin-top:12px">RSVP to join the conversation.</p>'}
    </div>
  </div>
  <aside><div class="panel"><h3>Who's going (${e.attendee_count}/${e.capacity})</h3>
    ${e.attendees.map(a => `<div class="person">${avatar(a)}<div class="info"><a class="name" href="#/user/${a.id}">${esc(a.name)}</a> <small>${esc(a.pronouns)}</small>
      ${a.shared?.length ? `<div class="chips" style="margin-top:4px">${chips(a.shared)}</div><small>in common with you</small>` : `<div class="muted" style="font-size:.85rem">${esc(a.interests.slice(0, 3).join(', '))}</div>`}</div></div>`).join('')}
  </div></aside></div>`;
  const guard = fn => async (...a) => { try { await fn(...a); } catch (err) { toast(err.message); } };
  $('#rsvp').onclick = guard(async () => {
    if (!needMe()) return;
    if (e.going) await api(`/events/${id}/rsvp`, { method: 'DELETE' });
    else { await api(`/events/${id}/rsvp`, { method: 'POST' }); toast("You're in! Say hi in the conversation."); }
    eventPage(id);
  });
  $('#rep-event')?.addEventListener('click', () => reportDialog({ title: 'Report this event', note: 'Tell us what is wrong. Reports are reviewed by our safety team.', onSubmit: (reason, details) => api('/reports', { method: 'POST', body: { kind: 'event', target_id: +id, reason, details } }) }));
  document.querySelectorAll('.rep-msg').forEach(b => b.onclick = () => reportDialog({ title: 'Report this message', note: 'The message and who sent it will be shared with our safety team.', onSubmit: (reason, details) => api('/reports', { method: 'POST', body: { kind: 'event_message', target_id: +b.dataset.id, reason, details } }) }));
  if (e.going) {
    const send = guard(async () => { const b = $('#msg').value.trim(); if (!b) return; await api(`/events/${id}/messages`, { method: 'POST', body: { body: b } }); eventPage(id); });
    $('#send').onclick = send; $('#msg').onkeydown = k => k.key === 'Enter' && send();
    document.querySelectorAll('.ice').forEach(b => b.onclick = () => { $('#msg').value = b.textContent; $('#msg').focus(); });
  }
}

async function people() {
  if (!needMe()) return;
  const list = await api('/me/matches');
  app.innerHTML = `<h1>People you may click with</h1><p class="muted">Ranked by shared interests, what you're each looking for, and events in common.</p>
  <div class="grid">${list.map(u => `<a class="card" href="#/user/${u.id}"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><h3>${esc(u.name)}</h3><small>${esc(u.city)} ${esc(u.pronouns)}</small></div></div>
    <div class="chips">${chips(u.shared)}</div>
    ${u.shared_goals.length ? `<small>Both looking for: ${esc(u.shared_goals.join(', '))}</small>` : ''}
    ${u.events_in_common ? `<small>${u.events_in_common} event${u.events_in_common > 1 ? 's' : ''} in common</small>` : ''}</a>`).join('') || '<div class="empty">Add some interests to your profile to see matches.</div>'}</div>`;
}

async function userPage(id) {
  const u = await api(`/users/${id}`);
  const mine = me && me.id === u.id;
  app.innerHTML = `<div class="panel"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><h1 style="margin:0">${esc(u.name)}</h1><span class="muted">${esc(u.city)} ${u.pronouns ? '· ' + esc(u.pronouns) : ''}</span></div></div>
  <p>${esc(u.bio) || '<span class="muted">No bio yet.</span>'}</p>
  <div class="chips">${chips(u.interests, '')}</div>
  ${u.looking_for.length ? `<p class="muted">Looking for: ${esc(u.looking_for.join(', '))}</p>` : ''}
  ${u.shared?.length ? `<div class="match">You both like: ${esc(u.shared.join(', '))}</div>` : ''}
  ${u.shared_events?.length ? `<p class="muted">You're both going to: ${esc(u.shared_events.join(', '))}</p>` : ''}
  <p>${mine ? '<a class="btn ghost" href="#/join?edit=1">Edit profile</a>'
    : u.public_key ? `<a class="btn" href="#/dm/${u.id}">Send an encrypted message</a>` : '<span class="muted">Sample profile (no messaging)</span>'}
  ${me && !mine ? `<button class="linkbtn" id="blk">${u.blocked ? 'Unblock' : 'Block'}</button><button class="linkbtn" id="rep">Report</button>` : ''}</p></div>
  <h2>Upcoming events</h2><div class="panel">${u.events.map(e => `<div class="msg"><a href="#/event/${e.id}">${esc(e.title)}</a> <small>${fmt(e.starts)}</small></div>`).join('') || '<span class="muted">Nothing yet.</span>'}</div>`;
  $('#blk')?.addEventListener('click', async () => { try { await api('/blocks/' + id, { method: u.blocked ? 'DELETE' : 'PUT' }); toast(u.blocked ? 'Unblocked' : 'Blocked. They can no longer message you.'); userPage(id); } catch (e) { toast(e.message); } });
  $('#rep')?.addEventListener('click', () => reportDialog({ title: `Report ${u.name}`, note: 'Their profile will be shared with our safety team. Your private messages are NOT shared unless you report a conversation.', onSubmit: (reason, details) => api('/reports', { method: 'POST', body: { kind: 'user', target_id: +id, reason, details } }) }));
}

async function join() {
  if (me && !location.hash.includes('edit=1')) { location.hash = '#/'; return; }
  const editing = location.hash.includes('edit=1') && me;
  const tags = editing ? [...me.interests] : [];
  const lf = new Set(editing ? me.looking_for : []);
  app.innerHTML = `<h1>${editing ? 'Edit your profile' : 'Join Huddle'}</h1><div class="cols"><div class="panel">
  ${editing ? '' : '<p class="muted" style="margin-top:0">No password, no email. Takes about a minute. Huddle is for adults 18+.</p>'}
  <label>Name</label><input id="n" maxlength="60" value="${esc(editing ? me.name : '')}">
  <label>City</label><input id="c" value="${esc(editing ? me.city : 'Austin')}">
  ${editing ? '' : '<label>Date of birth <small>(only used to confirm you are 18+, never stored)</small></label><input id="dob" type="date">'}
  <div class="hp" aria-hidden="true"><label>Website</label><input id="hp" tabindex="-1" autocomplete="off"></div>
  <label>Pronouns <small>(optional)</small></label><input id="p" placeholder="she/her, he/him, they/them, anything" value="${esc(editing ? me.pronouns : '')}">
  <label>Short bio</label><textarea id="b" rows="3" maxlength="400">${esc(editing ? me.bio : '')}</textarea>
  <label>Interests <small>(type and press Enter)</small></label><input id="i" placeholder="Hiking, Python, Board games..."><div class="chips" id="tags" style="margin-top:8px"></div>
  <label>I'm looking for</label><div class="chips" id="lf">${meta.looking_for.map(x => `<button type="button" class="chip ${lf.has(x) ? 'sel' : ''}" data-v="${esc(x)}">${esc(x)}</button>`).join('')}</div>
  <p><button class="btn" id="save">${editing ? 'Save' : 'Create profile'}</button> <span class="muted" id="status"></span></p></div>
  ${editing ? '' : `<div class="panel"><h3>Already have an account?</h3><p class="muted">Restore it from your account file. It holds your login and your private encryption key.</p>
    <input type="file" id="restore" accept="application/json"></div>`}</div>`;
  const drawTags = () => { $('#tags').innerHTML = tags.map((t, k) => `<button type="button" class="chip" data-k="${k}">${esc(t)} ×</button>`).join(''); document.querySelectorAll('#tags .chip').forEach(b => b.onclick = () => { tags.splice(+b.dataset.k, 1); drawTags(); }); };
  drawTags();
  $('#i').onkeydown = k => { if (k.key === 'Enter' || k.key === ',') { k.preventDefault(); const v = $('#i').value.trim(); if (v && !tags.some(t => t.toLowerCase() === v.toLowerCase())) tags.push(v); $('#i').value = ''; drawTags(); } };
  document.querySelectorAll('#lf .chip').forEach(b => b.onclick = () => { lf.has(b.dataset.v) ? lf.delete(b.dataset.v) : lf.add(b.dataset.v); b.classList.toggle('sel'); });
  $('#restore')?.addEventListener('change', async ev => {
    try {
      const f = JSON.parse(await ev.target.files[0].text());
      if (!f.huddle || !f.token || !f.user_id) throw new Error();
      store.set('huddle_token', f.token); if (f.private_key) store.set('huddle_priv_' + f.user_id, JSON.stringify(f.private_key));
      await loadMe(); if (!me) throw new Error(); toast('Welcome back, ' + me.name.split(' ')[0]); location.hash = '#/';
    } catch { store.del('huddle_token'); toast('That is not a valid account file'); }
  });
  $('#save').onclick = async () => {
    const pending = $('#i').value.trim(); if (pending) tags.push(pending);
    const profile = { name: $('#n').value, city: $('#c').value, pronouns: $('#p').value, bio: $('#b').value, interests: tags, looking_for: [...lf] };
    const status = t => $('#status').textContent = t;
    try {
      if (editing) { await api('/me', { method: 'PUT', body: profile }); await loadMe(); toast('Profile saved'); location.hash = '#/user/' + me.id; return; }
      if (!$('#dob').value) { toast('Please enter your date of birth'); return; }
      $('#save').disabled = true;
      status('Creating your private encryption keys…');
      const keys = await genKeys();
      status('Quick check that you are human…');
      const ch = await api('/pow');
      const counter = await solvePow(ch.challenge, ch.bits, i => status(`Quick check that you are human… ${Math.min(99, Math.round(i / 2 ** ch.bits * 100))}%`));
      const r = await api('/signup', { method: 'POST', body: { ...profile, birth_date: $('#dob').value, website: $('#hp').value, public_key: pubOnly(keys.pub), pow: { challenge: ch.challenge, counter } } });
      store.set('huddle_token', r.token); store.set('huddle_priv_' + r.user.id, JSON.stringify(keys.priv));
      await loadMe(); saveKeyPage();
    } catch (e) { $('#save').disabled = false; status(''); toast(e.message || 'Please check your details'); }
  };
}

function saveKeyPage() {
  app.innerHTML = `<div class="panel" style="max-width:560px;margin:20px auto"><h1>You're in, ${esc(me.name.split(' ')[0])}! 🎉</h1>
  <p>Your messages are end-to-end encrypted. The keys live <b>only in this browser</b>, so we can't recover them for you.</p>
  <p><b>Save your account file now.</b> It lets you sign back in and read your messages on another device or after clearing your browser. Keep it private, like a password.</p>
  <p><button class="btn" id="dl">Download account file</button> <a class="btn ghost" href="#/">Continue</a></p></div>`;
  $('#dl').onclick = () => { downloadAccountFile(); toast('Saved. Store it somewhere safe.'); };
}

function create() {
  if (!needMe()) return;
  const d = new Date(Date.now() + 7 * 864e5); d.setMinutes(0); const dv = new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16);
  app.innerHTML = `<h1>Host an event</h1><div class="panel">
  <label>Title</label><input id="t"><label>Category</label><select id="cat">${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
  <label>What's it about?</label><textarea id="d" rows="4" placeholder="Who is it for? What will you do? Say explicitly that newcomers and solo attendees are welcome."></textarea>
  <label>Venue <small>(use a public place)</small></label><input id="v"><label>City</label><input id="c" value="${esc(me.city)}">
  <label>Starts</label><input id="s" type="datetime-local" value="${dv}"><label>Capacity</label><input id="cap" type="number" min="2" max="500" value="15">
  <label>Vibe <small>(e.g. "Chill & beginner-friendly")</small></label><input id="vibe">
  <label>Topic tags <small>(comma separated, used to match interested people)</small></label><input id="tags" placeholder="Hiking, Coffee">
  <p><button class="btn" id="go">Publish event</button></p></div>`;
  $('#go').onclick = async () => {
    try {
      const r = await api('/events', { method: 'POST', body: { title: $('#t').value, category: $('#cat').value, description: $('#d').value, venue: $('#v').value, city: $('#c').value, starts: $('#s').value, capacity: +$('#cap').value, vibe: $('#vibe').value, tags: $('#tags').value.split(',').map(x => x.trim()).filter(Boolean) } });
      toast('Event published'); location.hash = '#/event/' + r.id;
    } catch (e) { toast(/too fast|account|limit/i.test(e.message) ? e.message : 'Check the fields: title, description (10+ chars), venue and city are required'); }
  };
}

async function inbox() {
  if (!needMe()) return;
  const th = await api('/inbox');
  const rows = await Promise.all(th.map(async t => {
    let preview = '🔒 Encrypted message';
    try { preview = await decrypt(await convoKey(t.user.public_key), t); } catch {}
    return `<div class="person">${avatar(t.user)}<div class="info"><a class="name" href="#/dm/${t.user.id}">${esc(t.user.name)}</a><br><span class="muted">${t.mine ? 'You: ' : ''}${esc(preview.slice(0, 120))}</span></div></div>`;
  }));
  app.innerHTML = `<h1>Messages</h1><p class="muted">🔒 End-to-end encrypted. Only you and the other person can read these.</p>
  <div class="panel">${rows.join('') || '<div class="empty">No conversations yet. Find someone on an event page and say hello.</div>'}</div>`;
}

async function dm(other) {
  if (!needMe()) return;
  const u = await api('/users/' + other);
  if (!u.public_key) { app.innerHTML = '<div class="empty">This sample profile can\'t receive encrypted messages.</div>'; return; }
  const [raw, msgs] = await Promise.all([convoKey(u.public_key), api(`/dm/${other}`)]);
  const plain = await Promise.all(msgs.map(m => decrypt(raw, m)));
  const sn = await safetyNumber(u.public_key);
  app.innerHTML = `<a href="#/inbox" class="muted">&larr; Messages</a><h1>${esc(u.name)}</h1>
  <p class="muted"><small>🔒 End-to-end encrypted. Safety number: <code>${sn}</code>. If it matches on their screen, no one is in the middle.</small></p>
  ${u.shared?.length ? `<div class="match">Conversation starter: you both like ${esc(u.shared.join(', '))}</div>` : ''}
  <div class="panel" style="margin-top:12px">${msgs.map((m, i) => `<div class="bubble ${m.from_id === me.id ? 'mine' : ''}">${esc(plain[i])}</div>`).join('') || '<div class="muted">No messages yet.</div>'}
  <div class="row" style="margin-top:12px"><input id="m" maxlength="1500" placeholder="Write a message"><button class="btn" id="s">Send</button></div>
  <p style="margin-bottom:0"><button class="linkbtn" id="rep">Report this conversation</button><button class="linkbtn" id="blk">Block</button></p></div>`;
  const send = async () => {
    const b = $('#m').value.trim(); if (!b) return;
    try { await api('/dm', { method: 'POST', body: { to_id: +other, ...(await encrypt(raw, b)) } }); dm(other); } catch (e) { toast(e.message); }
  };
  $('#s').onclick = send; $('#m').onkeydown = k => k.key === 'Enter' && send();
  $('#blk').onclick = async () => { await api('/blocks/' + other, { method: 'PUT' }); toast('Blocked'); location.hash = '#/inbox'; };
  $('#rep').onclick = () => reportDialog({
    title: 'Report this conversation',
    note: 'Messages are private, so reporting this conversation shares its recent messages (up to 100, decrypted by you) with our safety team. Other conversations stay private.',
    onSubmit: (reason, details) => api('/reports', { method: 'POST', body: { kind: 'dm', target_id: +other, reason, details, key: b64(raw) } }),
  });
}

const routes = [
  [/^#\/event\/(\d+)/, eventPage], [/^#\/user\/(\d+)/, userPage], [/^#\/dm\/(\d+)/, dm],
  [/^#\/people/, people], [/^#\/join/, join], [/^#\/create/, create], [/^#\/inbox/, inbox],
];
async function route() {
  const h = location.hash || '#/';
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === h));
  window.scrollTo(0, 0);
  for (const [re, fn] of routes) { const m = h.match(re); if (m) return fn(m[1]).catch(e => app.innerHTML = `<div class="empty">${esc(e.message)}</div>`); }
  home();
}
addEventListener('hashchange', route);
(async () => { meta = await api('/meta'); await loadMe(); route(); })();
