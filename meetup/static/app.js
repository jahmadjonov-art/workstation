const $ = (s, r = document) => r.querySelector(s);
const app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let meta = { categories: [], looking_for: [] };
let me = null;

const api = async (path, opts = {}) => {
  const r = await fetch('/api' + path, { headers: { 'Content-Type': 'application/json' }, ...opts, body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(typeof e.detail === 'string' ? e.detail : 'Something went wrong'); }
  return r.json();
};
const toast = m => { const t = $('#toast'); t.textContent = m; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2600); };
const colors = ['#ff5a4e', '#0f9d8a', '#7c5cff', '#e6a100', '#2b7de9', '#d6409f'];
const avatar = (u, cls = '') => `<span class="avatar ${cls}" style="background:${colors[u.id % colors.length]}" title="${esc(u.name)}">${esc(u.name.trim()[0] || '?').toUpperCase()}</span>`;
const fmt = iso => new Date(iso).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
const vq = () => me ? `viewer=${me.id}` : '';
const chips = (xs, cls = '') => xs.map(x => `<span class="chip ${cls}">${esc(x)}</span>`).join('');

async function loadMe() {
  const id = localStorage.getItem('huddle_uid');
  me = null;
  if (id) { try { me = await api('/users/' + id); } catch { localStorage.removeItem('huddle_uid'); } }
  $('#me').innerHTML = me
    ? `<span class="meprof">${avatar(me)}<a href="#/user/${me.id}">${esc(me.name.split(' ')[0])}</a><button class="btn ghost" id="out">Switch</button></span>`
    : `<a class="btn" href="#/join">Join</a>`;
  if (me) $('#out').onclick = () => { localStorage.removeItem('huddle_uid'); location.hash = '#/join'; };
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
    if (me) p.set('viewer', me.id);
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
  const e = await api(`/events/${id}?${vq()}`);
  const full = e.spots_left === 0 && !e.going;
  app.innerHTML = `
  <a href="#/" class="muted">&larr; All events</a>
  <div class="cols"><div>
    <div class="when">${fmt(e.starts)}</div><h1>${esc(e.title)}</h1>
    <p class="muted">${esc(e.venue)}, ${esc(e.city)} · Hosted by <a href="#/user/${e.host.id}">${esc(e.host.name)}</a></p>
    <div class="chips"><span class="chip warm">${esc(e.category)}</span>${e.vibe ? `<span class="chip plain">${esc(e.vibe)}</span>` : ''}${chips(e.tags)}</div>
    <p style="white-space:pre-wrap">${esc(e.description)}</p>
    <button class="btn" id="rsvp" ${full ? 'disabled' : ''}>${e.going ? 'Going, tap to cancel' : full ? 'Event is full' : 'Count me in'}</button>
    <h2>Conversation</h2>
    <div class="panel">
      ${e.messages.map(m => `<div class="msg"><b><a href="#/user/${m.user.id}">${esc(m.user.name)}</a></b><br>${esc(m.body)}</div>`).join('') || '<div class="muted">Nobody has said anything yet. Break the ice!</div>'}
      ${e.going ? `<div class="row" style="margin-top:12px"><input id="msg" placeholder="Say hi to the group"><button class="btn" id="send">Send</button></div>
      <p class="muted" style="margin:12px 0 4px">Need a starter? Tap one:</p>${e.icebreakers.map(i => `<button class="ice">${esc(i)}</button>`).join('')}`
      : '<p class="muted" style="margin-top:12px">RSVP to join the conversation.</p>'}
    </div>
  </div>
  <aside><div class="panel"><h3>Who's going (${e.attendee_count}/${e.capacity})</h3>
    ${e.attendees.map(a => `<div class="person">${avatar(a)}<div class="info"><a class="name" href="#/user/${a.id}">${esc(a.name)}</a> <small>${esc(a.pronouns)}</small>
      ${a.shared?.length ? `<div class="chips" style="margin-top:4px">${chips(a.shared)}</div><small>in common with you</small>` : `<div class="muted" style="font-size:.85rem">${esc(a.interests.slice(0, 3).join(', '))}</div>`}</div></div>`).join('')}
  </div></aside></div>`;
  $('#rsvp').onclick = async () => {
    if (!needMe()) return;
    try {
      if (e.going) await api(`/events/${id}/rsvp/${me.id}`, { method: 'DELETE' });
      else { await api(`/events/${id}/rsvp`, { method: 'POST', body: { user_id: me.id } }); toast("You're in! Say hi in the conversation."); }
      eventPage(id);
    } catch (err) { toast(err.message); }
  };
  if (e.going) {
    const send = async () => { const b = $('#msg').value.trim(); if (!b) return; await api(`/events/${id}/messages`, { method: 'POST', body: { user_id: me.id, body: b } }); eventPage(id); };
    $('#send').onclick = send; $('#msg').onkeydown = k => k.key === 'Enter' && send();
    document.querySelectorAll('.ice').forEach(b => b.onclick = () => { $('#msg').value = b.textContent; $('#msg').focus(); });
  }
}

async function people() {
  if (!needMe()) return;
  const list = await api(`/users/${me.id}/matches`);
  app.innerHTML = `<h1>People you may click with</h1><p class="muted">Ranked by shared interests, what you're each looking for, and events in common.</p>
  <div class="grid">${list.map(u => `<a class="card" href="#/user/${u.id}"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><h3>${esc(u.name)}</h3><small>${esc(u.city)} ${esc(u.pronouns)}</small></div></div>
    <div class="chips">${chips(u.shared)}</div>
    ${u.shared_goals.length ? `<small>Both looking for: ${esc(u.shared_goals.join(', '))}</small>` : ''}
    ${u.events_in_common ? `<small>${u.events_in_common} event${u.events_in_common > 1 ? 's' : ''} in common</small>` : ''}</a>`).join('') || '<div class="empty">Add some interests to your profile to see matches.</div>'}</div>`;
}

async function userPage(id) {
  const u = await api(`/users/${id}?${vq()}`);
  const mine = me && me.id === u.id;
  app.innerHTML = `<div class="panel"><div class="row" style="align-items:center">${avatar(u, 'lg')}<div><h1 style="margin:0">${esc(u.name)}</h1><span class="muted">${esc(u.city)} ${u.pronouns ? '· ' + esc(u.pronouns) : ''}</span></div></div>
  <p>${esc(u.bio) || '<span class="muted">No bio yet.</span>'}</p>
  <div class="chips">${chips(u.interests, '')}</div>
  ${u.looking_for.length ? `<p class="muted">Looking for: ${esc(u.looking_for.join(', '))}</p>` : ''}
  ${u.shared?.length ? `<div class="match">You both like: ${esc(u.shared.join(', '))}</div>` : ''}
  ${u.shared_events?.length ? `<p class="muted">You're both going to: ${esc(u.shared_events.join(', '))}</p>` : ''}
  ${mine ? '<a class="btn ghost" href="#/join?edit=1">Edit profile</a>' : `<a class="btn" href="#/dm/${u.id}">Say hello</a>`}</div>
  <h2>Upcoming events</h2><div class="panel">${u.events.map(e => `<div class="msg"><a href="#/event/${e.id}">${esc(e.title)}</a> <small>${fmt(e.starts)}</small></div>`).join('') || '<span class="muted">Nothing yet.</span>'}</div>`;
}

async function join() {
  const editing = location.hash.includes('edit=1') && me;
  const demo = editing ? [] : await api('/users');
  const tags = editing ? [...me.interests] : [];
  const lf = new Set(editing ? me.looking_for : []);
  app.innerHTML = `<h1>${editing ? 'Edit your profile' : 'Join Huddle'}</h1><div class="cols"><div class="panel">
  <label>Name</label><input id="n" maxlength="60" value="${esc(editing ? me.name : '')}">
  <label>City</label><input id="c" value="${esc(editing ? me.city : 'Austin')}">
  <label>Pronouns <small>(optional)</small></label><input id="p" placeholder="she/her, he/him, they/them, anything" value="${esc(editing ? me.pronouns : '')}">
  <label>Short bio</label><textarea id="b" rows="3" maxlength="400">${esc(editing ? me.bio : '')}</textarea>
  <label>Interests <small>(type and press Enter)</small></label><input id="i" placeholder="Hiking, Python, Board games..."><div class="chips" id="tags" style="margin-top:8px"></div>
  <label>I'm looking for</label><div class="chips" id="lf">${meta.looking_for.map(x => `<button type="button" class="chip ${lf.has(x) ? 'sel' : ''}" data-v="${esc(x)}">${esc(x)}</button>`).join('')}</div>
  <p><button class="btn" id="save">${editing ? 'Save' : 'Create profile'}</button></p></div>
  ${editing ? '' : `<div class="panel"><h3>Or try as a sample person</h3><div class="pick">${demo.map(u => `<button data-id="${u.id}">${avatar(u)}<span><b>${esc(u.name)}</b><br><small>${esc(u.interests.slice(0, 3).join(', '))}</small></span></button>`).join('')}</div></div>`}</div>`;
  const drawTags = () => { $('#tags').innerHTML = tags.map((t, k) => `<button type="button" class="chip" data-k="${k}">${esc(t)} ×</button>`).join(''); document.querySelectorAll('#tags .chip').forEach(b => b.onclick = () => { tags.splice(+b.dataset.k, 1); drawTags(); }); };
  drawTags();
  $('#i').onkeydown = k => { if (k.key === 'Enter' || k.key === ',') { k.preventDefault(); const v = $('#i').value.trim(); if (v && !tags.some(t => t.toLowerCase() === v.toLowerCase())) tags.push(v); $('#i').value = ''; drawTags(); } };
  document.querySelectorAll('#lf .chip').forEach(b => b.onclick = () => { lf.has(b.dataset.v) ? lf.delete(b.dataset.v) : lf.add(b.dataset.v); b.classList.toggle('sel'); });
  document.querySelectorAll('.pick button').forEach(b => b.onclick = async () => { localStorage.setItem('huddle_uid', b.dataset.id); await loadMe(); location.hash = '#/'; });
  $('#save').onclick = async () => {
    const pending = $('#i').value.trim(); if (pending) tags.push(pending);
    const body = { name: $('#n').value, city: $('#c').value, pronouns: $('#p').value, bio: $('#b').value, interests: tags, looking_for: [...lf] };
    try {
      const u = editing ? await api('/users/' + me.id, { method: 'PUT', body }) : await api('/users', { method: 'POST', body });
      localStorage.setItem('huddle_uid', u.id); await loadMe(); toast('Profile saved'); location.hash = editing ? '#/user/' + u.id : '#/';
    } catch (e) { toast('Please check your name and city'); }
  };
}

function create() {
  if (!needMe()) return;
  const d = new Date(Date.now() + 7 * 864e5); d.setMinutes(0); const dv = new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16);
  app.innerHTML = `<h1>Host an event</h1><div class="panel">
  <label>Title</label><input id="t"><label>Category</label><select id="cat">${meta.categories.map(c => `<option>${esc(c)}</option>`).join('')}</select>
  <label>What's it about?</label><textarea id="d" rows="4" placeholder="Who is it for? What will you do? Say explicitly that newcomers and solo attendees are welcome."></textarea>
  <label>Venue</label><input id="v"><label>City</label><input id="c" value="${esc(me.city)}">
  <label>Starts</label><input id="s" type="datetime-local" value="${dv}"><label>Capacity</label><input id="cap" type="number" min="2" max="500" value="15">
  <label>Vibe <small>(e.g. "Chill & beginner-friendly")</small></label><input id="vibe">
  <label>Topic tags <small>(comma separated, used to match interested people)</small></label><input id="tags" placeholder="Hiking, Coffee">
  <p><button class="btn" id="go">Publish event</button></p></div>`;
  $('#go').onclick = async () => {
    try {
      const r = await api('/events', { method: 'POST', body: { host_id: me.id, title: $('#t').value, category: $('#cat').value, description: $('#d').value, venue: $('#v').value, city: $('#c').value, starts: $('#s').value, capacity: +$('#cap').value, vibe: $('#vibe').value, tags: $('#tags').value.split(',').map(x => x.trim()).filter(Boolean) } });
      toast('Event published'); location.hash = '#/event/' + r.id;
    } catch (e) { toast('Check the fields: title, description (10+ chars), venue and city are required'); }
  };
}

async function inbox() {
  if (!needMe()) return;
  const th = await api('/inbox/' + me.id);
  app.innerHTML = `<h1>Messages</h1><div class="panel">${th.map(t => `<div class="person">${avatar(t.user)}<div class="info"><a class="name" href="#/dm/${t.user.id}">${esc(t.user.name)}</a><br><span class="muted">${t.mine ? 'You: ' : ''}${esc(t.last)}</span></div></div>`).join('') || '<div class="empty">No conversations yet. Find someone on an event page and say hello.</div>'}</div>`;
}

async function dm(other) {
  if (!needMe()) return;
  const [u, msgs] = await Promise.all([api('/users/' + other + '?' + vq()), api(`/dm/${me.id}/${other}`)]);
  app.innerHTML = `<a href="#/inbox" class="muted">&larr; Messages</a><h1>${esc(u.name)}</h1>
  ${u.shared?.length ? `<div class="match">Conversation starter: you both like ${esc(u.shared.join(', '))}</div>` : ''}
  <div class="panel" style="margin-top:12px">${msgs.map(m => `<div class="bubble ${m.from_id === me.id ? 'mine' : ''}">${esc(m.body)}</div>`).join('') || '<div class="muted">No messages yet.</div>'}
  <div class="row" style="margin-top:12px"><input id="m" placeholder="Write a message"><button class="btn" id="s">Send</button></div></div>`;
  const send = async () => { const b = $('#m').value.trim(); if (!b) return; await api('/dm', { method: 'POST', body: { from_id: me.id, to_id: +other, body: b } }); dm(other); };
  $('#s').onclick = send; $('#m').onkeydown = k => k.key === 'Enter' && send();
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
