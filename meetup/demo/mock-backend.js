/* Demo-only stand-in for server.py. It runs inside the browser tab and answers the same /api
   requests, so the real front end (static/app.js) runs unchanged. Nothing is saved: reload to reset.
   The sample people have real encryption keys, so message requests and encrypted chats work for real. */
(() => {
  const subtle = crypto.subtle;
  const enc = new TextEncoder();
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const rnd = n => b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[^a-z0-9]/gi, '');
  const iso = d => new Date(d).toISOString().slice(0, 19) + 'Z';
  const nowIso = () => iso(Date.now());
  const HOUR = 36e5, DAY = 864e5;

  const CATEGORIES = ['Outdoors', 'Tech', 'Food & Drink', 'Arts & Culture', 'Games', 'Sports & Fitness', 'Books & Writing', 'Music', 'Language', 'Wellness', 'Career', 'Pets'];
  const LOOKING_FOR = ['Friends', 'Activity partners', 'Networking', 'Learning together', 'Dating-free socializing', 'Mentors'];
  const ICEBREAKERS = [
    "What's something you're into right now that you could talk about for an hour?", 'What brought you to this event?',
    "What's the best thing you've done or eaten this month?", 'If you could instantly master any skill, what would it be?',
    "What's a small thing that always makes your day better?", "What's a hobby you've picked up in the last year?",
  ];
  const BOT_LINES = [
    'That sounds great. What got you into it?', 'Love that. Are you going to anything this week?',
    'Ha, same here. Have you been to one of the events yet?', 'Nice! I will see you at the next one then.',
    'Totally. I am always looking for people to try new spots with.',
  ];

  const db = { users: [], events: [], rsvps: [], emsgs: [], posts: [], replies: [], blocks: [], convos: [], dms: [], tokens: {}, ids: { user: 0, event: 0, emsg: 0, post: 0, reply: 0, dm: 0, report: 0 } };
  const nid = k => ++db.ids[k];
  const bots = {};  // user id -> private CryptoKey, so sample people can answer in encrypted chats

  class HttpError extends Error { constructor(status, detail) { super(detail); this.status = status; this.detail = detail; } }
  const fail = (s, d) => { throw new HttpError(s, d); };

  /* ---------- seed ---------- */
  const ready = (async () => {
    const people = [
      ['Maya Okafor', 'she/her', ['Hiking', 'Photography', 'Coffee', 'Board games'], ['Friends', 'Activity partners'], 'Weekend trail-chaser. Always carrying too many snacks.'],
      ['Daniel Reyes', 'he/him', ['Python', 'Startups', 'Running', 'Coffee'], ['Networking', 'Learning together'], 'Backend dev, recovering marathon over-trainer.'],
      ['Sam Lindqvist', 'they/them', ['Board games', 'Cooking', 'Books', 'Sci-fi'], ['Friends'], 'I will absolutely teach you Catan, whether you like it or not.'],
      ['Priya Nair', 'she/her', ['Yoga', 'Meditation', 'Cooking', 'Travel'], ['Friends', 'Activity partners'], 'New in town and trying every taco truck.'],
      ['Tomás Silva', 'he/him', ['Guitar', 'Live music', 'Coffee', 'Languages'], ['Friends', 'Learning together'], 'Learning Japanese, teaching Portuguese.'],
      ['Jordan Blake', '', ['Running', 'Cycling', 'Climbing', 'Hiking'], ['Activity partners'], "If it has a summit or a finish line I'm in."],
      ['Aisha Rahman', 'she/her', ['Design', 'Startups', 'Photography', 'Art'], ['Networking', 'Mentors'], 'Product designer. Happy to review your portfolio.'],
      ['Leo Chen', 'he/him', ['Python', 'Machine learning', 'Board games', 'Sci-fi'], ['Learning together', 'Friends'], 'Reading group organizer, bad at poker faces.'],
    ];
    for (const [name, pronouns, interests, looking_for, bio] of people) {
      const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
      const j = await subtle.exportKey('jwk', kp.publicKey);
      const id = nid('user');
      bots[id] = kp.privateKey;
      db.users.push({ id, name, city: 'Austin', bio, pronouns, interests, looking_for, created: iso(Date.now() - 30 * DAY), public_key: { kty: j.kty, crv: j.crv, x: j.x, y: j.y }, token: null, suspended: false, deleted: false });
    }
    const base = new Date(); base.setMinutes(0, 0, 0);
    const evs = [
      ['Sunrise Hike at Barton Creek', 'An easy 5 km loop to start the weekend. All paces welcome, we wait at every turn. Coffee after at the trailhead.', 'Outdoors', 'Trailhead Lot B', 2, 6, 12, 1, ['Hiking', 'Photography', 'Coffee'], 'Chill & beginner-friendly'],
      ['Beginner Python Study Circle', 'Bring a laptop and a small project idea. We pair up, help each other get unstuck, and share what we built.', 'Tech', 'Public Library, Room 3', 3, 19, 10, 2, ['Python', 'Learning', 'Startups'], 'Collaborative, no experience needed'],
      ['Board Game Night: Newcomers Welcome', "We have 30+ games and patient teachers. Solo attendees are the norm here, nobody will leave you standing alone.", 'Games', "Gnome's Hollow Cafe", 4, 18, 16, 3, ['Board games', 'Sci-fi', 'Cooking'], 'Friendly, low-pressure'],
      ['Taco Truck Crawl', "Three trucks, small bites, zero pretension. We'll swap favorite spots and plan the next crawl.", 'Food & Drink', 'Meet at East 6th Fountain', 5, 17, 14, 4, ['Cooking', 'Travel', 'Coffee'], 'Casual & curious'],
      ['Japanese & Portuguese Language Swap', 'Half the evening in each language, with a timer so everyone gets a turn. Every level is welcome.', 'Language', "Mellow Johnny's Cafe", 6, 19, 20, 5, ['Languages', 'Travel', 'Live music'], 'Relaxed, supportive'],
      ['Morning 5K + Coffee', "Conversational pace run, then coffee. Walkers welcome, we'll set up a walking group too.", 'Sports & Fitness', 'Lady Bird Lake Boardwalk', 7, 7, 25, 6, ['Running', 'Cycling', 'Coffee'], 'Easy pace, inclusive'],
      ['Portfolio Feedback Jam', 'Bring work in progress for kind, specific feedback from designers and builders. Mentors and mentees both welcome.', 'Career', 'Co-work Loft', 8, 18, 18, 7, ['Design', 'Startups', 'Art'], 'Supportive, growth-minded'],
      ['Sci-Fi Book Club: Discussion + Drinks', "This month's pick, plus a quick vote on the next one. Haven't finished it? Come anyway.", 'Books & Writing', 'Book People Reading Nook', 9, 19, 15, 8, ['Sci-fi', 'Books', 'Board games'], 'Thoughtful & fun'],
      ['Sunset Yoga in the Park', 'Gentle all-levels flow followed by tea. Mats provided if you need one.', 'Wellness', 'Zilker Great Lawn', 10, 18, 25, 4, ['Yoga', 'Meditation', 'Travel'], 'Calm, welcoming'],
    ];
    evs.forEach(([title, description, category, venue, days, hour, capacity, host_id, tags, vibe], i) => {
      const d = new Date(base.getTime() + days * DAY); d.setHours(hour);
      const id = nid('event');
      db.events.push({ id, title, description, category, city: 'Austin', venue, starts: new Date(d.getTime() - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16), capacity, host_id, tags, vibe });
      const going = new Set([host_id]);
      for (let k = 0; k < 3 + (i % 4); k++) going.add(1 + ((i * 3 + k * 2) % 8));
      going.forEach(u => db.rsvps.push({ event_id: id, user_id: u }));
    });
    const em = (event_id, user_id, body) => db.emsgs.push({ id: nid('emsg'), event_id, user_id, body, created: nowIso() });
    em(1, 1, 'Reminder: bring water and a layer, it is chilly at sunrise!'); em(1, 6, 'First time here, can I bring a friend?'); em(3, 3, 'I will bring Wingspan and Azul for beginners.');
    [[1, 'Barton Creek is flowing again after the rain. Saw a great blue heron on the sunrise loop today!', '', ['Hiking', 'Photography']],
     [2, "Handy find: the Austin library now lends out laptops and wifi hotspots for free. Great if you're learning to code.", 'https://library.austintexas.gov', ['Python']],
     [3, 'Anyone tried Heat: Pedal to the Metal? Looking for opinions before game night on Wednesday.', '', ['Board games']],
     [5, "Small tip for language learners: ten minutes of speaking out loud beats an hour of flashcards.", '', ['Languages']],
     [6, 'Lady Bird Lake trail has a new water fountain at the east end. Good news for long runs!', '', ['Running', 'Cycling']],
     [4, "Found a lovely beginner yoga video series that doesn't require any equipment. Happy to share if anyone wants.", '', ['Yoga', 'Meditation']]]
      .forEach(([user_id, body, url, tags], i) => db.posts.push({ id: nid('post'), user_id, body, url, tags, city: 'Austin', created: iso(Date.now() - (3 + i * 7) * HOUR) }));
    db.replies.push({ id: nid('reply'), post_id: 1, user_id: 6, body: 'Love that loop. Was it busy?', created: nowIso() });
  })();

  /* ---------- helpers that mirror server.py ---------- */
  const user = id => db.users.find(u => u.id === id);
  const pub = u => ({ id: u.id, name: u.name, city: u.city, bio: u.bio, pronouns: u.pronouns, interests: u.interests, looking_for: u.looking_for, public_key: u.public_key });
  const getUser = id => { const u = user(id); if (!u) fail(404, 'User not found'); return pub(u); };
  const shared = (a, b) => { const s = new Set(a.interests.map(x => x.toLowerCase())); return b.interests.filter(x => s.has(x.toLowerCase())); };
  const isNew = u => Date.now() - new Date(u.created) < DAY;
  const upcoming = e => new Date(e.starts) >= new Date(Date.now() - HOUR);
  const hidden = vid => { const out = new Set(); if (vid) db.blocks.forEach(b => { if (b.blocker === vid) out.add(b.blocked); else if (b.blocked === vid) out.add(b.blocker); }); return out; };
  const blockedEither = (a, b) => db.blocks.some(x => (x.blocker === a && x.blocked === b) || (x.blocker === b && x.blocked === a));
  const pair = (a, b) => [Math.min(a, b), Math.max(a, b)];
  const convo = (a, b) => { const [x, y] = pair(a, b); return db.convos.find(c => c.a === x && c.b === y); };

  function chatState(me, other) {
    const o = user(other);
    if (!o || me === other || !o.public_key || o.deleted || o.suspended || blockedEither(me, other)) return 'unavailable';
    const c = convo(me, other);
    if (!c) return 'none';
    if (c.status === 'accepted') return 'accepted';
    if (c.requester === me) return 'request_out';
    return c.status === 'pending' ? 'request_in' : 'none';
  }

  function eventDict(e, viewer) {
    const attendees = db.rsvps.filter(r => r.event_id === e.id).map(r => pub(user(r.user_id)));
    const d = { ...e, host: getUser(e.host_id), attendee_count: attendees.length, spots_left: Math.max(0, e.capacity - attendees.length), attendees };
    delete d.host_id;
    if (viewer) {
      d.going = attendees.some(a => a.id === viewer.id);
      attendees.forEach(a => { a.shared = a.id !== viewer.id ? shared(viewer, a) : []; });
      d.fit = shared(viewer, { interests: e.tags }).length;
      d.people_like_you = attendees.filter(a => a.id !== viewer.id && a.shared.length).length;
    }
    return d;
  }

  function postDict(p, vid) {
    return { id: p.id, body: p.body, url: p.url, tags: p.tags, city: p.city, created: p.created, author: getUser(p.user_id), mine: p.user_id === vid, reply_count: db.replies.filter(r => r.post_id === p.id).length };
  }
  const live = u => { const x = user(u); return x && !x.suspended && !x.deleted; };
  const cleanList = (xs, n) => { const seen = new Set(), out = []; for (let x of xs || []) { x = String(x).trim().slice(0, 30); if (x && !seen.has(x.toLowerCase())) { seen.add(x.toLowerCase()); out.push(x); } } return out.slice(0, n); };
  const LINK_RE = /https?:\/\/|www\./i;

  /* ---------- sample people answer in real encrypted chats ---------- */
  async function botSend(botId, toId, text) {
    const toUser = user(toId); if (!toUser || toUser.deleted) return;
    const priv = bots[botId];
    const theirs = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: toUser.public_key.x, y: toUser.public_key.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const raw = await subtle.deriveBits({ name: 'ECDH', public: theirs }, priv, 256);
    const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
    db.dms.push({ id: nid('dm'), from_id: botId, to_id: toId, iv: b64(iv), ciphertext: b64(ct), created: nowIso() });
    const c = convo(botId, toId); if (c) c.updated = nowIso();
  }
  const first = u => u.name.split(' ')[0];
  function botReactions(from, toId) {
    const bot = user(toId); if (!bots[toId]) return;
    const st = chatState(toId, from.id);
    if (st === 'request_in') {
      setTimeout(() => { const c = convo(toId, from.id); if (c && c.status === 'pending') c.status = 'accepted'; }, 1800);
      const common = shared(from, bot);
      setTimeout(() => botSend(toId, from.id, `Hi ${first(from)}! Thanks for reaching out. ${common.length ? `I see we both like ${common[0]}. ` : ''}What are you hoping to find on Huddle?`), 3200);
    } else if (st === 'accepted') {
      const n = db.dms.filter(d => d.from_id === toId && d.to_id === from.id).length;
      setTimeout(() => botSend(toId, from.id, BOT_LINES[n % BOT_LINES.length]), 2200);
    }
  }
  function scheduleWelcome(u) {  // a sample member sends the new person a message request so the flow is visible
    setTimeout(async () => {
      if (!user(u.id) || user(u.id).deleted || convo(1, u.id)) return;
      const [x, y] = pair(1, u.id);
      db.convos.push({ a: x, b: y, requester: 1, status: 'pending', created: nowIso(), updated: nowIso() });
      await botSend(1, u.id, `Hi ${first(u)}, welcome to Huddle! A few of us are heading to the Barton Creek sunrise hike on Monday. Want to join us?`);
    }, 4000);
  }

  /* ---------- routes ---------- */
  const routes = [];
  const R = (method, path, fn, auth = false) => routes.push({ method, re: new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, auth });

  R('GET', '/meta', () => ({ categories: CATEGORIES, looking_for: LOOKING_FOR }));
  R('GET', '/pow', () => ({ challenge: 'demo.' + rnd(8), bits: 10 }));

  R('POST', '/signup', ({ body: b }) => {
    if (b.website) fail(400, 'Could not create account');
    const born = new Date(b.birth_date); if (isNaN(born)) fail(400, 'Enter a valid birth date');
    const age = (Date.now() - born) / (365.25 * DAY); if (age < 18) fail(403, 'Huddle is for adults aged 18 and over');
    if (!b.name?.trim() || (b.city || '').trim().length < 2) fail(400, 'Please add your name and city');
    if (!b.public_key || b.public_key.kty !== 'EC') fail(400, 'Invalid encryption key');
    const token = rnd(32);
    const u = { id: nid('user'), name: b.name.trim().slice(0, 60), city: b.city.trim(), bio: (b.bio || '').trim(), pronouns: (b.pronouns || '').trim(), interests: cleanList(b.interests, 12), looking_for: cleanList(b.looking_for, 6), created: nowIso(), public_key: { kty: 'EC', crv: 'P-256', x: b.public_key.x, y: b.public_key.y }, token, suspended: false, deleted: false };
    db.users.push(u); db.tokens[token] = u.id; scheduleWelcome(u);
    return { user: pub(u), token };
  });

  R('GET', '/me', ({ me }) => ({ ...pub(me), created: me.created, stats: {
    posts: db.posts.filter(p => p.user_id === me.id).length,
    events: db.rsvps.filter(r => r.user_id === me.id && upcoming(db.events.find(e => e.id === r.event_id))).length } }), true);
  R('PUT', '/me', ({ me, body: b }) => {
    if (!b.name?.trim() || (b.city || '').trim().length < 2) fail(422, 'Please add your name and city');
    Object.assign(me, { name: b.name.trim(), city: b.city.trim(), bio: (b.bio || '').trim(), pronouns: (b.pronouns || '').trim(), interests: cleanList(b.interests, 12), looking_for: cleanList(b.looking_for, 6) });
    return pub(me);
  }, true);
  R('DELETE', '/me', ({ me }) => {
    const id = me.id;
    db.dms = db.dms.filter(d => d.from_id !== id && d.to_id !== id); db.convos = db.convos.filter(c => c.a !== id && c.b !== id);
    db.blocks = db.blocks.filter(b => b.blocker !== id && b.blocked !== id);
    db.events.filter(e => e.host_id === id).forEach(e => { db.emsgs = db.emsgs.filter(m => m.event_id !== e.id); db.rsvps = db.rsvps.filter(r => r.event_id !== e.id); });
    db.events = db.events.filter(e => e.host_id !== id);
    db.emsgs = db.emsgs.filter(m => m.user_id !== id); db.rsvps = db.rsvps.filter(r => r.user_id !== id);
    const mine = new Set(db.posts.filter(p => p.user_id === id).map(p => p.id));
    db.replies = db.replies.filter(r => r.user_id !== id && !mine.has(r.post_id)); db.posts = db.posts.filter(p => p.user_id !== id);
    delete db.tokens[me.token]; Object.assign(me, { name: 'Deleted user', city: '', bio: '', pronouns: '', interests: [], looking_for: [], public_key: null, token: null, deleted: true });
    return { ok: true };
  }, true);
  R('GET', '/me/counts', ({ me }) => ({ requests: db.convos.filter(c => (c.a === me.id || c.b === me.id) && c.status === 'pending' && c.requester !== me.id && chatState(me.id, c.requester) === 'request_in').length }), true);

  R('GET', '/me/matches', ({ me }) => {
    const out = [];
    for (const u of db.users) {
      if (u.id === me.id || u.suspended || u.deleted) continue;
      const o = pub(u), sh = shared(me, o), goals = o.looking_for.filter(g => me.looking_for.includes(g));
      const common = db.rsvps.filter(a => a.user_id === me.id && db.rsvps.some(b => b.user_id === u.id && b.event_id === a.event_id)).length;
      const score = sh.length * 3 + goals.length * 2 + common * 2 + (o.city.toLowerCase() === me.city.toLowerCase() ? 2 : 0);
      if (sh.length || goals.length) { const st = chatState(me.id, u.id); out.push({ ...o, shared: sh, shared_goals: goals, events_in_common: common, score, chat: st, can_message: st !== 'unavailable' }); }
    }
    return out.sort((a, b) => b.score - a.score).slice(0, 12);
  }, true);

  R('GET', '/events', ({ q, me }) => {
    let list = db.events.filter(upcoming).sort((a, b) => a.starts.localeCompare(b.starts));
    const cat = q.get('category'), city = (q.get('city') || '').toLowerCase(), text = (q.get('q') || '').toLowerCase().split(/\s+/).filter(Boolean);
    list = list.filter(e => (!cat || e.category === cat) && (!city || e.city.toLowerCase().includes(city))
      && text.every(t => [e.title, e.description, e.category, e.tags.join(' '), e.venue].join(' ').toLowerCase().includes(t)));
    const out = list.map(e => { const d = eventDict(e, me); d.attendees = d.attendees.slice(0, 5); return d; });
    if (me && q.get('sort') === 'match') out.sort((a, b) => (b.fit * 2 + b.people_like_you) - (a.fit * 2 + a.people_like_you) || a.starts.localeCompare(b.starts));
    return out;
  });
  R('GET', '/events/:id', ({ params, me }) => {
    const e = db.events.find(x => x.id === +params.id); if (!e) fail(404, 'Event not found');
    const d = eventDict(e, me), hide = hidden(me?.id);
    d.messages = db.emsgs.filter(m => m.event_id === e.id && !hide.has(m.user_id)).map(m => ({ id: m.id, body: m.body, created: m.created, user: getUser(m.user_id) }));
    d.icebreakers = [0, 1, 2].map(i => ICEBREAKERS[(e.id + i * 2) % ICEBREAKERS.length]);
    return d;
  });
  R('POST', '/events', ({ me, body: b }) => {
    if (!CATEGORIES.includes(b.category)) fail(400, 'Unknown category');
    if ((b.title || '').trim().length < 3 || (b.description || '').trim().length < 10 || (b.venue || '').trim().length < 2 || (b.city || '').trim().length < 2) fail(422, 'Please fill in the title, a short description, venue and city');
    if (db.events.filter(e => e.host_id === me.id).length >= (isNew(me) ? 1 : 5)) fail(429, 'New accounts can host 1 event a day; others 5.');
    const e = { id: nid('event'), title: b.title.trim(), description: b.description.trim(), category: b.category, city: b.city.trim(), venue: b.venue.trim(), starts: b.starts, capacity: Math.min(500, Math.max(2, +b.capacity || 15)), host_id: me.id, tags: cleanList(b.tags, 8), vibe: (b.vibe || '').trim() };
    db.events.push(e); db.rsvps.push({ event_id: e.id, user_id: me.id }); return { id: e.id };
  }, true);
  R('POST', '/events/:id/rsvp', ({ params, me }) => {
    const e = db.events.find(x => x.id === +params.id); if (!e) fail(404, 'Event not found');
    const going = db.rsvps.some(r => r.event_id === e.id && r.user_id === me.id);
    if (!going && db.rsvps.filter(r => r.event_id === e.id).length >= e.capacity) fail(409, 'This event is full');
    if (!going) db.rsvps.push({ event_id: e.id, user_id: me.id }); return { ok: true };
  }, true);
  R('DELETE', '/events/:id/rsvp', ({ params, me }) => { db.rsvps = db.rsvps.filter(r => !(r.event_id === +params.id && r.user_id === me.id)); return { ok: true }; }, true);
  R('POST', '/events/:id/messages', ({ params, me, body: b }) => {
    if (!db.rsvps.some(r => r.event_id === +params.id && r.user_id === me.id)) fail(403, 'RSVP to join the conversation');
    const text = (b.body || '').trim(); if (!text) fail(422, 'Write something first');
    const last = db.emsgs.filter(m => m.event_id === +params.id && m.user_id === me.id).at(-1);
    if (last && last.body === text) fail(400, 'You already posted that');
    db.emsgs.push({ id: nid('emsg'), event_id: +params.id, user_id: me.id, body: text, created: nowIso() }); return { ok: true };
  }, true);

  R('GET', '/users/:id', ({ params, me }) => {
    const id = +params.id, u = getUser(id);
    if (user(id).deleted) fail(404, 'This account no longer exists');
    u.events = db.rsvps.filter(r => r.user_id === id).map(r => db.events.find(e => e.id === r.event_id)).filter(upcoming).sort((a, b) => a.starts.localeCompare(b.starts)).map(e => ({ id: e.id, title: e.title, starts: e.starts, category: e.category }));
    if (me && me.id !== id) {
      u.shared = shared(me, u);
      u.shared_events = db.events.filter(e => db.rsvps.some(r => r.event_id === e.id && r.user_id === id) && db.rsvps.some(r => r.event_id === e.id && r.user_id === me.id)).map(e => e.title);
      u.blocked = db.blocks.some(b => b.blocker === me.id && b.blocked === id);
      u.chat = chatState(me.id, id); u.can_message = u.chat !== 'unavailable';
    }
    return u;
  });
  R('GET', '/users/:id/posts', ({ params, me }) => {
    const id = +params.id;
    if (hidden(me?.id).has(id)) return [];
    if (!live(id)) fail(404, 'This account no longer exists');
    return db.posts.filter(p => p.user_id === id).sort((a, b) => b.id - a.id).slice(0, 30).map(p => postDict(p, me?.id));
  });

  R('GET', '/posts', ({ q, me }) => {
    const scope = q.get('scope') || 'foryou', tag = (q.get('tag') || '').toLowerCase(), hide = hidden(me?.id);
    const out = [];
    [...db.posts].sort((a, b) => b.id - a.id).filter(p => live(p.user_id)).forEach((p, rank) => {
      if (hide.has(p.user_id) || (tag && !p.tags.some(t => t.toLowerCase() === tag))) return;
      const sameCity = !!me && p.city.toLowerCase() === me.city.toLowerCase();
      if (scope === 'near' && !sameCity) return;
      const d = postDict(p, me?.id), match = me ? shared(me, { interests: p.tags }) : [];
      d.match = match; d._s = match.length * 3 + (sameCity ? 2 : 0) - rank * 0.05; out.push(d);
    });
    if (scope === 'foryou' && me) out.sort((a, b) => b._s - a._s);
    out.forEach(d => delete d._s); return out.slice(0, 60);
  });
  R('POST', '/posts', ({ me, body: b }) => {
    const text = (b.body || '').trim(); if (!text) fail(422, 'Write something first');
    const url = (b.url || '').trim();
    if (url && !/^https?:\/\/\S+$/.test(url)) fail(400, "That link doesn't look right. It should start with http:// or https://");
    if (isNew(me) && (url || LINK_RE.test(text))) fail(403, 'Links unlock after your first day on Huddle. It keeps spam out.');
    const mine = db.posts.filter(p => p.user_id === me.id);
    if (mine.at(-1)?.body === text) fail(400, 'You already posted that');
    if (mine.length >= (isNew(me) ? 3 : 20)) fail(429, "You've reached today's posting limit.");
    const p = { id: nid('post'), user_id: me.id, body: text, url, tags: cleanList(b.tags, 3), city: me.city, created: nowIso() };
    db.posts.push(p); return { id: p.id };
  }, true);
  R('GET', '/posts/:id', ({ params, me }) => {
    const p = db.posts.find(x => x.id === +params.id), hide = hidden(me?.id);
    if (!p || !live(p.user_id) || hide.has(p.user_id)) fail(404, 'Post not found');
    return { ...postDict(p, me?.id), replies: db.replies.filter(r => r.post_id === p.id && !hide.has(r.user_id)).map(r => ({ id: r.id, body: r.body, created: r.created, author: getUser(r.user_id), mine: r.user_id === me?.id })) };
  });
  R('POST', '/posts/:id/replies', ({ params, me, body: b }) => {
    const p = db.posts.find(x => x.id === +params.id); if (!p) fail(404, 'Post not found');
    const text = (b.body || '').trim(); if (!text) fail(422, 'Write something first');
    if (isNew(me) && LINK_RE.test(text)) fail(403, 'Links unlock after your first day on Huddle. It keeps spam out.');
    if (hidden(me.id).has(p.user_id)) fail(403, "You can't reply to this post");
    db.replies.push({ id: nid('reply'), post_id: p.id, user_id: me.id, body: text, created: nowIso() }); return { ok: true };
  }, true);
  R('DELETE', '/posts/:id', ({ params, me }) => {
    const p = db.posts.find(x => x.id === +params.id); if (!p || p.user_id !== me.id) fail(404, 'Post not found');
    db.replies = db.replies.filter(r => r.post_id !== p.id); db.posts = db.posts.filter(x => x.id !== p.id); return { ok: true };
  }, true);
  R('DELETE', '/replies/:id', ({ params, me }) => {
    const r = db.replies.find(x => x.id === +params.id); if (!r || r.user_id !== me.id) fail(404, 'Reply not found');
    db.replies = db.replies.filter(x => x.id !== r.id); return { ok: true };
  }, true);

  R('GET', '/blocks', ({ me }) => db.blocks.filter(b => b.blocker === me.id).map(b => getUser(b.blocked)), true);
  R('PUT', '/blocks/:id', ({ params, me }) => { getUser(+params.id); if (!db.blocks.some(b => b.blocker === me.id && b.blocked === +params.id)) db.blocks.push({ blocker: me.id, blocked: +params.id }); return { ok: true }; }, true);
  R('DELETE', '/blocks/:id', ({ params, me }) => { db.blocks = db.blocks.filter(b => !(b.blocker === me.id && b.blocked === +params.id)); return { ok: true }; }, true);

  R('POST', '/dm', ({ me, body: b }) => {
    const to = +b.to_id; if (to === me.id) fail(400, "Can't message yourself");
    const other = getUser(to); if (!other.public_key) fail(400, "This sample profile can't receive encrypted messages");
    const st = chatState(me.id, to);
    if (st === 'unavailable') fail(403, "You can't message this person");
    if (st === 'request_out') fail(403, 'Your request is waiting. You can keep chatting once they accept.');
    let status = 'accepted';
    if (st === 'none') {
      if (convo(me.id, to)) convo(me.id, to).status = 'accepted';
      else {
        if (db.convos.filter(c => c.requester === me.id).length >= (isNew(me) ? 3 : 15)) fail(429, "You've sent a lot of requests today. Try again tomorrow.");
        const [x, y] = pair(me.id, to); db.convos.push({ a: x, b: y, requester: me.id, status: 'pending', created: nowIso(), updated: nowIso() }); status = 'pending';
      }
    } else if (st === 'request_in') convo(me.id, to).status = 'accepted';
    db.dms.push({ id: nid('dm'), from_id: me.id, to_id: to, iv: b.iv, ciphertext: b.ciphertext, created: nowIso() });
    botReactions(me, to);
    return { ok: true, status };
  }, true);
  R('GET', '/inbox', ({ me }) => {
    const seen = new Set(), out = [];
    [...db.dms].filter(d => d.from_id === me.id || d.to_id === me.id).sort((a, b) => b.id - a.id).forEach(d => {
      const other = d.from_id === me.id ? d.to_id : d.from_id; if (seen.has(other)) return; seen.add(other);
      const st = chatState(me.id, other); if (st === 'unavailable' || st === 'none') return;
      out.push({ user: getUser(other), iv: d.iv, ciphertext: d.ciphertext, created: d.created, mine: d.from_id === me.id, status: st });
    });
    return out;
  }, true);
  R('GET', '/dm/:other', ({ params, me }) => db.dms.filter(d => (d.from_id === me.id && d.to_id === +params.other) || (d.from_id === +params.other && d.to_id === me.id)).map(d => ({ id: d.id, from_id: d.from_id, iv: d.iv, ciphertext: d.ciphertext, created: d.created })), true);
  const reqAct = status => ({ params, me }) => {
    const c = convo(me.id, +params.id);
    if (!c || c.requester !== +params.id || c.status !== 'pending') fail(404, 'Request not found');
    c.status = status; return { ok: true };
  };
  R('POST', '/requests/:id/accept', reqAct('accepted'), true);
  R('POST', '/requests/:id/decline', reqAct('declined'), true);

  R('POST', '/reports', ({ body: b }) => {
    if (!['child_safety', 'harassment', 'spam', 'scam', 'other'].includes(b.reason)) fail(400, 'Unknown reason');
    return { id: nid('report') };  // the real server stores this for the safety team; the demo just acknowledges it
  }, true);

  /* ---------- fetch shim ---------- */
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = async (input, init = {}) => {
    const raw = typeof input === 'string' ? input : input.url;
    if (!raw.startsWith('/api/')) return realFetch ? realFetch(input, init) : Promise.reject(new TypeError('offline'));
    await ready;
    const url = new URL(raw, 'http://demo.invalid');  // the page's own address can be about:srcdoc, so parse against a dummy base
    const path = url.pathname.slice('/api'.length), method = (init.method || 'GET').toUpperCase();
    const hdr = new Headers(init.headers || {}), auth = hdr.get('authorization') || '';
    const uid = auth.startsWith('Bearer ') ? db.tokens[auth.slice(7)] : null;
    const me = uid ? user(uid) : null;
    for (const r of routes) {
      if (r.method !== method) continue;
      const m = path.match(r.re); if (!m) continue;
      try {
        if (r.auth && !me) fail(401, 'Please sign in');
        const body = init.body ? JSON.parse(init.body) : {};
        return json(await r.fn({ params: m.groups || {}, q: url.searchParams, body, me }));
      } catch (e) {
        if (e instanceof HttpError) return json({ detail: e.detail }, e.status);
        console.error(e); return json({ detail: 'Something went wrong' }, 500);
      }
    }
    return json({ detail: 'Not found' }, 404);
  };
})();
