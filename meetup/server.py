import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_PATH = os.environ.get("HUDDLE_DB", str(BASE / "huddle.db"))

app = FastAPI(title="Huddle")

CATEGORIES = [
    "Outdoors", "Tech", "Food & Drink", "Arts & Culture", "Games", "Sports & Fitness",
    "Books & Writing", "Music", "Language", "Wellness", "Career", "Pets",
]
LOOKING_FOR = ["Friends", "Activity partners", "Networking", "Learning together", "Dating-free socializing", "Mentors"]

ICEBREAKERS = [
    "What's something you're into right now that you could talk about for an hour?",
    "What brought you to this event?",
    "What's the best thing you've done or eaten this month?",
    "If you could instantly master any skill, what would it be?",
    "What's a small thing that always makes your day better?",
    "What's a hobby you've picked up in the last year?",
]




def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, city TEXT NOT NULL, bio TEXT DEFAULT '',
    pronouns TEXT DEFAULT '', interests TEXT DEFAULT '[]', looking_for TEXT DEFAULT '[]',
    created TEXT NOT NULL, public_key TEXT, token_hash TEXT, suspended INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL,
    city TEXT NOT NULL, venue TEXT NOT NULL, starts TEXT NOT NULL, capacity INTEGER NOT NULL,
    host_id INTEGER NOT NULL REFERENCES users(id), tags TEXT DEFAULT '[]', vibe TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rsvps (
    event_id INTEGER NOT NULL REFERENCES events(id), user_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (event_id, user_id)
);
CREATE TABLE IF NOT EXISTS event_messages (
    id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
    user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL
);
-- Direct messages are end-to-end encrypted in the browser. The server only ever stores ciphertext.
CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY, from_id INTEGER NOT NULL REFERENCES users(id),
    to_id INTEGER NOT NULL REFERENCES users(id), iv TEXT NOT NULL, ciphertext TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
    url TEXT DEFAULT '', tags TEXT DEFAULT '[]', city TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id),
    user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, PRIMARY KEY (blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL, kind TEXT NOT NULL, target_id INTEGER NOT NULL,
    target_user_id INTEGER, reason TEXT NOT NULL, details TEXT DEFAULT '', evidence TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open', note TEXT DEFAULT '', created TEXT NOT NULL, resolved TEXT
);
CREATE TABLE IF NOT EXISTS mod_audit (
    id INTEGER PRIMARY KEY, moderator TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT '',
    ip TEXT DEFAULT '', created TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def migrate(conn):
    dm_cols = {r["name"] for r in conn.execute("PRAGMA table_info(dms)")}
    if dm_cols and "iv" not in dm_cols:  # old plaintext DMs can't be carried over
        conn.execute("DROP TABLE dms")
    conn.executescript(SCHEMA)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    for name, ddl in [("public_key", "TEXT"), ("token_hash", "TEXT"), ("suspended", "INTEGER DEFAULT 0"), ("deleted", "INTEGER DEFAULT 0")]:
        if name not in cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")


def seed(conn):
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return
    rnd = random.Random(7)
    people = [
        ("Maya Okafor", "Austin", "she/her", ["Hiking", "Photography", "Coffee", "Board games"], ["Friends", "Activity partners"], "Weekend trail-chaser. Always carrying too many snacks."),
        ("Daniel Reyes", "Austin", "he/him", ["Python", "Startups", "Running", "Coffee"], ["Networking", "Learning together"], "Backend dev, recovering marathon over-trainer."),
        ("Sam Lindqvist", "Austin", "they/them", ["Board games", "Cooking", "Books", "Sci-fi"], ["Friends"], "I will absolutely teach you Catan, whether you like it or not."),
        ("Priya Nair", "Austin", "she/her", ["Yoga", "Meditation", "Cooking", "Travel"], ["Friends", "Activity partners"], "New in town and trying every taco truck."),
        ("Tomás Silva", "Austin", "he/him", ["Guitar", "Live music", "Coffee", "Languages"], ["Friends", "Learning together"], "Learning Japanese, teaching Portuguese."),
        ("Jordan Blake", "Austin", "", ["Running", "Cycling", "Climbing", "Hiking"], ["Activity partners"], "If it has a summit or a finish line I'm in."),
        ("Aisha Rahman", "Austin", "she/her", ["Design", "Startups", "Photography", "Art"], ["Networking", "Mentors"], "Product designer. Happy to review your portfolio."),
        ("Leo Chen", "Austin", "he/him", ["Python", "Machine learning", "Board games", "Sci-fi"], ["Learning together", "Friends"], "Reading group organizer, bad at poker faces."),
    ]
    for name, city, pr, ints, looking, bio in people:
        conn.execute(
            "INSERT INTO users (name, city, bio, pronouns, interests, looking_for, created) VALUES (?,?,?,?,?,?,?)",
            (name, city, bio, pr, json.dumps(ints), json.dumps(looking), now()),
        )
    base = datetime.now().replace(minute=0, second=0, microsecond=0)
    events = [
        ("Sunrise Hike at Barton Creek", "An easy 5 km loop to start the weekend. All paces welcome, we wait at every turn. Coffee after at the trailhead.", "Outdoors", "Trailhead Lot B", 2, 6, 12, 1, ["Hiking", "Photography", "Coffee"], "Chill & beginner-friendly"),
        ("Beginner Python Study Circle", "Bring a laptop and a small project idea. We pair up, help each other get unstuck, and share what we built.", "Tech", "Public Library, Room 3", 3, 19, 10, 2, ["Python", "Learning", "Startups"], "Collaborative, no experience needed"),
        ("Board Game Night: Newcomers Welcome", "We have 30+ games and patient teachers. Solo attendees are the norm here, nobody will leave you standing alone.", "Games", "Gnome's Hollow Cafe", 4, 18, 16, 3, ["Board games", "Sci-fi", "Cooking"], "Friendly, low-pressure"),
        ("Taco Truck Crawl", "Three trucks, small bites, zero pretension. We'll swap favorite spots and plan the next crawl.", "Food & Drink", "Meet at East 6th Fountain", 5, 17, 14, 4, ["Cooking", "Travel", "Coffee"], "Casual & curious"),
        ("Japanese & Portuguese Language Swap", "Half the evening in each language, with a timer so everyone gets a turn. Every level is welcome.", "Language", "Mellow Johnny's Cafe", 6, 19, 20, 5, ["Languages", "Travel", "Live music"], "Relaxed, supportive"),
        ("Morning 5K + Coffee", "Conversational pace run, then coffee. Walkers welcome, we'll set up a walking group too.", "Sports & Fitness", "Lady Bird Lake Boardwalk", 7, 7, 25, 6, ["Running", "Cycling", "Coffee"], "Easy pace, inclusive"),
        ("Portfolio Feedback Jam", "Bring work in progress for kind, specific feedback from designers and builders. Mentors and mentees both welcome.", "Career", "Co-work Loft", 8, 18, 18, 7, ["Design", "Startups", "Art"], "Supportive, growth-minded"),
        ("Sci-Fi Book Club: Discussion + Drinks", "This month's pick, plus a quick vote on the next one. Haven't finished it? Come anyway.", "Books & Writing", "Book People Reading Nook", 9, 19, 15, 8, ["Sci-fi", "Books", "Board games"], "Thoughtful & fun"),
        ("Sunset Yoga in the Park", "Gentle all-levels flow followed by tea. Mats provided if you need one.", "Wellness", "Zilker Great Lawn", 10, 18, 25, 4, ["Yoga", "Meditation", "Travel"], "Calm, welcoming"),
    ]
    for title, desc, cat, venue, days, hour, cap, host, tags, vibe in events:
        starts = (base + timedelta(days=days)).replace(hour=hour).isoformat(timespec="minutes")
        conn.execute(
            "INSERT INTO events (title, description, category, city, venue, starts, capacity, host_id, tags, vibe) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (title, desc, cat, "Austin", venue, starts, cap, host, json.dumps(tags), vibe),
        )
    for eid in range(1, len(events) + 1):
        pool = list(range(1, len(people) + 1))
        rnd.shuffle(pool)
        for uid in pool[: rnd.randint(3, 6)]:
            conn.execute("INSERT OR IGNORE INTO rsvps VALUES (?,?)", (eid, uid))
        conn.execute("INSERT OR IGNORE INTO rsvps VALUES (?,?)", (eid, events[eid - 1][7]))
    conn.execute("INSERT INTO event_messages (event_id,user_id,body,created) VALUES (1,1,'Reminder: bring water and a layer, it is chilly at sunrise!',?)", (now(),))
    conn.execute("INSERT INTO event_messages (event_id,user_id,body,created) VALUES (1,6,'First time here, can I bring a friend?',?)", (now(),))
    conn.execute("INSERT INTO event_messages (event_id,user_id,body,created) VALUES (3,3,'I will bring Wingspan and Azul for beginners.',?)", (now(),))
    conn.commit()



def seed_posts(conn):
    if conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0] or not conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        return
    samples = [
        (1, "Barton Creek is flowing again after the rain. Saw a great blue heron on the sunrise loop today!", "", ["Hiking", "Photography"]),
        (2, "Handy find: the Austin library now lends out laptops and wifi hotspots for free. Great if you're learning to code.", "https://library.austintexas.gov", ["Python"]),
        (3, "Anyone tried Heat: Pedal to the Metal? Looking for opinions before game night on Wednesday.", "", ["Board games"]),
        (5, "Small tip for language learners: ten minutes of speaking out loud beats an hour of flashcards.", "", ["Languages"]),
        (6, "Lady Bird Lake trail has a new water fountain at the east end. Good news for long runs!", "", ["Running", "Cycling"]),
        (4, "Found a lovely beginner yoga video series that doesn't require any equipment. Happy to share if anyone wants.", "", ["Yoga", "Meditation"]),
    ]
    for i, (uid, body, url, tags) in enumerate(samples):
        when = (datetime.now(timezone.utc) - timedelta(hours=3 + i * 7)).isoformat(timespec="seconds")
        conn.execute("INSERT INTO posts (user_id, body, url, tags, city, created) VALUES (?,?,?,?,?,?)", (uid, body, url, json.dumps(tags), "Austin", when))
    conn.execute("INSERT INTO replies (post_id, user_id, body, created) VALUES (1, 6, 'Love that loop. Was it busy?', ?)", (now(),))
    conn.commit()


@app.on_event("startup")
def startup():
    with db() as conn:
        migrate(conn)
        seed(conn)
        seed_posts(conn)


# ── Abuse protection ──────────────────────────────────────────────────────────
class Limiter:
    """Sliding-window rate limiter (in-memory; use Redis if you run more than one process)."""

    def __init__(self):
        self.hits = defaultdict(deque)

    def check(self, key, n, window, msg="You're doing that too fast. Please slow down."):
        t = time.time()
        q = self.hits[key]
        while q and q[0] < t - window:
            q.popleft()
        if len(q) >= n:
            raise HTTPException(429, msg)
        q.append(t)

    def clear(self):
        self.hits.clear()


limiter = Limiter()
HOUR, DAY = 3600, 86400
SECRET = (os.environ.get("HUDDLE_SECRET") or "").encode() or secrets.token_bytes(32)
POW_BASE_BITS = 16
POW_TTL = 600
_used_pow = {}
_recent_signups = deque()


def client_ip(request: Request):
    if os.environ.get("HUDDLE_TRUST_PROXY") == "1":
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def pow_bits():
    """Sign-up gets costlier for bots automatically when sign-ups spike."""
    t = time.time()
    while _recent_signups and _recent_signups[0] < t - HOUR:
        _recent_signups.popleft()
    return POW_BASE_BITS + min(6, len(_recent_signups) // 25)


def _sig(payload: str):
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]


def make_challenge():
    payload = f"{int(time.time())}.{secrets.token_hex(8)}.{pow_bits()}"
    return {"challenge": f"{payload}.{_sig(payload)}", "bits": pow_bits()}


def verify_pow(challenge: str, counter: str):
    parts = challenge.split(".")
    if len(parts) != 4 or not counter.isdigit() or len(counter) > 12:
        raise HTTPException(400, "Invalid human check")
    payload = ".".join(parts[:3])
    if not hmac.compare_digest(parts[3], _sig(payload)):
        raise HTTPException(400, "Invalid human check")
    ts, bits = int(parts[0]), int(parts[2])
    t = time.time()
    if t - ts > POW_TTL:
        raise HTTPException(400, "Human check expired, please try again")
    for k in [k for k, v in _used_pow.items() if t - v > POW_TTL]:
        del _used_pow[k]
    if challenge in _used_pow:
        raise HTTPException(400, "Human check already used")
    digest = hashlib.sha256(f"{challenge}:{counter}".encode()).digest()
    if 256 - int.from_bytes(digest, "big").bit_length() < bits:
        raise HTTPException(400, "Human check failed")
    _used_pow[challenge] = t


def is_new(u):
    return datetime.now(timezone.utc) - datetime.fromisoformat(u["created"]) < timedelta(hours=24)


# ── Auth ──────────────────────────────────────────────────────────────────────
def _auth(request: Request, required: bool):
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer "):
        if required:
            raise HTTPException(401, "Please sign in")
        return None
    th = hashlib.sha256(h[7:].encode()).hexdigest()
    with db() as conn:
        r = conn.execute("SELECT * FROM users WHERE token_hash=?", (th,)).fetchone()
    if not r:
        if required:
            raise HTTPException(401, "Please sign in")
        return None
    if r["suspended"]:
        raise HTTPException(403, "This account has been suspended")
    return {**user_dict(r), "created": r["created"]}


def me_req(request: Request):
    return _auth(request, True)


def me_opt(request: Request):
    return _auth(request, False)


def user_dict(r):
    return {
        "id": r["id"], "name": r["name"], "city": r["city"], "bio": r["bio"], "pronouns": r["pronouns"],
        "interests": json.loads(r["interests"]), "looking_for": json.loads(r["looking_for"]),
        "public_key": json.loads(r["public_key"]) if r["public_key"] else None,
    }


def get_user(conn, uid):
    r = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not r:
        raise HTTPException(404, "User not found")
    return user_dict(r)


def shared(a, b):
    sa = {i.lower() for i in a["interests"]}
    return [i for i in b["interests"] if i.lower() in sa]


def event_dict(conn, r, viewer=None):
    attendees = [
        user_dict(u) for u in conn.execute(
            "SELECT u.* FROM users u JOIN rsvps s ON s.user_id=u.id WHERE s.event_id=? ORDER BY s.rowid", (r["id"],)
        )
    ]
    d = {
        "id": r["id"], "title": r["title"], "description": r["description"], "category": r["category"],
        "city": r["city"], "venue": r["venue"], "starts": r["starts"], "capacity": r["capacity"],
        "tags": json.loads(r["tags"]), "vibe": r["vibe"],
        "host": get_user(conn, r["host_id"]), "attendee_count": len(attendees),
        "spots_left": max(0, r["capacity"] - len(attendees)),
        "attendees": attendees,
    }
    if viewer:
        d["going"] = any(a["id"] == viewer["id"] for a in attendees)
        for a in attendees:
            a["shared"] = shared(viewer, a) if a["id"] != viewer["id"] else []
        d["fit"] = len(shared(viewer, {"interests": d["tags"]}))
        d["people_like_you"] = sum(1 for a in attendees if a["id"] != viewer["id"] and a["shared"])
    return d


@app.get("/api/meta")
def meta():
    return {"categories": CATEGORIES, "looking_for": LOOKING_FOR}


@app.get("/api/events")
def list_events(q: str = "", category: str = "", city: str = "", sort: str = "soon", v=Depends(me_opt)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM events WHERE starts >= ? ORDER BY starts", (datetime.now().isoformat(timespec="minutes"),)).fetchall()
        out = []
        for r in rows:
            if category and r["category"] != category:
                continue
            if city and city.lower() not in r["city"].lower():
                continue
            if q:
                hay = " ".join([r["title"], r["description"], r["category"], r["tags"], r["venue"]]).lower()
                if not all(t in hay for t in q.lower().split()):
                    continue
            ev = event_dict(conn, r, v)
            ev["attendees"] = ev["attendees"][:5]  # preview only
            out.append(ev)
        if v and sort == "match":
            out.sort(key=lambda e: (-(e["fit"] * 2 + e["people_like_you"]), e["starts"]))
        return out


@app.get("/api/events/{eid}")
def get_event(eid: int, v=Depends(me_opt)):
    with db() as conn:
        r = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not r:
            raise HTTPException(404, "Event not found")
        ev = event_dict(conn, r, v)
        hide = hidden_users(conn, v["id"] if v else 0)
        ev["messages"] = [
            {"id": m["id"], "body": m["body"], "created": m["created"], "user": get_user(conn, m["user_id"])}
            for m in conn.execute("SELECT * FROM event_messages WHERE event_id=? ORDER BY id", (eid,))
            if m["user_id"] not in hide
        ]
        ev["icebreakers"] = random.Random(eid).sample(ICEBREAKERS, 3)
        return ev


class EventIn(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    category: str
    city: str = Field(min_length=2, max_length=80)
    venue: str = Field(min_length=2, max_length=120)
    starts: str
    capacity: int = Field(ge=2, le=500)
    tags: list[str] = []
    vibe: str = Field(default="", max_length=80)


@app.post("/api/events")
def create_event(e: EventIn, me=Depends(me_req)):
    if e.category not in CATEGORIES:
        raise HTTPException(400, "Unknown category")
    try:
        datetime.fromisoformat(e.starts)
    except ValueError:
        raise HTTPException(400, "Invalid start time")
    limiter.check(f"host:{me['id']}", 1 if is_new(me) else 5, DAY, "New accounts can host 1 event a day; others 5.")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO events (title, description, category, city, venue, starts, capacity, host_id, tags, vibe) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (e.title.strip(), e.description.strip(), e.category, e.city.strip(), e.venue.strip(), e.starts, e.capacity, me["id"], json.dumps(clean_list(e.tags, 8)), e.vibe.strip()),
        )
        conn.execute("INSERT INTO rsvps VALUES (?,?)", (cur.lastrowid, me["id"]))
        return {"id": cur.lastrowid}


@app.post("/api/events/{eid}/rsvp")
def rsvp(eid: int, me=Depends(me_req)):
    limiter.check(f"rsvp:{me['id']}", 10 if is_new(me) else 60, DAY, "RSVP limit reached for today.")
    with db() as conn:
        r = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not r:
            raise HTTPException(404, "Event not found")
        count = conn.execute("SELECT COUNT(*) FROM rsvps WHERE event_id=?", (eid,)).fetchone()[0]
        already = conn.execute("SELECT 1 FROM rsvps WHERE event_id=? AND user_id=?", (eid, me["id"])).fetchone()
        if not already and count >= r["capacity"]:
            raise HTTPException(409, "This event is full")
        conn.execute("INSERT OR IGNORE INTO rsvps VALUES (?,?)", (eid, me["id"]))
        return {"ok": True}


@app.delete("/api/events/{eid}/rsvp")
def cancel_rsvp(eid: int, me=Depends(me_req)):
    with db() as conn:
        conn.execute("DELETE FROM rsvps WHERE event_id=? AND user_id=?", (eid, me["id"]))
        return {"ok": True}


class MsgIn(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


@app.post("/api/events/{eid}/messages")
def post_message(eid: int, m: MsgIn, me=Depends(me_req)):
    limiter.check(f"emsg-min:{me['id']}", 8, 60)
    limiter.check(f"emsg-hr:{me['id']}", 30 if is_new(me) else 120, HOUR)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM rsvps WHERE event_id=? AND user_id=?", (eid, me["id"])).fetchone():
            raise HTTPException(403, "RSVP to join the conversation")
        body = m.body.strip()
        last = conn.execute("SELECT body FROM event_messages WHERE event_id=? AND user_id=? ORDER BY id DESC LIMIT 1", (eid, me["id"])).fetchone()
        if last and last["body"] == body:
            raise HTTPException(400, "You already posted that")
        conn.execute("INSERT INTO event_messages (event_id,user_id,body,created) VALUES (?,?,?,?)", (eid, me["id"], body, now()))
        return {"ok": True}


def clean_list(xs, n):
    seen, out = set(), []
    for x in xs:
        x = x.strip()[:30]
        if x and x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out[:n]


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    city: str = Field(min_length=2, max_length=80)
    bio: str = Field(default="", max_length=400)
    pronouns: str = Field(default="", max_length=30)
    interests: list[str] = []
    looking_for: list[str] = []


class PowIn(BaseModel):
    challenge: str
    counter: str


class SignupIn(ProfileIn):
    birth_date: str  # used once to confirm 18+, never stored
    public_key: dict  # ECDH P-256 public JWK, generated in the browser
    pow: PowIn
    website: str = ""  # honeypot: real users never fill this in


def valid_pubkey(k):
    return (
        k.get("kty") == "EC" and k.get("crv") == "P-256" and "d" not in k
        and all(isinstance(k.get(f), str) and 40 <= len(k[f]) <= 50 for f in ("x", "y"))
    )


@app.get("/api/pow")
def get_pow(request: Request):
    limiter.check(f"pow:{client_ip(request)}", 30, HOUR)
    return make_challenge()


@app.post("/api/signup")
def signup(u: SignupIn, request: Request):
    ip = client_ip(request)
    if u.website:  # bot filled the hidden field; pretend it worked
        raise HTTPException(400, "Could not create account")
    limiter.check(f"signup-h:{ip}", 5, HOUR, "Too many sign-ups from your network. Try again later.")
    limiter.check(f"signup-d:{ip}", 15, DAY, "Too many sign-ups from your network. Try again later.")
    try:
        born = date.fromisoformat(u.birth_date)
    except ValueError:
        raise HTTPException(400, "Enter a valid birth date")
    today = date.today()
    if today.year - born.year - ((today.month, today.day) < (born.month, born.day)) < 18:
        raise HTTPException(403, "Huddle is for adults aged 18 and over")
    if not valid_pubkey(u.public_key):
        raise HTTPException(400, "Invalid encryption key")
    verify_pow(u.pow.challenge, u.pow.counter)
    token = secrets.token_urlsafe(32)
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO users (name, city, bio, pronouns, interests, looking_for, created, public_key, token_hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (u.name.strip(), u.city.strip(), u.bio.strip(), u.pronouns.strip(), json.dumps(clean_list(u.interests, 12)),
             json.dumps(clean_list(u.looking_for, 6)), now(), json.dumps(u.public_key), hashlib.sha256(token.encode()).hexdigest()),
        )
        _recent_signups.append(time.time())
        return {"user": get_user(conn, cur.lastrowid), "token": token}


@app.get("/api/me")
def whoami(me=Depends(me_req)):
    return me


@app.put("/api/me")
def update_me(u: ProfileIn, me=Depends(me_req)):
    with db() as conn:
        conn.execute(
            "UPDATE users SET name=?, city=?, bio=?, pronouns=?, interests=?, looking_for=? WHERE id=?",
            (u.name.strip(), u.city.strip(), u.bio.strip(), u.pronouns.strip(), json.dumps(clean_list(u.interests, 12)), json.dumps(clean_list(u.looking_for, 6)), me["id"]),
        )
        return get_user(conn, me["id"])


@app.get("/api/users/{uid}")
def profile(uid: int, v=Depends(me_opt)):
    with db() as conn:
        u = get_user(conn, uid)
        if conn.execute("SELECT deleted FROM users WHERE id=?", (uid,)).fetchone()["deleted"]:
            raise HTTPException(404, "This account no longer exists")
        u["events"] = [
            {"id": r["id"], "title": r["title"], "starts": r["starts"], "category": r["category"]}
            for r in conn.execute(
                "SELECT e.* FROM events e JOIN rsvps s ON s.event_id=e.id WHERE s.user_id=? AND e.starts>=? ORDER BY e.starts",
                (uid, datetime.now().isoformat(timespec="minutes")),
            )
        ]
        if v and v["id"] != uid:
            u["shared"] = shared(v, u)
            u["shared_events"] = [
                r["title"] for r in conn.execute(
                    "SELECT e.title FROM events e JOIN rsvps a ON a.event_id=e.id AND a.user_id=? "
                    "JOIN rsvps b ON b.event_id=e.id AND b.user_id=?", (uid, v["id"])
                )
            ]
            u["blocked"] = bool(conn.execute("SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (v["id"], uid)).fetchone())
            u["can_message"] = dm_allowed(conn, v["id"], uid)[0]
        return u


@app.get("/api/me/matches")
def matches(me=Depends(me_req)):
    """People you may click with: shared interests + shared goals + same city + events in common."""
    uid = me["id"]
    with db() as conn:
        out = []
        for r in conn.execute("SELECT * FROM users WHERE id != ? AND suspended=0 AND deleted=0", (uid,)):
            o = user_dict(r)
            sh = shared(me, o)
            goals = [g for g in o["looking_for"] if g in me["looking_for"]]
            common = conn.execute(
                "SELECT COUNT(*) FROM rsvps a JOIN rsvps b ON a.event_id=b.event_id WHERE a.user_id=? AND b.user_id=?", (uid, o["id"])
            ).fetchone()[0]
            score = len(sh) * 3 + len(goals) * 2 + common * 2 + (2 if o["city"].lower() == me["city"].lower() else 0)
            if sh or goals:
                o.update(shared=sh, shared_goals=goals, events_in_common=common, score=score, can_message=dm_allowed(conn, uid, o["id"])[0])
                out.append(o)
        out.sort(key=lambda x: -x["score"])
        return out[:12]


# ── Blocks ────────────────────────────────────────────────────────────────────
@app.put("/api/blocks/{uid}")
def block(uid: int, me=Depends(me_req)):
    with db() as conn:
        get_user(conn, uid)
        conn.execute("INSERT OR IGNORE INTO blocks VALUES (?,?)", (me["id"], uid))
        return {"ok": True}


@app.delete("/api/blocks/{uid}")
def unblock(uid: int, me=Depends(me_req)):
    with db() as conn:
        conn.execute("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?", (me["id"], uid))
        return {"ok": True}


@app.get("/api/blocks")
def list_blocks(me=Depends(me_req)):
    with db() as conn:
        return [get_user(conn, r["blocked_id"]) for r in conn.execute("SELECT blocked_id FROM blocks WHERE blocker_id=?", (me["id"],))]


def hidden_users(conn, viewer_id):
    """Ids whose content a viewer should not see (they blocked them, or were blocked by them)."""
    if not viewer_id:
        return set()
    return {
        r["blocked_id"] if r["blocker_id"] == viewer_id else r["blocker_id"]
        for r in conn.execute("SELECT * FROM blocks WHERE blocker_id=? OR blocked_id=?", (viewer_id, viewer_id))
    }


def dm_allowed(conn, a, b):
    """(allowed, is_new_conversation). You can message people you share an event with, or already talk to."""
    other = conn.execute("SELECT public_key, deleted, suspended FROM users WHERE id=?", (b,)).fetchone()
    if not other or not other["public_key"] or other["deleted"] or other["suspended"] or a == b or blocked_either_way(conn, a, b):
        return False, False
    if conn.execute("SELECT 1 FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) LIMIT 1", (a, b, b, a)).fetchone():
        return True, False
    met = conn.execute("SELECT 1 FROM rsvps x JOIN rsvps y ON x.event_id=y.event_id WHERE x.user_id=? AND y.user_id=? LIMIT 1", (a, b)).fetchone()
    return bool(met), True


def blocked_either_way(conn, a, b):
    return bool(conn.execute(
        "SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)", (a, b, b, a)
    ).fetchone())


# ── End-to-end encrypted direct messages ──────────────────────────────────────
# The browser derives a shared AES-GCM key from ECDH(my private key, their public key).
# The server stores only (iv, ciphertext) and has no key, so it cannot read any DM.
class DmIn(BaseModel):
    to_id: int
    iv: str = Field(max_length=64)
    ciphertext: str = Field(min_length=8, max_length=8000)


def _b64_ok(s):
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


@app.post("/api/dm")
def send_dm(d: DmIn, me=Depends(me_req)):
    if d.to_id == me["id"]:
        raise HTTPException(400, "Can't message yourself")
    if not (_b64_ok(d.iv) and _b64_ok(d.ciphertext)):
        raise HTTPException(400, "Malformed message")
    with db() as conn:
        other = get_user(conn, d.to_id)
        if not other["public_key"]:
            raise HTTPException(400, "This sample profile can't receive encrypted messages")
        if blocked_either_way(conn, me["id"], d.to_id):
            raise HTTPException(403, "You can't message this person")
        ok, new_convo = dm_allowed(conn, me["id"], d.to_id)
        if not ok:
            # Safety: you can only start a conversation with someone you share an event with.
            raise HTTPException(403, "You can message people once you've RSVP'd to the same event")
        if new_convo:
            limiter.check(f"dm-new:{me['id']}", 3 if is_new(me) else 15, DAY, "New-conversation limit reached for today.")
        limiter.check(f"dm-min:{me['id']}", 15, 60)
        limiter.check(f"dm-hr:{me['id']}", 60 if is_new(me) else 300, HOUR)
        conn.execute("INSERT INTO dms (from_id,to_id,iv,ciphertext,created) VALUES (?,?,?,?,?)", (me["id"], d.to_id, d.iv, d.ciphertext, now()))
        return {"ok": True}


@app.get("/api/inbox")
def inbox(me=Depends(me_req)):
    uid = me["id"]
    with db() as conn:
        rows = conn.execute("SELECT * FROM dms WHERE from_id=? OR to_id=? ORDER BY id DESC", (uid, uid)).fetchall()
        seen, threads = set(), []
        for r in rows:
            other = r["to_id"] if r["from_id"] == uid else r["from_id"]
            if other in seen:
                continue
            seen.add(other)
            if blocked_either_way(conn, uid, other):
                continue
            threads.append({"user": get_user(conn, other), "iv": r["iv"], "ciphertext": r["ciphertext"], "created": r["created"], "mine": r["from_id"] == uid})
        return threads


@app.get("/api/dm/{other}")
def thread(other: int, me=Depends(me_req)):
    uid = me["id"]
    with db() as conn:
        return [
            {"id": r["id"], "from_id": r["from_id"], "iv": r["iv"], "ciphertext": r["ciphertext"], "created": r["created"]}
            for r in conn.execute(
                "SELECT * FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id", (uid, other, other, uid)
            )
        ]


# ── Delete account ────────────────────────────────────────────────────────────
@app.delete("/api/me")
def delete_me(me=Depends(me_req)):
    """Erase the account: messages, posts, RSVPs, hosted events and keys. The row is scrubbed, not kept.
    Safety reports that mention the account are retained so abuse can still be investigated."""
    uid = me["id"]
    with db() as conn:
        conn.execute("DELETE FROM dms WHERE from_id=? OR to_id=?", (uid, uid))
        conn.execute("DELETE FROM blocks WHERE blocker_id=? OR blocked_id=?", (uid, uid))
        for e in [r["id"] for r in conn.execute("SELECT id FROM events WHERE host_id=?", (uid,))]:
            conn.execute("DELETE FROM event_messages WHERE event_id=?", (e,))
            conn.execute("DELETE FROM rsvps WHERE event_id=?", (e,))
            conn.execute("DELETE FROM events WHERE id=?", (e,))
        conn.execute("DELETE FROM event_messages WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM rsvps WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM replies WHERE user_id=? OR post_id IN (SELECT id FROM posts WHERE user_id=?)", (uid, uid))
        conn.execute("DELETE FROM posts WHERE user_id=?", (uid,))
        conn.execute(
            "UPDATE users SET name='Deleted user', city='', bio='', pronouns='', interests='[]', looking_for='[]', "
            "public_key=NULL, token_hash=NULL, deleted=1 WHERE id=?", (uid,),
        )
    return {"ok": True}


# ── Feed: share news and interests ────────────────────────────────────────────
LINK_RE = re.compile(r"https?://|www\.", re.I)


class PostIn(BaseModel):
    body: str = Field(min_length=1, max_length=500)
    url: str = Field(default="", max_length=300)
    tags: list[str] = []


def clean_url(u):
    u = u.strip()
    if not u:
        return ""
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.netloc or " " in u:
        raise HTTPException(400, "That link doesn't look right. It should start with http:// or https://")
    return u


def post_dict(conn, r, viewer_id=0):
    return {
        "id": r["id"], "body": r["body"], "url": r["url"], "tags": json.loads(r["tags"]), "city": r["city"], "created": r["created"],
        "author": get_user(conn, r["user_id"]), "mine": r["user_id"] == viewer_id,
        "reply_count": conn.execute("SELECT COUNT(*) FROM replies WHERE post_id=?", (r["id"],)).fetchone()[0],
    }


@app.get("/api/posts")
def list_posts(scope: str = "foryou", tag: str = "", v=Depends(me_opt)):
    with db() as conn:
        hide = hidden_users(conn, v["id"] if v else 0)
        rows = conn.execute(
            "SELECT p.* FROM posts p JOIN users u ON u.id=p.user_id WHERE u.suspended=0 AND u.deleted=0 ORDER BY p.id DESC LIMIT 200"
        ).fetchall()
        out = []
        for rank, r in enumerate(rows):
            if r["user_id"] in hide:
                continue
            tags = json.loads(r["tags"])
            if tag and tag.lower() not in [t.lower() for t in tags]:
                continue
            same_city = bool(v) and r["city"].lower() == v["city"].lower()
            if scope == "near" and not same_city:
                continue
            p = post_dict(conn, r, v["id"] if v else 0)
            overlap = len(shared(v, {"interests": tags})) if v else 0
            p["_score"] = overlap * 3 + (2 if same_city else 0) - rank * 0.05
            p["match"] = shared(v, {"interests": tags}) if v else []
            out.append(p)
        if scope == "foryou" and v:
            out.sort(key=lambda p: -p["_score"])
        for p in out:
            p.pop("_score")
        return out[:60]


@app.post("/api/posts")
def create_post(p: PostIn, me=Depends(me_req)):
    body = p.body.strip()
    if not body:
        raise HTTPException(400, "Write something first")
    url = clean_url(p.url)
    if is_new(me) and (url or LINK_RE.search(body)):
        raise HTTPException(403, "Links unlock after your first day on Huddle. It keeps spam out.")
    limiter.check(f"post:{me['id']}", 3 if is_new(me) else 20, DAY, "You've reached today's posting limit.")
    limiter.check(f"post-min:{me['id']}", 3, 60)
    with db() as conn:
        last = conn.execute("SELECT body FROM posts WHERE user_id=? ORDER BY id DESC LIMIT 1", (me["id"],)).fetchone()
        if last and last["body"] == body:
            raise HTTPException(400, "You already posted that")
        cur = conn.execute(
            "INSERT INTO posts (user_id, body, url, tags, city, created) VALUES (?,?,?,?,?,?)",
            (me["id"], body, url, json.dumps(clean_list(p.tags, 3)), me["city"], now()),
        )
        return {"id": cur.lastrowid}


@app.get("/api/posts/{pid}")
def get_post(pid: int, v=Depends(me_opt)):
    with db() as conn:
        r = conn.execute("SELECT p.* FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=? AND u.suspended=0", (pid,)).fetchone()
        vid = v["id"] if v else 0
        hide = hidden_users(conn, vid)
        if not r or r["user_id"] in hide:
            raise HTTPException(404, "Post not found")
        out = post_dict(conn, r, vid)
        out["replies"] = [
            {"id": x["id"], "body": x["body"], "created": x["created"], "author": get_user(conn, x["user_id"]), "mine": x["user_id"] == vid}
            for x in conn.execute("SELECT * FROM replies WHERE post_id=? ORDER BY id", (pid,)) if x["user_id"] not in hide
        ]
        return out


class ReplyIn(BaseModel):
    body: str = Field(min_length=1, max_length=500)


@app.post("/api/posts/{pid}/replies")
def reply(pid: int, rp: ReplyIn, me=Depends(me_req)):
    body = rp.body.strip()
    if not body:
        raise HTTPException(400, "Write something first")
    if is_new(me) and LINK_RE.search(body):
        raise HTTPException(403, "Links unlock after your first day on Huddle. It keeps spam out.")
    limiter.check(f"reply-min:{me['id']}", 6, 60)
    limiter.check(f"reply-hr:{me['id']}", 20 if is_new(me) else 120, HOUR)
    with db() as conn:
        p = conn.execute("SELECT user_id FROM posts WHERE id=?", (pid,)).fetchone()
        if not p:
            raise HTTPException(404, "Post not found")
        if p["user_id"] in hidden_users(conn, me["id"]):
            raise HTTPException(403, "You can't reply to this post")
        conn.execute("INSERT INTO replies (post_id, user_id, body, created) VALUES (?,?,?,?)", (pid, me["id"], body, now()))
        return {"ok": True}


@app.delete("/api/posts/{pid}")
def delete_post(pid: int, me=Depends(me_req)):
    with db() as conn:
        r = conn.execute("SELECT user_id FROM posts WHERE id=?", (pid,)).fetchone()
        if not r or r["user_id"] != me["id"]:
            raise HTTPException(404, "Post not found")
        conn.execute("DELETE FROM replies WHERE post_id=?", (pid,))
        conn.execute("DELETE FROM posts WHERE id=?", (pid,))
        return {"ok": True}


@app.delete("/api/replies/{rid}")
def delete_reply(rid: int, me=Depends(me_req)):
    with db() as conn:
        r = conn.execute("SELECT user_id FROM replies WHERE id=?", (rid,)).fetchone()
        if not r or r["user_id"] != me["id"]:
            raise HTTPException(404, "Reply not found")
        conn.execute("DELETE FROM replies WHERE id=?", (rid,))
        return {"ok": True}


# ── Reports (the only way moderators ever see DM content) ─────────────────────
REPORT_REASONS = ["child_safety", "harassment", "spam", "scam", "other"]


class ReportIn(BaseModel):
    kind: str  # dm | event_message | user | event | post | reply
    target_id: int
    reason: str
    details: str = Field(default="", max_length=1000)
    key: str = ""  # dm only: base64 of the pair's AES key, which the reporter chooses to disclose


def decrypt_thread(conn, a, b, key_b64):
    try:
        key = base64.b64decode(key_b64, validate=True)
        aes = AESGCM(key)
    except Exception:
        raise HTTPException(400, "Invalid conversation key")
    rows = conn.execute(
        "SELECT * FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id DESC LIMIT 100", (a, b, b, a)
    ).fetchall()
    if not rows:
        raise HTTPException(400, "There are no messages to report")
    out = []
    for r in reversed(rows):
        try:
            text = aes.decrypt(base64.b64decode(r["iv"]), base64.b64decode(r["ciphertext"]), None).decode()
        except Exception:
            raise HTTPException(400, "That key does not match this conversation")
        out.append({"from_id": r["from_id"], "text": text, "sent": r["created"]})
    return out


@app.post("/api/reports")
def create_report(rep: ReportIn, me=Depends(me_req)):
    if rep.reason not in REPORT_REASONS:
        raise HTTPException(400, "Unknown reason")
    limiter.check(f"report:{me['id']}", 20, DAY, "Report limit reached for today.")
    with db() as conn:
        target_user, evidence = None, {}
        if rep.kind == "dm":
            target_user = get_user(conn, rep.target_id)["id"]
            evidence = {"messages": decrypt_thread(conn, me["id"], target_user, rep.key)}
        elif rep.kind == "event_message":
            m = conn.execute("SELECT * FROM event_messages WHERE id=?", (rep.target_id,)).fetchone()
            if not m:
                raise HTTPException(404, "Message not found")
            target_user = m["user_id"]
            evidence = {"event_id": m["event_id"], "body": m["body"], "posted": m["created"]}
        elif rep.kind == "user":
            target_user = get_user(conn, rep.target_id)["id"]
            u = get_user(conn, target_user)
            evidence = {"name": u["name"], "bio": u["bio"], "interests": u["interests"]}
        elif rep.kind == "post":
            p = conn.execute("SELECT * FROM posts WHERE id=?", (rep.target_id,)).fetchone()
            if not p:
                raise HTTPException(404, "Post not found")
            target_user = p["user_id"]
            evidence = {"body": p["body"], "url": p["url"], "posted": p["created"]}
        elif rep.kind == "reply":
            p = conn.execute("SELECT * FROM replies WHERE id=?", (rep.target_id,)).fetchone()
            if not p:
                raise HTTPException(404, "Reply not found")
            target_user = p["user_id"]
            evidence = {"post_id": p["post_id"], "body": p["body"], "posted": p["created"]}
        elif rep.kind == "event":
            e = conn.execute("SELECT * FROM events WHERE id=?", (rep.target_id,)).fetchone()
            if not e:
                raise HTTPException(404, "Event not found")
            target_user = e["host_id"]
            evidence = {"title": e["title"], "description": e["description"], "venue": e["venue"]}
        else:
            raise HTTPException(400, "Unknown report type")
        if target_user == me["id"]:
            raise HTTPException(400, "You can't report yourself")
        cur = conn.execute(
            "INSERT INTO reports (reporter_id, kind, target_id, target_user_id, reason, details, evidence, created) VALUES (?,?,?,?,?,?,?,?)",
            (me["id"], rep.kind, rep.target_id, target_user, rep.reason, rep.details.strip(), json.dumps(evidence), now()),
        )
        return {"id": cur.lastrowid}


# ── Moderator API ─────────────────────────────────────────────────────────────
# Authenticated with HUDDLE_MOD_KEY (X-Mod-Key header). Moderators can read public content and
# reports. They can NOT read DMs: the server has no keys. Every call is written to an audit log.
def mod_req(request: Request):
    key = os.environ.get("HUDDLE_MOD_KEY", "")
    if len(key) < 24:
        raise HTTPException(503, "Moderator API is disabled (set HUDDLE_MOD_KEY, 24+ characters)")
    limiter.check(f"mod-auth:{client_ip(request)}", 60, 60, "Too many requests")
    if not hmac.compare_digest(request.headers.get("x-mod-key", "").encode(), key.encode()):
        raise HTTPException(401, "Invalid moderator key")
    return {"name": request.headers.get("x-mod-name", "moderator")[:60], "ip": client_ip(request)}


def audit(mod, action, detail=""):
    with db() as conn:
        conn.execute("INSERT INTO mod_audit (moderator, action, detail, ip, created) VALUES (?,?,?,?,?)", (mod["name"], action, detail, mod["ip"], now()))


@app.get("/api/mod/reports")
def mod_reports(status: str = "open", reason: str = "", limit: int = 50, mod=Depends(mod_req)):
    audit(mod, "list_reports", f"status={status} reason={reason}")
    with db() as conn:
        q, args = "SELECT id, reporter_id, kind, target_user_id, reason, status, created FROM reports WHERE status=?", [status]
        if reason:
            q += " AND reason=?"
            args.append(reason)
        # child-safety reports first
        q += " ORDER BY (reason='child_safety') DESC, id DESC LIMIT ?"
        args.append(min(max(limit, 1), 200))
        return [dict(r) for r in conn.execute(q, args)]


@app.get("/api/mod/reports/{rid}")
def mod_report(rid: int, mod=Depends(mod_req)):
    with db() as conn:
        r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found")
        audit(mod, "read_report", f"report={rid} kind={r['kind']}")
        d = dict(r)
        d["evidence"] = json.loads(d["evidence"])
        d["reporter"] = get_user(conn, r["reporter_id"])
        d["target_user"] = get_user(conn, r["target_user_id"]) if r["target_user_id"] else None
        return d


class ResolveIn(BaseModel):
    action: str  # dismiss | actioned
    note: str = Field(default="", max_length=1000)
    suspend_user: bool = False


@app.post("/api/mod/reports/{rid}/resolve")
def mod_resolve(rid: int, body: ResolveIn, mod=Depends(mod_req)):
    if body.action not in ("dismiss", "actioned"):
        raise HTTPException(400, "action must be dismiss or actioned")
    with db() as conn:
        r = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found")
        conn.execute("UPDATE reports SET status=?, note=?, resolved=? WHERE id=?", ("dismissed" if body.action == "dismiss" else "actioned", body.note, now(), rid))
        if body.suspend_user and r["target_user_id"]:
            conn.execute("UPDATE users SET suspended=1 WHERE id=?", (r["target_user_id"],))
    audit(mod, "resolve_report", f"report={rid} action={body.action} suspend={body.suspend_user}")
    return {"ok": True}


@app.post("/api/mod/users/{uid}/suspend")
def mod_suspend(uid: int, mod=Depends(mod_req)):
    with db() as conn:
        get_user(conn, uid)
        conn.execute("UPDATE users SET suspended=1 WHERE id=?", (uid,))
    audit(mod, "suspend_user", f"user={uid}")
    return {"ok": True}


@app.post("/api/mod/users/{uid}/unsuspend")
def mod_unsuspend(uid: int, mod=Depends(mod_req)):
    with db() as conn:
        get_user(conn, uid)
        conn.execute("UPDATE users SET suspended=0 WHERE id=?", (uid,))
    audit(mod, "unsuspend_user", f"user={uid}")
    return {"ok": True}


@app.get("/api/mod/events/{eid}/messages")
def mod_event_messages(eid: int, mod=Depends(mod_req)):
    audit(mod, "read_event_messages", f"event={eid}")
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM event_messages WHERE event_id=? ORDER BY id", (eid,))]


@app.delete("/api/mod/event-messages/{mid}")
def mod_delete_message(mid: int, mod=Depends(mod_req)):
    with db() as conn:
        conn.execute("DELETE FROM event_messages WHERE id=?", (mid,))
    audit(mod, "delete_event_message", f"message={mid}")
    return {"ok": True}


@app.get("/api/mod/posts")
def mod_posts(user_id: int = 0, limit: int = 50, mod=Depends(mod_req)):
    audit(mod, "list_posts", f"user={user_id}")
    with db() as conn:
        q, args = "SELECT * FROM posts", []
        if user_id:
            q += " WHERE user_id=?"
            args.append(user_id)
        rows = conn.execute(q + " ORDER BY id DESC LIMIT ?", args + [min(max(limit, 1), 200)]).fetchall()
        return [{**dict(r), "replies": [dict(x) for x in conn.execute("SELECT * FROM replies WHERE post_id=? ORDER BY id", (r["id"],))]} for r in rows]


@app.delete("/api/mod/posts/{pid}")
def mod_delete_post(pid: int, mod=Depends(mod_req)):
    with db() as conn:
        conn.execute("DELETE FROM replies WHERE post_id=?", (pid,))
        conn.execute("DELETE FROM posts WHERE id=?", (pid,))
    audit(mod, "delete_post", f"post={pid}")
    return {"ok": True}


@app.delete("/api/mod/replies/{rid}")
def mod_delete_reply(rid: int, mod=Depends(mod_req)):
    with db() as conn:
        conn.execute("DELETE FROM replies WHERE id=?", (rid,))
    audit(mod, "delete_reply", f"reply={rid}")
    return {"ok": True}


@app.get("/api/mod/audit")
def mod_audit_log(limit: int = 100, mod=Depends(mod_req)):
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM mod_audit ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),))]


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.get("/{path:path}")
def spa(path: str):
    return FileResponse(BASE / "static" / "index.html")
