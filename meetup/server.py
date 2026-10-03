import base64
import hashlib
import hmac
import io
import json
import logging
import os
import random
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image, ImageOps
from pydantic import BaseModel, Field

BASE = Path(__file__).parent
DB_PATH = os.environ.get("HUDDLE_DB", str(BASE / "huddle.db"))

DOCS_ON = os.environ.get("HUDDLE_DOCS") == "1"
app = FastAPI(title="Huddle", docs_url="/docs" if DOCS_ON else None, redoc_url=None, openapi_url="/openapi.json" if DOCS_ON else None)

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


# ── Browser protections, request size limits, and a coarse per-network flood limit ──
MAX_JSON_BODY = 1_000_000
MAX_UPLOAD_BODY = 45 * 1024 * 1024  # a 40 MB video plus form overhead
FLOOD_PER_MINUTE = 3000             # generous: an office behind one address must still work


def _inline_script_hashes():
    """The few pages that carry a tiny inline 'can't connect' script are allowed by hash, nothing else inline."""
    out = []
    for page in ("index.html", "corp.html"):
        try:
            html = (BASE / "static" / page).read_text()
        except OSError:
            continue
        for body in re.findall(r"<script>(.*?)</script>", html, re.S):
            out.append("'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'")
    return " ".join(out)


def page_csp():
    return ("default-src 'none'; script-src 'self' " + _inline_script_hashes() + "; style-src 'self'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; manifest-src 'self'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'")


@app.middleware("http")
async def protect(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        try:
            limiter.check(f"flood:{client_ip(request)}", FLOOD_PER_MINUTE, 60, "Too many requests from your network. Please slow down.")
        except HTTPException as e:
            return JSONResponse({"detail": e.detail}, status_code=429)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if "chunked" in request.headers.get("transfer-encoding", "").lower():
                return JSONResponse({"detail": "Length required"}, status_code=411)
            cl = request.headers.get("content-length", "0")
            if cl.isdigit() and int(cl) > (MAX_UPLOAD_BODY if path == "/api/media" else MAX_JSON_BODY):
                return JSONResponse({"detail": "That request is too large"}, status_code=413)
    resp = await call_next(request)
    h = resp.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["X-Frame-Options"] = "DENY"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if os.environ.get("HUDDLE_HSTS") == "1":
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if path.startswith("/api/"):
        h["Cache-Control"] = "no-store"  # responses hold private data; never let a browser or proxy keep them
    elif "text/html" in h.get("content-type", ""):
        h["Content-Security-Policy"] = page_csp()
        h["Cache-Control"] = "no-cache"
    return resp


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, city TEXT NOT NULL, bio TEXT DEFAULT '',
    pronouns TEXT DEFAULT '', interests TEXT DEFAULT '[]', looking_for TEXT DEFAULT '[]',
    created TEXT NOT NULL, public_key TEXT, token_hash TEXT, suspended INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
    show_mature INTEGER NOT NULL DEFAULT 0
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
    url TEXT DEFAULT '', tags TEXT DEFAULT '[]', city TEXT NOT NULL, created TEXT NOT NULL,
    group_id INTEGER, repost_of INTEGER
);
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', owner_id INTEGER NOT NULL,
    city TEXT DEFAULT '', tags TEXT DEFAULT '[]', mature INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created TEXT NOT NULL, PRIMARY KEY (post_id, user_id)
);
CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, post_id INTEGER, kind TEXT NOT NULL, name TEXT NOT NULL UNIQUE,
    width INTEGER DEFAULT 0, height INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id),
    user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL
);
-- One row per pair of people who have messaged. A first message starts as a 'pending' request;
-- it becomes 'accepted' when the recipient accepts or replies, or 'declined' (silent to the sender).
CREATE TABLE IF NOT EXISTS convos (
    user_a INTEGER NOT NULL, user_b INTEGER NOT NULL, requester_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL, updated TEXT NOT NULL,
    PRIMARY KEY (user_a, user_b)
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
    conn.execute(
        "INSERT OR IGNORE INTO convos SELECT min(from_id,to_id) AS a, max(from_id,to_id) AS b, min(from_id,to_id), 'accepted', min(created), max(created) "
        "FROM dms GROUP BY a, b"
    )
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    for name, ddl in [("public_key", "TEXT"), ("token_hash", "TEXT"), ("suspended", "INTEGER DEFAULT 0"), ("deleted", "INTEGER DEFAULT 0"),
                      ("show_mature", "INTEGER NOT NULL DEFAULT 0")]:
        if name not in cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
    pcols = {r["name"] for r in conn.execute("PRAGMA table_info(posts)")}
    for name in ("group_id", "repost_of"):
        if name not in pcols:
            conn.execute(f"ALTER TABLE posts ADD COLUMN {name} INTEGER")


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
    groups = [
        ("Austin Trail Runners", "Early-morning runs, trail swaps and race-day company. All paces welcome.", ["Running", "Hiking"], 0, 6, [1, 2, 3]),
        ("Board Game Crew", "Weekly game nights and a shared wishlist. Newcomers get a teacher.", ["Board games"], 0, 3, [8, 1]),
        ("Cocktail Hour (18+)", "Tasting nights and bar crawls for people who enjoy a drink. 18+ side of Huddle.", ["Cooking", "Travel"], 1, 4, [5]),
    ]
    for name, desc, tags, mature, owner, members in groups:
        gid = conn.execute("INSERT INTO groups (name, description, owner_id, city, tags, mature, created) VALUES (?,?,?,?,?,?,?)",
                           (name, desc, owner, "Austin", json.dumps(tags), mature, now())).lastrowid
        conn.execute("INSERT INTO group_members VALUES (?,?,?,?)", (gid, owner, "owner", now()))
        for m in members:
            conn.execute("INSERT OR IGNORE INTO group_members VALUES (?,?,?,?)", (gid, m, "member", now()))
        if gid == 1:
            conn.execute("INSERT INTO posts (user_id, body, url, tags, city, created, group_id) VALUES (6, ?, '', ?, 'Austin', ?, ?)",
                         ("Saturday long run: 14 km on the Greenbelt, easy pace, coffee after. Who is in?", json.dumps(["Running"]), now(), gid))
    conn.commit()


@app.on_event("startup")
def startup():
    with db() as conn:
        migrate(conn)
        prune_orphans(conn)
        conn.executescript(_corp.SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(corp_invites)")}
        if "new_hire" not in cols:
            conn.execute("ALTER TABLE corp_invites ADD COLUMN new_hire INTEGER NOT NULL DEFAULT 1")
        seed(conn)
        seed_posts(conn)
    if not SCAN_URL:
        log.warning("Photo/video uploads are ON but no safety scanner is configured (HUDDLE_MEDIA_SCAN_URL). "
                    "Do not open this site to the public until uploads are scanned for child sexual abuse material.")


# ── Abuse protection ──────────────────────────────────────────────────────────
class Limiter:
    """Sliding-window rate limiter (in-memory; use Redis if you run more than one process).
    Old entries are swept regularly so a flood of one-off visitors can't make it grow without bound."""

    def __init__(self):
        self.hits = defaultdict(deque)
        self.windows = {}
        self.calls = 0

    def check(self, key, n, window, msg="You're doing that too fast. Please slow down."):
        t = time.time()
        self.calls += 1
        if self.calls % 2000 == 0:
            self.sweep(t)
        q = self.hits[key]
        self.windows[key] = max(window, self.windows.get(key, 0))
        while q and q[0] < t - window:
            q.popleft()
        if len(q) >= n:
            raise HTTPException(429, msg)
        q.append(t)

    def sweep(self, t=None):
        t = t or time.time()
        for k in [k for k, q in self.hits.items() if not q or q[-1] < t - self.windows.get(k, 0)]:
            self.hits.pop(k, None)
            self.windows.pop(k, None)

    def clear(self):
        self.hits.clear()
        self.windows.clear()


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
    return {**user_dict(r), "created": r["created"], "show_mature": bool(r["show_mature"])}


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
    no_links_if_new(me, e.title, e.description, e.venue, e.vibe, " ".join(e.tags))
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
    no_links_if_new(me, m.body)
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
    if any(LINK_RE.search(t or "") for t in (u.name, u.city, u.bio, u.pronouns, " ".join(u.interests))):
        raise HTTPException(400, "Names and bios can't contain links")
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
    with db() as conn:
        posts = conn.execute("SELECT COUNT(*) FROM posts WHERE user_id=?", (me["id"],)).fetchone()[0]
        events = conn.execute(
            "SELECT COUNT(*) FROM rsvps s JOIN events e ON e.id=s.event_id WHERE s.user_id=? AND e.starts>=?",
            (me["id"], datetime.now().isoformat(timespec="minutes")),
        ).fetchone()[0]
    return {**me, "stats": {"posts": posts, "events": events}}


@app.put("/api/me")
def update_me(u: ProfileIn, me=Depends(me_req)):
    no_links_if_new(me, u.name, u.city, u.bio, u.pronouns, " ".join(u.interests))
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
            u["chat"] = chat_state(conn, v["id"], uid)
            u["can_message"] = u["chat"] != "unavailable"
        return u


@app.get("/api/users/{uid}/posts")
def user_posts(uid: int, v=Depends(me_opt)):
    with db() as conn:
        if uid in hidden_users(conn, v["id"] if v else 0):
            return []
        u = conn.execute("SELECT suspended, deleted FROM users WHERE id=?", (uid,)).fetchone()
        if not u or u["suspended"] or u["deleted"]:
            raise HTTPException(404, "This account no longer exists")
        hide = hidden_users(conn, v["id"] if v else 0)
        rows = conn.execute("SELECT * FROM posts WHERE user_id=? ORDER BY id DESC LIMIT 60", (uid,)).fetchall()
        rows = [r for r in rows if in_main_feed(conn, r) and post_visible(conn, r, v, hide)]
        return [post_dict(conn, r, v["id"] if v else 0) for r in rows[:30]]


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
                o.update(shared=sh, shared_goals=goals, events_in_common=common, score=score, chat=(st := chat_state(conn, uid, o["id"])), can_message=st != "unavailable")
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


def chat_state(conn, me, other):
    """unavailable | none | request_out | request_in | accepted, from `me`'s point of view.
    A declined request still reads as request_out to the sender, so declining is silent."""
    o = conn.execute("SELECT public_key, deleted, suspended FROM users WHERE id=?", (other,)).fetchone()
    if not o or me == other or not o["public_key"] or o["deleted"] or o["suspended"] or blocked_either_way(conn, me, other):
        return "unavailable"
    c = conn.execute("SELECT * FROM convos WHERE user_a=? AND user_b=?", (min(me, other), max(me, other))).fetchone()
    if not c:
        return "none"
    if c["status"] == "accepted":
        return "accepted"
    if c["requester_id"] == me:
        return "request_out"
    return "request_in" if c["status"] == "pending" else "none"


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
    uid = me["id"]
    if d.to_id == uid:
        raise HTTPException(400, "Can't message yourself")
    if not (_b64_ok(d.iv) and _b64_ok(d.ciphertext)):
        raise HTTPException(400, "Malformed message")
    with db() as conn:
        other = get_user(conn, d.to_id)
        if not other["public_key"]:
            raise HTTPException(400, "This sample profile can't receive encrypted messages")
        st = chat_state(conn, uid, d.to_id)
        pair = (min(uid, d.to_id), max(uid, d.to_id))
        if st == "unavailable":
            raise HTTPException(403, "You can't message this person")
        if st == "request_out":
            raise HTTPException(403, "Your request is waiting. You can keep chatting once they accept.")
        limiter.check(f"dm-min:{uid}", 15, 60)
        limiter.check(f"dm-hr:{uid}", 60 if is_new(me) else 300, HOUR)
        status = "accepted"
        if st == "none":
            existing = conn.execute("SELECT 1 FROM convos WHERE user_a=? AND user_b=?", pair).fetchone()
            if existing:  # I had declined their request; writing to them now opens the chat
                conn.execute("UPDATE convos SET status='accepted', updated=? WHERE user_a=? AND user_b=?", (now(), *pair))
            else:
                limiter.check(f"dm-new:{uid}", 3 if is_new(me) else 15, DAY, "You've sent a lot of requests today. Try again tomorrow.")
                if conn.execute("SELECT COUNT(*) FROM convos WHERE requester_id=? AND status='pending'", (uid,)).fetchone()[0] >= 20:
                    raise HTTPException(429, "You have many requests waiting. Wait for replies before sending more.")
                conn.execute("INSERT INTO convos VALUES (?,?,?,?,?,?)", (*pair, uid, "pending", now(), now()))
                status = "pending"
        elif st == "request_in":  # replying to a request accepts it
            conn.execute("UPDATE convos SET status='accepted', updated=? WHERE user_a=? AND user_b=?", (now(), *pair))
        else:
            conn.execute("UPDATE convos SET updated=? WHERE user_a=? AND user_b=?", (now(), *pair))
        conn.execute("INSERT INTO dms (from_id,to_id,iv,ciphertext,created) VALUES (?,?,?,?,?)", (uid, d.to_id, d.iv, d.ciphertext, now()))
        return {"ok": True, "status": status}


def _request_row(conn, me_id, requester_id):
    c = conn.execute("SELECT * FROM convos WHERE user_a=? AND user_b=?", (min(me_id, requester_id), max(me_id, requester_id))).fetchone()
    if not c or c["requester_id"] != requester_id or requester_id == me_id or c["status"] != "pending":
        raise HTTPException(404, "Request not found")


@app.post("/api/requests/{uid}/accept")
def accept_request(uid: int, me=Depends(me_req)):
    with db() as conn:
        _request_row(conn, me["id"], uid)
        conn.execute("UPDATE convos SET status='accepted', updated=? WHERE user_a=? AND user_b=?", (now(), min(me["id"], uid), max(me["id"], uid)))
        return {"ok": True}


@app.post("/api/requests/{uid}/decline")
def decline_request(uid: int, me=Depends(me_req)):
    """Silent: the sender keeps seeing 'request sent' and can't send again."""
    with db() as conn:
        _request_row(conn, me["id"], uid)
        conn.execute("UPDATE convos SET status='declined', updated=? WHERE user_a=? AND user_b=?", (now(), min(me["id"], uid), max(me["id"], uid)))
        return {"ok": True}


@app.get("/api/me/counts")
def counts(me=Depends(me_req)):
    with db() as conn:
        n = sum(
            1 for r in conn.execute("SELECT * FROM convos WHERE (user_a=? OR user_b=?) AND status='pending' AND requester_id!=?", (me["id"],) * 3)
            if chat_state(conn, me["id"], r["requester_id"]) == "request_in"
        )
        return {"requests": n}


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
            st = chat_state(conn, uid, other)
            if st in ("unavailable", "none"):  # blocked, deleted, or a request I declined
                continue
            threads.append({"user": get_user(conn, other), "iv": r["iv"], "ciphertext": r["ciphertext"], "created": r["created"], "mine": r["from_id"] == uid, "status": st})
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
        conn.execute("DELETE FROM convos WHERE user_a=? OR user_b=?", (uid, uid))
        for e in [r["id"] for r in conn.execute("SELECT id FROM events WHERE host_id=?", (uid,))]:
            conn.execute("DELETE FROM event_messages WHERE event_id=?", (e,))
            conn.execute("DELETE FROM rsvps WHERE event_id=?", (e,))
            conn.execute("DELETE FROM events WHERE id=?", (e,))
        conn.execute("DELETE FROM event_messages WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM rsvps WHERE user_id=?", (uid,))
        for g in conn.execute("SELECT id FROM groups WHERE owner_id=?", (uid,)).fetchall():
            purge_group(conn, g["id"])
        for p in conn.execute("SELECT id FROM posts WHERE user_id=?", (uid,)).fetchall():
            purge_post(conn, p["id"])
        conn.execute("DELETE FROM replies WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM likes WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM group_members WHERE user_id=?", (uid,))
        drop_media(conn, conn.execute("SELECT id, name FROM media WHERE user_id=?", (uid,)).fetchall())
        conn.execute(
            "UPDATE users SET name='Deleted user', city='', bio='', pronouns='', interests='[]', looking_for='[]', "
            "public_key=NULL, token_hash=NULL, deleted=1 WHERE id=?", (uid,),
        )
    return {"ok": True}


# ── Media: photos and videos ──────────────────────────────────────────────────
# Safety notes: files are identified by their bytes (never their name), photos are re-encoded (which also removes
# location data), videos get metadata stripped when ffmpeg is present, new accounts get fewer uploads and no
# video, and every file can pass through an external scanner (HUDDLE_MEDIA_SCAN_URL) before it is stored.
log = logging.getLogger("huddle")
UPLOAD_DIR = Path(os.environ.get("HUDDLE_UPLOADS", str(BASE / "uploads")))
MAX_IMAGE, MAX_VIDEO, MAX_PIXELS = 8 * 1024 * 1024, 40 * 1024 * 1024, 40_000_000
SCAN_URL = os.environ.get("HUDDLE_MEDIA_SCAN_URL", "")
FFMPEG = shutil.which("ffmpeg")
MAX_USER_BYTES = 500 * 1024 * 1024  # stored media per person
MEDIA_NAME_RE = re.compile(r"^[a-f0-9]{32}\.(webp|mp4|webm)$")
MEDIA_TYPES = {"webp": "image/webp", "mp4": "video/mp4", "webm": "video/webm"}
Image.MAX_IMAGE_PIXELS = MAX_PIXELS


def sniff_media(data: bytes):
    """Identify an upload from its first bytes: 'image', 'mp4', 'webm' or None."""
    if data[:3] == b"\xff\xd8\xff" or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:4] == b"GIF8" or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        return "image"
    if data[4:8] == b"ftyp":
        return "mp4"
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return "webm"
    return None


def process_image(data: bytes):
    try:
        im = Image.open(io.BytesIO(data))
        if im.width * im.height > MAX_PIXELS:
            raise HTTPException(400, "That photo is too large. Try a smaller one.")
        im.load()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "That photo couldn't be read")
    im = ImageOps.exif_transpose(im)
    im.thumbnail((2048, 2048))
    im = im.convert("RGBA" if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info else "RGB")
    out = io.BytesIO()
    im.save(out, "WEBP", quality=85, method=4)  # re-encoding drops EXIF, including GPS location
    return out.getvalue(), im.width, im.height


def process_video(data: bytes, ext: str):
    if not FFMPEG:
        return data  # no ffmpeg: stored as uploaded (metadata is not stripped). See README.
    with tempfile.TemporaryDirectory() as d:
        src, dst = Path(d) / f"in.{ext}", Path(d) / f"out.{ext}"
        src.write_bytes(data)
        # force the demuxer for the format we already verified, so ffmpeg never guesses (playlists, concat files, URLs)
        cmd = [FFMPEG, "-nostdin", "-y", "-v", "error", "-protocol_whitelist", "file", "-f", "mov" if ext == "mp4" else "matroska", "-i", str(src),
               "-map", "0:v:0", "-map", "0:a:0?", "-c", "copy", "-map_metadata", "-1"]
        cmd += ["-movflags", "+faststart"] if ext == "mp4" else []
        try:
            res = subprocess.run(cmd + [str(dst)], capture_output=True, timeout=90)
        except subprocess.TimeoutExpired:
            raise HTTPException(400, "That video took too long to process")
        if res.returncode != 0 or not dst.exists():
            raise HTTPException(400, "That video couldn't be read")
        return dst.read_bytes()


def scan_media(data: bytes, kind: str):
    """Send the file to an external safety scanner (hash matching such as PhotoDNA/NCMEC tooling, or a classifier).
    The scanner must answer {"allowed": true}. If it is configured but unreachable, uploads fail closed."""
    if not SCAN_URL:
        return
    if urlparse(SCAN_URL).scheme not in ("http", "https"):
        raise HTTPException(503, "Upload check is misconfigured")
    import urllib.request
    req = urllib.request.Request(SCAN_URL, data=data, method="POST", headers={"Content-Type": "application/octet-stream", "X-Media-Kind": kind})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            allowed = json.loads(r.read()).get("allowed") is True
    except Exception:
        if os.environ.get("HUDDLE_SCAN_FAIL_OPEN") == "1":
            return
        raise HTTPException(503, "Upload check is unavailable. Please try again later.")
    if not allowed:
        raise HTTPException(422, "This file can't be uploaded.")


@app.post("/api/media")
def upload_media(file: UploadFile = File(...), me=Depends(me_req)):
    limiter.check(f"upload:{me['id']}", 5 if is_new(me) else 40, DAY, "You've reached today's upload limit.")
    data = file.file.read(MAX_VIDEO + 1)
    if len(data) > MAX_VIDEO:
        raise HTTPException(413, "That file is too large (videos can be up to 40 MB)")
    kind = sniff_media(data)
    if kind is None:
        raise HTTPException(400, "Use a JPEG, PNG, GIF or WebP photo, or an MP4 or WebM video.")
    w = h = 0
    if kind == "image":
        if len(data) > MAX_IMAGE:
            raise HTTPException(413, "Photos can be up to 8 MB")
        out, w, h = process_image(data)
        ext, mkind = "webp", "image"
    else:
        if is_new(me):
            raise HTTPException(403, "Videos unlock after your first day on Huddle. Photos are fine now.")
        out, ext, mkind = process_video(data, kind), kind, "video"
    scan_media(out, mkind)
    with db() as conn:
        prune_orphans(conn)
        if conn.execute("SELECT COALESCE(SUM(bytes), 0) FROM media WHERE user_id=?", (me["id"],)).fetchone()[0] + len(out) > MAX_USER_BYTES:
            raise HTTPException(413, "You've used all of your photo and video storage. Delete some posts to free space.")
    name = f"{secrets.token_hex(16)}.{ext}"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / name).write_bytes(out)
    with db() as conn:
        cur = conn.execute("INSERT INTO media (user_id, kind, name, width, height, bytes, created) VALUES (?,?,?,?,?,?,?)", (me["id"], mkind, name, w, h, len(out), now()))
        return {"id": cur.lastrowid, "kind": mkind, "url": f"/media/{name}", "width": w, "height": h}


@app.delete("/api/media/{mid}")
def delete_upload(mid: int, me=Depends(me_req)):
    """Remove an upload that was never attached to a post (for example, a photo taken out of a draft)."""
    with db() as conn:
        drop_media(conn, conn.execute("SELECT id, name FROM media WHERE id=? AND user_id=? AND post_id IS NULL", (mid, me["id"])).fetchall())
        return {"ok": True}


@app.get("/media/{name}")
def serve_media(name: str):
    if not MEDIA_NAME_RE.match(name) or not (UPLOAD_DIR / name).is_file():
        raise HTTPException(404, "Not found")
    return FileResponse(UPLOAD_DIR / name, media_type=MEDIA_TYPES[name.rsplit(".", 1)[1]], headers={
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cross-Origin-Resource-Policy": "same-origin", "Cache-Control": "private, max-age=3600"})


def prune_orphans(conn):
    """Uploads that were never attached to a post are removed after a day, so abandoned drafts don't fill the disk."""
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    drop_media(conn, conn.execute("SELECT id, name FROM media WHERE post_id IS NULL AND created < ?", (old,)).fetchall())


def drop_media(conn, rows):
    for r in rows:
        try:
            (UPLOAD_DIR / r["name"]).unlink()
        except OSError:
            pass
        conn.execute("DELETE FROM media WHERE id=?", (r["id"],))


def media_for(conn, pid):
    return [{"id": m["id"], "kind": m["kind"], "url": f"/media/{m['name']}", "width": m["width"], "height": m["height"]}
            for m in conn.execute("SELECT * FROM media WHERE post_id=? ORDER BY id", (pid,))]


# ── Groups, including the separate 18+ side ───────────────────────────────────
# A group is either open to everyone or an 18+ group, and its creator must say which. 18+ groups never appear in
# the main feed, search, group directory, trends or profiles. Only members who switched on "18+ groups" in Settings
# can find them. Sexually explicit content is not allowed anywhere on Huddle, 18+ groups included.
def can_view_group(g, viewer):
    return bool(g) and (not g["mature"] or bool(viewer and viewer.get("show_mature")))


def need_group(conn, gid, viewer):
    g = conn.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        raise HTTPException(404, "Group not found")
    if not can_view_group(g, viewer):
        raise HTTPException(403, "mature_hidden")
    return g


def group_dict(conn, g, viewer=None):
    d = {
        "id": g["id"], "name": g["name"], "description": g["description"], "city": g["city"], "tags": json.loads(g["tags"]),
        "mature": bool(g["mature"]), "created": g["created"], "owner": get_user(conn, g["owner_id"]),
        "member_count": conn.execute("SELECT COUNT(*) FROM group_members WHERE group_id=?", (g["id"],)).fetchone()[0],
        "post_count": conn.execute("SELECT COUNT(*) FROM posts WHERE group_id=? AND repost_of IS NULL", (g["id"],)).fetchone()[0],
    }
    if viewer:
        m = conn.execute("SELECT role FROM group_members WHERE group_id=? AND user_id=?", (g["id"], viewer["id"])).fetchone()
        d["joined"], d["role"] = bool(m), (m["role"] if m else None)
    return d


class GroupIn(BaseModel):
    name: str = Field(min_length=3, max_length=60)
    description: str = Field(default="", max_length=500)
    city: str = Field(default="", max_length=80)
    tags: list[str] = []
    mature: bool  # required on purpose: the creator must answer "is this an 18+ group?"


@app.get("/api/groups")
def list_groups(scope: str = "discover", q: str = "", v=Depends(me_opt)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM groups ORDER BY id DESC").fetchall()
        if scope == "mature":
            if not v or not v["show_mature"]:
                raise HTTPException(403, "mature_hidden")
            rows = [g for g in rows if g["mature"]]
        else:
            rows = [g for g in rows if not g["mature"]]
        if scope == "mine":
            if not v:
                raise HTTPException(401, "Please sign in")
            mine = {r["group_id"] for r in conn.execute("SELECT group_id FROM group_members WHERE user_id=?", (v["id"],))}
            rows = [g for g in rows if g["id"] in mine]
        text = q.lower().split()
        out = []
        for g in rows:
            d = group_dict(conn, g, v)
            if text and not all(t in " ".join([g["name"], g["description"], g["tags"], g["city"]]).lower() for t in text):
                continue
            d["_s"] = (len(shared(v, {"interests": d["tags"]})) * 3 if v else 0) + (2 if v and g["city"] and g["city"].lower() == v["city"].lower() else 0) + d["member_count"] * 0.1
            out.append(d)
        out.sort(key=lambda d: -d["_s"])
        for d in out:
            d.pop("_s")
        return out[:50]


@app.post("/api/groups")
def create_group(g: GroupIn, me=Depends(me_req)):
    if g.mature and not me["show_mature"]:
        raise HTTPException(403, "Turn on 18+ groups in Settings before creating one.")
    no_links_if_new(me, g.name, g.description, g.city, " ".join(g.tags))
    limiter.check(f"group:{me['id']}", 1 if is_new(me) else 3, DAY, "You can create 1 group a day at first, then 3.")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO groups (name, description, owner_id, city, tags, mature, created) VALUES (?,?,?,?,?,?,?)",
            (g.name.strip(), g.description.strip(), me["id"], g.city.strip(), json.dumps(clean_list(g.tags, 6)), int(g.mature), now()),
        )
        conn.execute("INSERT INTO group_members VALUES (?,?,?,?)", (cur.lastrowid, me["id"], "owner", now()))
        return {"id": cur.lastrowid}


@app.get("/api/groups/{gid}")
def get_group(gid: int, v=Depends(me_opt)):
    with db() as conn:
        g = need_group(conn, gid, v)
        d = group_dict(conn, g, v)
        d["members"] = [get_user(conn, m["user_id"]) for m in conn.execute(
            "SELECT m.user_id FROM group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=? AND u.deleted=0 AND u.suspended=0 ORDER BY (m.role='owner') DESC, m.joined LIMIT 30", (gid,))]
        return d


@app.get("/api/groups/{gid}/posts")
def group_posts(gid: int, v=Depends(me_opt)):
    with db() as conn:
        need_group(conn, gid, v)
        hide = hidden_users(conn, v["id"] if v else 0)
        rows = conn.execute("SELECT * FROM posts WHERE group_id=? AND repost_of IS NULL ORDER BY id DESC LIMIT 100", (gid,)).fetchall()
        return [post_dict(conn, r, v["id"] if v else 0) for r in rows if post_visible(conn, r, v, hide)][:60]


@app.post("/api/groups/{gid}/join")
def join_group(gid: int, me=Depends(me_req)):
    limiter.check(f"gjoin:{me['id']}", 10 if is_new(me) else 60, DAY, "You've joined a lot of groups today.")
    with db() as conn:
        need_group(conn, gid, me)
        conn.execute("INSERT OR IGNORE INTO group_members VALUES (?,?,?,?)", (gid, me["id"], "member", now()))
        return {"ok": True}


@app.delete("/api/groups/{gid}/join")
def leave_group(gid: int, me=Depends(me_req)):
    with db() as conn:
        m = conn.execute("SELECT role FROM group_members WHERE group_id=? AND user_id=?", (gid, me["id"])).fetchone()
        if m and m["role"] == "owner":
            raise HTTPException(400, "Owners can't leave their group. You can delete it instead.")
        conn.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (gid, me["id"]))
        return {"ok": True}


def purge_group(conn, gid):
    for p in conn.execute("SELECT id FROM posts WHERE group_id=?", (gid,)).fetchall():
        purge_post(conn, p["id"])
    conn.execute("DELETE FROM group_members WHERE group_id=?", (gid,))
    conn.execute("DELETE FROM groups WHERE id=?", (gid,))


def is_owner(conn, gid, uid):
    return bool(conn.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=? AND role='owner'", (gid, uid)).fetchone())


@app.delete("/api/groups/{gid}")
def delete_group(gid: int, me=Depends(me_req)):
    with db() as conn:
        if not is_owner(conn, gid, me["id"]):
            raise HTTPException(404, "Group not found")
        purge_group(conn, gid)
        return {"ok": True}


@app.delete("/api/groups/{gid}/members/{uid}")
def remove_member(gid: int, uid: int, me=Depends(me_req)):
    with db() as conn:
        if not is_owner(conn, gid, me["id"]) or uid == me["id"]:
            raise HTTPException(404, "Not found")
        conn.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (gid, uid))
        return {"ok": True}


@app.delete("/api/groups/{gid}/posts/{pid}")
def remove_group_post(gid: int, pid: int, me=Depends(me_req)):
    with db() as conn:
        if not is_owner(conn, gid, me["id"]) or not conn.execute("SELECT 1 FROM posts WHERE id=? AND group_id=?", (pid, gid)).fetchone():
            raise HTTPException(404, "Not found")
        purge_post(conn, pid)
        return {"ok": True}


class PrefsIn(BaseModel):
    show_mature: bool


@app.put("/api/me/prefs")
def set_prefs(p: PrefsIn, me=Depends(me_req)):
    with db() as conn:
        conn.execute("UPDATE users SET show_mature=? WHERE id=?", (int(p.show_mature), me["id"]))
    return {"show_mature": p.show_mature}


# ── Feed: photos, videos and news, with comments, likes and reposts ───────────
LINK_RE = re.compile(r"https?://|www\.|\b[a-z0-9-]{2,}\.(?:com|net|org|io|co|me|ly|gg|xyz|ru|cn|info|biz|app|dev|link|click|top|site|online|shop)\b", re.I)


class PostIn(BaseModel):
    body: str = Field(default="", max_length=500)
    url: str = Field(default="", max_length=300)
    tags: list[str] = []
    group_id: int | None = None
    media: list[int] = []


def no_links_if_new(me, *texts):
    """Brand-new accounts can't put links anywhere. It's the cheapest, most effective spam stop there is."""
    if is_new(me) and any(LINK_RE.search(t or "") for t in texts):
        raise HTTPException(403, "Links unlock after your first day on Huddle. It keeps spam out.")


def clean_url(u):
    u = u.strip()
    if not u:
        return ""
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.netloc or " " in u:
        raise HTTPException(400, "That link doesn't look right. It should start with http:// or https://")
    if p.username or p.password or "@" in p.netloc:  # https://yourbank.com@evil.site is a classic phishing trick
        raise HTTPException(400, "Links can't contain a username or password")
    return u


def post_dict(conn, r, viewer_id=0, nested=True):
    d = {
        "id": r["id"], "body": r["body"], "url": r["url"], "tags": json.loads(r["tags"]), "city": r["city"], "created": r["created"],
        "author": get_user(conn, r["user_id"]), "mine": r["user_id"] == viewer_id,
        "reply_count": conn.execute("SELECT COUNT(*) FROM replies WHERE post_id=?", (r["id"],)).fetchone()[0],
        "like_count": conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (r["id"],)).fetchone()[0],
        "liked": bool(viewer_id and conn.execute("SELECT 1 FROM likes WHERE post_id=? AND user_id=?", (r["id"], viewer_id)).fetchone()),
        "repost_count": conn.execute("SELECT COUNT(*) FROM posts WHERE repost_of=?", (r["id"],)).fetchone()[0],
        "reposted": bool(viewer_id and conn.execute("SELECT 1 FROM posts WHERE repost_of=? AND user_id=?", (r["id"], viewer_id)).fetchone()),
        "media": media_for(conn, r["id"]), "group": None, "repost": None,
    }
    if r["group_id"]:
        g = conn.execute("SELECT id, name, mature FROM groups WHERE id=?", (r["group_id"],)).fetchone()
        if g:
            d["group"] = {"id": g["id"], "name": g["name"], "mature": bool(g["mature"])}
    if r["repost_of"] and nested:
        o = conn.execute("SELECT * FROM posts WHERE id=?", (r["repost_of"],)).fetchone()
        d["repost"] = post_dict(conn, o, viewer_id, nested=False) if o else None
    return d


def post_visible(conn, r, viewer, hide):
    """Can this viewer see this post at all? (blocks, suspended/deleted authors, 18+ groups, reposts of hidden people)"""
    a = conn.execute("SELECT suspended, deleted FROM users WHERE id=?", (r["user_id"],)).fetchone()
    if not a or a["suspended"] or a["deleted"] or r["user_id"] in hide:
        return False
    if r["group_id"] and not can_view_group(conn.execute("SELECT * FROM groups WHERE id=?", (r["group_id"],)).fetchone(), viewer):
        return False
    if r["repost_of"]:
        o = conn.execute("SELECT user_id FROM posts WHERE id=?", (r["repost_of"],)).fetchone()
        if not o or o["user_id"] in hide:
            return False
    return True


def in_main_feed(conn, r):
    if not r["group_id"]:
        return True
    g = conn.execute("SELECT mature FROM groups WHERE id=?", (r["group_id"],)).fetchone()
    return bool(g) and not g["mature"]


def purge_post(conn, pid):
    """Delete a post with everything attached to it: comments, likes, photos/videos, and reposts of it."""
    for i in [pid] + [r["id"] for r in conn.execute("SELECT id FROM posts WHERE repost_of=?", (pid,))]:
        conn.execute("DELETE FROM replies WHERE post_id=?", (i,))
        conn.execute("DELETE FROM likes WHERE post_id=?", (i,))
        drop_media(conn, conn.execute("SELECT id, name FROM media WHERE post_id=?", (i,)).fetchall())
        conn.execute("DELETE FROM posts WHERE id=?", (i,))


@app.get("/api/posts")
def list_posts(scope: str = "foryou", tag: str = "", v=Depends(me_opt)):
    with db() as conn:
        vid = v["id"] if v else 0
        hide = hidden_users(conn, vid)
        if scope == "mature" and not (v and v["show_mature"]):
            raise HTTPException(403, "mature_hidden")
        mine = {r["group_id"] for r in conn.execute("SELECT group_id FROM group_members WHERE user_id=?", (vid,))} if v else set()
        rows = conn.execute("SELECT * FROM posts ORDER BY id DESC LIMIT 300").fetchall()
        out = []
        for rank, r in enumerate(rows):
            if scope == "mature":
                if not r["group_id"] or r["group_id"] not in mine or in_main_feed(conn, r):
                    continue
            elif not in_main_feed(conn, r):
                continue
            if not post_visible(conn, r, v, hide):
                continue
            tags = json.loads(r["tags"])
            if tag and tag.lower() not in [t.lower() for t in tags]:
                continue
            same_city = bool(v) and r["city"].lower() == v["city"].lower()
            if scope == "near" and not same_city:
                continue
            p = post_dict(conn, r, vid)
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
    if not body and not p.media:
        raise HTTPException(400, "Write something or add a photo first")
    url = clean_url(p.url)
    if is_new(me) and (url or LINK_RE.search(body)):
        raise HTTPException(403, "Links unlock after your first day on Huddle. It keeps spam out.")
    limiter.check(f"post:{me['id']}", 3 if is_new(me) else 20, DAY, "You've reached today's posting limit.")
    limiter.check(f"post-min:{me['id']}", 3, 60)
    with db() as conn:
        if p.group_id:
            g = need_group(conn, p.group_id, me)
            if not conn.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (g["id"], me["id"])).fetchone():
                raise HTTPException(403, "Join the group to post in it")
        items = []
        for mid in dict.fromkeys(p.media):
            m = conn.execute("SELECT * FROM media WHERE id=? AND user_id=? AND post_id IS NULL", (mid, me["id"])).fetchone()
            if not m:
                raise HTTPException(400, "One of those uploads isn't available. Please add it again.")
            items.append(m)
        videos = [m for m in items if m["kind"] == "video"]
        if len(items) > 4 or len(videos) > 1 or (videos and len(items) > 1):
            raise HTTPException(400, "Add up to 4 photos, or 1 video.")
        last = conn.execute("SELECT body FROM posts WHERE user_id=? AND repost_of IS NULL ORDER BY id DESC LIMIT 1", (me["id"],)).fetchone()
        if body and last and last["body"] == body:
            raise HTTPException(400, "You already posted that")
        cur = conn.execute(
            "INSERT INTO posts (user_id, body, url, tags, city, created, group_id) VALUES (?,?,?,?,?,?,?)",
            (me["id"], body, url, json.dumps(clean_list(p.tags, 3)), me["city"], now(), p.group_id),
        )
        for m in items:
            conn.execute("UPDATE media SET post_id=? WHERE id=?", (cur.lastrowid, m["id"]))
        return {"id": cur.lastrowid}


def need_post(conn, pid, viewer):
    r = conn.execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
    if not r or not post_visible(conn, r, viewer, hidden_users(conn, viewer["id"] if viewer else 0)):
        raise HTTPException(404, "Post not found")
    return r


@app.get("/api/posts/{pid}")
def get_post(pid: int, v=Depends(me_opt)):
    with db() as conn:
        r = need_post(conn, pid, v)
        vid = v["id"] if v else 0
        hide = hidden_users(conn, vid)
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
        need_post(conn, pid, me)
        conn.execute("INSERT INTO replies (post_id, user_id, body, created) VALUES (?,?,?,?)", (pid, me["id"], body, now()))
        return {"ok": True}


@app.put("/api/posts/{pid}/like")
def like_post(pid: int, me=Depends(me_req)):
    limiter.check(f"like:{me['id']}", 30, 60)
    limiter.check(f"like-d:{me['id']}", 150 if is_new(me) else 1000, DAY)
    with db() as conn:
        need_post(conn, pid, me)
        conn.execute("INSERT OR IGNORE INTO likes VALUES (?,?,?)", (pid, me["id"], now()))
        return {"liked": True, "like_count": conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (pid,)).fetchone()[0]}


@app.delete("/api/posts/{pid}/like")
def unlike_post(pid: int, me=Depends(me_req)):
    with db() as conn:
        conn.execute("DELETE FROM likes WHERE post_id=? AND user_id=?", (pid, me["id"]))
        return {"liked": False, "like_count": conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (pid,)).fetchone()[0]}


class RepostIn(BaseModel):
    body: str = Field(default="", max_length=300)


@app.post("/api/posts/{pid}/repost")
def repost(pid: int, rp: RepostIn, me=Depends(me_req)):
    limiter.check(f"repost:{me['id']}", 5 if is_new(me) else 40, DAY, "You've reached today's repost limit.")
    body = rp.body.strip()
    if is_new(me) and LINK_RE.search(body):
        raise HTTPException(403, "Links unlock after your first day on Huddle. It keeps spam out.")
    with db() as conn:
        r = need_post(conn, pid, me)
        if r["repost_of"]:  # reposting a repost shares the original
            r = need_post(conn, r["repost_of"], me)
        if r["group_id"] and not in_main_feed(conn, r):
            raise HTTPException(403, "Posts from 18+ groups can't be reposted.")
        if r["user_id"] == me["id"]:
            raise HTTPException(400, "You can't repost your own post")
        if conn.execute("SELECT 1 FROM posts WHERE repost_of=? AND user_id=?", (r["id"], me["id"])).fetchone():
            raise HTTPException(409, "You already reposted this")
        cur = conn.execute("INSERT INTO posts (user_id, body, url, tags, city, created, repost_of) VALUES (?,?,?,?,?,?,?)",
                           (me["id"], body, "", "[]", me["city"], now(), r["id"]))
        return {"id": cur.lastrowid}


@app.delete("/api/posts/{pid}")
def delete_post(pid: int, me=Depends(me_req)):
    with db() as conn:
        r = conn.execute("SELECT user_id FROM posts WHERE id=?", (pid,)).fetchone()
        if not r or r["user_id"] != me["id"]:
            raise HTTPException(404, "Post not found")
        purge_post(conn, pid)
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
    kind: str  # dm | event_message | user | event | post | reply | group
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
            evidence = {"body": p["body"], "url": p["url"], "posted": p["created"], "group_id": p["group_id"], "repost_of": p["repost_of"],
                        "media": [{"id": m["id"], "kind": m["kind"], "name": m["name"]} for m in conn.execute("SELECT * FROM media WHERE post_id=?", (p["id"],))]}
        elif rep.kind == "reply":
            p = conn.execute("SELECT * FROM replies WHERE id=?", (rep.target_id,)).fetchone()
            if not p:
                raise HTTPException(404, "Reply not found")
            target_user = p["user_id"]
            evidence = {"post_id": p["post_id"], "body": p["body"], "posted": p["created"]}
        elif rep.kind == "group":
            g = conn.execute("SELECT * FROM groups WHERE id=?", (rep.target_id,)).fetchone()
            if not g or not can_view_group(g, me):
                raise HTTPException(404, "Group not found")
            target_user = g["owner_id"]
            evidence = {"name": g["name"], "description": g["description"], "mature": bool(g["mature"])}
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
        limiter.check(f"mod-fail:{client_ip(request)}", 8, HOUR, "Too many wrong keys. Locked out for an hour.")
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
        purge_post(conn, pid)
    audit(mod, "delete_post", f"post={pid}")
    return {"ok": True}


@app.delete("/api/mod/replies/{rid}")
def mod_delete_reply(rid: int, mod=Depends(mod_req)):
    with db() as conn:
        conn.execute("DELETE FROM replies WHERE id=?", (rid,))
    audit(mod, "delete_reply", f"reply={rid}")
    return {"ok": True}


@app.get("/api/mod/groups")
def mod_groups(mature: int = -1, mod=Depends(mod_req)):
    audit(mod, "list_groups", f"mature={mature}")
    with db() as conn:
        rows = conn.execute("SELECT * FROM groups ORDER BY id DESC LIMIT 200").fetchall()
        return [group_dict(conn, g) for g in rows if mature < 0 or bool(g["mature"]) == bool(mature)]


class MatureIn(BaseModel):
    mature: bool


@app.put("/api/mod/groups/{gid}/mature")
def mod_set_mature(gid: int, body: MatureIn, mod=Depends(mod_req)):
    """Reclassify a group (for example one that was labelled open but is really 18+)."""
    with db() as conn:
        if not conn.execute("SELECT 1 FROM groups WHERE id=?", (gid,)).fetchone():
            raise HTTPException(404, "Group not found")
        conn.execute("UPDATE groups SET mature=? WHERE id=?", (int(body.mature), gid))
    audit(mod, "set_group_mature", f"group={gid} mature={body.mature}")
    return {"ok": True}


@app.delete("/api/mod/groups/{gid}")
def mod_delete_group(gid: int, mod=Depends(mod_req)):
    with db() as conn:
        purge_group(conn, gid)
    audit(mod, "delete_group", f"group={gid}")
    return {"ok": True}


@app.get("/api/mod/media")
def mod_media(user_id: int = 0, limit: int = 50, mod=Depends(mod_req)):
    audit(mod, "list_media", f"user={user_id}")
    with db() as conn:
        q, args = "SELECT * FROM media", []
        if user_id:
            q += " WHERE user_id=?"
            args.append(user_id)
        return [{**dict(r), "url": f"/media/{r['name']}"} for r in conn.execute(q + " ORDER BY id DESC LIMIT ?", args + [min(max(limit, 1), 200)])]


@app.delete("/api/mod/media/{mid}")
def mod_delete_media(mid: int, mod=Depends(mod_req)):
    with db() as conn:
        drop_media(conn, conn.execute("SELECT id, name FROM media WHERE id=?", (mid,)).fetchall())
    audit(mod, "delete_media", f"media={mid}")
    return {"ok": True}


@app.get("/api/mod/audit")
def mod_audit_log(limit: int = 100, mod=Depends(mod_req)):
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM mod_audit ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),))]


# ── Huddle Corp: private encrypted workspaces for companies (separate accounts, tables and API) ──
import corp as _corp
from types import SimpleNamespace

app.include_router(_corp.build(SimpleNamespace(
    db=db, limiter=limiter, now=now, client_ip=client_ip, make_challenge=make_challenge, verify_pow=verify_pow,
    valid_pubkey=valid_pubkey, HOUR=HOUR, DAY=DAY)))

app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

# Three front doors: / lets people choose, /huddle is the social site, /corp is Huddle Corp.
PAGES = {"": "landing.html", "huddle": "index.html", "corp": "corp.html"}


@app.get("/{path:path}")
def spa(path: str):
    page = PAGES.get(path.strip("/"))
    if not page:
        raise HTTPException(404, "Not found")
    return FileResponse(BASE / "static" / page)
