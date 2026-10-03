import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
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
    created TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY, from_id INTEGER NOT NULL REFERENCES users(id),
    to_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


@app.on_event("startup")
def startup():
    with db() as conn:
        conn.executescript(SCHEMA)
        seed(conn)


def user_dict(r):
    return {
        "id": r["id"], "name": r["name"], "city": r["city"], "bio": r["bio"], "pronouns": r["pronouns"],
        "interests": json.loads(r["interests"]), "looking_for": json.loads(r["looking_for"]),
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
        # how well this event fits the viewer: interest overlap with tags + people they'd click with
        d["fit"] = len(shared(viewer, {"interests": d["tags"]}))
        d["people_like_you"] = sum(1 for a in attendees if a["id"] != viewer["id"] and a["shared"])
    return d


@app.get("/api/meta")
def meta():
    return {"categories": CATEGORIES, "looking_for": LOOKING_FOR}


@app.get("/api/events")
def list_events(q: str = "", category: str = "", city: str = "", viewer: int = 0, sort: str = "soon"):
    with db() as conn:
        v = get_user(conn, viewer) if viewer else None
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
def get_event(eid: int, viewer: int = 0):
    with db() as conn:
        r = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not r:
            raise HTTPException(404, "Event not found")
        v = get_user(conn, viewer) if viewer else None
        ev = event_dict(conn, r, v)
        ev["messages"] = [
            {"id": m["id"], "body": m["body"], "created": m["created"], "user": get_user(conn, m["user_id"])}
            for m in conn.execute("SELECT * FROM event_messages WHERE event_id=? ORDER BY id", (eid,))
        ]
        ev["icebreakers"] = random.Random(eid).sample(ICEBREAKERS, 3)
        return ev


class EventIn(BaseModel):
    host_id: int
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    category: str
    city: str = Field(min_length=2, max_length=80)
    venue: str = Field(min_length=2, max_length=120)
    starts: str
    capacity: int = Field(ge=2, le=500)
    tags: list[str] = []
    vibe: str = ""


@app.post("/api/events")
def create_event(e: EventIn):
    if e.category not in CATEGORIES:
        raise HTTPException(400, "Unknown category")
    try:
        datetime.fromisoformat(e.starts)
    except ValueError:
        raise HTTPException(400, "Invalid start time")
    with db() as conn:
        get_user(conn, e.host_id)
        cur = conn.execute(
            "INSERT INTO events (title, description, category, city, venue, starts, capacity, host_id, tags, vibe) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (e.title, e.description, e.category, e.city, e.venue, e.starts, e.capacity, e.host_id, json.dumps(e.tags[:8]), e.vibe),
        )
        conn.execute("INSERT INTO rsvps VALUES (?,?)", (cur.lastrowid, e.host_id))
        return {"id": cur.lastrowid}


class RsvpIn(BaseModel):
    user_id: int


@app.post("/api/events/{eid}/rsvp")
def rsvp(eid: int, body: RsvpIn):
    with db() as conn:
        r = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if not r:
            raise HTTPException(404, "Event not found")
        get_user(conn, body.user_id)
        count = conn.execute("SELECT COUNT(*) FROM rsvps WHERE event_id=?", (eid,)).fetchone()[0]
        already = conn.execute("SELECT 1 FROM rsvps WHERE event_id=? AND user_id=?", (eid, body.user_id)).fetchone()
        if not already and count >= r["capacity"]:
            raise HTTPException(409, "This event is full")
        conn.execute("INSERT OR IGNORE INTO rsvps VALUES (?,?)", (eid, body.user_id))
        return {"ok": True}


@app.delete("/api/events/{eid}/rsvp/{uid}")
def cancel_rsvp(eid: int, uid: int):
    with db() as conn:
        conn.execute("DELETE FROM rsvps WHERE event_id=? AND user_id=?", (eid, uid))
        return {"ok": True}


class MsgIn(BaseModel):
    user_id: int
    body: str = Field(min_length=1, max_length=1000)


@app.post("/api/events/{eid}/messages")
def post_message(eid: int, m: MsgIn):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM rsvps WHERE event_id=? AND user_id=?", (eid, m.user_id)).fetchone():
            raise HTTPException(403, "RSVP to join the conversation")
        conn.execute("INSERT INTO event_messages (event_id,user_id,body,created) VALUES (?,?,?,?)", (eid, m.user_id, m.body.strip(), now()))
        return {"ok": True}


class UserIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    city: str = Field(min_length=2, max_length=80)
    bio: str = Field(default="", max_length=400)
    pronouns: str = Field(default="", max_length=30)
    interests: list[str] = []
    looking_for: list[str] = []


def clean_list(xs, n):
    seen, out = set(), []
    for x in xs:
        x = x.strip()[:30]
        if x and x.lower() not in seen:
            seen.add(x.lower())
            out.append(x)
    return out[:n]


@app.post("/api/users")
def create_user(u: UserIn):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO users (name, city, bio, pronouns, interests, looking_for, created) VALUES (?,?,?,?,?,?,?)",
            (u.name.strip(), u.city.strip(), u.bio.strip(), u.pronouns.strip(), json.dumps(clean_list(u.interests, 12)), json.dumps(clean_list(u.looking_for, 6)), now()),
        )
        return get_user(conn, cur.lastrowid)


@app.put("/api/users/{uid}")
def update_user(uid: int, u: UserIn):
    with db() as conn:
        get_user(conn, uid)
        conn.execute(
            "UPDATE users SET name=?, city=?, bio=?, pronouns=?, interests=?, looking_for=? WHERE id=?",
            (u.name.strip(), u.city.strip(), u.bio.strip(), u.pronouns.strip(), json.dumps(clean_list(u.interests, 12)), json.dumps(clean_list(u.looking_for, 6)), uid),
        )
        return get_user(conn, uid)


@app.get("/api/users")
def list_users():
    with db() as conn:
        return [user_dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id")]


@app.get("/api/users/{uid}")
def profile(uid: int, viewer: int = 0):
    with db() as conn:
        u = get_user(conn, uid)
        u["events"] = [
            {"id": r["id"], "title": r["title"], "starts": r["starts"], "category": r["category"]}
            for r in conn.execute(
                "SELECT e.* FROM events e JOIN rsvps s ON s.event_id=e.id WHERE s.user_id=? AND e.starts>=? ORDER BY e.starts",
                (uid, datetime.now().isoformat(timespec="minutes")),
            )
        ]
        if viewer and viewer != uid:
            v = get_user(conn, viewer)
            u["shared"] = shared(v, u)
            u["shared_events"] = [
                r["title"] for r in conn.execute(
                    "SELECT e.title FROM events e JOIN rsvps a ON a.event_id=e.id AND a.user_id=? "
                    "JOIN rsvps b ON b.event_id=e.id AND b.user_id=?", (uid, viewer)
                )
            ]
        return u


@app.get("/api/users/{uid}/matches")
def matches(uid: int):
    """People you may click with: shared interests + shared goals + same city + events in common."""
    with db() as conn:
        me = get_user(conn, uid)
        out = []
        for r in conn.execute("SELECT * FROM users WHERE id != ?", (uid,)):
            o = user_dict(r)
            sh = shared(me, o)
            goals = [g for g in o["looking_for"] if g in me["looking_for"]]
            common = conn.execute(
                "SELECT COUNT(*) FROM rsvps a JOIN rsvps b ON a.event_id=b.event_id WHERE a.user_id=? AND b.user_id=?", (uid, o["id"])
            ).fetchone()[0]
            score = len(sh) * 3 + len(goals) * 2 + common * 2 + (2 if o["city"].lower() == me["city"].lower() else 0)
            if sh or goals:
                o.update(shared=sh, shared_goals=goals, events_in_common=common, score=score)
                out.append(o)
        out.sort(key=lambda x: -x["score"])
        return out[:12]


class DmIn(BaseModel):
    from_id: int
    to_id: int
    body: str = Field(min_length=1, max_length=1000)


@app.post("/api/dm")
def send_dm(d: DmIn):
    with db() as conn:
        get_user(conn, d.from_id)
        get_user(conn, d.to_id)
        if d.from_id == d.to_id:
            raise HTTPException(400, "Can't message yourself")
        conn.execute("INSERT INTO dms (from_id,to_id,body,created) VALUES (?,?,?,?)", (d.from_id, d.to_id, d.body.strip(), now()))
        return {"ok": True}


@app.get("/api/inbox/{uid}")
def inbox(uid: int):
    with db() as conn:
        get_user(conn, uid)
        rows = conn.execute("SELECT * FROM dms WHERE from_id=? OR to_id=? ORDER BY id DESC", (uid, uid)).fetchall()
        seen, threads = set(), []
        for r in rows:
            other = r["to_id"] if r["from_id"] == uid else r["from_id"]
            if other in seen:
                continue
            seen.add(other)
            threads.append({"user": get_user(conn, other), "last": r["body"], "created": r["created"], "mine": r["from_id"] == uid})
        return threads


@app.get("/api/dm/{uid}/{other}")
def thread(uid: int, other: int):
    with db() as conn:
        return [
            {"id": r["id"], "from_id": r["from_id"], "body": r["body"], "created": r["created"]}
            for r in conn.execute(
                "SELECT * FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ORDER BY id", (uid, other, other, uid)
            )
        ]


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.get("/{path:path}")
def spa(path: str):
    return FileResponse(BASE / "static" / "index.html")
