"""Huddle Corp: private, end-to-end encrypted workspaces for companies.

Completely separate from the social site: its own accounts, tables (corp_*) and API (/api/corp/*).

What the server can and cannot see
- It never sees message, task, page, event or plan *content*. Each piece of content is encrypted in the member's
  browser with a key that belongs to a "scope" (the whole workspace, or a private group of people). The server stores
  ciphertext plus a little plaintext metadata it needs to function: who is in a workspace and scope, roles, task
  status / assignee / due date, event times, who created what and when.
- Scope keys are handed to members as "grants": the key wrapped for that member with an ECDH-derived secret.
  Any member who already holds a key can grant it to a new member, so no one needs a server-side key.
- Removing someone from a scope marks it for rotation: a remaining member's browser makes a new key for later
  content and re-wraps it for everyone who is left.
Known limit: a malicious *server operator* could add a fake member and receive grants. Members can compare key
fingerprints (People page) to catch this. Signed membership (as in MLS) would close it.
"""
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

SCHEMA = """
CREATE TABLE IF NOT EXISTS corp_users (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, title TEXT DEFAULT '', public_key TEXT NOT NULL,
    token_hash TEXT, created TEXT NOT NULL, suspended INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS corp_workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS corp_members (
    workspace_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL, title TEXT DEFAULT '',
    start_date TEXT, new_hire INTEGER DEFAULT 0, joined TEXT NOT NULL, PRIMARY KEY (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS corp_invites (
    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
    label TEXT DEFAULT '', created_by INTEGER NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL,
    max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, new_hire INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS corp_scopes (
    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, kind TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1,
    rotation_needed INTEGER NOT NULL DEFAULT 0, created_by INTEGER NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS corp_scope_members (scope_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (scope_id, user_id));
CREATE TABLE IF NOT EXISTS corp_grants (
    scope_id INTEGER NOT NULL, epoch INTEGER NOT NULL, user_id INTEGER NOT NULL, granter_id INTEGER NOT NULL,
    wrapped TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY (scope_id, epoch, user_id)
);
CREATE TABLE IF NOT EXISTS corp_items (
    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, scope_id INTEGER NOT NULL, kind TEXT NOT NULL,
    parent_id INTEGER, meta TEXT NOT NULL DEFAULT '{}', iv TEXT NOT NULL DEFAULT '', ct TEXT NOT NULL DEFAULT '',
    epoch INTEGER NOT NULL, created_by INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS corp_items_ws ON corp_items (workspace_id, kind, parent_id);
CREATE TABLE IF NOT EXISTS corp_rsvps (item_id INTEGER NOT NULL, user_id INTEGER NOT NULL, status TEXT NOT NULL, PRIMARY KEY (item_id, user_id));
CREATE TABLE IF NOT EXISTS corp_audit (
    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, actor_id INTEGER, action TEXT NOT NULL, detail TEXT DEFAULT '', created TEXT NOT NULL
);
"""

RANK = {"member": 1, "manager": 2, "admin": 3, "owner": 4}
KINDS = {"channel", "message", "task", "page", "workflow", "run", "event", "incentive"}
# the lowest role that may create each kind of item
MIN_ROLE = {"channel": "member", "message": "member", "task": "member", "page": "manager", "event": "manager",
            "run": "manager", "workflow": "admin", "incentive": "admin"}
STATUSES = {"todo", "doing", "blocked", "done"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
MAX_CT = 64_000


def build(h):
    """h carries helpers shared with the social site (database, rate limiter, proof of work, ...)."""
    router = APIRouter(prefix="/api/corp")
    db, limiter = h.db, h.limiter

    def now():
        return h.now()

    def b64ok(s):
        try:
            base64.b64decode(s, validate=True)
            return True
        except Exception:
            return False

    def valid_wrap(w):
        parts = w.split(".")
        return len(parts) == 2 and all(p and b64ok(p) for p in parts)

    # ── accounts and access ──────────────────────────────────────────────────────
    def corp_me(request: Request):
        hdr = request.headers.get("authorization", "")
        if not hdr.startswith("Bearer "):
            raise HTTPException(401, "Please sign in")
        th = hashlib.sha256(hdr[7:].encode()).hexdigest()
        with db() as conn:
            r = conn.execute("SELECT * FROM corp_users WHERE token_hash=? AND deleted=0 AND suspended=0", (th,)).fetchone()
        if not r:
            raise HTTPException(401, "Please sign in")
        return dict(r)

    def user_pub(r):
        return {"id": r["id"], "name": r["name"], "title": r["title"], "public_key": json.loads(r["public_key"])}

    def need_member(conn, wid, uid):
        m = conn.execute("SELECT * FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, uid)).fetchone()
        if not m:
            raise HTTPException(404, "Workspace not found")
        return m

    def need_role(m, role):
        if RANK[m["role"]] < RANK[role]:
            raise HTTPException(403, f"This needs the {role} role")

    def audit(conn, wid, actor, action, detail=""):
        conn.execute("INSERT INTO corp_audit (workspace_id, actor_id, action, detail, created) VALUES (?,?,?,?,?)", (wid, actor, action, detail, now()))

    def scope_row(conn, wid, sid):
        s = conn.execute("SELECT * FROM corp_scopes WHERE id=? AND workspace_id=?", (sid, wid)).fetchone()
        if not s:
            raise HTTPException(404, "Not found")
        return s

    def in_scope(conn, sid, uid):
        return bool(conn.execute("SELECT 1 FROM corp_scope_members WHERE scope_id=? AND user_id=?", (sid, uid)).fetchone())

    def new_account(conn, name, title, public_key):
        token = secrets.token_urlsafe(32)
        cur = conn.execute("INSERT INTO corp_users (name, title, public_key, token_hash, created) VALUES (?,?,?,?,?)",
                           (name.strip(), title.strip(), json.dumps(public_key), hashlib.sha256(token.encode()).hexdigest(), now()))
        return cur.lastrowid, token

    def workspace_scope(conn, wid):
        return conn.execute("SELECT * FROM corp_scopes WHERE workspace_id=? AND kind='workspace'", (wid,)).fetchone()

    def add_to_workspace(conn, wid, uid, role, title="", new_hire=False):
        conn.execute("INSERT INTO corp_members (workspace_id, user_id, role, title, start_date, new_hire, joined) VALUES (?,?,?,?,?,?,?)",
                     (wid, uid, role, title, now()[:10] if new_hire else None, int(new_hire), now()))
        conn.execute("INSERT OR IGNORE INTO corp_scope_members VALUES (?,?)", (workspace_scope(conn, wid)["id"], uid))

    class SignupIn(BaseModel):
        name: str = Field(min_length=1, max_length=60)
        title: str = Field(default="", max_length=60)
        public_key: dict
        pow: dict
        website: str = ""  # honeypot

    class CompanyIn(SignupIn):
        company: str = Field(min_length=2, max_length=80)
        authorized: bool  # "I am allowed to create this workspace for my company"

    def check_signup(request, b):
        ip = h.client_ip(request)
        if b.website:
            raise HTTPException(400, "Could not create account")
        limiter.check(f"corp-signup-h:{ip}", 5, h.HOUR, "Too many sign-ups from your network. Try again later.")
        limiter.check(f"corp-signup-d:{ip}", 20, h.DAY, "Too many sign-ups from your network. Try again later.")
        if not h.valid_pubkey(b.public_key):
            raise HTTPException(400, "Invalid encryption key")
        h.verify_pow(str(b.pow.get("challenge", "")), str(b.pow.get("counter", "")))

    @router.get("/pow")
    def pow_(request: Request):
        limiter.check(f"pow:{h.client_ip(request)}", 30, h.HOUR)
        return h.make_challenge()

    @router.post("/signup")
    def signup(b: CompanyIn, request: Request):
        """Create an account and a new company workspace. The browser then uploads the workspace key grant."""
        if not b.authorized:
            raise HTTPException(400, "Please confirm you are allowed to create this workspace")
        check_signup(request, b)
        with db() as conn:
            uid, token = new_account(conn, b.name, b.title, b.public_key)
            wid = conn.execute("INSERT INTO corp_workspaces (name, owner_id, created) VALUES (?,?,?)", (b.company.strip(), uid, now())).lastrowid
            sid = conn.execute("INSERT INTO corp_scopes (workspace_id, kind, created_by, created) VALUES (?,?,?,?)", (wid, "workspace", uid, now())).lastrowid
            conn.execute("INSERT INTO corp_members (workspace_id, user_id, role, title, joined) VALUES (?,?,?,?,?)", (wid, uid, "owner", b.title.strip(), now()))
            conn.execute("INSERT INTO corp_scope_members VALUES (?,?)", (sid, uid))
            audit(conn, wid, uid, "workspace_created")
            return {"token": token, "user_id": uid, "workspace_id": wid, "scope_id": sid}

    class NewWorkspaceIn(BaseModel):
        company: str = Field(min_length=2, max_length=80)
        authorized: bool

    @router.post("/workspaces")
    def create_workspace(b: NewWorkspaceIn, u=Depends(corp_me)):
        """An existing account starts another company workspace and becomes its owner."""
        if not b.authorized:
            raise HTTPException(400, "Please confirm you are allowed to create this workspace")
        limiter.check(f"corp-newws:{u['id']}", 5, h.DAY, "You can create 5 workspaces a day.")
        with db() as conn:
            wid = conn.execute("INSERT INTO corp_workspaces (name, owner_id, created) VALUES (?,?,?)", (b.company.strip(), u["id"], now())).lastrowid
            sid = conn.execute("INSERT INTO corp_scopes (workspace_id, kind, created_by, created) VALUES (?,?,?,?)", (wid, "workspace", u["id"], now())).lastrowid
            conn.execute("INSERT INTO corp_members (workspace_id, user_id, role, title, joined) VALUES (?,?,?,?,?)", (wid, u["id"], "owner", u["title"], now()))
            conn.execute("INSERT INTO corp_scope_members VALUES (?,?)", (sid, u["id"]))
            audit(conn, wid, u["id"], "workspace_created")
            return {"workspace_id": wid, "scope_id": sid}

    @router.get("/me")
    def me(u=Depends(corp_me)):
        with db() as conn:
            ws = [{"id": r["id"], "name": r["name"], "role": r["role"], "title": r["title"]} for r in conn.execute(
                "SELECT w.id, w.name, m.role, m.title FROM corp_members m JOIN corp_workspaces w ON w.id=m.workspace_id WHERE m.user_id=? ORDER BY w.id", (u["id"],))]
            return {"user": user_pub(u), "workspaces": ws}

    class ProfileIn(BaseModel):
        name: str = Field(min_length=1, max_length=60)
        title: str = Field(default="", max_length=60)

    @router.put("/me")
    def update_me(b: ProfileIn, u=Depends(corp_me)):
        with db() as conn:
            conn.execute("UPDATE corp_users SET name=?, title=? WHERE id=?", (b.name.strip(), b.title.strip(), u["id"]))
            conn.execute("UPDATE corp_members SET title=? WHERE user_id=?", (b.title.strip(), u["id"]))
        return {"ok": True}

    # ── invites ──────────────────────────────────────────────────────────────────
    class InviteIn(BaseModel):
        role: str = "member"
        label: str = Field(default="", max_length=60)
        days: int = Field(default=7, ge=1, le=30)
        max_uses: int = Field(default=5, ge=1, le=100)
        new_hire: bool = True

    @router.post("/w/{wid}/invites")
    def create_invite(wid: int, b: InviteIn, u=Depends(corp_me)):
        if b.role not in ("member", "manager", "admin"):
            raise HTTPException(400, "Choose member, manager or admin")
        limiter.check(f"corp-invite:{u['id']}", 20, h.DAY)
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            need_role(m, "admin")
            if RANK[b.role] >= RANK[m["role"]] and m["role"] != "owner":
                raise HTTPException(403, "You can only invite people to roles below your own")
            token = secrets.token_urlsafe(24)
            exp = (datetime.now(timezone.utc) + timedelta(days=b.days)).isoformat(timespec="seconds")
            cur = conn.execute("INSERT INTO corp_invites (workspace_id, token_hash, role, label, created_by, created, expires, max_uses, new_hire) VALUES (?,?,?,?,?,?,?,?,?)",
                               (wid, hashlib.sha256(token.encode()).hexdigest(), b.role, b.label.strip(), u["id"], now(), exp, b.max_uses, int(b.new_hire)))
            audit(conn, wid, u["id"], "invite_created", f"role={b.role} uses={b.max_uses}")
            return {"id": cur.lastrowid, "token": token, "role": b.role, "expires": exp}  # the token is shown once and never stored

    @router.get("/w/{wid}/invites")
    def list_invites(wid: int, u=Depends(corp_me)):
        with db() as conn:
            need_role(need_member(conn, wid, u["id"]), "admin")
            return [dict(r) for r in conn.execute(
                "SELECT id, role, label, created, expires, max_uses, uses, revoked, new_hire FROM corp_invites WHERE workspace_id=? ORDER BY id DESC", (wid,))]

    @router.delete("/w/{wid}/invites/{iid}")
    def revoke_invite(wid: int, iid: int, u=Depends(corp_me)):
        with db() as conn:
            need_role(need_member(conn, wid, u["id"]), "admin")
            conn.execute("UPDATE corp_invites SET revoked=1 WHERE id=? AND workspace_id=?", (iid, wid))
            audit(conn, wid, u["id"], "invite_revoked", str(iid))
        return {"ok": True}

    def live_invite(conn, token):
        inv = conn.execute("SELECT * FROM corp_invites WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not inv or inv["revoked"] or inv["uses"] >= inv["max_uses"] or inv["expires"] < now():
            raise HTTPException(404, "This invite link isn't valid any more. Ask your admin for a new one.")
        return inv

    @router.get("/invites/{token}")
    def peek_invite(token: str, request: Request):
        limiter.check(f"corp-peek:{h.client_ip(request)}", 30, h.HOUR)
        with db() as conn:
            inv = live_invite(conn, token)
            w = conn.execute("SELECT name FROM corp_workspaces WHERE id=?", (inv["workspace_id"],)).fetchone()
            return {"workspace": w["name"], "role": inv["role"]}

    class JoinIn(SignupIn):
        token: str

    @router.post("/join")
    def join(b: JoinIn, request: Request):
        check_signup(request, b)
        with db() as conn:
            inv = live_invite(conn, b.token)
            uid, token = new_account(conn, b.name, b.title, b.public_key)
            add_to_workspace(conn, inv["workspace_id"], uid, inv["role"], b.title.strip(), new_hire=bool(inv["new_hire"]))
            conn.execute("UPDATE corp_invites SET uses=uses+1 WHERE id=?", (inv["id"],))
            audit(conn, inv["workspace_id"], uid, "member_joined", f"role={inv['role']}")
            return {"token": token, "user_id": uid, "workspace_id": inv["workspace_id"]}

    @router.post("/invites/{token}/accept")
    def accept_invite(token: str, u=Depends(corp_me)):
        """An existing account joins another workspace."""
        with db() as conn:
            inv = live_invite(conn, token)
            if conn.execute("SELECT 1 FROM corp_members WHERE workspace_id=? AND user_id=?", (inv["workspace_id"], u["id"])).fetchone():
                return {"workspace_id": inv["workspace_id"]}
            add_to_workspace(conn, inv["workspace_id"], u["id"], inv["role"], u["title"], new_hire=bool(inv["new_hire"]))
            conn.execute("UPDATE corp_invites SET uses=uses+1 WHERE id=?", (inv["id"],))
            audit(conn, inv["workspace_id"], u["id"], "member_joined", f"role={inv['role']}")
            return {"workspace_id": inv["workspace_id"]}

    # ── the workspace, its people and its keys ───────────────────────────────────
    def member_dict(conn, r):
        u = conn.execute("SELECT * FROM corp_users WHERE id=?", (r["user_id"],)).fetchone()
        return {**user_pub(u), "title": r["title"], "role": r["role"], "start_date": r["start_date"], "new_hire": bool(r["new_hire"]), "joined": r["joined"]}

    @router.get("/w/{wid}")
    def get_workspace(wid: int, u=Depends(corp_me)):
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            w = conn.execute("SELECT * FROM corp_workspaces WHERE id=?", (wid,)).fetchone()
            members = [member_dict(conn, r) for r in conn.execute("SELECT * FROM corp_members WHERE workspace_id=? ORDER BY joined", (wid,))]
            scopes = []
            for s in conn.execute("SELECT s.* FROM corp_scopes s JOIN corp_scope_members x ON x.scope_id=s.id WHERE s.workspace_id=? AND x.user_id=? ORDER BY s.id", (wid, u["id"])):
                scopes.append({"id": s["id"], "kind": s["kind"], "epoch": s["epoch"], "rotation_needed": bool(s["rotation_needed"]), "created_by": s["created_by"],
                               "member_ids": [x["user_id"] for x in conn.execute("SELECT user_id FROM corp_scope_members WHERE scope_id=?", (s["id"],))]})
            sids = [s["id"] for s in scopes]
            grants = [dict(g) for g in conn.execute(
                f"SELECT scope_id, epoch, granter_id, wrapped FROM corp_grants WHERE user_id=? AND scope_id IN ({','.join('?' * len(sids)) or 'NULL'})", [u["id"], *sids])]
            granters = {}
            for g in grants:  # keys of whoever granted, even if they have since left, so old grants can still be opened
                gu = conn.execute("SELECT * FROM corp_users WHERE id=?", (g["granter_id"],)).fetchone()
                if gu:
                    granters[gu["id"]] = json.loads(gu["public_key"])
            return {"id": w["id"], "name": w["name"], "created": w["created"], "me": {"id": u["id"], "role": m["role"]},
                    "members": members, "scopes": scopes, "grants": grants, "granter_keys": granters}

    class WorkspaceIn(BaseModel):
        name: str = Field(min_length=2, max_length=80)

    @router.put("/w/{wid}")
    def rename_workspace(wid: int, b: WorkspaceIn, u=Depends(corp_me)):
        with db() as conn:
            need_role(need_member(conn, wid, u["id"]), "admin")
            conn.execute("UPDATE corp_workspaces SET name=? WHERE id=?", (b.name.strip(), wid))
            audit(conn, wid, u["id"], "workspace_renamed")
        return {"ok": True}

    @router.delete("/w/{wid}")
    def delete_workspace(wid: int, u=Depends(corp_me)):
        with db() as conn:
            need_role(need_member(conn, wid, u["id"]), "owner")
            sids = [s["id"] for s in conn.execute("SELECT id FROM corp_scopes WHERE workspace_id=?", (wid,))]
            for sid in sids:
                conn.execute("DELETE FROM corp_grants WHERE scope_id=?", (sid,))
                conn.execute("DELETE FROM corp_scope_members WHERE scope_id=?", (sid,))
            conn.execute("DELETE FROM corp_rsvps WHERE item_id IN (SELECT id FROM corp_items WHERE workspace_id=?)", (wid,))
            for t in ("corp_items", "corp_scopes", "corp_invites", "corp_members", "corp_audit"):
                conn.execute(f"DELETE FROM {t} WHERE workspace_id=?", (wid,))
            conn.execute("DELETE FROM corp_workspaces WHERE id=?", (wid,))
        return {"ok": True}

    class MemberIn(BaseModel):
        role: str | None = None
        title: str | None = Field(default=None, max_length=60)
        new_hire: bool | None = None
        start_date: str | None = None

    @router.put("/w/{wid}/members/{uid}")
    def update_member(wid: int, uid: int, b: MemberIn, u=Depends(corp_me)):
        with db() as conn:
            me_m = need_member(conn, wid, u["id"])
            target = conn.execute("SELECT * FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, uid)).fetchone()
            if not target:
                raise HTTPException(404, "Person not found")
            own = uid == u["id"]
            if not own:
                need_role(me_m, "admin")
            elif (b.role is not None or b.new_hire is not None) and RANK[me_m["role"]] < RANK["admin"]:
                raise HTTPException(403, "Only an admin can change that")
            if b.role is not None:
                if b.role not in RANK or b.role == "owner":
                    raise HTTPException(400, "Choose member, manager or admin")
                if target["role"] == "owner" or uid == u["id"]:
                    raise HTTPException(403, "You can't change that person's role")
                need_role(me_m, "admin")
                if me_m["role"] != "owner" and (RANK[target["role"]] >= RANK[me_m["role"]] or RANK[b.role] >= RANK[me_m["role"]]):
                    raise HTTPException(403, "Only the owner can manage admins")
                conn.execute("UPDATE corp_members SET role=? WHERE workspace_id=? AND user_id=?", (b.role, wid, uid))
                audit(conn, wid, u["id"], "role_changed", f"user={uid} role={b.role}")
            if b.title is not None:
                conn.execute("UPDATE corp_members SET title=? WHERE workspace_id=? AND user_id=?", (b.title.strip(), wid, uid))
            if b.new_hire is not None:
                if b.start_date and not DATE_RE.match(b.start_date):
                    raise HTTPException(400, "Use a date like 2026-01-15")
                conn.execute("UPDATE corp_members SET new_hire=?, start_date=COALESCE(?, start_date) WHERE workspace_id=? AND user_id=?", (int(b.new_hire), b.start_date, wid, uid))
                audit(conn, wid, u["id"], "new_hire_flag", f"user={uid} on={b.new_hire}")
        return {"ok": True}

    def drop_from_scope(conn, sid, uid):
        conn.execute("DELETE FROM corp_scope_members WHERE scope_id=? AND user_id=?", (sid, uid))
        if conn.execute("SELECT 1 FROM corp_scope_members WHERE scope_id=?", (sid,)).fetchone():
            conn.execute("UPDATE corp_scopes SET rotation_needed=1 WHERE id=?", (sid,))  # someone who knew the key just left

    @router.delete("/w/{wid}/members/{uid}")
    def remove_member(wid: int, uid: int, u=Depends(corp_me)):
        with db() as conn:
            me_m = need_member(conn, wid, u["id"])
            target = conn.execute("SELECT * FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, uid)).fetchone()
            if not target:
                raise HTTPException(404, "Person not found")
            if target["role"] == "owner":
                raise HTTPException(403, "The owner can't be removed. Delete the workspace instead.")
            if uid != u["id"]:
                need_role(me_m, "admin")
                if me_m["role"] != "owner" and RANK[target["role"]] >= RANK[me_m["role"]]:
                    raise HTTPException(403, "Only the owner can remove admins")
            for s in conn.execute("SELECT id FROM corp_scopes WHERE workspace_id=?", (wid,)).fetchall():
                drop_from_scope(conn, s["id"], uid)
            conn.execute("DELETE FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, uid))
            audit(conn, wid, u["id"], "member_removed" if uid != u["id"] else "member_left", f"user={uid}")
        return {"ok": True}

    # ── scopes (private groups) and key grants ───────────────────────────────────
    class ScopeIn(BaseModel):
        member_ids: list[int] = Field(min_length=1, max_length=200)

    @router.post("/w/{wid}/scopes")
    def create_scope(wid: int, b: ScopeIn, u=Depends(corp_me)):
        limiter.check(f"corp-scope:{u['id']}", 60, h.HOUR)
        with db() as conn:
            need_member(conn, wid, u["id"])
            ids = set(b.member_ids) | {u["id"]}
            for i in ids:
                if not conn.execute("SELECT 1 FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, i)).fetchone():
                    raise HTTPException(400, "Everyone in a private group must belong to this workspace")
            sid = conn.execute("INSERT INTO corp_scopes (workspace_id, kind, created_by, created) VALUES (?,?,?,?)", (wid, "private", u["id"], now())).lastrowid
            for i in ids:
                conn.execute("INSERT INTO corp_scope_members VALUES (?,?)", (sid, i))
            audit(conn, wid, u["id"], "private_group_created", f"scope={sid} members={len(ids)}")
            return {"id": sid, "epoch": 1}

    @router.put("/w/{wid}/scopes/{sid}/members/{uid}")
    def add_scope_member(wid: int, sid: int, uid: int, u=Depends(corp_me)):
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            s = scope_row(conn, wid, sid)
            if s["kind"] != "private" or not in_scope(conn, sid, u["id"]):
                raise HTTPException(404, "Not found")
            if s["created_by"] != u["id"] and RANK[m["role"]] < RANK["admin"]:
                raise HTTPException(403, "Only the person who made this group, or an admin, can add people")
            if not conn.execute("SELECT 1 FROM corp_members WHERE workspace_id=? AND user_id=?", (wid, uid)).fetchone():
                raise HTTPException(400, "That person isn't in this workspace")
            conn.execute("INSERT OR IGNORE INTO corp_scope_members VALUES (?,?)", (sid, uid))
            audit(conn, wid, u["id"], "private_group_member_added", f"scope={sid} user={uid}")
        return {"ok": True}

    @router.delete("/w/{wid}/scopes/{sid}/members/{uid}")
    def remove_scope_member(wid: int, sid: int, uid: int, u=Depends(corp_me)):
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            s = scope_row(conn, wid, sid)
            if s["kind"] != "private" or not in_scope(conn, sid, u["id"]):
                raise HTTPException(404, "Not found")
            if uid != u["id"] and s["created_by"] != u["id"] and RANK[m["role"]] < RANK["admin"]:
                raise HTTPException(403, "Only the person who made this group, or an admin, can remove people")
            drop_from_scope(conn, sid, uid)
            audit(conn, wid, u["id"], "private_group_member_removed", f"scope={sid} user={uid}")
        return {"ok": True}

    class GrantIn(BaseModel):
        user_id: int
        wrapped: str = Field(max_length=2000)

    class GrantsIn(BaseModel):
        epoch: int
        grants: list[GrantIn] = Field(max_length=300)

    def holds(conn, sid, epoch, uid):
        return bool(conn.execute("SELECT 1 FROM corp_grants WHERE scope_id=? AND epoch=? AND user_id=?", (sid, epoch, uid)).fetchone())

    @router.post("/w/{wid}/scopes/{sid}/grants")
    def post_grants(wid: int, sid: int, b: GrantsIn, u=Depends(corp_me)):
        limiter.check(f"corp-grant:{u['id']}", 120, h.HOUR)
        with db() as conn:
            need_member(conn, wid, u["id"])
            s = scope_row(conn, wid, sid)
            if not in_scope(conn, sid, u["id"]) or b.epoch < 1 or b.epoch > s["epoch"]:
                raise HTTPException(404, "Not found")
            first_ever = not conn.execute("SELECT 1 FROM corp_grants WHERE scope_id=? AND epoch=?", (sid, b.epoch)).fetchone()
            if not (holds(conn, sid, b.epoch, u["id"]) or (first_ever and b.epoch == 1 and s["created_by"] == u["id"])):
                raise HTTPException(403, "You don't hold this key yet, so you can't share it")
            done = 0
            for g in b.grants:
                if not in_scope(conn, sid, g.user_id) or not valid_wrap(g.wrapped):
                    continue
                cur = conn.execute("INSERT OR IGNORE INTO corp_grants VALUES (?,?,?,?,?,?)", (sid, b.epoch, g.user_id, u["id"], g.wrapped, now()))
                done += cur.rowcount
            return {"granted": done}

    @router.get("/w/{wid}/pending")
    def pending(wid: int, u=Depends(corp_me)):
        """Who in my scopes is missing a key I could give them? My browser answers this automatically."""
        out = []
        with db() as conn:
            need_member(conn, wid, u["id"])
            for s in conn.execute("SELECT s.id FROM corp_scopes s JOIN corp_scope_members x ON x.scope_id=s.id WHERE s.workspace_id=? AND x.user_id=?", (wid, u["id"])):
                epochs = [g["epoch"] for g in conn.execute("SELECT epoch FROM corp_grants WHERE scope_id=? AND user_id=?", (s["id"], u["id"]))]
                for x in conn.execute("SELECT c.id, c.public_key FROM corp_scope_members x JOIN corp_users c ON c.id=x.user_id WHERE x.scope_id=? AND x.user_id!=?", (s["id"], u["id"])):
                    for e in epochs:
                        if not holds(conn, s["id"], e, x["id"]):
                            out.append({"scope_id": s["id"], "epoch": e, "user_id": x["id"], "public_key": json.loads(x["public_key"])})
        return out[:300]

    class RotateIn(BaseModel):
        epoch: int
        grants: list[GrantIn] = Field(max_length=300)

    @router.post("/w/{wid}/scopes/{sid}/rotate")
    def rotate(wid: int, sid: int, b: RotateIn, u=Depends(corp_me)):
        """After someone leaves a scope, a remaining member makes a fresh key and wraps it for everyone who is left."""
        with db() as conn:
            need_member(conn, wid, u["id"])
            s = scope_row(conn, wid, sid)
            if not in_scope(conn, sid, u["id"]) or not holds(conn, sid, s["epoch"], u["id"]):
                raise HTTPException(403, "You don't hold this key")
            if b.epoch != s["epoch"] + 1:
                raise HTTPException(409, "stale_epoch")
            members = {x["user_id"] for x in conn.execute("SELECT user_id FROM corp_scope_members WHERE scope_id=?", (sid,))}
            if {g.user_id for g in b.grants} != members:
                raise HTTPException(400, "The new key must be shared with exactly the people who are in this group now")
            if not all(valid_wrap(g.wrapped) for g in b.grants):
                raise HTTPException(400, "Malformed key")
            for g in b.grants:
                conn.execute("INSERT OR REPLACE INTO corp_grants VALUES (?,?,?,?,?,?)", (sid, b.epoch, g.user_id, u["id"], g.wrapped, now()))
            conn.execute("UPDATE corp_scopes SET epoch=?, rotation_needed=0 WHERE id=?", (b.epoch, sid))
            audit(conn, wid, u["id"], "key_rotated", f"scope={sid} epoch={b.epoch}")
        return {"epoch": b.epoch}

    # ── encrypted items: channels, messages, tasks, pages, workflows, runs, events, incentives ──
    class ItemIn(BaseModel):
        kind: str
        scope_id: int
        parent_id: int | None = None
        meta: dict = {}
        iv: str = Field(max_length=64)
        ct: str = Field(max_length=MAX_CT)
        epoch: int

    class ItemPatch(BaseModel):
        meta: dict | None = None
        iv: str | None = Field(default=None, max_length=64)
        ct: str | None = Field(default=None, max_length=MAX_CT)
        epoch: int | None = None

    def clean_meta(conn, wid, scope_id, kind, meta):
        """Plaintext metadata the server needs. Anything else is dropped, so content can't leak into it."""
        def date(v):
            if v is not None and not (isinstance(v, str) and DATE_RE.match(v)):
                raise HTTPException(400, "Use dates like 2026-01-15")
            return v

        def person(v):
            if v is None:
                return None
            if not isinstance(v, int) or not in_scope(conn, scope_id, v):
                raise HTTPException(400, "That person can't see this item. Pick someone from its group.")
            return v
        if kind == "task":
            status = meta.get("status", "todo")
            if status not in STATUSES:
                raise HTTPException(400, "Unknown status")
            pr = meta.get("priority", 2)
            return {"status": status, "assignee_id": person(meta.get("assignee_id")), "due": date(meta.get("due")),
                    "priority": pr if pr in (1, 2, 3) else 2, "run_id": meta.get("run_id") if isinstance(meta.get("run_id"), int) else None}
        if kind == "run":
            return {"workflow_id": meta.get("workflow_id") if isinstance(meta.get("workflow_id"), int) else None, "subject_id": person(meta.get("subject_id")),
                    "status": meta.get("status") if meta.get("status") in ("active", "done") else "active"}
        if kind == "event":
            starts = meta.get("starts")
            if not isinstance(starts, str) or not DT_RE.match(starts):
                raise HTTPException(400, "Choose when the event starts")
            return {"starts": starts, "ends": meta.get("ends") if isinstance(meta.get("ends"), str) and DT_RE.match(meta["ends"]) else None}
        if kind == "incentive":
            return {"status": "closed" if meta.get("status") == "closed" else "active", "ends": date(meta.get("ends"))}
        if kind == "page":
            return {"pinned": bool(meta.get("pinned"))}
        if kind == "channel":
            return {"archived": bool(meta.get("archived"))}
        return {}

    def item_dict(conn, r, uid):
        d = {"id": r["id"], "kind": r["kind"], "scope_id": r["scope_id"], "parent_id": r["parent_id"], "meta": json.loads(r["meta"]),
             "iv": r["iv"], "ct": r["ct"], "epoch": r["epoch"], "created_by": r["created_by"], "created": r["created"], "updated": r["updated"]}
        if r["kind"] == "event":
            d["rsvps"] = [{"user_id": x["user_id"], "status": x["status"]} for x in conn.execute("SELECT * FROM corp_rsvps WHERE item_id=?", (r["id"],))]
        return d

    def create_item(conn, wid, u, m, b):
        if b.kind not in KINDS:
            raise HTTPException(400, "Unknown item type")
        need_role(m, MIN_ROLE[b.kind])
        s = scope_row(conn, wid, b.scope_id)
        if not in_scope(conn, s["id"], u["id"]):
            raise HTTPException(404, "Not found")
        if b.epoch != s["epoch"]:
            raise HTTPException(409, "stale_epoch")
        if not (b64ok(b.iv) and b64ok(b.ct)) or not b.ct:
            raise HTTPException(400, "Malformed content")
        if b.kind == "message":
            p = conn.execute("SELECT * FROM corp_items WHERE id=? AND workspace_id=? AND scope_id=? AND deleted=0", (b.parent_id or 0, wid, s["id"])).fetchone()
            if not p or p["kind"] not in ("channel", "task"):
                raise HTTPException(400, "Messages belong in a channel or on a task")
        elif b.parent_id is not None:
            raise HTTPException(400, "Only messages can have a parent")
        meta = clean_meta(conn, wid, s["id"], b.kind, b.meta or {})
        cur = conn.execute("INSERT INTO corp_items (workspace_id, scope_id, kind, parent_id, meta, iv, ct, epoch, created_by, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (wid, s["id"], b.kind, b.parent_id, json.dumps(meta), b.iv, b.ct, b.epoch, u["id"], now(), now()))
        if b.kind not in ("message", "task"):
            audit(conn, wid, u["id"], f"{b.kind}_created", f"item={cur.lastrowid}")
        return cur.lastrowid

    @router.post("/w/{wid}/items")
    def post_item(wid: int, b: ItemIn, u=Depends(corp_me)):
        limiter.check(f"corp-item-min:{u['id']}", 90, 60, "You're doing that too fast. Please slow down.")
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            return {"id": create_item(conn, wid, u, m, b)}

    class BatchIn(BaseModel):
        items: list[ItemIn] = Field(min_length=1, max_length=60)

    @router.post("/w/{wid}/items/batch")
    def post_batch(wid: int, b: BatchIn, u=Depends(corp_me)):
        limiter.check(f"corp-batch:{u['id']}", 30, h.HOUR)
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            return {"ids": [create_item(conn, wid, u, m, i) for i in b.items]}

    @router.get("/w/{wid}/items")
    def list_items(wid: int, kind: str = "", parent_id: int = 0, after_id: int = 0, u=Depends(corp_me)):
        with db() as conn:
            need_member(conn, wid, u["id"])
            q = ("SELECT i.* FROM corp_items i JOIN corp_scope_members x ON x.scope_id=i.scope_id AND x.user_id=? "
                 "WHERE i.workspace_id=? AND i.deleted=0 AND i.id>?")
            args = [u["id"], wid, after_id]
            if kind:
                q += " AND i.kind=?"
                args.append(kind)
            if parent_id:
                q += " AND i.parent_id=?"
                args.append(parent_id)
            return [item_dict(conn, r, u["id"]) for r in conn.execute(q + " ORDER BY i.id LIMIT 1000", args)]

    def own_item(conn, wid, iid, u):
        r = conn.execute("SELECT * FROM corp_items WHERE id=? AND workspace_id=? AND deleted=0", (iid, wid)).fetchone()
        if not r or not in_scope(conn, r["scope_id"], u["id"]):
            raise HTTPException(404, "Not found")
        return r

    @router.put("/w/{wid}/items/{iid}")
    def patch_item(wid: int, iid: int, b: ItemPatch, u=Depends(corp_me)):
        limiter.check(f"corp-item-min:{u['id']}", 90, 60, "You're doing that too fast. Please slow down.")
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            r = own_item(conn, wid, iid, u)
            mine = r["created_by"] == u["id"]
            meta = json.loads(r["meta"])
            assignee = r["kind"] == "task" and meta.get("assignee_id") == u["id"]
            boss = RANK[m["role"]] >= RANK["manager"]
            if b.iv is not None or b.ct is not None:  # editing the content
                if not (mine or boss) or b.iv is None or b.ct is None or b.epoch is None:
                    raise HTTPException(403, "You can't edit this")
                s = scope_row(conn, wid, r["scope_id"])
                if b.epoch != s["epoch"]:
                    raise HTTPException(409, "stale_epoch")
                if not (b64ok(b.iv) and b64ok(b.ct)) or not b.ct:
                    raise HTTPException(400, "Malformed content")
                conn.execute("UPDATE corp_items SET iv=?, ct=?, epoch=?, updated=? WHERE id=?", (b.iv, b.ct, b.epoch, now(), iid))
            if b.meta is not None:
                if not (mine or boss or assignee) or (r["kind"] == "workflow" and RANK[m["role"]] < RANK["admin"]):
                    raise HTTPException(403, "You can't change this")
                merged = clean_meta(conn, wid, r["scope_id"], r["kind"], {**meta, **b.meta})
                if r["kind"] == "task" and assignee and not (mine or boss):  # assignees can move their task along, not hand it off
                    merged["assignee_id"], merged["due"], merged["priority"] = meta.get("assignee_id"), meta.get("due"), meta.get("priority", 2)
                conn.execute("UPDATE corp_items SET meta=?, updated=? WHERE id=?", (json.dumps(merged), now(), iid))
        return {"ok": True}

    @router.delete("/w/{wid}/items/{iid}")
    def delete_item(wid: int, iid: int, u=Depends(corp_me)):
        with db() as conn:
            m = need_member(conn, wid, u["id"])
            r = own_item(conn, wid, iid, u)
            if r["created_by"] != u["id"] and RANK[m["role"]] < RANK["manager" if r["kind"] != "message" else "admin"]:
                raise HTTPException(403, "You can't delete this")
            ids = [iid] + [c["id"] for c in conn.execute("SELECT id FROM corp_items WHERE parent_id=?", (iid,))]
            for i in ids:
                conn.execute("UPDATE corp_items SET deleted=1, iv='', ct='', updated=? WHERE id=?", (now(), i))
                conn.execute("DELETE FROM corp_rsvps WHERE item_id=?", (i,))
            if r["kind"] not in ("message", "task"):
                audit(conn, wid, u["id"], f"{r['kind']}_deleted", f"item={iid}")
        return {"ok": True}

    class RsvpIn(BaseModel):
        status: str

    @router.put("/w/{wid}/items/{iid}/rsvp")
    def rsvp(wid: int, iid: int, b: RsvpIn, u=Depends(corp_me)):
        if b.status not in ("yes", "no", "maybe"):
            raise HTTPException(400, "Choose yes, no or maybe")
        with db() as conn:
            need_member(conn, wid, u["id"])
            r = own_item(conn, wid, iid, u)
            if r["kind"] != "event":
                raise HTTPException(400, "That isn't an event")
            conn.execute("INSERT OR REPLACE INTO corp_rsvps VALUES (?,?,?)", (iid, u["id"], b.status))
        return {"ok": True}

    @router.get("/w/{wid}/audit")
    def get_audit(wid: int, u=Depends(corp_me)):
        with db() as conn:
            need_role(need_member(conn, wid, u["id"]), "admin")
            return [dict(r) for r in conn.execute("SELECT * FROM corp_audit WHERE workspace_id=? ORDER BY id DESC LIMIT 200", (wid,))]

    @router.delete("/me")
    def delete_me(u=Depends(corp_me)):
        with db() as conn:
            if conn.execute("SELECT 1 FROM corp_members WHERE user_id=? AND role='owner'", (u["id"],)).fetchone():
                raise HTTPException(400, "You own a workspace. Delete it first, or ask to hand it over.")
            for w in conn.execute("SELECT workspace_id FROM corp_members WHERE user_id=?", (u["id"],)).fetchall():
                for s in conn.execute("SELECT id FROM corp_scopes WHERE workspace_id=?", (w["workspace_id"],)).fetchall():
                    drop_from_scope(conn, s["id"], u["id"])
                audit(conn, w["workspace_id"], u["id"], "member_left", f"user={u['id']}")
            conn.execute("DELETE FROM corp_members WHERE user_id=?", (u["id"],))
            conn.execute("DELETE FROM corp_rsvps WHERE user_id=?", (u["id"],))
            conn.execute("UPDATE corp_users SET name='Former member', title='', token_hash=NULL, deleted=1 WHERE id=?", (u["id"],))
        return {"ok": True}

    return router
