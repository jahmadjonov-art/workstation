"""Huddle Corp tests. The helpers below do what a browser does: make keys, wrap workspace keys for teammates,
and encrypt content, so the server only ever sees ciphertext."""
import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import server
from test_server import jwk_pub, pub_from_jwk, solve

b64 = lambda b: base64.b64encode(b).decode()
unb = lambda s: base64.b64decode(s)


@pytest.fixture()
def c(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_PATH", str(tmp_path / "t.db"))
    server.limiter.clear()
    server._recent_signups.clear()
    with TestClient(server.app) as client:
        yield client


def wrap(my_priv, their_pub_jwk, raw_key):
    secret = my_priv.exchange(ec.ECDH(), pub_from_jwk(their_pub_jwk))
    iv = os.urandom(12)
    return b64(iv) + "." + b64(AESGCM(secret).encrypt(iv, raw_key, None))


def unwrap(my_priv, granter_pub_jwk, wrapped):
    iv, ct = wrapped.split(".")
    return AESGCM(my_priv.exchange(ec.ECDH(), pub_from_jwk(granter_pub_jwk))).decrypt(unb(iv), unb(ct), None)


class P:
    """One person in a workspace, with their own keys."""

    def __init__(self, c, name="Pat", company=None, token=None, title="", throttle=False):
        if not throttle:  # tests make lots of accounts from one address; the sign-up limit has its own test
            for k in [k for k in server.limiter.hits if k.startswith("corp-signup")]:
                del server.limiter.hits[k]
        self.c, self.priv, self.keys, self.name = c, ec.generate_private_key(ec.SECP256R1()), {}, name
        ch = c.get("/api/corp/pow").json()
        body = {"name": name, "title": title, "public_key": jwk_pub(self.priv), "pow": {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])}}
        if company:
            r = c.post("/api/corp/signup", json={**body, "company": company, "authorized": True})
        else:
            r = c.post("/api/corp/join", json={**body, "token": token})
        self.resp = r
        if r.status_code == 200:
            j = r.json()
            self.id, self.wid, self.h = j["user_id"], j["workspace_id"], {"Authorization": "Bearer " + j["token"]}
            self.scope_id = j.get("scope_id")

    @property
    def pub(self):
        return jwk_pub(self.priv)

    def ws(self):
        return self.c.get(f"/api/corp/w/{self.wid}", headers=self.h).json()

    def start_workspace(self):
        """Founder: make the workspace key and give it to yourself."""
        self.keys[(self.scope_id, 1)] = os.urandom(32)
        r = self.c.post(f"/api/corp/w/{self.wid}/scopes/{self.scope_id}/grants", headers=self.h,
                        json={"epoch": 1, "grants": [{"user_id": self.id, "wrapped": wrap(self.priv, self.pub, self.keys[(self.scope_id, 1)])}]})
        assert r.status_code == 200, r.text

    def grant_pending(self):
        """What a member's browser does on its own: give keys to teammates who are waiting for them."""
        n = 0
        for p in self.c.get(f"/api/corp/w/{self.wid}/pending", headers=self.h).json():
            key = self.keys.get((p["scope_id"], p["epoch"]))
            if key:
                r = self.c.post(f"/api/corp/w/{self.wid}/scopes/{p['scope_id']}/grants", headers=self.h,
                                json={"epoch": p["epoch"], "grants": [{"user_id": p["user_id"], "wrapped": wrap(self.priv, p["public_key"], key)}]})
                n += r.json()["granted"]
        return n

    def unlock(self):
        """Open the key grants I have been given."""
        w = self.ws()
        for g in w["grants"]:
            self.keys[(g["scope_id"], g["epoch"])] = unwrap(self.priv, w["granter_keys"][str(g["granter_id"])], g["wrapped"])
        return w

    def seal(self, scope_id, epoch, kind, parent_id, obj):
        iv = os.urandom(12)
        aad = f"{self.wid}|{scope_id}|{kind}|{parent_id or 0}".encode()
        return b64(iv), b64(AESGCM(self.keys[(scope_id, epoch)]).encrypt(iv, json.dumps(obj).encode(), aad))

    def open(self, item):
        aad = f"{self.wid}|{item['scope_id']}|{item['kind']}|{item['parent_id'] or 0}".encode()
        return json.loads(AESGCM(self.keys[(item["scope_id"], item["epoch"])]).decrypt(unb(item["iv"]), unb(item["ct"]), aad))

    def post(self, kind, obj, scope=None, parent=None, meta=None, epoch=None):
        scope = scope or self.scope_id or self.ws()["scopes"][0]["id"]
        epoch = epoch or next(s["epoch"] for s in self.ws()["scopes"] if s["id"] == scope)
        iv, ct = self.seal(scope, epoch, kind, parent, obj)
        return self.c.post(f"/api/corp/w/{self.wid}/items", headers=self.h,
                           json={"kind": kind, "scope_id": scope, "parent_id": parent, "meta": meta or {}, "iv": iv, "ct": ct, "epoch": epoch})

    def items(self, kind="", parent=0):
        return self.c.get(f"/api/corp/w/{self.wid}/items?kind={kind}&parent_id={parent}", headers=self.h).json()

    def invite(self, role="member", **kw):
        r = self.c.post(f"/api/corp/w/{self.wid}/invites", headers=self.h, json={"role": role, **kw})
        return r.json()["token"] if r.status_code == 200 else None


def company(c, name="Ada", co="Northwind"):
    owner = P(c, name, company=co)
    owner.start_workspace()
    return owner


def joiner(c, owner, name="Bo", role="member", ws_scope=None):
    p = P(c, name, token=owner.invite(role))
    assert p.resp.status_code == 200, p.resp.text
    assert owner.grant_pending() >= 1  # the founder's browser notices and shares the workspace key
    p.unlock()
    return p


def test_content_is_encrypted_and_the_server_never_holds_plaintext(c):
    a = company(c)
    sid = a.scope_id
    ch = a.post("channel", {"name": "launch-plans-q4"}).json()["id"]
    r = a.post("message", {"text": "the secret acquisition target is Contoso"}, parent=ch)
    assert r.status_code == 200, r.text
    raw = open(server.DB_PATH, "rb").read()
    assert b"Contoso" not in raw and b"launch-plans-q4" not in raw
    msgs = a.items("message", ch)
    assert a.open(msgs[0])["text"].endswith("Contoso") and "Contoso" not in json.dumps(msgs)
    # content is bound to where it lives: a ciphertext moved elsewhere no longer opens
    other = dict(msgs[0], parent_id=ch + 1)
    with pytest.raises(Exception):
        a.open(other)


def test_workspaces_are_separate_from_the_social_site(c):
    a = company(c)
    assert c.get("/api/me", headers=a.h).status_code == 401  # a Huddle Corp token means nothing on Huddle
    assert c.get("/api/corp/me").status_code == 401
    assert c.get("/api/corp/me", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/api/posts?scope=all").status_code == 200 and "Ada" not in json.dumps(c.get("/api/posts?scope=all").json())
    assert c.get("/api/users/1").status_code in (200, 404)


def test_signup_needs_proof_of_work_consent_and_blocks_bots(c):
    priv = ec.generate_private_key(ec.SECP256R1())
    ch = c.get("/api/corp/pow").json()
    good = {"name": "A", "public_key": jwk_pub(priv), "company": "Acme", "authorized": True, "pow": {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])}}
    assert c.post("/api/corp/signup", json={**good, "authorized": False}).status_code == 400
    assert c.post("/api/corp/signup", json={**good, "website": "http://spam"}).status_code == 400
    assert c.post("/api/corp/signup", json={**good, "pow": {"challenge": ch["challenge"], "counter": "1"}}).status_code == 400
    assert c.post("/api/corp/signup", json=good).status_code == 200
    assert c.post("/api/corp/signup", json=good).status_code == 400  # a solved check can't be reused
    server.limiter.clear()
    codes = [P(c, f"u{i}", company=f"Co{i}", throttle=True).resp.status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]  # at most 5 sign-ups an hour from one network


def test_invite_flow_grants_the_key_and_lets_a_new_member_read(c):
    a = company(c)
    ch = a.post("channel", {"name": "general"}).json()["id"]
    a.post("message", {"text": "welcome aboard"}, parent=ch)
    b = P(c, "Bo", token=a.invite("member"))
    assert b.resp.status_code == 200
    assert b.ws()["grants"] == []  # in the workspace, but can't read anything yet
    assert [i["kind"] for i in b.items()] != [] and b.items("message", ch)  # the server shows ciphertext only
    with pytest.raises(KeyError):
        b.open(b.items("message", ch)[0])  # no key yet
    assert a.grant_pending() == 1
    b.unlock()
    assert b.open(b.items("message", ch)[0])["text"] == "welcome aboard"
    assert b.post("message", {"text": "thanks!"}, parent=ch).status_code == 200
    assert a.open(a.items("message", ch)[-1])["text"] == "thanks!"
    assert next(m for m in b.ws()["members"] if m["id"] == b.id)["new_hire"] is True


def test_invite_rules_expiry_limits_and_revocation(c):
    a = company(c)
    assert c.get("/api/corp/invites/bad").status_code == 404
    t = a.invite("member", max_uses=1)
    assert c.get(f"/api/corp/invites/{t}").json() == {"workspace": "Northwind", "role": "member"}
    P(c, "One", token=t)
    assert P(c, "Two", token=t).resp.status_code == 404  # single use
    t2 = a.invite("member")
    inv = c.get(f"/api/corp/w/{a.wid}/invites", headers=a.h).json()
    c.delete(f"/api/corp/w/{a.wid}/invites/{inv[0]['id']}", headers=a.h)
    assert P(c, "Three", token=t2).resp.status_code == 404  # revoked
    assert "token" not in json.dumps(inv)  # tokens are never stored in a readable form
    m = joiner(c, a, "Mia", "member")
    assert m.invite("member") is None  # members can't invite
    adm = joiner(c, a, "Adm", "admin")
    assert adm.invite("admin") is None and adm.invite("manager") is not None  # admins invite below their own level
    assert a.invite("admin") is not None  # the owner can invite admins


def test_roles_decide_who_can_create_what(c):
    a = company(c)
    mem, mgr, adm = joiner(c, a, "Mem", "member"), joiner(c, a, "Mgr", "manager"), joiner(c, a, "Adm", "admin")
    ok = lambda p, kind, meta=None: p.post(kind, {"x": 1}, meta=meta or ({"starts": "2030-01-01T10:00"} if kind == "event" else {})).status_code == 200
    assert [ok(mem, k) for k in ("channel", "task")] == [True, True]
    assert [ok(mem, k) for k in ("page", "event", "run", "workflow", "incentive")] == [False] * 5
    assert [ok(mgr, k) for k in ("page", "event", "run")] == [True] * 3 and [ok(mgr, k) for k in ("workflow", "incentive")] == [False] * 2
    assert [ok(adm, k) for k in ("workflow", "incentive", "page")] == [True] * 3


def test_task_metadata_assignees_and_who_can_change_what(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    t = a.post("task", {"title": "Set up laptop"}, meta={"status": "todo", "assignee_id": b.id, "due": "2030-02-01", "priority": 1, "secret": "leak?"})
    assert t.status_code == 200
    item = a.items("task")[0]
    assert item["meta"] == {"status": "todo", "assignee_id": b.id, "due": "2030-02-01", "priority": 1, "run_id": None}  # unknown keys dropped
    assert a.post("task", {"t": 1}, meta={"status": "nope"}).status_code == 400
    assert a.post("task", {"t": 1}, meta={"due": "tomorrow"}).status_code == 400
    assert a.post("task", {"t": 1}, meta={"assignee_id": 9999}).status_code == 400
    put = lambda p, meta: c.put(f"/api/corp/w/{a.wid}/items/{item['id']}", headers=p.h, json={"meta": meta})
    assert put(b, {"status": "doing", "due": "2031-01-01", "assignee_id": a.id}).status_code == 200  # assignee moves it along...
    now_meta = a.items("task")[0]["meta"]
    assert now_meta["status"] == "doing" and now_meta["due"] == "2030-02-01" and now_meta["assignee_id"] == b.id  # ...but can't reschedule or hand off
    other = joiner(c, a, "Cy")
    assert put(other, {"status": "done"}).status_code == 403


def test_private_groups_keep_content_from_other_members(c):
    a = company(c)
    b, d = joiner(c, a, "Bo"), joiner(c, a, "Di")
    sid = c.post(f"/api/corp/w/{a.wid}/scopes", headers=a.h, json={"member_ids": [b.id]}).json()["id"]
    a.keys[(sid, 1)] = os.urandom(32)
    ws = a.ws()
    members = {m["id"]: m for m in ws["members"]}
    r = c.post(f"/api/corp/w/{a.wid}/scopes/{sid}/grants", headers=a.h, json={"epoch": 1, "grants": [
        {"user_id": a.id, "wrapped": wrap(a.priv, a.pub, a.keys[(sid, 1)])}, {"user_id": b.id, "wrapped": wrap(a.priv, members[b.id]["public_key"], a.keys[(sid, 1)])}]})
    assert r.json()["granted"] == 2
    a.post("channel", {"name": "leadership"}, scope=sid)
    assert len(a.items("channel")) == 1 and len(b.unlock() and b.items("channel")) == 1
    assert d.items("channel") == []  # Di is in the workspace but not in this group
    assert c.post(f"/api/corp/w/{a.wid}/items", headers=d.h, json={"kind": "channel", "scope_id": sid, "meta": {}, "iv": b64(b"x" * 12), "ct": b64(b"x"), "epoch": 1}).status_code == 404
    assert a.post("task", {"t": 1}, scope=sid, meta={"assignee_id": d.id}).status_code == 400  # can't assign to someone who can't see it
    assert c.post(f"/api/corp/w/{a.wid}/scopes/{sid}/grants", headers=d.h, json={"epoch": 1, "grants": []}).status_code == 404


def test_removing_someone_rotates_the_key_so_they_lose_future_content(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    ch = a.post("channel", {"name": "general"}).json()["id"]
    a.post("message", {"text": "before"}, parent=ch)
    assert b.items("message", ch)  # Bo can read now
    assert c.delete(f"/api/corp/w/{a.wid}/members/{b.id}", headers=a.h).status_code == 200
    assert c.get(f"/api/corp/w/{a.wid}", headers=b.h).status_code == 404  # no access to anything
    assert b.items("message", ch) in ([], {"detail": "Workspace not found"})
    w = a.ws()
    s = w["scopes"][0]
    assert s["rotation_needed"] is True and s["member_ids"] == [a.id]
    # a remaining member's browser makes epoch 2
    new_key = os.urandom(32)
    bad = c.post(f"/api/corp/w/{a.wid}/scopes/{s['id']}/rotate", headers=a.h, json={"epoch": 5, "grants": []})
    assert bad.status_code == 409
    incomplete = c.post(f"/api/corp/w/{a.wid}/scopes/{s['id']}/rotate", headers=a.h, json={"epoch": 2, "grants": []})
    assert incomplete.status_code == 400
    ok = c.post(f"/api/corp/w/{a.wid}/scopes/{s['id']}/rotate", headers=a.h, json={"epoch": 2, "grants": [{"user_id": a.id, "wrapped": wrap(a.priv, a.pub, new_key)}]})
    assert ok.status_code == 200
    a.keys[(s["id"], 2)] = new_key
    assert a.post("message", {"text": "after"}, parent=ch, epoch=1).status_code == 409  # old key is retired
    assert a.post("message", {"text": "after"}, parent=ch).status_code == 200
    texts = [a.open(m)["text"] for m in a.items("message", ch)]
    assert texts == ["before", "after"]  # history still readable by those who remain
    assert a.ws()["scopes"][0]["rotation_needed"] is False
    with pytest.raises(Exception):  # Bo's old key can't open the new message
        b.keys[(s["id"], 1)] = a.keys[(s["id"], 1)]
        b.open(a.items("message", ch)[-1])


def test_role_changes_removal_limits_and_audit(c):
    a = company(c)
    mem, mgr, adm = joiner(c, a, "Mem"), joiner(c, a, "Mgr", "manager"), joiner(c, a, "Adm", "admin")
    put = lambda p, uid, body: c.put(f"/api/corp/w/{a.wid}/members/{uid}", headers=p.h, json=body)
    assert put(mem, mem.id, {"role": "admin"}).status_code == 403  # nobody promotes themselves
    assert put(mgr, mem.id, {"role": "manager"}).status_code == 403
    assert put(adm, mem.id, {"role": "manager", "title": "Designer"}).status_code == 200
    assert put(adm, mgr.id, {"role": "member"}).status_code == 200  # admins manage below themselves...
    assert put(adm, a.id, {"role": "member"}).status_code == 403 and put(a, adm.id, {"role": "member"}).status_code == 200  # ...only the owner manages admins
    assert put(mem, mem.id, {"title": "Senior designer"}).status_code == 200  # anyone can edit their own title
    assert next(m for m in a.ws()["members"] if m["id"] == mem.id)["title"] == "Senior designer"
    assert put(a, mem.id, {"new_hire": False}).status_code == 200
    assert c.delete(f"/api/corp/w/{a.wid}/members/{a.id}", headers=adm.h).status_code == 403  # the owner can't be removed
    assert c.delete(f"/api/corp/w/{a.wid}/members/{mem.id}", headers=mgr.h).status_code == 403
    assert c.get(f"/api/corp/w/{a.wid}/audit", headers=mem.h).status_code == 403
    log = c.get(f"/api/corp/w/{a.wid}/audit", headers=a.h).json()
    assert {"member_joined", "role_changed", "workspace_created"} <= {e["action"] for e in log}
    assert "Designer" not in json.dumps(log)  # the audit log records actions, not content


def test_events_rsvps_and_soft_deletes(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    ev = a.post("event", {"title": "All hands", "where": "Room 4"}, meta={"starts": "2030-03-01T09:00"}).json()["id"]
    assert a.post("event", {"t": 1}, meta={"starts": "soon"}).status_code == 400
    assert c.put(f"/api/corp/w/{a.wid}/items/{ev}/rsvp", headers=b.h, json={"status": "yes"}).status_code == 200
    got = a.items("event")[0]
    assert got["rsvps"] == [{"user_id": b.id, "status": "yes"}] and got["meta"]["starts"] == "2030-03-01T09:00"
    ch = a.post("channel", {"name": "ops"}).json()["id"]
    m = a.post("message", {"text": "hi"}, parent=ch).json()["id"]
    assert c.delete(f"/api/corp/w/{a.wid}/items/{m}", headers=b.h).status_code == 403  # only the author or an admin deletes a message
    assert c.delete(f"/api/corp/w/{a.wid}/items/{ch}", headers=a.h).status_code == 200
    assert a.items("message", ch) == [] and a.items("channel") == []
    assert a.post("message", {"t": 1}, parent=ch).status_code == 400  # can't post into a deleted channel
    assert a.post("message", {"t": 1}, parent=None).status_code == 400


def test_workflow_runs_create_linked_tasks_in_one_step(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    scope = a.scope_id
    wf = a.post("workflow", {"name": "New hire onboarding", "steps": [{"title": "Laptop"}, {"title": "Accounts"}]}).json()["id"]
    run_iv, run_ct = a.seal(scope, 1, "run", None, {"name": "Onboarding: Bo"})
    items = [{"kind": "run", "scope_id": scope, "meta": {"workflow_id": wf, "subject_id": b.id}, "iv": run_iv, "ct": run_ct, "epoch": 1}]
    for t in ("Laptop", "Accounts"):
        iv, ct = a.seal(scope, 1, "task", None, {"title": t})
        items.append({"kind": "task", "scope_id": scope, "meta": {"assignee_id": b.id, "due": "2030-01-10"}, "iv": iv, "ct": ct, "epoch": 1})
    r = c.post(f"/api/corp/w/{a.wid}/items/batch", headers=a.h, json={"items": items})
    assert r.status_code == 200 and len(r.json()["ids"]) == 3
    run = a.items("run")[0]
    assert run["meta"] == {"workflow_id": wf, "subject_id": b.id, "status": "active"}
    assert len(a.items("task")) == 2
    assert c.put(f"/api/corp/w/{a.wid}/items/{run['id']}", headers=a.h, json={"meta": {"status": "done"}}).status_code == 200
    assert a.items("run")[0]["meta"]["status"] == "done"


def test_grants_cannot_be_forged_or_overwritten(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    d = P(c, "Di", token=a.invite("member"))  # in the workspace, has no key yet
    s = a.scope_id
    forged = c.post(f"/api/corp/w/{a.wid}/scopes/{s}/grants", headers=d.h, json={"epoch": 1, "grants": [{"user_id": d.id, "wrapped": wrap(d.priv, d.pub, os.urandom(32))}]})
    assert forged.status_code == 403  # you can't hand yourself a key
    again = c.post(f"/api/corp/w/{a.wid}/scopes/{s}/grants", headers=a.h, json={"epoch": 1, "grants": [{"user_id": b.id, "wrapped": wrap(a.priv, jwk_pub(b.priv), os.urandom(32))}]})
    assert again.json()["granted"] == 0  # an existing grant isn't replaced
    assert b.unlock() and b.keys[(s, 1)] == a.keys[(s, 1)]
    junk = c.post(f"/api/corp/w/{a.wid}/scopes/{s}/grants", headers=a.h, json={"epoch": 1, "grants": [{"user_id": d.id, "wrapped": "not base64!"}]})
    assert junk.json()["granted"] == 0


def test_deleting_a_workspace_and_leaving(c):
    a = company(c)
    b = joiner(c, a, "Bo")
    a.post("channel", {"name": "x"})
    assert c.delete(f"/api/corp/w/{a.wid}", headers=b.h).status_code == 403  # only the owner
    assert c.delete(f"/api/corp/me", headers=a.h).status_code == 400  # owners must delete or hand over first
    assert c.delete(f"/api/corp/w/{a.wid}/members/{b.id}", headers=b.h).status_code == 200  # leaving is allowed
    assert c.delete(f"/api/corp/w/{a.wid}", headers=a.h).status_code == 200
    assert c.get(f"/api/corp/w/{a.wid}", headers=a.h).status_code == 404
    rows = server.db().execute("SELECT COUNT(*) FROM corp_items").fetchone()[0] + server.db().execute("SELECT COUNT(*) FROM corp_grants").fetchone()[0]
    assert rows == 0
    assert c.delete("/api/corp/me", headers=a.h).status_code == 200 and c.get("/api/corp/me", headers=a.h).status_code == 401


def test_one_account_can_belong_to_several_workspaces(c):
    a = company(c, "Ada", "Northwind")
    r = c.post("/api/corp/workspaces", headers=a.h, json={"company": "Side Project", "authorized": True})
    assert r.status_code == 200
    assert c.post("/api/corp/workspaces", headers=a.h, json={"company": "Nope", "authorized": False}).status_code == 400
    me = c.get("/api/corp/me", headers=a.h).json()
    assert [w["name"] for w in me["workspaces"]] == ["Northwind", "Side Project"] and all(w["role"] == "owner" for w in me["workspaces"])
    other = c.get(f"/api/corp/w/{r.json()['workspace_id']}", headers=a.h).json()
    assert other["scopes"][0]["id"] == r.json()["scope_id"] and other["grants"] == []  # its key is made next, in the browser
    b = joiner(c, a, "Bo")  # invites to the first workspace don't leak into the second
    assert c.get(f"/api/corp/w/{r.json()['workspace_id']}", headers=b.h).status_code == 404
    # a person can join a second company with the same account
    t = P(c, "Cy", company="Cy Co").invite("member")
    assert t and c.post(f"/api/corp/invites/{t}/accept", headers=a.h).status_code == 200
    assert len(c.get("/api/corp/me", headers=a.h).json()["workspaces"]) == 3
