"""Run with: pytest -q  (from the meetup/ directory)"""
import base64
import hashlib
import json
import os
import tempfile

os.environ["HUDDLE_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["HUDDLE_MOD_KEY"] = "m" * 32

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import server

b64 = lambda b: base64.b64encode(b).decode()
ub64 = lambda s: base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_")


def jwk_pub(priv):
    n = priv.public_key().public_numbers()
    enc = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
    return {"kty": "EC", "crv": "P-256", "x": enc(n.x), "y": enc(n.y)}


def pub_from_jwk(j):
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(ub64(j["x"]), "big"), int.from_bytes(ub64(j["y"]), "big"), ec.SECP256R1()
    ).public_key()


def solve(challenge, bits):
    i = 0
    while True:
        d = hashlib.sha256(f"{challenge}:{i}".encode()).digest()
        if 256 - int.from_bytes(d, "big").bit_length() >= bits:
            return str(i)
        i += 1


@pytest.fixture()
def c(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setitem(os.environ, "HUDDLE_DB", server.DB_PATH)
    server.limiter.clear()
    server._recent_signups.clear()
    with TestClient(server.app) as client:
        yield client


class Person:
    def __init__(self, c, name="Pat", born="1990-01-01"):
        self.c, self.priv = c, ec.generate_private_key(ec.SECP256R1())
        ch = c.get("/api/pow").json()
        r = c.post("/api/signup", json={
            "name": name, "city": "Austin", "birth_date": born, "interests": ["Hiking"],
            "public_key": jwk_pub(self.priv), "pow": {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])},
        })
        self.resp = r
        if r.status_code == 200:
            self.id, self.h = r.json()["user"]["id"], {"Authorization": "Bearer " + r.json()["token"]}

    def key_for(self, other_pub):
        return self.priv.exchange(ec.ECDH(), pub_from_jwk(other_pub))  # == browser's derived AES key bytes

    def dm(self, other, text):
        iv = os.urandom(12)
        ct = AESGCM(self.key_for(jwk_pub(other.priv))).encrypt(iv, text.encode(), None)
        return self.c.post("/api/dm", headers=self.h, json={"to_id": other.id, "iv": b64(iv), "ciphertext": b64(ct)})

    def rsvp(self, eid):
        return self.c.post(f"/api/events/{eid}/rsvp", headers=self.h)


def test_signup_requires_valid_pow_and_is_single_use(c):
    p = Person(c)
    assert p.resp.status_code == 200
    ch = c.get("/api/pow").json()
    body = {"name": "B", "city": "Austin", "birth_date": "1990-01-01", "public_key": jwk_pub(p.priv)}
    assert c.post("/api/signup", json={**body, "pow": {"challenge": ch["challenge"], "counter": "1"}}).status_code == 400
    ok = {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])}
    assert c.post("/api/signup", json={**body, "pow": ok}).status_code == 200
    assert c.post("/api/signup", json={**body, "pow": ok}).status_code == 400  # replay


def test_signup_blocks_minors_honeypot_and_tampered_challenge(c):
    assert Person(c, born="2015-06-01").resp.status_code == 403
    ch = c.get("/api/pow").json()
    pk = jwk_pub(ec.generate_private_key(ec.SECP256R1()))
    base = {"name": "B", "city": "Austin", "birth_date": "1990-01-01", "public_key": pk}
    assert c.post("/api/signup", json={**base, "website": "http://spam", "pow": {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])}}).status_code == 400
    forged = ch["challenge"].rsplit(".", 1)[0].replace(f".{ch['bits']}", ".1") + ".0" * 1
    assert c.post("/api/signup", json={**base, "pow": {"challenge": forged, "counter": "0"}}).status_code == 400


def test_signup_ip_rate_limit(c):
    codes = [Person(c, name=f"u{i}").resp.status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


def test_actions_need_auth_and_cannot_impersonate(c):
    assert c.post("/api/events/1/rsvp").status_code == 401
    assert c.post("/api/dm", json={"to_id": 1, "iv": "AAAA", "ciphertext": "AAAAAAAA"}).status_code == 401
    assert c.get("/api/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_dm_is_ciphertext_only_and_starts_as_request(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    r = a.dm(b, "secret plans")  # strangers can send ONE message, as a request
    assert r.status_code == 200 and r.json()["status"] == "pending"
    assert a.dm(b, "are you there?").status_code == 403  # no pestering while pending
    assert b"secret plans" not in open(server.DB_PATH, "rb").read()
    rows = c.get(f"/api/dm/{a.id}", headers=b.h).json()
    assert len(rows) == 1 and "secret plans" not in json.dumps(rows)
    key = b.key_for(jwk_pub(a.priv))
    assert AESGCM(key).decrypt(ub64(rows[0]["iv"]), ub64(rows[0]["ciphertext"]), None) == b"secret plans"


def test_request_accept_flow_and_counts(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    a.dm(b, "hi!")
    assert c.get("/api/me/counts", headers=b.h).json() == {"requests": 1}
    assert c.get("/api/me/counts", headers=a.h).json() == {"requests": 0}
    assert c.get("/api/inbox", headers=b.h).json()[0]["status"] == "request_in"
    assert c.get("/api/inbox", headers=a.h).json()[0]["status"] == "request_out"
    assert c.get(f"/api/users/{a.id}", headers=b.h).json()["chat"] == "request_in"
    assert c.post(f"/api/requests/{b.id}/accept", headers=b.h).status_code == 404  # only the recipient can accept
    assert c.post(f"/api/requests/{a.id}/accept", headers=b.h).status_code == 200
    assert c.get("/api/me/counts", headers=b.h).json() == {"requests": 0}
    assert a.dm(b, "great, hello").status_code == 200 and b.dm(a, "hey!").status_code == 200
    assert c.get("/api/inbox", headers=a.h).json()[0]["status"] == "accepted"


def test_replying_to_a_request_accepts_it(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    a.dm(b, "hi")
    assert b.dm(a, "hello back").json()["status"] == "accepted"
    assert a.dm(b, "nice").status_code == 200


def test_decline_is_silent_permanent_and_hidden(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    a.dm(b, "hi")
    assert c.post(f"/api/requests/{a.id}/decline", headers=b.h).status_code == 200
    assert c.get("/api/inbox", headers=b.h).json() == []  # gone for the recipient
    assert c.get("/api/me/counts", headers=b.h).json() == {"requests": 0}
    assert c.get("/api/inbox", headers=a.h).json()[0]["status"] == "request_out"  # sender isn't told
    assert a.dm(b, "please?").status_code == 403
    assert b.dm(a, "actually, hi").status_code == 200  # the recipient can still open the chat themselves
    assert a.dm(b, "thanks!").status_code == 200


def test_request_can_be_reported_before_accepting(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    a.dm(b, "inappropriate opener")
    key = b64(b.key_for(jwk_pub(a.priv)))
    r = c.post("/api/reports", headers=b.h, json={"kind": "dm", "target_id": a.id, "reason": "harassment", "key": key})
    assert r.status_code == 200
    det = c.get(f"/api/mod/reports/{r.json()['id']}", headers={"X-Mod-Key": "m" * 32}).json()
    assert det["evidence"]["messages"][0]["text"] == "inappropriate opener"


def test_blocked_users_cannot_send_requests(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    c.put(f"/api/blocks/{a.id}", headers=b.h)
    assert a.dm(b, "hi").status_code == 403
    assert c.get(f"/api/users/{b.id}", headers=a.h).json()["chat"] == "unavailable"


def test_cannot_dm_demo_profile_without_key(c):
    a = Person(c)
    r = c.post("/api/dm", headers=a.h, json={"to_id": 1, "iv": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAAAAAA"})
    assert r.status_code == 400


def test_new_account_new_conversation_cap(c):
    a = Person(c)
    others = [Person(c, f"o{i}") for i in range(4)]
    codes = [a.dm(o, "hello").status_code for o in others]
    assert codes == [200, 200, 200, 429]


def test_block_stops_messages(c):
    a, b = Person(c, "A"), Person(c, "B")
    assert c.put(f"/api/blocks/{a.id}", headers=b.h).status_code == 200
    assert a.dm(b, "hey").status_code == 403


def test_report_dm_reveals_only_that_thread_and_mods_cannot_read_dms(c):
    a, b, x = Person(c, "A"), Person(c, "B"), Person(c, "X")
    a.dm(b, "reported content"), b.dm(a, "reply"), a.dm(x, "unrelated private chat")
    mod = {"X-Mod-Key": "m" * 32, "X-Mod-Name": "alice"}
    key = b64(b.key_for(jwk_pub(a.priv)))
    # wrong key (from a different pair) is rejected: you can't use a report to expose other threads
    assert c.post("/api/reports", headers=b.h, json={"kind": "dm", "target_id": a.id, "reason": "child_safety", "key": b64(b.key_for(jwk_pub(x.priv)))}).status_code == 400
    r = c.post("/api/reports", headers=b.h, json={"kind": "dm", "target_id": a.id, "reason": "child_safety", "key": key})
    assert r.status_code == 200
    # an outsider cannot report a thread they're not in
    assert c.post("/api/reports", headers=x.h, json={"kind": "dm", "target_id": b.id, "reason": "spam", "key": key}).status_code == 400
    lst = c.get("/api/mod/reports", headers=mod).json()
    assert lst[0]["reason"] == "child_safety"
    det = c.get(f"/api/mod/reports/{r.json()['id']}", headers=mod).json()
    assert [m["text"] for m in det["evidence"]["messages"]] == ["reported content", "reply"]
    assert "unrelated private chat" not in json.dumps(det)
    # no mod endpoint exposes raw DMs
    assert all("dm" not in route.path for route in server.app.routes if route.path.startswith("/api/mod"))
    assert c.post(f"/api/mod/reports/{r.json()['id']}/resolve", headers=mod, json={"action": "actioned", "suspend_user": True}).status_code == 200
    assert c.get("/api/me", headers=a.h).status_code == 403  # suspended
    log = c.get("/api/mod/audit", headers=mod).json()
    assert {e["action"] for e in log} >= {"list_reports", "read_report", "resolve_report"} and log[0]["moderator"] == "alice"


def test_mod_api_auth(c, monkeypatch):
    assert c.get("/api/mod/reports").status_code == 401
    assert c.get("/api/mod/reports", headers={"X-Mod-Key": "wrong" * 8}).status_code == 401
    monkeypatch.delenv("HUDDLE_MOD_KEY")
    assert c.get("/api/mod/reports", headers={"X-Mod-Key": "m" * 32}).status_code == 503


def test_event_chat_report_and_rate_limit(c):
    a = Person(c)
    a.rsvp(1)
    codes = [c.post("/api/events/1/messages", headers=a.h, json={"body": f"m{i}"}).status_code for i in range(10)]
    assert codes.count(429) >= 1
    mid = c.get("/api/events/1").json()["messages"][-1]["id"]
    b = Person(c, "B")
    assert c.post("/api/reports", headers=b.h, json={"kind": "event_message", "target_id": mid, "reason": "spam"}).status_code == 200


def test_delete_account_erases_everything_but_keeps_safety_reports(c):
    a, b = Person(c, "Ann"), Person(c, "Bo")
    a.dm(b, "hello"), b.dm(a, "hi back")
    c.post("/api/posts", headers=a.h, json={"body": "my post", "tags": ["Hiking"]})
    c.post("/api/events/1/messages", headers=a.h, json={"body": "chat msg"})
    ev = c.post("/api/events", headers=a.h, json={"title": "Ann's walk", "description": "A short walk together", "category": "Outdoors",
                "city": "Austin", "venue": "Park", "starts": "2099-01-01T10:00", "capacity": 5}).json()["id"]
    key = b64(b.key_for(jwk_pub(a.priv)))
    rid = c.post("/api/reports", headers=b.h, json={"kind": "dm", "target_id": a.id, "reason": "harassment", "key": key}).json()["id"]
    assert c.delete("/api/me", headers=a.h).status_code == 200
    assert c.get("/api/me", headers=a.h).status_code == 401  # session is gone
    assert c.get(f"/api/users/{a.id}").status_code == 404
    assert c.get(f"/api/events/{ev}").status_code == 404
    assert c.get(f"/api/dm/{a.id}", headers=b.h).json() == []
    assert all(m["user"]["id"] != a.id for m in c.get("/api/events/1").json()["messages"])
    assert all(p["author"]["id"] != a.id for p in c.get("/api/posts").json())
    assert a.id not in [u["id"] for u in c.get("/api/me/matches", headers=b.h).json()]
    row = server.db().execute("SELECT * FROM users WHERE id=?", (a.id,)).fetchone()
    assert row["name"] == "Deleted user" and row["public_key"] is None and row["token_hash"] is None and row["bio"] == ""
    mod = {"X-Mod-Key": "m" * 32}
    assert c.get(f"/api/mod/reports/{rid}", headers=mod).status_code == 200  # safety evidence retained


def test_block_hides_content_both_ways_and_can_be_undone(c):
    a, b = Person(c, "A"), Person(c, "B")
    pid = c.post("/api/posts", headers=a.h, json={"body": "hello feed"}).json()["id"]
    assert any(p["id"] == pid for p in c.get("/api/posts", headers=b.h).json())
    c.put(f"/api/blocks/{a.id}", headers=b.h)
    assert not any(p["id"] == pid for p in c.get("/api/posts", headers=b.h).json())
    assert c.get(f"/api/posts/{pid}", headers=b.h).status_code == 404
    assert [u["id"] for u in c.get("/api/blocks", headers=b.h).json()] == [a.id]
    c.delete(f"/api/blocks/{a.id}", headers=b.h)
    assert any(p["id"] == pid for p in c.get("/api/posts", headers=b.h).json())


def test_feed_posting_replies_and_spam_limits(c):
    a, b = Person(c, "A"), Person(c, "B")
    assert c.post("/api/posts", headers=a.h, json={"body": "check https://spam.example"}).status_code == 403  # new accounts: no links
    assert c.post("/api/posts", headers=a.h, json={"body": "ok", "url": "javascript:alert(1)"}).status_code in (400, 403)
    pid = c.post("/api/posts", headers=a.h, json={"body": "Trail report: lovely today", "tags": ["Hiking", "hiking", "Coffee"]}).json()["id"]
    assert c.post("/api/posts", headers=a.h, json={"body": "Trail report: lovely today"}).status_code == 400  # duplicate
    assert c.post(f"/api/posts/{pid}/replies", headers=b.h, json={"body": "thanks!"}).status_code == 200
    post = c.get(f"/api/posts/{pid}").json()
    assert post["tags"] == ["Hiking", "Coffee"] and post["replies"][0]["body"] == "thanks!"
    rid = post["replies"][0]["id"]
    assert c.delete(f"/api/replies/{rid}", headers=a.h).status_code == 404  # only the author can delete
    assert c.delete(f"/api/replies/{rid}", headers=b.h).status_code == 200
    codes = [c.post("/api/posts", headers=a.h, json={"body": f"post {i}"}).status_code for i in range(5)]
    assert 429 in codes  # new-account daily cap
    assert c.post("/api/posts", json={"body": "anon"}).status_code == 401


def test_profile_chat_state_and_post_reports(c):
    a, b = Person(c, "A"), Person(c, "B")
    assert c.get(f"/api/users/{b.id}", headers=a.h).json()["chat"] == "none"
    assert c.get(f"/api/users/{b.id}", headers=a.h).json()["can_message"] is True
    a.dm(b, "hello")
    assert c.get(f"/api/users/{b.id}", headers=a.h).json()["chat"] == "request_out"
    assert c.get(f"/api/users/{a.id}", headers=b.h).json()["chat"] == "request_in"
    pid = c.post("/api/posts", headers=a.h, json={"body": "something bad"}).json()["id"]
    assert c.post("/api/reports", headers=b.h, json={"kind": "post", "target_id": pid, "reason": "spam"}).status_code == 200
    mod = {"X-Mod-Key": "m" * 32}
    assert c.delete(f"/api/mod/posts/{pid}", headers=mod).status_code == 200
    assert c.get(f"/api/posts/{pid}").status_code == 404
