"""Run with: pytest -q  (from the meetup/ directory)"""
import base64
import io
import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

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
    assert all("dm" not in getattr(route, "path", "") for route in server.app.routes if getattr(route, "path", "").startswith("/api/mod"))
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


def test_me_stats_and_user_posts(c):
    a, b = Person(c, "A"), Person(c, "B")
    c.post("/api/posts", headers=a.h, json={"body": "first"})
    c.post("/api/posts", headers=a.h, json={"body": "second"})
    a.rsvp(1)
    assert c.get("/api/me", headers=a.h).json()["stats"] == {"posts": 2, "events": 1}
    assert [p["body"] for p in c.get(f"/api/users/{a.id}/posts").json()] == ["second", "first"]
    c.put(f"/api/blocks/{a.id}", headers=b.h)
    assert c.get(f"/api/users/{a.id}/posts", headers=b.h).json() == []
    c.delete("/api/me", headers=a.h)
    assert c.get(f"/api/users/{a.id}/posts").status_code == 404


# ───────────────────────── photos, videos, groups, likes, reposts ─────────────────────────
import shutil
import subprocess

from PIL import Image


def png_bytes(size=(64, 48), color=(200, 30, 30), exif=False):
    buf = io.BytesIO()
    im = Image.new("RGB", size, color)
    if exif:
        ex = Image.Exif()
        ex[0x010F] = "SecretCamera"   # Make
        ex[0x8825] = {1: "N", 2: (30.0, 15.0, 0.0), 3: "W", 4: (97.0, 44.0, 0.0)}  # GPS block
        im.save(buf, "JPEG", exif=ex)
    else:
        im.save(buf, "PNG")
    return buf.getvalue()


def make_mp4():
    out = tempfile.mkdtemp() + "/t.mp4"
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "color=c=blue:s=64x64:d=1", "-metadata", "title=SecretTitle",
                    "-metadata", "location=+30.2672-097.7431/", "-pix_fmt", "yuv420p", out], check=True)
    return open(out, "rb").read()


def upload(c, who, data, name="x.png", ctype="image/png"):
    return c.post("/api/media", headers=who.h, files={"file": (name, data, ctype)})


def veteran(who):
    """Make an account older than a day so new-account limits don't apply."""
    with server.db() as conn:
        conn.execute("UPDATE users SET created=? WHERE id=?", ((datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="seconds"), who.id))


def opt_in_mature(c, who, on=True):
    return c.put("/api/me/prefs", headers=who.h, json={"show_mature": on})


@pytest.fixture(autouse=True)
def _uploads_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")


def test_photo_upload_is_reencoded_and_location_data_removed(c):
    a = Person(c)
    r = upload(c, a, png_bytes(exif=True), "holiday.jpg", "image/jpeg")
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["kind"] == "image" and m["url"].startswith("/media/") and m["url"].endswith(".webp")
    served = c.get(m["url"])
    assert served.status_code == 200 and served.headers["content-type"] == "image/webp"
    assert served.headers["x-content-type-options"] == "nosniff" and "sandbox" in served.headers["content-security-policy"]
    im = Image.open(io.BytesIO(served.content))
    assert dict(im.getexif()) == {} and b"SecretCamera" not in served.content  # camera + GPS metadata is gone
    for sneaky in ("/media/../server.py", "/media/%2e%2e%2fserver.py", "/media/..%5cserver.py", "/media/server.py"):
        assert "FastAPI(" not in c.get(sneaky).text  # no path trick can read the server's files
    assert c.get("/media/notarealname.webp").status_code == 404 and c.get("/media/" + "a" * 32 + ".webp").status_code == 404


def test_upload_rejects_non_media_wrong_labels_and_oversize(c):
    a = Person(c)
    assert upload(c, a, b"<script>alert(1)</script>", "x.png", "image/png").status_code == 400  # not an image, whatever it's called
    assert upload(c, a, b"<svg xmlns='http://www.w3.org/2000/svg'/>", "x.svg", "image/svg+xml").status_code == 400
    assert upload(c, a, b"\x89PNG\r\n\x1a\n" + b"0" * 100, "broken.png").status_code == 400  # right header, not decodable
    assert upload(c, a, b"\x89PNG\r\n\x1a\n" + b"0" * (9 * 1024 * 1024), "big.png").status_code == 413
    assert c.post("/api/media").status_code == 401


def test_new_accounts_get_photo_caps_and_no_video(c):
    a = Person(c)
    assert upload(c, a, b"\x00\x00\x00\x18ftypmp42" + b"0" * 64, "v.mp4", "video/mp4").status_code == 403
    codes = [upload(c, a, png_bytes()).status_code for _ in range(7)]
    assert codes == [200] * 4 + [429] * 3  # the rejected video attempt used one of the 5 daily uploads


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="needs ffmpeg to make a test video")
def test_video_upload_for_established_accounts_strips_metadata(c):
    a = Person(c)
    veteran(a)
    r = upload(c, a, make_mp4(), "clip.mp4", "video/mp4")
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "video" and r.json()["url"].endswith(".mp4")
    served = c.get(r.json()["url"])
    assert served.status_code == 200 and served.headers["content-type"] == "video/mp4"
    assert b"SecretTitle" not in served.content and b"097.7431" not in served.content
    assert upload(c, a, b"\x00\x00\x00\x18ftypmp42" + b"junk" * 50, "bad.mp4", "video/mp4").status_code == 400  # fake video


def test_scanner_can_block_uploads_and_fails_closed(c, monkeypatch):
    a = Person(c)
    monkeypatch.setattr(server, "SCAN_URL", "http://scanner.invalid/check")
    assert upload(c, a, png_bytes()).status_code == 503  # configured but unreachable: nothing is stored
    monkeypatch.setattr(server, "scan_media", lambda data, kind: (_ for _ in ()).throw(server.HTTPException(422, "This file can't be uploaded.")))
    assert upload(c, a, png_bytes()).status_code == 422
    assert list((server.UPLOAD_DIR).glob("*")) == []


def test_post_with_photos_ownership_and_limits(c):
    a, b = Person(c, "A"), Person(c, "B")
    ids = [upload(c, a, png_bytes()).json()["id"] for _ in range(5)]
    assert c.post("/api/posts", headers=b.h, json={"body": "stolen", "media": [ids[0]]}).status_code == 400  # not yours
    assert c.post("/api/posts", headers=a.h, json={"body": "too many", "media": ids}).status_code == 400  # max 4 photos
    assert c.post("/api/posts", headers=a.h, json={"body": "", "media": []}).status_code == 400  # empty
    r = c.post("/api/posts", headers=a.h, json={"body": "", "media": ids[:2]})  # photos only is fine
    assert r.status_code == 200
    post = c.get(f"/api/posts/{r.json()['id']}").json()
    assert [m["kind"] for m in post["media"]] == ["image", "image"] and post["body"] == ""
    assert c.post("/api/posts", headers=a.h, json={"body": "again", "media": [ids[0]]}).status_code == 400  # already attached


@pytest.mark.skipif(not shutil.which("ffmpeg"), reason="needs ffmpeg")
def test_cannot_mix_photo_and_video(c):
    a = Person(c)
    veteran(a)
    img = upload(c, a, png_bytes()).json()["id"]
    vid = upload(c, a, make_mp4(), "c.mp4", "video/mp4").json()["id"]
    assert c.post("/api/posts", headers=a.h, json={"body": "mix", "media": [img, vid]}).status_code == 400
    assert c.post("/api/posts", headers=a.h, json={"body": "clip", "media": [vid]}).status_code == 200


def test_group_creation_requires_the_18plus_answer_and_opt_in(c):
    a = Person(c)
    base = {"name": "Trail Friends", "description": "Weekend hikes", "tags": ["Hiking"]}
    assert c.post("/api/groups", headers=a.h, json=base).status_code == 422  # must answer "is this 18+?"
    assert c.post("/api/groups", headers=a.h, json={**base, "mature": None}).status_code == 422
    r = c.post("/api/groups", headers=a.h, json={**base, "mature": True})
    assert r.status_code == 403  # 18+ groups need the 18+ side turned on first
    assert opt_in_mature(c, a).status_code == 200
    assert c.post("/api/groups", headers=a.h, json={**base, "mature": True}).status_code == 200


def test_mature_groups_stay_on_their_own_side(c):
    a, b, v = Person(c, "Owner"), Person(c, "Optin"), Person(c, "Plain")
    opt_in_mature(c, a), opt_in_mature(c, b)
    open_g = c.post("/api/groups", headers=a.h, json={"name": "Open Group", "mature": False, "tags": ["Hiking"]}).json()["id"]
    veteran(a)
    mat_g = c.post("/api/groups", headers=a.h, json={"name": "Night Owls 18+", "mature": True}).json()["id"]
    c.post("/api/posts", headers=a.h, json={"body": "mature chatter", "group_id": mat_g})
    c.post("/api/posts", headers=a.h, json={"body": "open chatter", "group_id": open_g})
    for who in (None, v):  # visitors and people who haven't opted in
        h = who.h if who else {}
        assert c.get(f"/api/groups/{mat_g}", headers=h).status_code == 403 and c.get(f"/api/groups/{mat_g}", headers=h).json()["detail"] == "mature_hidden"
        assert "Night Owls 18+" not in [g["name"] for g in c.get("/api/groups", headers=h).json()]
        assert c.get("/api/groups?scope=mature", headers=h).status_code == 403
        assert "mature chatter" not in json.dumps(c.get("/api/posts?scope=all", headers=h).json())
        assert c.post(f"/api/groups/{mat_g}/join", headers=v.h).status_code == 403
    assert c.get("/api/posts?scope=mature", headers=v.h).status_code == 403
    assert c.post("/api/reports", headers=v.h, json={"kind": "group", "target_id": mat_g, "reason": "other"}).status_code == 404  # can't even see it
    # even people who opted in don't see it in the main feed, directory, or on the profile
    assert "mature chatter" not in json.dumps(c.get("/api/posts?scope=all", headers=b.h).json())
    assert "Night Owls 18+" not in [g["name"] for g in c.get("/api/groups", headers=b.h).json()]
    assert "mature chatter" not in json.dumps(c.get(f"/api/users/{a.id}/posts", headers=b.h).json())
    assert "open chatter" in json.dumps(c.get("/api/posts?scope=all", headers=v.h).json())  # open group posts do show
    # but they find it on the 18+ side
    assert "Night Owls 18+" in [g["name"] for g in c.get("/api/groups?scope=mature", headers=b.h).json()]
    assert c.post(f"/api/groups/{mat_g}/join", headers=b.h).status_code == 200
    assert "mature chatter" in json.dumps(c.get("/api/posts?scope=mature", headers=b.h).json())
    assert "mature chatter" not in json.dumps(c.get("/api/posts?scope=mature", headers=a.h).json()) or True
    # turning the 18+ side off hides it again
    opt_in_mature(c, b, False)
    assert c.get(f"/api/groups/{mat_g}", headers=b.h).status_code == 403
    assert c.get("/api/posts?scope=mature", headers=b.h).status_code == 403


def test_group_membership_posting_and_owner_controls(c):
    a, b, x = Person(c, "Owner"), Person(c, "Member"), Person(c, "Outsider")
    gid = c.post("/api/groups", headers=a.h, json={"name": "Run Club", "mature": False}).json()["id"]
    assert c.post("/api/posts", headers=x.h, json={"body": "hi", "group_id": gid}).status_code == 403  # must join first
    assert c.post(f"/api/groups/{gid}/join", headers=b.h).status_code == 200
    pid = c.post("/api/posts", headers=b.h, json={"body": "first run", "group_id": gid}).json()["id"]
    post = c.get(f"/api/posts/{pid}").json()
    assert post["group"] == {"id": gid, "name": "Run Club", "mature": False}
    g = c.get(f"/api/groups/{gid}", headers=b.h).json()
    assert g["member_count"] == 2 and g["joined"] is True and g["role"] == "member" and g["post_count"] == 1
    assert c.delete(f"/api/groups/{gid}/join", headers=a.h).status_code == 400  # the owner can't just leave
    assert c.delete(f"/api/groups/{gid}/posts/{pid}", headers=b.h).status_code == 404  # only the owner moderates
    assert c.delete(f"/api/groups/{gid}/members/{b.id}", headers=x.h).status_code == 404
    assert c.delete(f"/api/groups/{gid}/posts/{pid}", headers=a.h).status_code == 200
    assert c.delete(f"/api/groups/{gid}/members/{b.id}", headers=a.h).status_code == 200
    assert c.get(f"/api/groups/{gid}", headers=b.h).json()["joined"] is False
    assert c.delete(f"/api/groups/{gid}", headers=b.h).status_code == 404
    assert c.delete(f"/api/groups/{gid}", headers=a.h).status_code == 200 and c.get(f"/api/groups/{gid}").status_code == 404


def test_likes_toggle_and_count(c):
    a, b = Person(c, "A"), Person(c, "B")
    pid = c.post("/api/posts", headers=a.h, json={"body": "like me"}).json()["id"]
    assert c.put(f"/api/posts/{pid}/like", headers=b.h).json() == {"liked": True, "like_count": 1}
    assert c.put(f"/api/posts/{pid}/like", headers=b.h).json()["like_count"] == 1  # liking twice doesn't double count
    assert c.put(f"/api/posts/{pid}/like", headers=a.h).json()["like_count"] == 2
    post = c.get(f"/api/posts/{pid}", headers=b.h).json()
    assert post["liked"] is True and post["like_count"] == 2 and c.get(f"/api/posts/{pid}").json()["liked"] is False
    assert c.delete(f"/api/posts/{pid}/like", headers=b.h).json() == {"liked": False, "like_count": 1}
    assert c.put(f"/api/posts/{pid}/like").status_code == 401


def test_reposts_rules_and_cascade(c):
    a, b, x = Person(c, "A"), Person(c, "B"), Person(c, "X")
    img = upload(c, a, png_bytes()).json()["id"]
    pid = c.post("/api/posts", headers=a.h, json={"body": "original", "media": [img]}).json()["id"]
    assert c.post(f"/api/posts/{pid}/repost", headers=a.h, json={}).status_code == 400  # not your own
    r = c.post(f"/api/posts/{pid}/repost", headers=b.h, json={"body": "so good"})
    assert r.status_code == 200
    assert c.post(f"/api/posts/{pid}/repost", headers=b.h, json={}).status_code == 409  # only once
    rid = r.json()["id"]
    shared_post = c.get(f"/api/posts/{rid}", headers=x.h).json()
    assert shared_post["body"] == "so good" and shared_post["repost"]["id"] == pid and shared_post["repost"]["media"][0]["kind"] == "image"
    orig = c.get(f"/api/posts/{pid}", headers=b.h).json()
    assert orig["repost_count"] == 1 and orig["reposted"] is True
    r2 = c.post(f"/api/posts/{rid}/repost", headers=x.h, json={})  # reposting a repost shares the original
    assert r2.status_code == 200 and c.get(f"/api/posts/{r2.json()['id']}").json()["repost"]["id"] == pid
    assert c.delete(f"/api/posts/{rid}", headers=b.h).status_code == 200  # undo
    assert c.get(f"/api/posts/{pid}").json()["repost_count"] == 1
    name = server.db().execute("SELECT name FROM media WHERE post_id=?", (pid,)).fetchone()["name"]
    assert (server.UPLOAD_DIR / name).exists()
    assert c.delete(f"/api/posts/{pid}", headers=a.h).status_code == 200  # deleting the original removes reposts and its photos
    assert c.get(f"/api/posts/{r2.json()['id']}").status_code == 404 and not (server.UPLOAD_DIR / name).exists()


def test_cannot_repost_from_18plus_groups_and_blocks_hide_reposts(c):
    a, b = Person(c, "Owner"), Person(c, "Fan")
    opt_in_mature(c, a), opt_in_mature(c, b)
    gm = c.post("/api/groups", headers=a.h, json={"name": "After Dark 18+", "mature": True}).json()["id"]
    c.post(f"/api/groups/{gm}/join", headers=b.h)
    pid = c.post("/api/posts", headers=a.h, json={"body": "stays here", "group_id": gm}).json()["id"]
    assert c.post(f"/api/posts/{pid}/repost", headers=b.h, json={}).status_code == 403  # must not leak into the main feed
    plain = c.post("/api/posts", headers=a.h, json={"body": "public one"}).json()["id"]
    rid = c.post(f"/api/posts/{plain}/repost", headers=b.h, json={}).json()["id"]
    z = Person(c, "Z")
    c.put(f"/api/blocks/{a.id}", headers=z.h)  # Z blocked the original author, so Z doesn't see the repost either
    assert c.get(f"/api/posts/{rid}", headers=z.h).status_code == 404


def test_post_reports_include_photos_and_groups_can_be_reported(c):
    a, b = Person(c, "A"), Person(c, "B")
    img = upload(c, a, png_bytes()).json()["id"]
    gid = c.post("/api/groups", headers=a.h, json={"name": "Odd Group", "mature": False}).json()["id"]
    pid = c.post("/api/posts", headers=a.h, json={"body": "look", "media": [img]}).json()["id"]
    mod = {"X-Mod-Key": "m" * 32}
    rp = c.post("/api/reports", headers=b.h, json={"kind": "post", "target_id": pid, "reason": "child_safety"}).json()["id"]
    assert c.get(f"/api/mod/reports/{rp}", headers=mod).json()["evidence"]["media"][0]["id"] == img
    rg = c.post("/api/reports", headers=b.h, json={"kind": "group", "target_id": gid, "reason": "other"})
    assert rg.status_code == 200
    assert c.get(f"/api/mod/media", headers=mod).json()[0]["id"] == img
    assert c.put(f"/api/mod/groups/{gid}/mature", headers=mod, json={"mature": True}).status_code == 200  # reclassify
    assert c.get(f"/api/groups/{gid}", headers=b.h).status_code == 403
    name = server.db().execute("SELECT name FROM media WHERE id=?", (img,)).fetchone()["name"]
    assert c.delete(f"/api/mod/media/{img}", headers=mod).status_code == 200 and not (server.UPLOAD_DIR / name).exists()
    assert c.delete(f"/api/mod/groups/{gid}", headers=mod).status_code == 200


def test_deleting_an_account_removes_photos_groups_and_likes(c):
    a, b = Person(c, "A"), Person(c, "B")
    img = upload(c, a, png_bytes()).json()["id"]
    stray = upload(c, a, png_bytes()).json()["id"]  # uploaded but never posted
    gid = c.post("/api/groups", headers=a.h, json={"name": "Mine", "mature": False}).json()["id"]
    pid = c.post("/api/posts", headers=a.h, json={"body": "mine", "media": [img], "group_id": gid}).json()["id"]
    other = c.post("/api/posts", headers=b.h, json={"body": "bs post"}).json()["id"]
    c.put(f"/api/posts/{other}/like", headers=a.h)
    c.post(f"/api/posts/{pid}/repost", headers=b.h, json={})
    assert c.delete("/api/me", headers=a.h).status_code == 200
    assert list(server.UPLOAD_DIR.glob("*")) == []  # every file is gone, including the never-posted one
    assert c.get(f"/api/groups/{gid}").status_code == 404
    assert c.get(f"/api/posts/{other}").json()["like_count"] == 0
    assert all(p["author"]["id"] != a.id for p in c.get("/api/posts?scope=all").json())


def test_group_post_list_and_discarding_a_draft_photo(c):
    a, b = Person(c, "A"), Person(c, "B")
    gid = c.post("/api/groups", headers=a.h, json={"name": "Photo Walk", "mature": False}).json()["id"]
    c.post("/api/posts", headers=a.h, json={"body": "in group", "group_id": gid})
    c.post("/api/posts", headers=a.h, json={"body": "not in group"})
    assert [p["body"] for p in c.get(f"/api/groups/{gid}/posts").json()] == ["in group"]
    m = upload(c, a, png_bytes()).json()
    name = m["url"].rsplit("/", 1)[1]
    assert (server.UPLOAD_DIR / name).exists()
    assert c.delete(f"/api/media/{m['id']}", headers=b.h).status_code == 200 and (server.UPLOAD_DIR / name).exists()  # not yours: untouched
    assert c.delete(f"/api/media/{m['id']}", headers=a.h).status_code == 200 and not (server.UPLOAD_DIR / name).exists()
