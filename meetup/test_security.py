"""Security regression tests: browser protections, request limits, spam rules, upload limits, token handling."""
import io
import json

import pytest
from fastapi.testclient import TestClient

import server
from test_server import Person, jwk_pub, png_bytes, solve, upload, veteran  # noqa: F401  (shared helpers)
from test_corp import P as CorpPerson, company, joiner  # noqa: F401


@pytest.fixture()
def c(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    server.limiter.clear()
    server._recent_signups.clear()
    with TestClient(server.app) as client:
        yield client


def test_pages_carry_strict_browser_protections(c):
    for path in ("/", "/huddle", "/corp"):
        r = c.get(path)
        assert r.status_code == 200
        csp = r.headers["content-security-policy"]
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
        assert "'unsafe-eval'" not in csp and "script-src 'self'" in csp and "script-src *" not in csp
        assert "unsafe-inline" not in csp.split("style-src-attr")[0]  # no inline scripts or style blocks, only style="" attributes
        assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer" and "camera=()" in r.headers["permissions-policy"]
    assert "sha256-" in c.get("/corp").headers["content-security-policy"]  # the one tiny inline script is allowed by hash only


def test_private_api_responses_are_never_cached_and_docs_are_off(c):
    a = Person(c)
    r = c.get("/api/me", headers=a.h)
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert c.get(path).status_code == 404  # the API map (including the moderator API) isn't published
    assert c.get("/api/corp/pow").headers["cache-control"] == "no-store"


def test_pages_have_no_inline_scripts_or_handlers_the_policy_would_block():
    import re
    from pathlib import Path
    for page in ("index.html", "corp.html", "landing.html"):
        html = (Path(server.BASE) / "static" / page).read_text()
        assert not re.search(r"\son[a-z]+\s*=", html), f"{page} has an inline event handler"
        assert "javascript:" not in html and "<style" not in html
    for js in ("app.js", "corp.js"):
        src = (Path(server.BASE) / "static" / js).read_text()
        assert not re.search(r"\son(click|error|load|change|submit)\s*=\s*[\"']", src), f"{js} builds inline handlers"


def test_oversized_and_chunked_requests_are_refused(c):
    a = Person(c)
    big = json.dumps({"body": "x" * 2_000_000})
    assert c.post("/api/posts", headers={**a.h, "Content-Type": "application/json"}, content=big).status_code == 413
    r = c.post("/api/media", headers={**a.h}, files={"file": ("x.png", b"0" * 10, "image/png")})
    assert r.status_code == 400  # small uploads reach validation; the cap is for giant bodies
    assert c.post("/api/posts", headers={**a.h, "Content-Type": "application/json", "Transfer-Encoding": "chunked"}, content=b'{"body":"x"}').status_code in (411, 400)


def test_rate_limiter_forgets_old_visitors(c):
    for i in range(500):
        server.limiter.check(f"ip:10.0.{i // 250}.{i % 250}", 5, 1)
    assert len(server.limiter.hits) >= 500
    import time
    time.sleep(1.1)
    server.limiter.sweep()
    assert len(server.limiter.hits) == 0  # memory doesn't grow forever under a flood of one-off visitors


def test_flood_limit_protects_the_api_without_blocking_normal_use(c, monkeypatch):
    monkeypatch.setattr(server, "FLOOD_PER_MINUTE", 20)
    codes = [c.get("/api/meta").status_code for _ in range(25)]
    assert codes[:20] == [200] * 20 and codes[20:] == [429] * 5
    assert c.get("/").status_code == 200  # pages themselves still load


def test_new_accounts_cannot_put_links_in_any_text_field(c):
    a = Person(c)
    link = "buy now at cheap-pills.com or https://spam.example"
    assert c.put("/api/me", headers=a.h, json={"name": "Pat", "city": "Austin", "bio": link}).status_code == 403
    assert c.post("/api/events", headers=a.h, json={"title": "Free stuff", "description": link, "category": "Outdoors", "city": "Austin", "venue": "Park", "starts": "2099-01-01T10:00", "capacity": 5}).status_code == 403
    assert c.post("/api/groups", headers=a.h, json={"name": "Deals", "description": link, "mature": False}).status_code == 403
    a.rsvp(1)
    assert c.post("/api/events/1/messages", headers=a.h, json={"body": "visit www.spam.biz"}).status_code == 403
    assert c.post("/api/posts", headers=a.h, json={"body": "see bit.ly/abc"}).status_code == 403
    ok = c.post("/api/events/1/messages", headers=a.h, json={"body": "Looking forward to this one. See you at 7.5 miles!"})
    assert ok.status_code == 200  # ordinary text with dots and numbers is fine
    veteran(a)
    assert c.put("/api/me", headers=a.h, json={"name": "Pat", "city": "Austin", "bio": "My site: https://example.org"}).status_code == 200  # after a day, links are fine


def test_signup_rejects_links_in_names_and_bios(c):
    import os
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    ch = c.get("/api/pow").json()
    body = {"name": "Visit spam-site.com", "city": "Austin", "birth_date": "1990-01-01", "public_key": jwk_pub(priv), "pow": {"challenge": ch["challenge"], "counter": solve(ch["challenge"], ch["bits"])}}
    assert c.post("/api/signup", json=body).status_code == 400


def test_links_with_embedded_logins_are_refused(c):
    a = Person(c)
    veteran(a)
    for bad in ("https://mybank.com@evil.example/login", "https://user:pw@example.org", "javascript:alert(1)", "data:text/html,hi", "ftp://x.org/a"):
        assert c.post("/api/posts", headers=a.h, json={"body": "hello", "url": bad}).status_code == 400, bad
    assert c.post("/api/posts", headers=a.h, json={"body": "hello", "url": "https://example.org/page?a=1"}).status_code == 200


def test_storage_quota_and_abandoned_uploads(c, monkeypatch):
    a = Person(c)
    veteran(a)
    monkeypatch.setattr(server, "MAX_USER_BYTES", 6000)
    def noise():  # random pixels don't compress, so each photo takes real space
        import os
        from PIL import Image
        buf = io.BytesIO()
        Image.frombytes("RGB", (64, 64), os.urandom(64 * 64 * 3)).save(buf, "PNG")
        return buf.getvalue()
    codes = [upload(c, a, noise()).status_code for _ in range(6)]
    assert 413 in codes and codes[0] == 200  # a person can't fill the disk
    # drafts that never became a post are cleared after a day
    with server.db() as conn:
        conn.execute("UPDATE media SET created='2020-01-01T00:00:00+00:00'")
        server.prune_orphans(conn)
        assert conn.execute("SELECT COUNT(*) FROM media").fetchone()[0] == 0
    assert list(server.UPLOAD_DIR.glob("*")) == []


def test_posted_media_is_kept_by_the_orphan_sweep(c):
    a = Person(c)
    m = upload(c, a, png_bytes()).json()
    c.post("/api/posts", headers=a.h, json={"body": "keep me", "media": [m["id"]]})
    with server.db() as conn:
        conn.execute("UPDATE media SET created='2020-01-01T00:00:00+00:00'")
        server.prune_orphans(conn)
        assert conn.execute("SELECT COUNT(*) FROM media").fetchone()[0] == 1


def test_scanner_url_must_be_http(c, monkeypatch):
    a = Person(c)
    monkeypatch.setattr(server, "SCAN_URL", "file:///etc/passwd")
    assert upload(c, a, png_bytes()).status_code == 503


def test_moderator_key_guessing_locks_out(c, monkeypatch):
    monkeypatch.setenv("HUDDLE_MOD_KEY", "m" * 32)
    codes = [c.get("/api/mod/reports", headers={"X-Mod-Key": "wrong" * 8}).status_code for _ in range(10)]
    assert codes[:8] == [401] * 8 and codes[8:] == [429, 429]
    assert c.get("/api/mod/reports", headers={"X-Mod-Key": "m" * 32}).status_code == 200  # the right key still works


def test_invite_tokens_never_appear_in_urls_or_storage(c):
    a = company(c)
    token = a.invite("member")
    assert c.get(f"/api/corp/invites/{token}").status_code in (404, 405)
    assert c.post("/api/corp/invites/peek", json={"token": token}).status_code == 200
    assert token.encode() not in open(server.DB_PATH, "rb").read()  # only a hash is stored


def test_api_never_leaks_credentials(c):
    a = Person(c)
    blob = json.dumps([c.get("/api/me", headers=a.h).json(), c.get(f"/api/users/{a.id}").json(), c.get("/api/users/1").json(), c.get("/api/events").json(), c.get("/api/groups").json()])
    assert "token" not in blob and "hash" not in blob.lower() and "password" not in blob.lower()
    k = CorpPerson(c, "Ada", company="Co")
    k.start_workspace()
    blob2 = json.dumps([c.get("/api/corp/me", headers=k.h).json(), c.get(f"/api/corp/w/{k.wid}", headers=k.h).json(), c.get(f"/api/corp/w/{k.wid}/invites", headers=k.h).json()])
    assert "token" not in blob2.replace("tokens", "") and "token_hash" not in blob2


PUBLIC_WRITES = {"/api/signup", "/api/pow", "/api/corp/pow", "/api/corp/signup", "/api/corp/join", "/api/corp/invites/peek", "/api/corp/demo-join"}


def test_no_endpoint_accepts_a_write_without_logging_in(c):
    """Walk every route the app publishes and try it with no credentials."""
    import re
    tried = 0
    for path, methods in server.app.openapi()["paths"].items():
        for method in ("post", "put", "patch", "delete"):
            if method not in methods or path in PUBLIC_WRITES:
                continue
            r = c.request(method.upper(), re.sub(r"\{\w+\}", "1", path), json={})
            assert r.status_code in (401, 403, 404, 405, 422, 429, 503), f"{method.upper()} {path} answered {r.status_code} without credentials"
            tried += 1
    assert tried > 50  # the whole API, both products (57 write endpoints at the time of writing)


def test_corp_workspaces_cannot_reach_into_each_other(c):
    a = company(c, "Ada", "Alpha")
    b = company(c, "Bea", "Beta")
    item = b.post("channel", {"name": "secret-plans"}).json()["id"]
    msg = b.post("message", {"text": "only Beta"}, parent=item).json()["id"]
    inv = b.invite("member")
    bsid = b.scope_id
    bw = b.wid
    # Ada's token against Beta's ids, on every kind of endpoint
    probes = [
        ("get", f"/api/corp/w/{bw}"), ("get", f"/api/corp/w/{bw}/items?kind=channel"), ("get", f"/api/corp/w/{bw}/audit"),
        ("get", f"/api/corp/w/{bw}/pending"), ("get", f"/api/corp/w/{bw}/invites"),
        ("put", f"/api/corp/w/{bw}/items/{item}", {"meta": {"archived": True}}), ("delete", f"/api/corp/w/{bw}/items/{msg}"),
        ("put", f"/api/corp/w/{bw}/items/{item}/rsvp", {"status": "yes"}),
        ("post", f"/api/corp/w/{bw}/items", {"kind": "channel", "scope_id": bsid, "meta": {}, "iv": "AAAA", "ct": "AAAA", "epoch": 1}),
        ("post", f"/api/corp/w/{bw}/scopes/{bsid}/grants", {"epoch": 1, "grants": []}),
        ("post", f"/api/corp/w/{bw}/scopes/{bsid}/rotate", {"epoch": 2, "grants": []}),
        ("put", f"/api/corp/w/{bw}/members/{b.id}", {"role": "member"}), ("delete", f"/api/corp/w/{bw}/members/{b.id}"),
        ("post", f"/api/corp/w/{bw}/invites", {"role": "admin"}), ("put", f"/api/corp/w/{bw}", {"name": "Hijacked"}), ("delete", f"/api/corp/w/{bw}"),
    ]
    for method, url, *body in probes:
        r = c.request(method.upper(), url, headers=a.h, json=body[0] if body else None)
        assert r.status_code in (403, 404), f"{method.upper()} {url} gave {r.status_code}"
    # and through Alpha's own workspace id, using Beta's scope or item ids
    wrong = c.post(f"/api/corp/w/{a.wid}/items", headers=a.h, json={"kind": "channel", "scope_id": bsid, "meta": {}, "iv": "AAAA", "ct": "AAAA", "epoch": 1})
    assert wrong.status_code == 404
    assert c.put(f"/api/corp/w/{a.wid}/items/{item}", headers=a.h, json={"meta": {"archived": True}}).status_code == 404
    assert c.delete(f"/api/corp/w/{a.wid}/items/{msg}", headers=a.h).status_code == 404
    assert a.items("channel") == [] and b.items("channel")[0]["meta"]["archived"] is False  # nothing changed
    # an invite for one company grants nothing in the other
    joined = CorpPerson(c, "Cy", token=inv)
    assert c.get(f"/api/corp/w/{a.wid}", headers=joined.h).status_code == 404


def test_people_cannot_change_each_others_things_on_the_social_site(c):
    a, b = Person(c, "A"), Person(c, "B")
    img = upload(c, b, png_bytes()).json()
    post = c.post("/api/posts", headers=b.h, json={"body": "mine", "media": [img["id"]]}).json()["id"]
    grp = c.post("/api/groups", headers=b.h, json={"name": "Bs Group", "mature": False}).json()["id"]
    ev = c.post("/api/events", headers=b.h, json={"title": "Bs event", "description": "ten chars+", "category": "Outdoors", "city": "Austin", "venue": "Park", "starts": "2099-01-01T10:00", "capacity": 5}).json()["id"]
    reply = c.post(f"/api/posts/{post}/replies", headers=b.h, json={"body": "mine too"}).json()
    assert c.delete(f"/api/posts/{post}", headers=a.h).status_code == 404
    assert c.delete(f"/api/groups/{grp}", headers=a.h).status_code == 404
    assert c.delete(f"/api/groups/{grp}/members/{b.id}", headers=a.h).status_code == 404
    assert c.delete(f"/api/media/{img['id']}", headers=a.h).status_code == 200  # no-op: not a's, and already attached
    assert c.get(f"/api/posts/{post}").json()["media"] and (server.UPLOAD_DIR / img["url"].rsplit("/", 1)[1]).exists()
    assert c.put("/api/me", headers=a.h, json={"name": "A renamed", "city": "Austin"}).status_code == 200
    assert c.get(f"/api/users/{b.id}").json()["name"] == "B"
    assert c.get(f"/api/dm/{b.id}", headers=a.h).json() == []  # a only ever sees their own thread with b
    assert c.post(f"/api/requests/{b.id}/accept", headers=a.h).status_code == 404
