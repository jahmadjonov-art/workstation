# Security notes

## What is covered
- **E2EE**: DMs and all Huddle Corp content are encrypted in the browser. The server stores ciphertext only.
- **Browser protections**: strict CSP (no inline script, `default-src 'none'`), `nosniff`, no framing, `Referrer-Policy: no-referrer`, `no-store` on API responses. Optional HSTS (`HUDDLE_HSTS=1`).
- **Spam and bots**: signed single-use proof-of-work on sign-up, honeypot, per-IP and per-user rate limits (swept so memory stays bounded), tighter limits and no links for accounts under 24 h old, photos only for new accounts.
- **Uploads**: type sniffing, re-encode photos, strip video metadata, per-user storage quota, orphan cleanup, optional external scanner that fails closed.
- **Input**: request-size limits, link validation (no `javascript:`, no embedded credentials), parameterised SQL, escaped output.
- **Access control**: tests cover unauthenticated writes, cross-tenant Corp isolation and social IDOR.
- **Moderation**: moderators see only reported evidence, with an audit log and a lockout on bad keys.
- **Dependencies**: `pip-audit` clean at time of writing.

## Known gaps
- No "sign out everywhere" and sessions do not expire yet.
- Media URLs are unguessable capability links, not authenticated.
- Rate limiting is in-process; use a shared store (e.g. Redis) when running several workers.
- A same-origin XSS would reach both products' local storage. CSP and escaping are the defence.
- Lose the login file and the private key, and encrypted data cannot be recovered. That is by design.

## Deployment checklist
HTTPS with `HUDDLE_HSTS=1`; set `HUDDLE_SECRET` and `HUDDLE_MOD_KEY`; `HUDDLE_TRUST_PROXY=1` only behind your own proxy; body-size limits at the proxy; configure `HUDDLE_MEDIA_SCAN_URL` (CSAM scanning) before allowing uploads publicly; back up the database; keep `/docs` off.
