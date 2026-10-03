# Huddle

A meetup site focused on connection: see who's going, what you share with them, and say hello easily. Open to everyone.

## Run
```
cd meetup
pip install -r requirements.txt
uvicorn server:app --reload
```
Open http://localhost:8000. A SQLite database (`huddle.db`) is created and seeded with sample data on first start.

## What it feels like
- **Join in under a minute**: first name, city, birthday, tap a few interests, one button. No password or email.
  You land on events picked for you; a small banner offers to save your login file.
- **Feed**: share news, finds and links, tagged by interest. "For you" ranks by your interests and city.
  Reply on a post. New accounts can't post links for 24 hours (anti-spam).
- **Message requests**: tap Message on anyone and send one first message as a request. They see it (with what
  you have in common), then Accept, Decline or Block. Until they accept you can't send more; replying also
  accepts. Declining is silent and permanent, so the sender just keeps seeing "Request sent" and can't pester.
  Requests can be reported before accepting. A badge on Messages shows how many are waiting.
- **Live chats**: they update on their own, and a waiting screen unlocks by itself the moment a request is accepted.
- **A calm, polished look**: ivory/ink/gold palette with a dark mode, serif headings, frosted header, springy
  hover and press feedback, animated menus, dialogs and chat bubbles, skeleton loading, and a phone layout.
  Motion is switched off for people who prefer reduced motion. No third-party fonts or requests.
- **Block in one tap** from a profile, chat, post or reply, with Undo; manage the list in Settings.
- **Delete your account in two taps** (Settings): messages, posts, RSVPs, hosted events and keys are erased.
  Safety reports involving the account are retained so abuse can still be investigated.

## Connection features
- **Interest matching**: events and people ranked by what you have in common ("Best for me", People tab).
- **Who's going**: every attendee shows shared interests with you.
- **Icebreakers + event conversation**: RSVP'd attendees can chat, with one-tap conversation starters.
- **Direct messages** with a shared-interest conversation starter.
- **Inclusive profiles**: optional pronouns, "looking for" goals (friends, activity partners, networking...), no gender field.

## Privacy and safety model
**Direct messages are end-to-end encrypted.** Each browser generates an ECDH P-256 key pair at sign-up and
keeps the private key. A per-conversation AES-GCM key is derived from your private key and the other person's
public key (WebCrypto). The server stores only ciphertext and holds no keys, so neither Huddle nor anyone with
database access can read DMs. Both people can compare a safety number to detect a man-in-the-middle.

**How moderation works without a backdoor**
- A participant can *report a conversation*. Their browser decrypts and discloses that one thread's key; the
  server verifies it against the stored ciphertext, then saves up to 100 messages as report evidence.
  Other conversations stay private. Nothing else gives moderators DM access.
- Event chats, profiles and events are not E2EE (they are public to attendees), so moderators can read and
  delete them, and users are told they are reviewed.
- Moderator API (`/api/mod/*`, see `/docs`): list/read/resolve reports (child-safety reports sorted first),
  suspend users, read/delete event messages, read the audit log. Auth: `X-Mod-Key` header matching the
  `HUDDLE_MOD_KEY` env var (24+ chars; the API is disabled if unset). Every call is written to an audit log.
- Safety by design: 18+ only (birth date checked once, not stored), every new conversation starts as a request
  the recipient must accept, blocking, and per-account limits (new accounts: 3 new requests a day, 1 hosted
  event, no links for 24 hours).

**Easy to join, hard to bot**: no password or email. Sign-up needs a small proof-of-work (a couple of seconds in
the browser; it automatically gets harder if sign-ups spike), plus a honeypot field, single-use signed
challenges and per-IP limits. Event chat, RSVPs, hosting and DMs are rate-limited per account.

**Accounts**: your login and private key live in the browser. The *login file* (offered after sign-up and in Settings)
It is the only way to restore your account and read old messages on a new device. Lose it and the messages are
unrecoverable by design.

## Configuration
| Env var | Purpose |
|---|---|
| `HUDDLE_MOD_KEY` | Enables the moderator API (24+ chars) |
| `HUDDLE_SECRET` | Signs sign-up challenges; set it so they survive restarts and multiple workers |
| `HUDDLE_TRUST_PROXY=1` | Use `X-Forwarded-For` for the client IP, only behind a proxy you control |
| `HUDDLE_DB` | SQLite path |

## Before going public
- Serve over HTTPS (browsers only allow WebCrypto on HTTPS or localhost).
- The age check is a self-declaration, not verification. For stronger protection add ID or age-estimation
  checks, plus hash-matching (e.g. NCMEC/PhotoDNA) if you ever allow image uploads.
- If you operate in the US/EU/UK, get legal advice on child-safety reporting duties (e.g. NCMEC reporting) and
  build a report-handling process around the moderator API.
- Add optional email or phone verification, and move rate limiting to Redis when running multiple workers.

## Tests
`pytest -q` runs API tests covering sign-up abuse protection, ciphertext-only storage, moderator boundaries, blocking, the feed, account deletion and limits.
