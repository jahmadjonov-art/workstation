# Huddle

A meetup site focused on connection: see who's going, what you share with them, and say hello easily. Open to everyone.

## Try it without a server
`python demo/build_demo.py` writes `demo/dist/huddle-demo.html`: one file you can double-click. It is the real
front end talking to a pretend server inside the page (`demo/mock-backend.js`), seeded with sample people who
have real encryption keys and answer message requests. Nothing is saved and reloading starts over. Use it to
look around or show the site to someone.

Opening `static/index.html` directly does not work, because the real site needs its server. The page now says
so ("Can't connect to the Huddle server") instead of failing quietly.

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
- **Photos and videos**: attach up to 4 photos or 1 video to any post, shown in the feed and in a photo grid on
  profiles. Photos are re-encoded on upload (which removes location data); videos have metadata stripped when
  `ffmpeg` is installed. New accounts can post photos (5 a day) but not video until they are a day old.
- **Likes, comments and reposts**: like a post, comment on it, or repost it to your profile with an optional note.
  Reposts show the original underneath and disappear if the original is deleted.
- **Groups**: join or start a group, post to it, and see its posts in your feed. Owners can remove posts and members.
- **The 18+ side**: when someone creates a group they must answer "Is this an 18+ activities group?". 18+ groups stay
  on a separate side. They never appear in the main feed, search, group directory, trends or profiles, and
  can't be reposted. People only see them after switching on "18+ groups" in Settings, and joining asks for
  confirmation. Photos in them are blurred until tapped. Sexually explicit content is not allowed anywhere.
- **Feed**: share news, finds and links, tagged by interest. "For you" ranks by your interests and city.
  Reply on a post. New accounts can't post links for 24 hours (anti-spam).
- **Message requests**: tap Message on anyone and send one first message as a request. They see it (with what
  you have in common), then Accept, Decline or Block. Until they accept you can't send more; replying also
  accepts. Declining is silent and permanent, so the sender just keeps seeing "Request sent" and can't pester.
  Requests can be reported before accepting. A badge on Messages shows how many are waiting.
- **Live chats**: they update on their own, and a waiting screen unlocks by itself the moment a request is accepted.
- **A plain, friendly timeline look** in the spirit of the early-2010s social web: charcoal top bar, three columns
  (your profile card, the timeline, "people you may like" and nearby events), flat white panels with thin rules,
  blue links and #hashtags, calendar-page date blocks for events, and a classic dim dark mode. Fast, subtle hover
  fades only; motion is off for people who prefer reduced motion. System fonts, no third-party requests.

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

## Photos, videos and child safety
Uploads are the highest-risk part of any social site. What is built in: files are identified by their bytes, never
their name; photos are decoded and re-encoded; new accounts have tighter upload limits and no video; links and
uploads are rate limited; every post, comment, group and profile has Report; moderators can list and delete media
and groups; and every upload can pass through an external scanner. What is **not** built in, and must be before
public launch: a hash-matching service for child sexual abuse material.

Set `HUDDLE_MEDIA_SCAN_URL` to an HTTP endpoint that receives each file (`POST`, raw bytes, `X-Media-Kind: image|video`)
and answers `{"allowed": true}` or `{"allowed": false}`. If it is configured but unreachable, uploads fail closed
(set `HUDDLE_SCAN_FAIL_OPEN=1` to override, not recommended). The server logs a warning at start-up while no scanner is set.
Examples to look at: PhotoDNA, NCMEC hash lists via an approved provider, Cloudflare's CSAM scanning tool, Thorn Safer.

## Configuration
| Env var | Purpose |
|---|---|
| `HUDDLE_MOD_KEY` | Enables the moderator API (24+ chars) |
| `HUDDLE_SECRET` | Signs sign-up challenges; set it so they survive restarts and multiple workers |
| `HUDDLE_TRUST_PROXY=1` | Use `X-Forwarded-For` for the client IP, only behind a proxy you control |
| `HUDDLE_DB` | SQLite path |
| `HUDDLE_UPLOADS` | Folder for uploaded photos and videos (default `meetup/uploads/`) |
| `HUDDLE_MEDIA_SCAN_URL` | Safety scanner every upload is sent to before it is stored |
| `HUDDLE_SCAN_FAIL_OPEN` | `1` lets uploads through if the scanner is down (default: fail closed) |

## Before going public
- **Scan uploads** for child sexual abuse material (see above), and have a process for reporting it. In the US,
  providers must report apparent CSAM to NCMEC.
- **Register a DMCA agent** and have a way to take down copyright-infringing uploads (US safe harbor).
- **Check the name.** "Huddle" is a common word and at least one company already uses it. Search trademarks, or rename.
- **Explicit content.** The rules ban it everywhere because the age gate is a self-declaration. If you ever want to
  allow it, you need real age verification and legal advice first.
- Move uploads to object storage (S3 or similar) behind a CDN, and add video transcoding and thumbnails.
- Serve over HTTPS (browsers only allow WebCrypto on HTTPS or localhost).
- The age check is a self-declaration, not verification. For stronger protection add ID or age-estimation
  checks, plus hash-matching (e.g. NCMEC/PhotoDNA) if you ever allow image uploads.
- If you operate in the US/EU/UK, get legal advice on child-safety reporting duties (e.g. NCMEC reporting) and
  build a report-handling process around the moderator API.
- Add optional email or phone verification, and move rate limiting to Redis when running multiple workers.

## Tests
`pytest -q` runs API tests covering sign-up abuse protection, ciphertext-only storage, moderator boundaries, blocking, the feed, account deletion and limits.
