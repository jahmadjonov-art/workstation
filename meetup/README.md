# Huddle

A meetup site focused on connection: see who's going, what you share with them, and say hello easily. Open to everyone.

## Run
```
cd meetup
pip install -r requirements.txt
uvicorn server:app --reload
```
Open http://localhost:8000. A SQLite database (`huddle.db`) is created and seeded with sample data on first start.

## Connection features
- **Interest matching**: events and people ranked by what you have in common ("Best for me", People tab).
- **Who's going**: every attendee shows shared interests with you.
- **Icebreakers + event conversation**: RSVP'd attendees can chat, with one-tap conversation starters.
- **Direct messages** with a shared-interest conversation starter.
- **Inclusive profiles**: optional pronouns, "looking for" goals (friends, activity partners, networking...), no gender field.

## Notes
Sign-in is a demo: your profile id is kept in the browser (no passwords). Add real authentication before public use.
