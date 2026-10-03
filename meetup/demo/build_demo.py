#!/usr/bin/env python3
"""Build a single-file, no-server demo of Huddle.

The demo is the real front end (static/) running against demo/mock-backend.js, a pretend server that
lives inside the page. Open the result straight from disk or host it anywhere static.

    python demo/build_demo.py                          # writes demo/dist/huddle-demo.html
    python demo/build_demo.py --fragment out.html      # body-only version for hosts that add their own <html>
"""
import argparse
import re
from pathlib import Path

HERE = Path(__file__).parent
STATIC = HERE.parent / "static"

DEMO_CSS = """
#demobar{background:var(--note);border-bottom:1px solid var(--note-line);color:var(--text);padding:7px 14px;font-size:.85rem;display:flex;gap:10px;justify-content:center;align-items:center;flex-wrap:wrap;text-align:center}
[hidden]{display:none!important}
"""
DEMO_BAR = ('<div id="demobar"><span><b>Demo.</b> Sample data that lives only in this page. Nothing is saved, and reloading starts over.</span>'
            '<button class="btn small" id="demo-go" type="button">Jump in as a sample member</button></div>')
DEMO_JS = """
(() => {
  const go = document.getElementById('demo-go');
  const sync = () => { go.hidden = !!me; };
  setInterval(sync, 400); sync();
  go.onclick = async () => {
    go.disabled = true;
    try {
      const keys = await genKeys();
      const r = await api('/signup', { method: 'POST', body: { name: 'Jamie', city: 'Austin', interests: ['Hiking', 'Coffee', 'Python', 'Photography'], looking_for: ['Friends', 'Activity partners'],
        birth_date: '1992-04-12', website: '', public_key: pubOnly(keys.pub), pow: { challenge: 'demo', counter: '0' } } });
      store.set('huddle_token', r.token); store.set('huddle_priv_' + r.user.id, JSON.stringify(keys.priv));
      await loadMe(); toast('You are Jamie, a sample member. Look around!'); if (location.hash && location.hash !== '#/') location.hash = '#/'; else route();
    } catch (e) { toast(e.message); } finally { go.disabled = false; }
  };
})();
"""


def js(src: str) -> str:
    return src.replace("</script", "<\\/script")


def build(fragment: bool) -> str:
    html = (STATIC / "index.html").read_text()
    markup = html.split("<body>")[1].split("<script")[0].strip()
    css = (STATIC / "style.css").read_text() + DEMO_CSS
    app = (STATIC / "app.js").read_text()
    # the demo has no real account to back up, and demo frames block file downloads
    app = re.sub(r"function downloadAccountFile\(\) \{.*?\n\}\n", "function downloadAccountFile() { toast('Login files are not used in the demo.'); }\n", app, count=1, flags=re.S)
    app = js(app)
    mock = js((HERE / "mock-backend.js").read_text())
    body = f"{DEMO_BAR}\n{markup}\n<script>window.__DEMO = true;\n{mock}</script>\n<script>\n{app}</script>\n<script>{DEMO_JS}</script>\n"
    title = "<title>Huddle Demo</title>"
    if fragment:
        return f"{title}\n<style>{css}</style>\n{body}"
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'{title}<style>{css}</style></head><body>{body}</body></html>')


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fragment", help="write a body-only fragment to this path instead")
    ap.add_argument("--out", default=str(HERE / "dist" / "huddle-demo.html"))
    a = ap.parse_args()
    target = Path(a.fragment or a.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build(bool(a.fragment)))
    print(f"wrote {target} ({target.stat().st_size // 1024} KB)")
