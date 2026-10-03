#!/usr/bin/env python3
"""Build a single-file, no-server demo of Huddle and Huddle Corp.

The demo mirrors the real front door: a chooser page, then either product. Each product is the real front end
(static/) talking to a pretend server that lives inside the page (demo/mock-*.js). Nothing is saved, and reloading
starts over, so you can look around or show it to someone.

    python demo/build_demo.py                          # writes demo/dist/huddle-demo.html
    python demo/build_demo.py --fragment out.html      # body-only version for hosts that add their own <html>
"""
import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).parent
STATIC = HERE.parent / "static"
read = lambda p: Path(p).read_text()

DEMO_CSS = """
#demobar{background:var(--note,var(--warn,#fff8dc));border-bottom:1px solid var(--note-line,var(--warn-line,#ecdca0));color:var(--text);padding:7px 14px;font-size:.85rem;display:flex;gap:10px;justify-content:center;align-items:center;flex-wrap:wrap;text-align:center}
[hidden]{display:none!important}
"""
HUDDLE_BAR = ('<div id="demobar"><span><b>Demo.</b> Sample data that lives only in this page. Nothing is saved, and reloading starts over.</span>'
              '<button class="btn small" id="demo-go" type="button">Jump in as a sample member</button>'
              '<button class="linkbtn" id="demo-home" type="button">All Huddle products</button></div>')
CORP_BAR = ('<div id="demobar"><span><b>Demo.</b> A pretend company with sample teammates. Everything is encrypted in this page with real keys. Nothing is saved.</span>'
            '<button class="btn small" id="demo-go" type="button">Jump in as a sample admin</button></div>')

HUDDLE_JS = """
(() => {
  const go = document.getElementById('demo-go');
  setInterval(() => { go.hidden = !!me; }, 400); go.hidden = !!me;
  document.getElementById('demo-home').onclick = () => location.reload();
  document.addEventListener('click', e => { if (e.target.closest('a.prodswitch')) { e.preventDefault(); location.reload(); } });
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
CORP_JS = """
(() => {
  const go = document.getElementById('demo-go');
  setInterval(() => { go.hidden = !!me; }, 400); go.hidden = !!me;
  document.addEventListener('click', e => { if (e.target.closest('a.switch')) { e.preventDefault(); location.reload(); } });
  go.onclick = async () => {
    go.disabled = true;
    try {
      const keys = await genKeys();
      const r = await api('/demo-join', { method: 'POST', body: { name: 'Jamie Rivera', title: 'Operations Lead', public_key: keys.pub } });
      await startSession(r.token, r.user_id, keys.priv);
      await keepKeysFlowing(); toast('You are Jamie, an admin at Northwind Labs (sample).'); if (location.hash && location.hash !== '#/') location.hash = '#/'; else route();
    } catch (e) { toast(e.message); } finally { go.disabled = false; }
  };
})();
"""


def js(src: str) -> str:
    return src.replace("</script", "<\\/script")


def no_download(src: str, name: str, msg: str) -> str:
    """Demo frames block file downloads, and the demo has no real account to back up."""
    return re.sub(rf"function {name}\(\) \{{.*?\n\}}\n", f"function {name}() {{ toast('{msg}'); }}\n", src, count=1, flags=re.S)


def body_of(html: str) -> str:
    return html.split("<body>")[1].split("<script")[0].strip()


def huddle_payload():
    app = no_download(read(STATIC / "app.js"), "downloadAccountFile", "Login files are not used in the demo.")
    return {"css": read(STATIC / "style.css") + DEMO_CSS, "markup": HUDDLE_BAR + "\n" + body_of(read(STATIC / "index.html")),
            "scripts": ["window.__DEMO = true;\n" + read(HERE / "mock-backend.js"), app, HUDDLE_JS]}


def corp_payload():
    corp = no_download(read(STATIC / "corp.js"), "downloadLoginFile", "Login files are not used in the demo.")
    return {"css": read(STATIC / "corp.css") + DEMO_CSS, "markup": CORP_BAR + "\n" + body_of(read(STATIC / "corp.html")),
            "scripts": ["window.__DEMO = true;\n" + read(STATIC / "crypto.js"), read(HERE / "mock-corp-backend.js"), corp, CORP_JS]}


def landing_parts():
    html = read(STATIC / "landing.html")
    css = read(STATIC / "landing.css")
    markup = html.split("<body>")[1].split("</body>")[0]
    markup = markup.replace('href="/huddle"', 'href="#" data-go="huddle"').replace('href="/corp"', 'href="#" data-go="corp"')
    return css, markup


LOADER = """
const PRODUCTS = %s;
function launch(which) {
  const p = PRODUCTS[which];
  document.getElementById('landing-css').remove();
  const st = document.createElement('style'); st.textContent = p.css; document.head.appendChild(st);
  document.getElementById('stage').innerHTML = p.markup;
  for (const code of p.scripts) { const s = document.createElement('script'); s.textContent = code; document.body.appendChild(s); }
}
document.querySelectorAll('[data-go]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); launch(a.dataset.go); }));
"""


def build(fragment: bool) -> str:
    land_css, land_markup = landing_parts()
    products = json.dumps({"huddle": huddle_payload(), "corp": corp_payload()}).replace("</", "<\\/")
    body = f'<div id="stage">{land_markup}</div>\n<script>{LOADER % products}</script>\n'
    css = f'<style id="landing-css">{land_css}</style>'
    title = "<title>Huddle Demo</title>"
    if fragment:
        return f"{title}\n{css}\n{body}"
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f"{title}{css}</head><body>{body}</body></html>")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fragment", help="write a body-only fragment to this path instead")
    ap.add_argument("--out", default=str(HERE / "dist" / "huddle-demo.html"))
    a = ap.parse_args()
    target = Path(a.fragment or a.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(build(bool(a.fragment)))
    print(f"wrote {target} ({target.stat().st_size // 1024} KB)")
