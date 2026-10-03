/* Clean web search, shared by Huddle and Huddle Corp. Plain results, no ads, nothing saved. */
function searchView(app, shell, esc, nav) {
  const qs = new URLSearchParams((location.hash.split('?')[1] || ''));
  const q = qs.get('q') || '';
  app.innerHTML = shell(`<div class="box websearch"><h2>Search the web</h2>
    <form id="wsform" role="search"><input id="wsq" type="search" maxlength="200" placeholder="Search for anything" aria-label="Search the web" value="${esc(q)}" autofocus><button class="btn" type="submit">Search</button></form>
    <p class="sub">No ads, no sponsored results, no tracking tags. What you search for is not saved, and sites you open don't learn who sent you.</p>
    <div id="wsout"></div></div>`);
  const out = document.getElementById('wsout');
  document.getElementById('wsform').addEventListener('submit', e => {
    e.preventDefault(); const v = document.getElementById('wsq').value.trim();
    if (v) { const h = '#/web?q=' + encodeURIComponent(v); location.hash === h ? run(v) : (location.hash = h); }
  });
  async function run(term, page = 1) {
    out.innerHTML = '<p class="sub">Searching…</p>';
    try {
      const r = await fetch('/api/search?q=' + encodeURIComponent(term) + '&page=' + page);
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Search failed');
      const direct = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(term) ? (/^https?:\/\//i.test(term) ? term : 'https://' + term) : '';
      out.innerHTML = (direct ? `<div class="wsgo"><a href="${esc(direct)}" target="_blank" rel="noopener noreferrer">Go straight to ${esc(term)}</a></div>` : '') +
        (d.results.map(x => { let host = ''; try { host = new URL(x.url).hostname.replace(/^www\./, ''); } catch {}
          return `<div class="wsr"><a class="wst" href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.title)}</a><div class="wsu">${esc(host)}</div><div class="wss">${esc(x.snippet)}</div></div>`; }).join('')
        || '<p class="sub">Nothing found. Try different words.</p>') +
        (d.results.length ? `<p><button class="btn ghost" id="wsmore">More results</button></p>` : '');
      document.getElementById('wsmore')?.addEventListener('click', ev => { ev.target.remove(); more(term, page + 1); });
    } catch (e) { out.innerHTML = `<p class="sub">${esc(e.message)}</p>`; }
  }
  async function more(term, page) {
    try {
      const r = await fetch('/api/search?q=' + encodeURIComponent(term) + '&page=' + page); const d = await r.json();
      if (!r.ok) return;
      out.insertAdjacentHTML('beforeend', d.results.map(x => { let host = ''; try { host = new URL(x.url).hostname.replace(/^www\./, ''); } catch {}
        return `<div class="wsr"><a class="wst" href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.title)}</a><div class="wsu">${esc(host)}</div><div class="wss">${esc(x.snippet)}</div></div>`; }).join('') +
        (d.results.length ? `<p><button class="btn ghost" id="wsmore">More results</button></p>` : ''));
      document.getElementById('wsmore')?.addEventListener('click', ev => { ev.target.remove(); more(term, page + 1); });
    } catch {}
  }
  if (q) run(q);
}
