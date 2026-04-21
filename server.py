import asyncio
import logging
import re
import time
from urllib.parse import quote, urlparse

import httpx
from duckduckgo_search import DDGS
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

log = logging.getLogger("deepsearch")
app = FastAPI(title="DeepSearch")

# ── Ad/tracker domain blocklist ───────────────────────────────────────────────
AD_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "adsystem.amazon.com",
    "adservice.google.com", "ads.yahoo.com", "advertising.com",
    "taboola.com", "outbrain.com", "revcontent.com", "mgid.com",
    "adnxs.com", "criteo.com", "rubiconproject.com", "pubmatic.com",
    "openx.net", "sovrn.com", "sharethrough.com", "triplelift.com",
    "moatads.com", "contextweb.com", "casalemedia.com", "yieldmo.com",
    "33across.com", "smartadserver.com", "lijit.com", "undertone.com",
}

# URL query-string patterns that betray paid placement
AD_URL_PATTERNS = [
    r"[?&]gclid=",      # Google Ads click id
    r"[?&]gbraid=",     # Google Ads (iOS)
    r"[?&]wbraid=",     # Google Ads (web)
    r"[?&]msclkid=",    # Microsoft Ads click id
    r"[?&]utm_medium=cpc",
    r"[?&]utm_source=cpc",
    r"[?&]utm_source=adwords",
    r"[?&]ref=adwords",
    r"/sponsored/",
    r"/ads?/",
]

# Title / snippet phrases that signal sponsored placement
SPONSORED_TITLE_RE = re.compile(
    r"(^sponsored\b|^advertisement\b|\[sponsored\]|\[ad\]|- sponsored$|- advertisement$)",
    re.IGNORECASE,
)

# Domains that are almost entirely SEO / affiliate farms
SEO_FARM_DOMAINS = {
    "answerbag.com", "blurtit.com", "ask.fm", "quora.com",  # quora keeps real content too,
    # but its top results are usually SEO-optimised summaries – left here as optional toggle
}


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def is_ad(result: dict) -> bool:
    url = result.get("url", "").lower()
    title = result.get("title", "")
    domain = _domain(url)

    if any(ad == domain or domain.endswith("." + ad) for ad in AD_DOMAINS):
        return True
    for pat in AD_URL_PATTERNS:
        if re.search(pat, url, re.IGNORECASE):
            return True
    if SPONSORED_TITLE_RE.search(title):
        return True
    return False


# ── Search source functions ───────────────────────────────────────────────────

async def search_ddg(query: str, max_results: int = 25) -> list[dict]:
    """DuckDuckGo – no tracking, no personalisation bubbles."""
    results = []
    try:
        # DDGS is synchronous; run in thread to avoid blocking
        def _fetch():
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))

        raw = await asyncio.to_thread(_fetch)
        for r in raw:
            item = {
                "title": r.get("title", ""),
                "url": r.get("href", ""),
                "snippet": r.get("body", ""),
                "source": "web",
                "source_label": "Web",
            }
            if not is_ad(item):
                results.append(item)
    except Exception as exc:
        log.debug("[DDG] %s", exc)
    return results


async def search_hackernews(query: str, max_results: int = 8) -> list[dict]:
    """Hacker News – developer and tech discussions, often surface buried gems."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://hn.algolia.com/api/v1/search",
                params={"query": query, "hitsPerPage": max_results, "tags": "story"},
            )
            resp.raise_for_status()
            for hit in resp.json().get("hits", []):
                url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
                pts = hit.get("points", 0)
                cmt = hit.get("num_comments", 0)
                results.append({
                    "title": hit.get("title", ""),
                    "url": url,
                    "snippet": f"{pts} points · {cmt} comments",
                    "source": "hackernews",
                    "source_label": "Hacker News",
                })
    except Exception as exc:
        log.debug("[HN] %s", exc)
    return results


async def search_reddit(query: str, max_results: int = 8) -> list[dict]:
    """Reddit – community-sourced knowledge, niche subreddits."""
    results = []
    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={"User-Agent": "DeepSearch/1.0 (open-source research tool)"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                "https://www.reddit.com/search.json",
                params={"q": query, "limit": max_results, "sort": "relevance", "t": "all"},
            )
            resp.raise_for_status()
            for post in resp.json().get("data", {}).get("children", []):
                d = post.get("data", {})
                sub = d.get("subreddit", "")
                score = d.get("score", 0)
                cmt = d.get("num_comments", 0)
                results.append({
                    "title": d.get("title", ""),
                    "url": f"https://www.reddit.com{d.get('permalink', '')}",
                    "snippet": f"r/{sub} · {score} upvotes · {cmt} comments",
                    "source": "reddit",
                    "source_label": "Reddit",
                })
    except Exception as exc:
        log.debug("[Reddit] %s", exc)
    return results


async def search_wikipedia(query: str, max_results: int = 3) -> list[dict]:
    """Wikipedia – encyclopaedic depth, primary sources."""
    results = []
    try:
        async with httpx.AsyncClient(
            timeout=10,
            headers={
                "User-Agent": "DeepSearch/1.0 (deepsearch research tool; contact: opensource)",
                "Api-User-Agent": "DeepSearch/1.0",
            },
            follow_redirects=True,
        ) as client:
            # Use the REST v1 search endpoint — more permissive than the legacy MediaWiki API
            resp = await client.get(
                f"https://en.wikipedia.org/w/rest.php/v1/search/page",
                params={"q": query, "limit": max_results},
            )
            resp.raise_for_status()
            for item in resp.json().get("pages", []):
                title = item.get("title", "")
                excerpt = re.sub(r"<[^>]+>", "", item.get("excerpt") or "")
                results.append({
                    "title": title,
                    "url": f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}",
                    "snippet": excerpt + " …" if excerpt else "Wikipedia article",
                    "source": "wikipedia",
                    "source_label": "Wikipedia",
                })
    except Exception as exc:
        log.debug("[Wikipedia] %s", exc)
    return results


async def search_marginalia(query: str, max_results: int = 8) -> list[dict]:
    """Marginalia – indexes the non-commercial indie web; surfaces pages
    that Google buries because they lack SEO and backlinks."""
    results = []
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": "DeepSearch/1.0 (research tool)"},
        ) as client:
            resp = await client.get(
                f"https://api.marginalia.nu/api/rpc/search/{quote(query)}",
                params={"count": max_results},
            )
            resp.raise_for_status()
            for item in resp.json().get("results", []):
                url = item.get("url", "")
                results.append({
                    "title": item.get("title") or url,
                    "url": url,
                    "snippet": item.get("description") or "Independent web page",
                    "source": "indie",
                    "source_label": "Indie Web",
                })
    except Exception as exc:
        log.debug("[Marginalia] %s", exc)
    return results


async def search_archive(query: str, max_results: int = 5) -> list[dict]:
    """Internet Archive full-text search – resurfaces old and deleted pages."""
    results = []
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            resp = await client.get(
                "https://archive.org/advancedsearch.php",
                params={
                    "q": query,
                    "output": "json",
                    "rows": max_results,
                    "fl[]": "identifier,title,description",
                    "mediatype": "texts",
                },
            )
            resp.raise_for_status()
            docs = resp.json().get("response", {}).get("docs", [])
            for doc in docs:
                ident = doc.get("identifier", "")
                results.append({
                    "title": doc.get("title") or ident,
                    "url": f"https://archive.org/details/{ident}",
                    "snippet": doc.get("description") or "Text archived from the Internet Archive.",
                    "source": "archive",
                    "source_label": "Internet Archive",
                })
    except Exception as exc:
        log.debug("[Archive] %s", exc)
    return results


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(results: list[dict]) -> list[dict]:
    seen_urls: set[str] = set()
    domain_count: dict[str, int] = {}
    out = []
    for r in results:
        url = r.get("url", "")
        if not url or url in seen_urls:
            continue
        dom = _domain(url)
        if domain_count.get(dom, 0) >= 3:
            continue
        domain_count[dom] = domain_count.get(dom, 0) + 1
        seen_urls.add(url)
        out.append(r)
    return out


# ── API endpoints ─────────────────────────────────────────────────────────────

SOURCE_MAP = {
    "web": search_ddg,
    "hackernews": search_hackernews,
    "reddit": search_reddit,
    "wikipedia": search_wikipedia,
    "indie": search_marginalia,
    "archive": search_archive,
}


@app.get("/api/search")
async def search(
    q: str = Query(..., min_length=1),
    sources: str = Query(default="all"),
):
    q = q.strip()
    if not q:
        return {"results": [], "query": q, "total": 0, "elapsed_ms": 0}

    t0 = time.perf_counter()

    if sources == "all":
        active = list(SOURCE_MAP.values())
    else:
        active = [SOURCE_MAP[s] for s in sources.split(",") if s in SOURCE_MAP]

    batches = await asyncio.gather(*[fn(q) for fn in active], return_exceptions=True)

    # Separate web (primary) from enrichment sources
    web_results: list[dict] = []
    extra_results: list[dict] = []
    for batch in batches:
        if not isinstance(batch, list):
            continue
        for r in batch:
            if is_ad(r):
                continue
            if r.get("source") == "web":
                web_results.append(r)
            else:
                extra_results.append(r)

    # Interleave: insert one enrichment result every 4 web results so they
    # surface throughout the list rather than all clustering at the bottom.
    combined: list[dict] = []
    extra_iter = iter(extra_results)
    for i, r in enumerate(web_results):
        combined.append(r)
        if (i + 1) % 4 == 0:
            try:
                combined.append(next(extra_iter))
            except StopIteration:
                pass
    combined.extend(extra_iter)  # append any remaining enrichment results

    combined = deduplicate(combined)
    elapsed = round((time.perf_counter() - t0) * 1000)

    return {
        "results": combined,
        "query": q,
        "total": len(combined),
        "elapsed_ms": elapsed,
    }


@app.get("/api/status")
async def status():
    """Probe each search source with a lightweight request and report availability."""

    async def probe(name: str, fn) -> dict:
        try:
            results = await asyncio.wait_for(fn("test"), timeout=6)
            return {"source": name, "available": isinstance(results, list), "results": len(results)}
        except Exception as exc:
            return {"source": name, "available": False, "error": str(exc)[:80]}

    probes = await asyncio.gather(
        probe("web", search_ddg),
        probe("hackernews", search_hackernews),
        probe("reddit", search_reddit),
        probe("wikipedia", search_wikipedia),
        probe("indie", search_marginalia),
        probe("archive", search_archive),
    )
    return {"sources": probes}


# ── Static files & SPA root ───────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def root():
    return FileResponse("static/index.html")
