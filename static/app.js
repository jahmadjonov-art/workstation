/* DeepSearch — frontend */
(function () {
  "use strict";

  // ── DOM refs ──────────────────────────────────────────────────────────────
  const heroSection    = document.getElementById("hero");
  const resultsSection = document.getElementById("results-section");
  const resultsList    = document.getElementById("results-list");
  const resultsMeta    = document.getElementById("results-meta");
  const spinner        = document.getElementById("spinner");
  const errorMsg       = document.getElementById("error-msg");
  const siteHeader     = document.getElementById("site-header");
  const headerForm     = document.getElementById("header-form");
  const headerInput    = document.getElementById("header-input");
  const heroForm       = document.getElementById("hero-form");
  const heroInput      = document.getElementById("hero-input");
  const sourceNav      = document.getElementById("source-nav");
  const pills          = document.querySelectorAll(".pill");

  let currentSource = "all";
  let currentQuery  = "";

  // ── Source badge config ───────────────────────────────────────────────────
  const SOURCE_META = {
    web:        { label: "Web",            cls: "badge-web" },
    hackernews: { label: "Hacker News",    cls: "badge-hackernews" },
    reddit:     { label: "Reddit",         cls: "badge-reddit" },
    wikipedia:  { label: "Wikipedia",      cls: "badge-wikipedia" },
    indie:      { label: "Indie Web",      cls: "badge-indie" },
    archive:    { label: "Archive",        cls: "badge-archive" },
  };

  // ── State transitions ─────────────────────────────────────────────────────
  function enterResultsMode(query) {
    heroSection.classList.add("hidden");
    siteHeader.classList.remove("header-home");
    headerInput.value = query;
    headerForm.classList.remove("hidden");
    sourceNav.classList.remove("hidden");
    resultsSection.classList.remove("hidden");
  }

  // ── Build a result card ───────────────────────────────────────────────────
  function buildCard(r, index) {
    const meta = SOURCE_META[r.source] || { label: r.source_label || r.source, cls: "badge-web" };
    const delay = Math.min(index * 30, 300);

    const card = document.createElement("article");
    card.className = "result-card";
    card.style.animationDelay = `${delay}ms`;

    const urlDisplay = truncateUrl(r.url, 72);
    const snippet    = r.snippet ? escapeHtml(r.snippet).replace(/\n/g, " ") : "";

    card.innerHTML = `
      <div class="result-header">
        <a class="result-title" href="${escapeAttr(r.url)}" target="_blank" rel="noopener noreferrer">
          ${escapeHtml(r.title || r.url)}
        </a>
        <span class="badge ${meta.cls}">${meta.label}</span>
      </div>
      <div class="result-url">${escapeHtml(urlDisplay)}</div>
      ${snippet ? `<p class="result-snippet">${snippet}</p>` : ""}
    `;
    return card;
  }

  // ── Render results ────────────────────────────────────────────────────────
  function renderResults(data) {
    resultsList.innerHTML = "";
    spinner.classList.add("hidden");
    errorMsg.classList.add("hidden");

    const { results, total, elapsed_ms, query } = data;

    if (!results || results.length === 0) {
      resultsMeta.innerHTML = `No results found for <strong>"${escapeHtml(query)}"</strong>`;
      return;
    }

    resultsMeta.innerHTML =
      `<strong>${total}</strong> results for <strong>"${escapeHtml(query)}"</strong> — ` +
      `<span>${elapsed_ms} ms</span>`;

    const frag = document.createDocumentFragment();
    results.forEach((r, i) => frag.appendChild(buildCard(r, i)));
    resultsList.appendChild(frag);
  }

  // ── Fetch search results ──────────────────────────────────────────────────
  async function doSearch(query, source) {
    if (!query.trim()) return;
    query = query.trim();

    currentQuery  = query;
    currentSource = source || "all";

    enterResultsMode(query);
    resultsList.innerHTML = "";
    resultsMeta.innerHTML = "";
    errorMsg.classList.add("hidden");
    spinner.classList.remove("hidden");

    // Sync pills
    pills.forEach(p => p.classList.toggle("active", p.dataset.source === currentSource));

    const url = `/api/search?q=${encodeURIComponent(query)}&sources=${encodeURIComponent(currentSource)}`;

    try {
      const res  = await fetch(url);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      renderResults(data);
    } catch (err) {
      spinner.classList.add("hidden");
      errorMsg.classList.remove("hidden");
      errorMsg.textContent = `Search failed: ${err.message}. Make sure the server is running.`;
    }
  }

  // ── Event listeners ───────────────────────────────────────────────────────
  heroForm.addEventListener("submit", e => {
    e.preventDefault();
    const q = heroInput.value.trim();
    if (q) doSearch(q, currentSource);
  });

  headerForm.addEventListener("submit", e => {
    e.preventDefault();
    const q = headerInput.value.trim();
    if (q) doSearch(q, currentSource);
  });

  pills.forEach(pill => {
    pill.addEventListener("click", () => {
      const source = pill.dataset.source;
      if (currentQuery) doSearch(currentQuery, source);
    });
  });

  // ── URL-based state (simple ?q= support) ─────────────────────────────────
  const params = new URLSearchParams(window.location.search);
  const initialQ = params.get("q");
  if (initialQ) {
    heroInput.value = initialQ;
    doSearch(initialQ, "all");
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escapeAttr(str) {
    return String(str).replace(/"/g, "%22").replace(/'/g, "%27");
  }

  function truncateUrl(url, max) {
    if (url.length <= max) return url;
    return url.slice(0, max - 1) + "…";
  }
})();
