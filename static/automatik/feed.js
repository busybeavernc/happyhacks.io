// Lists for the app's tabs (user, 2026-11-19: concise tabs that load fast). One component for Patty, Activity,
// the Dashboard's requests and Alerts:
// - pages of 20 (newest first); older ones on scroll or "Show older" (the PC/relay take limit + before)
// - a tab loads only when it's opened; it opens at once from an encrypted cache on this phone, then asks only
//   for what is new or changed since its last answer (delta)
// - long items show 1-2 lines until tapped; grouped Today / Yesterday / This week / Older (older ones folded)
// - handled items (seen, answered, from an earlier visit) hidden unless "Show all"; items that need the user
//   (questions, urgent alerts, running work, refused requests) pinned on top; nothing pinned is ever hidden
// - items older than 7 days only with "Show archived"; the search box searches everything on the PC / relay
// Uses kvGet/kvSet, enc/dec and el() from app.js (loaded with it; both run before the page starts).
"use strict";
const FEED_ARCHIVE_DAYS = 7;
const FEED_TABS = ["patty", "activity", "dash", "alerts"];
const GROUPS = ["Today", "Yesterday", "This week", "Older"];

// ---------- the cache: AES-GCM with a key made on this phone that can't be exported (like the other keys) ----------
async function cacheKey(make) {
  let k = await kvGet("cacheKey");
  if (!k && make) {
    k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    await kvSet("cacheKey", k);
  }
  return k || null;
}
async function cacheGet(tab) {
  try {
    const box = await kvGet("cache:" + tab), k = box && await cacheKey(false);
    if (!k) return null;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: box.iv, additionalData: enc.encode("cache:" + tab) }, k, box.ct);
    return JSON.parse(dec.decode(pt));
  } catch (e) { return null; }
}
async function cachePut(tab, obj) {
  try {
    const k = await cacheKey(true), iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("cache:" + tab) }, k, enc.encode(JSON.stringify(obj)));
    await kvSet("cache:" + tab, { iv, ct });
  } catch (e) {}
}
// Lock and a revoked device: the cached lists and their key are deleted (the next open asks the PC again).
async function cacheClear() {
  for (const t of FEED_TABS) { try { await kvSet("cache:" + t, null); } catch (e) {} }
  try { await kvSet("cacheKey", null); } catch (e) {}
  for (const f of Object.values(feeds)) f.forget();
}
const feeds = {};

// ---------- speed: time to first render and bytes per tab, kept on this phone (Dashboard > App speed) ----------
function perfNote(tab, kind, ms, bytes) {
  try {
    const p = JSON.parse(localStorage.getItem("perf") || "{}");
    const r = p[tab] || (p[tab] = {});
    r[kind + "_ms"] = Math.round(ms); if (bytes != null) r[kind + "_bytes"] = bytes; r.at = Date.now();
    localStorage.setItem("perf", JSON.stringify(p));
  } catch (e) {}
}

function dayGroup(t, now) {
  const start = new Date(now); start.setHours(0, 0, 0, 0);
  const s = start.getTime() / 1000;
  return t >= s ? "Today" : t >= s - 86400 ? "Yesterday" : t >= s - 6 * 86400 ? "This week" : "Older";
}
function isTyping(node) {
  return !!node && (node.dataset.dirty === "1" || node.contains(document.activeElement));
}
function place(box, nodes) {        // make box's children exactly `nodes`, moving only what's out of place
  nodes.forEach((n, i) => { if (box.children[i] !== n) box.insertBefore(n, box.children[i] || null); });
  while (box.children.length > nodes.length) box.lastElementChild.remove();
}

class Feed {
  // o: tab, root, fetch(params) -> page, card(item) -> node, sig(item), order(items) -> items, update(node, item),
  //    seenRule (items from before the last visit count as handled), noun, empty, onRender(feed)
  constructor(o) {
    Object.assign(this, { limit: 20, cacheMax: 60, noun: "items", empty: "Nothing here yet.", order: (x) => x,
                          sig: (x) => JSON.stringify(x), update: () => {}, onRender: () => {} }, o);
    this.items = new Map(); this.since = null; this.more = false; this.hiddenArchived = 0;
    this.showAll = false; this.showArchived = false; this.q = ""; this.results = null;
    this.nodes = new Map(); this.shown = new Set(); this.open_ = {}; this.expanded = new Set();
    this.loading = false; this.cacheRead = false; this.visitStamped = false;
    this.seenBefore = Number(localStorage.getItem("seen_" + this.tab) || 0);
    feeds[this.tab] = this;
    this.build();
  }
  build() {
    const r = this.root; r.textContent = "";
    const bar = el("div", "feedbar");
    this.qbox = el("input"); this.qbox.type = "search"; this.qbox.placeholder = "Search " + this.noun + "…";
    this.qbox.setAttribute("aria-label", "Search " + this.noun); this.qbox.enterKeyHint = "search";
    let timer = null;
    this.qbox.oninput = () => { clearTimeout(timer); timer = setTimeout(() => this.search(this.qbox.value.trim()), 450); };
    this.allBtn = el("button", "chip", "Show all"); this.allBtn.type = "button";
    this.allBtn.onclick = () => { this.showAll = !this.showAll; this.render(); };
    this.arcBtn = el("button", "chip", "Show archived"); this.arcBtn.type = "button";
    this.arcBtn.onclick = () => { this.showArchived = !this.showArchived; this.since = null; this.items = new Map(); this.more = false; this.refresh(); };
    bar.append(this.qbox, this.allBtn, this.arcBtn);
    this.statusEl = el("div", "feedstatus muted");
    this.pinBox = el("div", "pins"); this.listBox = el("div", "feedlist");
    this.moreBtn = el("button", "link older", "Show older"); this.moreBtn.type = "button"; this.moreBtn.hidden = true;
    this.moreBtn.onclick = () => this.older();
    this.foot = el("div", "feedfoot muted");
    r.append(bar, this.statusEl, this.pinBox, this.listBox, this.moreBtn, this.foot);
    if ("IntersectionObserver" in window) {
      new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting) && !this.moreBtn.hidden) this.older(); },
                               { rootMargin: "200px" }).observe(this.moreBtn);
    }
  }
  forget() { this.items = new Map(); this.since = null; this.more = false; this.results = null; this.cacheRead = true; this.nodes = new Map(); this.render(); }
  status(t) { this.statusEl.textContent = t || ""; this.statusEl.hidden = !t; }
  isDone(it) { return !!it._done || (this.seenRule && it._t <= this.seenBefore); }
  params(extra) {
    const p = { limit: this.limit };
    if (this.seenBefore) p.seen_before = this.seenBefore;
    if (this.showArchived) p.archived = true;
    return Object.assign(p, extra);
  }
  // The tab was opened: from the cache at once (first time), then only what changed.
  async open() {
    const t0 = performance.now();
    this.shown = new Set(); this.visitStamped = false;
    this.seenBefore = Number(localStorage.getItem("seen_" + this.tab) || 0);
    if (!this.cacheRead) {
      this.cacheRead = true;
      const c = await cacheGet(this.tab);
      if (c && !this.items.size) {
        for (const it of c.items || []) this.items.set(String(it.id), it);
        this.since = c.since || null; this.more = c.more !== false;
        this.render(); perfNote(this.tab, "cache", performance.now() - t0, null);
      }
    }
    if (!this.items.size) { this.render(); this.status("Loading…"); }
    else this.render();
    // Opening a tab never asks for Face ID by itself when it has saved items: they show, Refresh updates them.
    if (this.needsSession && this.items.size && typeof sessionLive === "function" && !sessionLive()) {
      this.status("Saved items. Tap Refresh to update (Face ID)."); return;
    }
    return this.refresh(t0);
  }
  async refresh(t0) {
    if (this.q) return this.search(this.q);
    const start = t0 || performance.now(), delta = !!this.since, had = this.items.size;
    try {
      const pg = await this.fetch(this.params(delta ? { since: this.since } : {}));
      if (!delta || pg.reset) { this.items = new Map(); this.more = !!pg.more; }
      for (const it of [...(pg.pinned || []), ...(pg.items || [])]) this.items.set(String(it.id), it);
      if (delta && pg.pin_ids) {
        const ids = new Set(pg.pin_ids.map(String));
        for (const it of this.items.values()) if (it._pin && !ids.has(String(it.id))) it._pin = false;
      }
      this.since = pg.now || null; this.hiddenArchived = pg.hidden_archived || 0;
      if (!this.visitStamped && pg.now) {      // this visit's time (the PC's clock): earlier items count as seen next visit
        this.visitStamped = true;
        try { localStorage.setItem("seen_" + this.tab, String(pg.now)); } catch (e) {}
      }
      this.status(""); this.render();
      perfNote(this.tab, delta ? "delta" : had ? "full" : "first", performance.now() - start, pg._bytes);
      this.save();
      return pg;
    } catch (e) { this.status(e.message); }
  }
  async older() {
    if (this.loading) return;
    const src = this.results ? this.results.items : [...this.items.values()].filter((i) => !i._pin);
    if (!src.length) return;
    this.loading = true; this.moreBtn.textContent = "Loading…";
    try {
      const before = Math.min(...src.map((i) => i._t));
      const pg = await this.fetch(this.params(this.results ? { q: this.q, before } : { before }));
      if (this.results) { this.results.items.push(...(pg.items || [])); this.results.more = !!pg.more; }
      else { for (const it of pg.items || []) this.items.set(String(it.id), it); this.more = !!pg.more; }
      this.render(); this.save();
    } catch (e) { this.status(e.message); }
    finally { this.loading = false; this.moreBtn.textContent = "Show older"; }
  }
  async search(q) {
    this.q = q;
    if (!q) { this.results = null; this.render(); return; }
    if (q.length < 2) return;
    this.status("Searching…");
    try {
      const pg = await this.fetch(this.params({ q }));
      if (this.q !== q) return;                       // a newer search is on its way
      this.results = { items: pg.items || [], more: !!pg.more, total: pg.total || 0 };
      this.status(""); this.render();
    } catch (e) { this.status(e.message); }
  }
  save() {
    if (this.showArchived) return;                     // the cache holds the normal view only
    const all = [...this.items.values()].sort((a, b) => b._t - a._t);
    const pins = all.filter((i) => i._pin), rest = all.filter((i) => !i._pin);
    const keep = pins.concat(rest.slice(0, this.cacheMax));
    cachePut(this.tab, { items: keep, since: this.since, more: this.more || rest.length > this.cacheMax, saved: Date.now() });
  }
  node(it, pinned) {
    const id = String(it.id), sig = this.sig(it) + (pinned ? "|p" : "");
    const have = this.nodes.get(id);
    if (have && (have.sig === sig || isTyping(have.node))) { this.update(have.node, it); return have.node; }
    const n = this.card(it);
    n.dataset.id = id;
    this.collapse(n, id, pinned);
    this.nodes.set(id, { sig, node: n });
    return n;
  }
  // Long items: 1-2 lines until tapped (buttons, links and text boxes inside keep working as usual).
  collapse(n, id, pinned) {
    const long = [...n.querySelectorAll(".text, .res, .draft, .now")].some((x) => (x.textContent || "").length > 120) ||
                 !!n.querySelector(".fb, ol, .draft");
    if (!long) return;
    const tog = el("button", "link more-toggle"); tog.type = "button";
    const set = (open) => { n.classList.toggle("collapsed", !open); tog.textContent = open ? "Less ▴" : "More ▾";
                            if (open) this.expanded.add(id); else this.expanded.delete(id); };
    set(this.expanded.has(id));
    tog.onclick = (ev) => { ev.stopPropagation(); set(n.classList.contains("collapsed")); };
    n.addEventListener("click", (ev) => {
      if (!n.classList.contains("collapsed") || ev.target.closest("button, a, textarea, input, select, summary")) return;
      set(true);
    });
    n.append(tog);
  }
  render() {
    const now = Date.now();
    const searching = !!this.results;
    let pins = [], rest;
    if (searching) rest = this.results.items.slice();
    else {
      const cut = now / 1000 - FEED_ARCHIVE_DAYS * 86400;
      const all = [...this.items.values()].filter((i) => this.showArchived || i._pin || i._t >= cut).sort((a, b) => b._t - a._t);
      pins = all.filter((i) => i._pin);
      rest = all.filter((i) => !i._pin);
    }
    let hidden = 0;
    if (!searching && !this.showAll) {
      rest = rest.filter((i) => {
        const keep = !this.isDone(i) || this.shown.has(String(i.id));
        if (!keep) hidden++;
        return keep;
      });
    }
    for (const i of rest) this.shown.add(String(i.id));
    rest = this.order(rest);
    // The page is changed only where something is new or moved: a card you're typing in keeps its focus.
    this.pinHead ||= el("h4", "pinhead");
    this.pinHead.textContent = "Needs you · " + pins.length;
    place(this.pinBox, pins.length ? [this.pinHead, ...pins.map((p) => this.node(p, true))] : []);
    const groups = {};
    for (const i of rest) (groups[dayGroup(i._gt || i._t, now)] ||= []).push(i);
    this.groupEls ||= {};
    const first = GROUPS.find((x) => groups[x]);
    const boxes = [];
    for (const g of GROUPS) {
      if (!groups[g]) continue;
      let d = this.groupEls[g];
      if (!d) {
        d = this.groupEls[g] = el("details", "day"); d.append(el("summary"));
        d.open = searching || g === "Today" || g === "Yesterday" || g === first;   // older days folded
        d.ontoggle = () => (this.open_[g] = d.open);
      } else if (this.open_[g] == null) d.open = searching || g === "Today" || g === "Yesterday" || g === first;
      d.firstChild.textContent = g + " · " + groups[g].length;
      place(d, [d.firstChild, ...groups[g].map((i) => this.node(i, false))]);
      boxes.push(d);
    }
    if (!rest.length && !pins.length) {
      this.emptyEl ||= el("p", "muted");
      this.emptyEl.textContent = searching ? "Nothing found." : hidden ? "All caught up." : this.empty;
      boxes.push(this.emptyEl);
    }
    place(this.listBox, boxes);
    // On tabs where everything before the last visit counts as handled, older pages would only be hidden ones:
    // Show older appears with Show all (or a search).
    this.moreBtn.hidden = !(searching ? this.results.more : this.more && (this.showAll || !this.seenRule));
    // footer + toggles
    const bits = [];
    if (searching) bits.push(this.results.total + " found (archived included)");
    else {
      if (hidden) bits.push(hidden + " handled hidden");
      if (this.hiddenArchived && !this.showArchived) bits.push(this.hiddenArchived + " archived (older than " + FEED_ARCHIVE_DAYS + " days)");
    }
    this.foot.textContent = bits.join(" · ");
    this.allBtn.textContent = this.showAll ? "Hide handled" : "Show all" + (hidden ? " (" + hidden + ")" : "");
    this.allBtn.classList.toggle("on", this.showAll);
    this.arcBtn.textContent = this.showArchived ? "Hide archived" : "Show archived";
    this.arcBtn.classList.toggle("on", this.showArchived);
    const keep = new Set([...pins, ...rest].map((i) => String(i.id)));
    for (const id of [...this.nodes.keys()]) if (!keep.has(id)) this.nodes.delete(id);
    this.onRender(this);
  }
}
