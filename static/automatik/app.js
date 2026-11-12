// Automatik phone app. Requests are encrypted to the PC with WebCrypto (ECDH P-256 -> HKDF-SHA256 ->
// AES-256-GCM) and signed: with this phone's passkey (Face ID) to unlock a session, then with that
// session's key (made here, private half non-extractable) until the PC ends it (30 min idle, 8 h max).
// Sending email always needs Face ID. The relay (this site) only stores ciphertext. Devices are added
// only with a code made on the PC; there is no other way.
"use strict";
const VERSION = "2026.11.11-2";
const RP_ID = "happyhacks.io";
const API = "/automatik/api";
const enc = new TextEncoder(), dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

// ---------- small helpers ----------
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
const hex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function bigB64(bytes) {           // base64 for large files without blowing the call stack
  let s = ""; const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) s += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
  return btoa(s);
}

// ---------- IndexedDB: keys and device record stay on this phone ----------
function idb() {
  return new Promise((ok, bad) => {
    const r = indexedDB.open("automatik", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("kv");
    r.onsuccess = () => ok(r.result); r.onerror = () => bad(r.error);
  });
}
async function kvGet(k) { const db = await idb(); return new Promise((ok) => { const r = db.transaction("kv").objectStore("kv").get(k); r.onsuccess = () => ok(r.result); r.onerror = () => ok(undefined); }); }
async function kvSet(k, v) { const db = await idb(); return new Promise((ok, bad) => { const t = db.transaction("kv", "readwrite"); t.objectStore("kv").put(v, k); t.oncomplete = ok; t.onerror = () => bad(t.error); }); }

// ---------- the box ----------
async function boxKey(myPrivate, pcPublicRaw) {
  const pc = await crypto.subtle.importKey("raw", pcPublicRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pc }, myPrivate, 256);
  const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("automatik box v1") },
                                 hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("to-pc") }, key, enc.encode(JSON.stringify(obj)));
  const out = new Uint8Array(12 + ct.byteLength); out.set(iv); out.set(new Uint8Array(ct), 12);
  return bigB64(out);
}
async function unseal(key, text) {
  const data = unb64(text);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(0, 12), additionalData: enc.encode("to-device") }, key, data.slice(12));
  return JSON.parse(dec.decode(pt));
}

// ---------- relay calls ----------
async function relay(path, opts, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;   // a phone being added has no token yet
  const r = await fetch(API + path, { ...opts, headers });
  if (r.status === 401) throw new Error("The token was refused.");
  if (r.status === 429) throw new Error("Too many wrong tokens; wait 15 minutes.");
  if (r.status === 413) throw new Error("That's too big to send.");
  if (!r.ok && r.status !== 404) throw new Error("The relay answered " + r.status + ".");
  return r.json();
}
async function postAndWait(msg, token, key, onStatus) {
  const { id } = await relay("/request", { method: "POST", body: JSON.stringify({ msg }) }, token);
  const started = Date.now();
  while (Date.now() - started < 16 * 60 * 1000) {
    await sleep(1500);
    const r = await relay("/result/" + id, { method: "GET" }, token);
    if (r.status === "done") {
      if (r.error) {
        const err = new Error(r.error === "refused" ? "The PC refused that request." :
                              r.error === "session_expired" ? "The session ended; unlock with Face ID." : r.error);
        err.code = r.error; throw err;
      }
      return unseal(key, r.box);
    }
    if (r.status === "gone") throw new Error("The request expired before the PC answered.");
    onStatus && onStatus(r.status);
  }
  throw new Error("The PC didn't answer in time. Is it on?");
}

// ---------- state ----------
let device = null;      // {id, credential, pcPublic (b64), name}
let token = null;
let theKey = null;      // AES key shared with the PC
let conversation = null;
let pendingFiles = [];
let session = null;     // {priv (non-extractable ECDSA key), started, last, idle, max}: kept in IndexedDB
let unlocking = null;

async function load() {
  device = await kvGet("device");
  token = await kvGet("token");
  const priv = await kvGet("boxPrivate");
  if (device && priv) theKey = await boxKey(priv, unb64(device.pcPublic));
  session = (await kvGet("session")) || null;
  if (!sessionLive()) session = null;
  conversation = localStorage.getItem("conversation") || newConversation();
}
function newConversation() { const c = "c" + hex(6); try { localStorage.setItem("conversation", c); } catch (e) {} return c; }

// ---------- enrolment (only with a code from the PC) ----------
function enrolFrom(text) {
  const m = String(text || "").trim().match(/#enroll=([A-Z0-9]{10})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  return m ? { code: m[1], challenge: m[2], pcPublic: m[3] } : null;
}
function enrolFromHash() { return location.hash.startsWith("#enroll=") ? enrolFrom(location.hash) : null; }
// The Home Screen app has its own storage on iOS, so a link opened in the browser can't set it up:
// the link from the PC can be pasted here instead (same single-use code, nothing else changes).
function showEnrolForm(e) {
  $("setup-none").hidden = true; $("setup-form").hidden = false;
  $("setup-form").onsubmit = async (ev) => { ev.preventDefault(); try { await enrol(e); } catch (err) { $("setup-msg").textContent = err.message; } };
}
async function enrol(e) {
  const name = $("dev-name").value.trim() || "phone";
  const tok = $("dev-token").value;
  const say = (t) => ($("setup-msg").textContent = t);
  say("Creating a passkey…");
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: RP_ID, name: "Automatik" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "automatik-" + name, displayName: "Automatik (" + name + ")" },
    challenge: unb64url(e.challenge),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
    attestation: "none", timeout: 120000 } });
  const resp = cred.response;
  if (!resp.getPublicKey || resp.getPublicKeyAlgorithm() !== -7) throw new Error("This phone's passkeys aren't supported (needs iOS 16+).");
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const boxPublic = await crypto.subtle.exportKey("raw", pair.publicKey);
  const pcPublic = unb64url(e.pcPublic);
  const key = await boxKey(pair.privateKey, pcPublic);
  const data = { code: e.code, token: tok, name, passkey: {
    id: cred.id, alg: -7, publicKey: b64url(resp.getPublicKey()),
    clientDataJSON: b64url(resp.clientDataJSON), authenticatorData: b64url(resp.getAuthenticatorData()) } };
  say("Sending to the PC (it must be on)…");
  const out = await postAndWait({ enroll: { box_public: b64(boxPublic), box: await seal(key, data) } }, tok, key, (s) => say("PC status: " + s + "…"));
  if (out.type !== "enrolled") throw new Error("The PC didn't accept this phone.");
  await kvSet("boxPrivate", pair.privateKey);
  if (!out.token && !tok) throw new Error("The PC didn't send a token; type the token you set on the PC.");
  await kvSet("token", out.token || tok);
  await kvSet("device", { id: out.device, credential: cred.id, pcPublic: b64(pcPublic), name: out.name });
  history.replaceState(null, "", "/automatik/");
  await load();
  show("chat");
  addMsg("ai", "This phone is set up. Try a quick button above.");
}

// ---------- a signed request ----------
// Face ID (passkey) for: opening a session, Approve, "Send emails at once". Everything else is signed
// with the session key; if the PC says the session ended, Face ID unlocks a new one and it's sent again.
const SESSION_CONTEXT = "automatik session v1\n";
const needsFaceId = (type, body) => type === "approve" || type === "session" || (type === "chat" && body && body.mode === "send_now");
function sessionLive() {
  if (!session || !session.priv) return false;
  const now = Date.now(), margin = 60000;     // the PC's clock decides; end a minute early here
  return now - session.last < session.idle * 1000 - margin && now - session.started < session.max * 1000 - margin;
}
async function sendSigned(type, body, sess, onStatus) {
  const payload = JSON.stringify({ v: 1, id: hex(6), ts: Date.now(), nonce: hex(16), token, type, body });
  let inner;
  if (sess) {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, sess.priv, enc.encode(SESSION_CONTEXT + payload));
    inner = { payload, session_sig: b64url(sig) };
  } else {
    const challenge = await crypto.subtle.digest("SHA-256", enc.encode(payload));
    const a = await navigator.credentials.get({ publicKey: { challenge, rpId: RP_ID, userVerification: "required", timeout: 120000,
      allowCredentials: [{ type: "public-key", id: unb64url(device.credential) }] } });
    inner = { payload, assertion: { clientDataJSON: b64url(a.response.clientDataJSON),
              authenticatorData: b64url(a.response.authenticatorData), signature: b64url(a.response.signature) } };
  }
  const box = await seal(theKey, inner);
  return postAndWait({ device: device.id, box }, token, theKey, onStatus);
}
async function dropSession() { session = null; try { await kvSet("session", null); } catch (e) {} renderLock(); }
async function unlock(onStatus) {
  if (unlocking) return unlocking;           // two requests at once: one Face ID
  unlocking = (async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    const r = await sendSigned("session", { key: b64(raw) }, null, onStatus);
    if (r.type !== "session") throw new Error("The PC didn't open a session.");
    const now = Date.now();
    session = { priv: pair.privateKey, started: now, last: now, idle: r.idle_s, max: r.max_s };
    try { await kvSet("session", session); } catch (e) {}
    renderLock();
  })().finally(() => (unlocking = null));
  return unlocking;
}
async function lockNow() {
  const s = session; await dropSession();
  if (s && s.priv) { try { await sendSigned("end_session", {}, s); } catch (e) {} }   // the PC forgets it too
}
async function call(type, body, onStatus, onFaceId) {
  if (needsFaceId(type, body)) { onFaceId && onFaceId(); return sendSigned(type, body, null, onStatus); }
  for (let attempt = 0; ; attempt++) {
    if (!sessionLive()) { onFaceId && onFaceId(); await unlock(onStatus); }
    try {
      const r = await sendSigned(type, body, session, onStatus);
      if (session) { session.last = Date.now(); kvSet("session", session).catch(() => {}); }
      renderLock();
      return r;
    } catch (e) {
      if (e.code === "session_expired" && attempt === 0) { await dropSession(); continue; }   // e.g. the PC restarted
      if (e.code === "passkey_needed") { onFaceId && onFaceId(); return sendSigned(type, body, null, onStatus); }
      throw e;
    }
  }
}
function renderLock() {
  const b = $("lock"); if (!b) return;
  const live = sessionLive();
  b.textContent = live ? "🔓" : "🔒";
  b.title = live ? "Unlocked: tap to lock (Face ID again next time)" : "Locked: tap to unlock with Face ID";
  b.setAttribute("aria-label", b.title);
  b.classList.toggle("open", live);
}

// ---------- chat ----------
// Quick options, two levels (user, 2026-11-10): area -> tool -> choice. An area with no tools shows "No tools yet".
const QUICK = [
  ["Syngenta", [
    ["Outlook", [["Today's meetings", "What meetings do I have today?"], ["Tomorrow", "What meetings do I have tomorrow?"],
                 ["Unread work mail", "Any unread work emails today?"], ["New email…", "Draft a work email to ", true]]],
    ["Ariba", [["My last 3 requests", "What's the status of my last 3 Ariba requests?"], ["Waiting on me", "Is anything waiting for my approval in Ariba?"],
               ["Find supplier…", "Is this a valid supplier: ", true]]],
    ["OneDrive", [["Recent files", "What are my most recent OneDrive files?"], ["Shared with me", "What files were shared with me recently?"],
                  ["Search files…", "Find the file ", true], ["Summarise a document…", "Summarise the document ", true]]],
    ["Alation", [["Find a table…", "In SmartMart, which table has ", true], ["What does a MIO mean…", "What does this MIO measure: ", true]]],
  ]],
  ["HappyHacks", [
    ["Mail", [["New mail today", "Any new email in my Happy Hacks mailbox today?"], ["Unread mail", "Any unread email in my Happy Hacks mailbox?"],
              ["Draft an email…", "Draft a Happy Hacks email to ", true]]],
  ]],
  ["Busy Beaver", []],
  ["Personal", [
    ["Family", [["Today", "What's on the family calendar today?"], ["This week", "What's on the family calendar this week?"],
                ["Shopping list", "What's on the shopping list?"]]],
  ]],
  ["Automatik", [
    ["Status", [["Is everything working?", "Is everything in Automatik working?"], ["Morning brief", "Show me today's morning brief."]]],
  ]],
];
// Quick options: ☰ in the header opens a menu: areas (Syngenta, HappyHacks, ...) expand to tools, tools to
// choices; one area and one tool open at a time. A choice sends at once, or fills the box when it needs more
// (those end in "…"). The menu closes on a choice, a tap outside it, or Escape.
function oneOpen(container, sec, level) {
  sec.addEventListener("toggle", () => {
    if (sec.open) container.querySelectorAll(":scope > details." + level + "[open]").forEach((d) => d !== sec && (d.open = false));
  });
}
function renderQuickMenu() {
  const menu = $("quick-menu"), btn = $("quick");
  for (const [area, tools] of QUICK) {
    const group = document.createElement("details"); group.className = "area";
    const gs = document.createElement("summary"); gs.textContent = area; group.append(gs);
    oneOpen(menu, group, "area");
    if (!tools.length) { const none = document.createElement("div"); none.className = "none"; none.textContent = "No tools yet"; group.append(none); }
    for (const [tool, items] of tools) {
      const sec = document.createElement("details"); sec.className = "tool";
      const sum = document.createElement("summary"); sum.textContent = tool; sec.append(sum);
      oneOpen(group, sec, "tool");
      addItems(sec, items);
      group.append(sec);
    }
    menu.append(group);
  }
  btn.onclick = (ev) => { ev.stopPropagation(); menu.hidden ? openQuick() : closeQuick(); };
  document.addEventListener("click", (ev) => { if (!menu.hidden && !menu.contains(ev.target)) closeQuick(); });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !menu.hidden) { closeQuick(); btn.focus(); } });
}
function addItems(sec, items) {
    for (const [label, text, fill] of items) {
      const it = document.createElement("button"); it.type = "button"; it.className = "item"; it.setAttribute("role", "menuitem");
      it.textContent = label;
      if (fill) { const h = document.createElement("span"); h.className = "hint"; h.textContent = " · you finish it"; it.append(h); }
      it.onclick = () => {
        closeQuick();
        show("chat");
        $("text").value = text;
        if (fill) { $("text").focus(); $("text").setSelectionRange(text.length, text.length); } else sendChat();
      };
      sec.append(it);
    }
}
function openQuick() {
  const menu = $("quick-menu");
  menu.hidden = false; $("quick").setAttribute("aria-expanded", "true");
  // first time: open the first area so the menu isn't just a list of closed headings
  const first = menu.querySelector("details.area"); if (first && !menu.querySelector("details.area[open]")) first.open = true;
}
function closeQuick() {
  $("quick-menu").hidden = true; $("quick").setAttribute("aria-expanded", "false");
}
// "0:42" while waiting; "1m 12s" once answered (measured on this phone, from send to final reply)
function clock(ms) { const s = Math.floor(ms / 1000); return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
function took(ms) {
  if (ms == null) return "";
  const s = Math.round(ms / 1000);
  return s < 60 ? s + "s" : Math.floor(s / 60) + "m " + String(s % 60).padStart(2, "0") + "s";
}
function durLabel(ms, err) { const t = document.createElement("div"); t.className = "dur"; t.textContent = (err ? "Failed after " : "Answered in ") + took(ms); return t; }
function addMsg(who, text, extra) {
  const d = document.createElement("div"); d.className = "msg " + who + (extra && extra.err ? " err" : "");
  d.textContent = text;
  if (extra && extra.files && extra.files.length) {
    const a = document.createElement("div"); a.className = "att"; a.textContent = "📎 " + extra.files.join(", "); d.append(a);
  }
  if (extra && extra.ms != null) d.append(durLabel(extra.ms, extra.err));
  $("log").append(d); d.scrollIntoView({ block: "end" });
  if (!(extra && extra.noSave)) saveHistory(who, text, extra && extra.ms, extra && extra.err);
  return d;
}
function saveHistory(who, text, ms, err) {
  try {
    const h = JSON.parse(localStorage.getItem("h_" + conversation) || "[]");
    h.push(ms != null ? [who, text, ms, !!err] : [who, text]); localStorage.setItem("h_" + conversation, JSON.stringify(h.slice(-100)));
  } catch (e) {}
}
function restoreHistory() {
  $("log").innerHTML = "";
  try { for (const [who, text, ms, err] of JSON.parse(localStorage.getItem("h_" + conversation) || "[]")) {
    const d = document.createElement("div"); d.className = "msg " + who + (err ? " err" : ""); d.textContent = text;
    if (ms != null) d.append(durLabel(ms, err));
    $("log").append(d); } } catch (e) {}
}
function draftCard(d) {
  const c = document.createElement("div"); c.className = "card";
  const h = document.createElement("h3"); h.textContent = "Email draft (" + (d.tool === "outlook" ? "Outlook" : "Happy Hacks") + ")";
  const dl = document.createElement("dl");
  for (const [k, v] of [["To", (d.to || []).join(", ")], ["Cc", (d.cc || []).join(", ")], ["Subject", d.subject || ""]]) {
    if (!v) continue; const dt = document.createElement("dt"); dt.textContent = k; const dd = document.createElement("dd"); dd.textContent = v; dl.append(dt, dd);
  }
  const act = document.createElement("div"); act.className = "actions";
  const ok = document.createElement("button"); ok.className = "primary"; ok.textContent = "Approve and send";
  const no = document.createElement("button"); no.className = "link"; no.textContent = "Cancel";
  const done = document.createElement("div"); done.className = "done";
  ok.onclick = async () => {
    ok.disabled = no.disabled = true; done.textContent = "Sending…";
    try { const r = await call("approve", { tool: d.tool, draft: d.draft, code: d.code });
          done.textContent = r.sent ? "Sent ✓" : "Not sent: " + (r.error || "unknown"); if (!r.sent) ok.disabled = no.disabled = false; }
    catch (e) { done.textContent = e.message; ok.disabled = no.disabled = false; }
  };
  no.onclick = async () => { ok.disabled = no.disabled = true; done.textContent = "Cancelled; the draft stays in Drafts.";
    try { await call("cancel", { tool: d.tool, draft: d.draft }); } catch (e) {} };
  act.append(ok, no); c.append(h, dl, act, done);
  const note = document.createElement("div"); note.className = "muted"; note.style.fontSize = "13px";
  note.textContent = "Check the full text in the reply above before approving."; c.append(note);
  $("log").append(c); c.scrollIntoView({ block: "end" });
}
async function readFiles() {
  const out = [];
  for (const f of pendingFiles) out.push({ name: f.name, type: f.type || "application/octet-stream", data: bigB64(new Uint8Array(await f.arrayBuffer())) });
  return out;
}
// ---------- recents: the last 50 requests and their replies, kept only on this phone ----------
const RECENTS_MAX = 50;
function readRecents() { try { return JSON.parse(localStorage.getItem("recents") || "[]"); } catch (e) { return []; } }
function writeRecents(list) { try { localStorage.setItem("recents", JSON.stringify(list.slice(0, RECENTS_MAX))); } catch (e) {} }
function addRecent(entry) { const list = readRecents(); list.unshift(entry); writeRecents(list); return entry.id; }
function finishRecent(id, reply, ms) {
  const list = readRecents(); const r = list.find((x) => x.id === id);
  if (r) { r.reply = reply; r.ms = ms; writeRecents(list); }
}
function replyText(reply) {
  if (!reply) return "No reply was received.";
  if (reply.error) return "Error: " + reply.error;
  const lines = [reply.text || "(no text)"];
  for (const d of reply.drafts || []) {
    const s = (reply.sends || []).find((x) => x.draft === d.draft);
    lines.push("\n✉ Draft: " + (d.subject || "(no subject)") + " to " + (d.to || []).join(", ") +
               (s ? (s.sent ? " (sent)" : " (not sent: " + (s.error || "") + ")") : " (needed Approve)"));
  }
  return lines.join("\n");
}
function openRecents() {
  const body = $("sheet-body"); body.innerHTML = "";
  const list = readRecents();
  if (!list.length) { body.textContent = "No requests yet."; }
  for (const r of list) {
    const row = document.createElement("div"); row.className = "recent";
    const head = document.createElement("button"); head.type = "button";
    const when = document.createElement("div"); when.className = "when";
    const t = document.createElement("span"); t.textContent = new Date(r.ts).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    when.append(t);
    if (r.files && r.files.length) { const f = document.createElement("span"); f.textContent = (r.files.some((n) => /^voice-note/.test(n)) ? "🎙 " : "📎 ") + r.files.length; when.append(f); }
    if (r.mode === "send_now") { const m = document.createElement("span"); m.textContent = "sent at once"; when.append(m); }
    if (!r.reply) { const m = document.createElement("span"); m.textContent = "no reply"; when.append(m); }
    if (r.ms != null) { const m = document.createElement("span"); m.textContent = "⏱ " + took(r.ms); when.append(m); }
    const what = document.createElement("div"); what.className = "what"; what.textContent = r.text || "(attachment only)";
    head.append(when, what);
    const acts = document.createElement("div"); acts.className = "acts"; acts.hidden = true;
    const view = document.createElement("div"); view.className = "reply-view"; view.hidden = true; view.textContent = replyText(r.reply);
    const again = document.createElement("button"); again.type = "button"; again.className = "primary"; again.textContent = "Send again";
    const show = document.createElement("button"); show.type = "button"; show.className = "link"; show.textContent = "View response";
    again.onclick = () => resend(r);
    show.onclick = () => { view.hidden = !view.hidden; show.textContent = view.hidden ? "View response" : "Hide response"; };
    acts.append(again, show);
    head.onclick = () => { const open = acts.hidden; body.querySelectorAll(".acts").forEach((a) => (a.hidden = true));
                           body.querySelectorAll(".reply-view").forEach((v) => (v.hidden = true));
                           acts.hidden = !open; };
    row.append(head, acts, view); body.append(row);
  }
  $("sheet").hidden = false; $("recents").setAttribute("aria-expanded", "true");
}
function closeRecents() { $("sheet").hidden = true; $("recents").setAttribute("aria-expanded", "false"); }
function resend(r) {
  // Never repeats a send by itself: a repeat always goes in the normal mode, so any email comes back as a
  // draft card to Approve again. Attachments aren't kept here; the user re-attaches them if needed.
  if (r.mode === "send_now" && !confirm("This request sent email at once last time. Send it again? Any email will come back as a draft to approve, not be sent at once.")) return;
  if (r.files && r.files.length && !confirm("The attachments (" + r.files.join(", ") + ") aren't kept on the phone. Send the text again without them?")) return;
  closeRecents();
  show("chat");
  $("send-now").checked = false;
  $("text").value = r.text || "";
  if ($("text").value) sendChat();
}

async function sendChat(ev) {
  ev && ev.preventDefault();
  const text = $("text").value.trim();
  if (!text && !pendingFiles.length) return;
  const files = pendingFiles.map((f) => f.name);
  const recentId = addRecent({ id: hex(6), ts: Date.now(), text, files, mode: $("send-now").checked ? "send_now" : "approve", conversation });
  addMsg("me", text || "(attachment)", { files });
  $("text").value = ""; $("send").disabled = true;
  const t0 = Date.now();
  let status = "Sending…";
  const wait = addMsg("ai", status + " 0:00", { noSave: true });
  const tick = setInterval(() => (wait.textContent = status + " " + clock(Date.now() - t0)), 1000);
  try {
    const attachments = await readFiles();
    pendingFiles = []; renderFiles();
    const mode = $("send-now").checked ? "send_now" : "approve";
    const r = await call("chat", { text, conversation, attachments, mode }, (s) => (status = s === "working" ? "Working…" : "Waiting for the PC…"),
                         () => (status = "Waiting for Face ID…"));
    clearInterval(tick); wait.remove();
    const ms = Date.now() - t0;
    finishRecent(recentId, { text: r.text, error: r.error, drafts: r.drafts, sends: r.sends }, ms);
    if (r.error) addMsg("ai", r.error, { err: true, ms });
    else {
      addMsg("ai", r.text || "(no text)", { ms });
      for (const d of r.drafts || []) {
        const sent = (r.sends || []).find((s) => s.draft === d.draft);
        if (sent) addMsg("ai", sent.sent ? "Sent: " + (d.subject || "email") : "Not sent: " + (sent.error || ""), { err: !sent.sent });
        else draftCard(d);
      }
    }
  } catch (e) {
    clearInterval(tick); wait.remove();
    const ms = Date.now() - t0;
    finishRecent(recentId, { error: e.message }, ms); addMsg("ai", e.message, { err: true, ms });
  }
  finally { $("send").disabled = false; $("send-now").checked = false; }
}
function renderFiles() {
  const box = $("files"); box.innerHTML = "";
  pendingFiles.forEach((f, i) => {
    const s = document.createElement("span"); s.className = "file"; s.textContent = f.name + " ";
    const x = document.createElement("button"); x.type = "button"; x.textContent = "✕"; x.setAttribute("aria-label", "Remove " + f.name);
    x.onclick = () => { pendingFiles.splice(i, 1); renderFiles(); };
    s.append(x); box.append(s);
  });
}
function addFiles(list) {
  for (const f of list) {
    if (pendingFiles.length >= 5) { alert("At most 5 attachments per message."); break; }
    if (f.size > 25 * 1024 * 1024) { alert(f.name + " is larger than 25 MB."); continue; }
    pendingFiles.push(f);
  }
  renderFiles();
}
let recorder = null;
async function toggleMic() {
  if (recorder) { recorder.stop(); return; }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const chunks = []; recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (e) => chunks.push(e.data);
    recorder.onstop = () => {
      stream.getTracks().forEach((t) => t.stop());
      const type = recorder.mimeType || "audio/mp4"; recorder = null; $("mic").classList.remove("rec");
      const ext = type.includes("webm") ? "webm" : "m4a";
      addFiles([new File(chunks, "voice-note." + ext, { type: type.split(";")[0] })]);
    };
    recorder.start(); $("mic").classList.add("rec");
  } catch (e) { alert("Couldn't use the microphone: " + e.message); }
}

// ---------- dashboard and alerts ----------
async function loadDash() {
  const body = $("dash-body"); body.textContent = "Loading…";
  try {
    const d = await call("dashboard", {});
    body.innerHTML = "";
    const stats = document.createElement("div");
    for (const [k, v] of [["Paused", d.paused ? "yes" : "no"], ["Emails sent today", d.sends_today], ["Devices", (d.devices || []).length]]) {
      const s = document.createElement("span"); s.className = "stat"; const b = document.createElement("b"); b.textContent = v; s.append(b, k); stats.append(s);
    }
    body.append(stats);
    const t = document.createElement("table");
    t.innerHTML = "<thead><tr><th>Time</th><th>Request</th><th>Result</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const r of d.requests || []) {
      const tr = document.createElement("tr");
      for (const v of [String(r.ts || "").replace("T", " ").slice(5, 16), (r.type || "") + " " + (r.action || ""), (r.result || "") + (r.summary ? " · " + r.summary : "")]) {
        const td = document.createElement("td"); td.textContent = v; tr.append(td);
      }
      tb.append(tr);
    }
    t.append(tb); body.append(t);
  } catch (e) { body.textContent = e.message; }
}
async function loadAlerts(show) {
  if (!token) return;
  try {
    const { alerts } = await relay("/alerts", { method: "GET" }, token);
    const seen = Number(localStorage.getItem("alertsSeen") || 0);
    $("alertdot").hidden = !alerts.some((a) => a.created > seen);
    const pattySeen = Number(localStorage.getItem("pattySeen") || 0);
    $("pattydot").hidden = !alerts.some((a) => a.created > pattySeen && /^Patty/.test(a.text));
    if (show) {
      const box = $("alerts-body"); box.innerHTML = "";
      if (!alerts.length) box.textContent = "No alerts.";
      for (const a of alerts) {
        const d = document.createElement("div"); d.className = "alert " + a.level;
        d.textContent = new Date(a.created * 1000).toLocaleString() + " · " + a.text; box.append(d);
      }
      if (alerts[0]) localStorage.setItem("alertsSeen", String(alerts[0].created));
      $("alertdot").hidden = true;
    }
  } catch (e) {}
}
// ---------- Patty (assistant) ----------
const KIND_LABEL = { info: "For you", suggestion: "Suggestion", draft: "Draft idea", question: "Question", budget: "Budget", report: "Day report", reply: "Patty", message: "You" };
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function money(v) { return "$" + Number(v || 0).toFixed(2); }
// Refreshes update the list in place: a post already shown keeps its card (and whatever you're typing in it);
// only new or changed posts get a new card. A card you've typed in is never replaced until you send or clear it.
const pattyCards = new Map();          // post id -> { sig, node }
function postSig(p) { const { seen, feedback, ...rest } = p; return JSON.stringify(rest); }
function isTyping(node) {
  return !!node && (node.dataset.dirty === "1" || node.contains(document.activeElement));
}
async function loadPatty() {
  const body = $("patty-body");
  const first = !pattyCards.size;
  if (first) body.textContent = "Loading…";
  try {
    const d = await call("patty", {});
    if (d.error) { if (first) body.textContent = d.error; return; }
    const b = d.budget || {};
    $("patty-budget").textContent = b.patty_weekly_cap_usd != null
      ? "This week " + money(b.spent_week_usd) + " of " + money(b.patty_weekly_cap_usd) + " (" + Math.round(b.week_used_pct || 0) + "%) · today " + money(b.spent_today_usd) + " · " + d.prepared + " answers ready"
      : "";
    const posts = d.posts || [];
    // A message and Patty's reply read as one thread: the reply right under the message it answers.
    const replies = {}, order = [];
    for (const p of posts) if (p.kind === "reply" && p.reply_to) replies[p.reply_to] = p;
    for (const p of posts) {
      if (p.kind === "reply" && p.reply_to && posts.some((m) => m.id === p.reply_to)) continue;
      order.push(p);
      if (replies[p.id]) order.push(replies[p.id]);
    }
    const nodes = order.map((p) => {
      const have = pattyCards.get(p.id), sig = postSig(p);
      if (have && (have.sig === sig || isTyping(have.node))) {
        have.node.classList.toggle("unread", !p.seen && p.kind !== "message");
        return have.node;
      }
      const node = postCard(p);
      pattyCards.set(p.id, { sig, node });
      return node;
    });
    const keep = new Set(order.map((p) => p.id));
    for (const id of [...pattyCards.keys()]) if (!keep.has(id)) pattyCards.delete(id);
    if (!posts.length) nodes.push(el("p", "muted", "Nothing from Patty yet. She posts here as she learns your routine."));
    // Put the nodes in order, touching the page only where something moved or is new.
    if (body.firstChild && body.firstChild.nodeType === 3) body.textContent = "";
    nodes.forEach((n, i) => { if (body.children[i] !== n) body.insertBefore(n, body.children[i] || null); });
    while (body.children.length > nodes.length) body.lastElementChild.remove();
    for (const t of [...body.childNodes]) if (t.nodeType === 3) t.remove();
    const unseen = posts.filter((p) => !p.seen).map((p) => p.id);
    if (unseen.length) call("patty_seen", { ids: unseen }).catch(() => {});
    $("pattydot").hidden = true;
    try { localStorage.setItem("pattySeen", String(Date.now() / 1000)); } catch (e) {}
    return posts;
  } catch (e) { if (first) body.textContent = e.message; }
}
// Ask Patty directly: the PC wakes her at once; she usually answers within a minute or two. Poll a few minutes.
async function askPatty(ev) {
  ev.preventDefault();
  const t = $("patty-text"), wait = $("patty-wait"), btn = $("patty-send");
  const text = t.value.trim();
  if (!text) return;
  btn.disabled = true; wait.hidden = false; wait.textContent = "Sending…";
  try {
    const r = await call("patty_message", { text });
    if (r.error) throw new Error(r.error);
    t.value = "";
    const id = r.message && r.message.id;
    wait.textContent = "Sent. Patty is looking at it; her answer appears here (usually within a couple of minutes).";
    await loadPatty();
    for (let i = 0; i < 20 && id; i++) {
      await new Promise((ok) => setTimeout(ok, 15000));
      if ($("patty").hidden) break;
      const posts = await loadPatty();
      if (posts && posts.some((p) => p.reply_to === id)) { wait.hidden = true; break; }
    }
    if (!wait.hidden) wait.textContent = "Patty hasn't answered yet. She will reply here; tap Refresh later.";
  } catch (e) { wait.textContent = e.message; }
  finally { btn.disabled = false; }
}
function postCard(p) {
  if (p.kind === "message") {
    const m = el("div", "post mine");
    const meta = el("div", "meta");
    meta.append(el("span", "kind", p.from === "supervisor" ? "Via Supervisor" : "You"),
                el("span", null, new Date(p.ts).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" })));
    if (!p.answered) meta.append(el("span", null, "waiting for Patty"));
    m.append(meta, el("div", "text", p.text || ""));
    return m;
  }
  const c = el("div", "post" + (p.kind === "reply" ? " reply" : "") + (p.seen ? "" : " unread") + (p.urgent ? " urgent" : ""));
  const meta = el("div", "meta");
  meta.append(el("span", "kind", KIND_LABEL[p.kind] || p.kind),
              el("span", null, new Date(p.ts).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" })));
  if (p.urgent) meta.append(el("span", null, "urgent"));
  c.append(meta, el("h3", null, p.title), el("div", "text", p.text || ""));
  if (p.draft) {
    const d = p.draft, lines = [];
    if (d.account) lines.push("From: " + (d.account === "outlook" ? "Outlook (Syngenta)" : "Happy Hacks"));
    if (d.to && d.to.length) lines.push("To: " + d.to.join(", "));
    if (d.cc && d.cc.length) lines.push("Cc: " + d.cc.join(", "));
    if (d.subject) lines.push("Subject: " + d.subject);
    c.append(el("div", "draft", lines.join("\n") + "\n\n" + (d.body || "")));
  }
  if (p.ask) {
    // The user confirms: the request lands in the composer; they check it and tap Send. The Supervisor then
    // makes the real draft, which still needs their Approve.
    const go = el("button", "primary", "Send to Supervisor"); go.type = "button";
    go.onclick = () => { $("text").value = p.ask; show("chat"); $("text").focus(); $("text").dispatchEvent(new Event("input")); };
    const row = el("div", "fb");
    row.append(go, el("span", "muted", "You check it, then tap ➤. The Supervisor makes the draft for your approval."));
    c.append(row);
  }
  const fb = p.feedback || {};
  const row = el("div", "fb");
  const note = el("textarea"); note.rows = 2; note.maxLength = 1000;
  note.placeholder = p.kind === "question" ? "Your answer…" : "Tell Patty (optional)…";
  note.value = fb.text || "";
  note.oninput = () => { c.dataset.dirty = note.value.trim() !== (fb.text || "").trim() ? "1" : ""; };
  const up = el("button", "icon" + (fb.rating === "up" ? " on" : ""), "👍"); up.type = "button"; up.setAttribute("aria-label", "Helpful");
  const down = el("button", "icon" + (fb.rating === "down" ? " on" : ""), "👎"); down.type = "button"; down.setAttribute("aria-label", "Not needed right now");
  const send = el("button", "link", p.kind === "question" ? "Send answer" : "Send note"); send.type = "button";
  const given = el("div", "given", fb.ts ? "Sent " + new Date(fb.ts).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" }) : "");
  let rating = fb.rating || null;
  async function save(r) {
    if (r !== undefined) rating = rating === r ? null : r;
    given.textContent = "Sending…";
    try {
      const res = await call("patty_feedback", { id: p.id, rating, text: note.value.trim() });
      if (res.error) throw new Error(res.error);
      up.classList.toggle("on", rating === "up"); down.classList.toggle("on", rating === "down");
      given.textContent = "Thanks, Patty got it.";
      delete c.dataset.dirty;
    } catch (e) { given.textContent = e.message; }
  }
  up.onclick = () => save("up"); down.onclick = () => save("down"); send.onclick = () => save(undefined);
  if (p.kind !== "report" && p.kind !== "budget") row.append(up, down);
  row.append(note, send);
  c.append(row, given);
  return c;
}

// ---------- notifications (Web Push sent by the PC) ----------
const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const standalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
async function renderNotify() {
  const box = $("notify-box"); box.hidden = false;
  const msg = $("notify-msg"), on = $("notify-on"), off = $("notify-off");
  if (!pushSupported()) {
    msg.textContent = standalone() ? "This phone doesn't support notifications for web apps (iOS 16.4 or later is needed)."
      : "On iPhone, notifications work in the Home Screen app: Share → Add to Home Screen, open it from there, then turn them on.";
    on.hidden = true; off.hidden = true; return;
  }
  if (Notification.permission === "denied") {
    msg.textContent = "Notifications are blocked for this app. Allow them in iPhone Settings → Notifications → Automatik.";
    on.hidden = true; off.hidden = true; return;
  }
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  msg.textContent = sub ? "On: Patty's posts and alerts arrive as notifications (no email or calendar details in them)."
    : "Get a notification when Patty posts something or an alert comes in.";
  on.hidden = !!sub; off.hidden = !sub;
}
async function notifyOn() {
  const msg = $("notify-msg");
  try {
    const perm = await Notification.requestPermission();    // first, straight from the tap (iOS requires it)
    if (perm !== "granted") { msg.textContent = "Notifications weren't allowed."; return; }
    msg.textContent = "Turning on…";
    let key = await kvGet("pushKey");
    if (!key) {
      const r = await call("push_key", {});
      if (!r.key) throw new Error(r.error || "the PC didn't send its key");
      key = r.key; await kvSet("pushKey", key);
    }
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64url(key) });
    const r = await call("push_subscribe", { subscription: sub.toJSON() });
    if (r.error) throw new Error(r.error);
    await renderNotify();
    if (r.test_sent) msg.textContent += " A test notification is on its way.";
  } catch (e) { msg.textContent = "Couldn't turn them on: " + e.message; }
}
async function notifyOff() {
  try {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) { await call("push_unsubscribe", { endpoint: sub.endpoint }).catch(() => {}); await sub.unsubscribe(); }
  } catch (e) {}
  renderNotify();
}

async function pcStatus() {
  if (!token) return;
  try { const s = await relay("/status", { method: "GET" }, token);
        $("pc").textContent = s.pc_online ? "PC connected" : "PC offline"; $("pc").className = "pc " + (s.pc_online ? "on" : "off"); }
  catch (e) { $("pc").textContent = ""; }
}

// ---------- tabs, updates, start ----------
function show(tab) {
  for (const id of ["setup", "chat", "patty", "dash", "alerts"]) $(id).hidden = id !== tab;
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  if (tab === "alerts") loadAlerts(true);
  if (tab === "patty" && !$("patty-body").dataset.loaded) { $("patty-body").dataset.loaded = "1"; loadPatty(); }
  if (tab === "dash") renderNotify().catch(() => {});
}
async function watchUpdates() {
  if (!("serviceWorker" in navigator)) return;
  const reg = await navigator.serviceWorker.register("/automatik/sw", { scope: "/automatik/" });
  const offer = (w) => { $("update").hidden = false; $("update-ver").textContent = "new version";
    $("update-apply").onclick = () => w.postMessage("apply"); };
  if (reg.waiting) offer(reg.waiting);
  reg.addEventListener("updatefound", () => { const w = reg.installing;
    w.addEventListener("statechange", () => { if (w.state === "installed" && navigator.serviceWorker.controller) offer(w); }); });
  let reloading = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => { if (!reloading) { reloading = true; location.reload(); } });
}
document.addEventListener("DOMContentLoaded", async () => {
  await load();
  document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => device && show(b.dataset.tab)));
  const e = enrolFromHash();
  if (!device) {
    show("setup");
    if (e) showEnrolForm(e);
    $("paste-form").onsubmit = (ev) => { ev.preventDefault();
      const p = enrolFrom($("paste-link").value);
      if (p) showEnrolForm(p); else $("paste-msg").textContent = "That isn't an enrolment link from the PC. Copy the whole link it gave you."; };
  } else {
    $("quick-wrap").hidden = false; $("recents").hidden = false; $("lock").hidden = false;   // header buttons, once this phone is set up
    renderLock(); setInterval(renderLock, 30000);
    $("lock").onclick = async () => {
      if (sessionLive()) return lockNow();
      try { await unlock(); } catch (e) { if (e.name !== "NotAllowedError") alert(e.message); }
    };
    const want = (location.hash.match(/^#tab=(\w+)/) || [])[1];
    show(["patty", "dash", "alerts"].includes(want) ? want : "chat"); renderQuickMenu(); restoreHistory();
    if (want) history.replaceState(null, "", location.pathname);
    if ("serviceWorker" in navigator) navigator.serviceWorker.addEventListener("message", (ev) => { if (ev.data && ev.data.tab) show(ev.data.tab); });
    $("patty-refresh").onclick = loadPatty;
    $("patty-ask").onsubmit = askPatty;
    $("notify-on").onclick = notifyOn; $("notify-off").onclick = notifyOff;
    $("recents").onclick = (ev) => { ev.stopPropagation(); openRecents(); };
    $("sheet-close").onclick = closeRecents;
    $("sheet").onclick = (ev) => { if (ev.target === $("sheet")) closeRecents(); };
    document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !$("sheet").hidden) closeRecents(); });
    $("composer").onsubmit = sendChat;
    $("text").addEventListener("keydown", (ev) => { if (ev.key === "Enter" && !ev.shiftKey && !matchMedia("(pointer: coarse)").matches) sendChat(ev); });
    $("attach").onclick = () => $("file-input").click();
    $("file-input").onchange = (ev) => { addFiles(ev.target.files); ev.target.value = ""; };
    $("mic").onclick = toggleMic;
    $("new-chat").onclick = () => { conversation = newConversation(); restoreHistory(); };
    $("dash-refresh").onclick = loadDash;
    pcStatus(); loadAlerts(false);
    setInterval(pcStatus, 30000); setInterval(() => loadAlerts(false), 60000);
  }
  watchUpdates().catch(() => {});
});
