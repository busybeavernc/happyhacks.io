// Automatik app service worker. The installed app runs the version it has cached; a new version is
// downloaded in the background and used only after the user taps "Install update" (it waits until
// then). API calls (/automatik/api/...) are never cached. Bump CACHE with every app release.
"use strict";
const CACHE = "automatik-2026.11.10-1";

async function fillCache() {
  const c = await caches.open(CACHE);
  const page = await fetch("/automatik/", { cache: "no-store" });
  if (!page.ok) throw new Error("app page " + page.status);
  const html = await page.clone().text();
  await c.put("/automatik/", page);
  // the page's own script and stylesheet (versioned URLs), and the manifest
  const urls = [...html.matchAll(/(?:src|href)="(\/(?:static\/automatik\/[^"]+|automatik\/manifest\.webmanifest))"/g)].map((m) => m[1]);
  await c.addAll(urls);
}

self.addEventListener("install", (e) => e.waitUntil(fillCache()));   // no skipWaiting(): the page asks the user first
self.addEventListener("message", (e) => { if (e.data === "apply") self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/automatik/api/")) return;
  const isPage = e.request.mode === "navigate" && url.pathname.startsWith("/automatik");
  if (!isPage && !url.pathname.startsWith("/static/automatik/") && url.pathname !== "/automatik/manifest.webmanifest") return;
  // cache first: the approved version; the network only when it isn't cached yet
  e.respondWith(caches.open(CACHE).then((c) => c.match(isPage ? "/automatik/" : e.request, { ignoreSearch: false })
    .then((hit) => hit || fetch(e.request))));
});
