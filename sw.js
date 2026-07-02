// Minimal service worker: cache the app shell so the PWA opens offline (and is installable).
// Web Push (iOS 16.4+ home-screen PWAs) can be added here later for the "enter a code" nudge —
// though the PWA never captures codes, push could surface activation results/alerts.
const CACHE = 'techtool-pwa-v14';
const SHELL = ['./', './index.html', './app.js', './webcrypto.js', './manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  // Network-first for our OWN files so new deploys show up on a normal reload; fall back to the
  // cached copy when offline (keeps the PWA installable/offline). Cross-origin (raw docs, the MQTT
  // broker, unpkg) is left to the network untouched. We refresh the cache on every successful GET.
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  // {cache:'no-store'} bypasses the browser HTTP cache (GitHub Pages sends max-age=600), so a
  // network-first hit is genuinely fresh — not a 10-minute-stale copy.
  e.respondWith(
    fetch(e.request, { cache: 'no-store' })
      .then((res) => { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {}); return res; })
      .catch(() => caches.match(e.request).then((r) => r || caches.match('./index.html')))
  );
});
