// Retired worker. Replaces the old Tech Tool PWA service worker. It caches nothing, clears any
// old caches, unregisters itself, and reloads open clients so they follow the redirect in
// index.html to the new home. (ASCII-only comments: release tooling runs this through PS 5.1.)
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const ks = await caches.keys();
    await Promise.all(ks.map((k) => caches.delete(k)));
    try { await self.registration.unregister(); } catch (err) {}
    const cs = await self.clients.matchAll({ type: 'window' });
    cs.forEach((c) => { try { c.navigate(c.url); } catch (err) {} });
  })());
});
// No fetch handler: every request goes straight to the network.
