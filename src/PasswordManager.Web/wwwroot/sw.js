/* =====================================================================
   Dragon Vault — Service Worker (REQ-049, REQ-050, REQ-051)
   =====================================================================
   - Versioned cache: swap CACHE_VERSION on deploy to bust all caches
   - Network-first for navigation with offline shell fallback
   - Cache-first for static assets (CSS, JS, fonts, icons, WASM)
   - Network-only for authenticated API endpoints — NEVER cache
   ===================================================================== */

const CACHE_VERSION = 'dragon-vault-v2';
const CACHE_STATIC = `${CACHE_VERSION}-static`;

// Core shell assets to pre-cache on install.
// These represent the minimum set needed to render the navigation shell.
const PRECACHE_URLS = [
  '/',
  '/css/site.css',
  '/css/fonts.css',
  '/manifest.webmanifest',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon.png',
  '/icons/favicon-32.png',
  '/icons/favicon-16.png',
  '/fonts/Inter.woff2',
  '/fonts/JetBrainsMono-400.woff2',
  '/fonts/JetBrainsMono-500.woff2',
];

// Path prefixes that MUST never be cached (REQ-050).
// These receive network-only treatment.
const NEVER_CACHE_PREFIXES = [
  '/api/vault/',
  '/api/webauthn/',
  '/api/account/',
  '/signin-google',
];

// Static asset extensions eligible for cache-first strategy.
// These patterns match CSS, JS, fonts, icons, WASM, and images.
const STATIC_EXTENSIONS = /\.(css|js|mjs|wasm|woff2?|ttf|otf|png|svg|ico|webp|jpg|jpeg|gif)(\?.*)?$/i;

/* ---- Install: pre-cache core shell ---- */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_STATIC).then((cache) => {
      return cache.addAll(PRECACHE_URLS);
    })
  );
  // Activate immediately — don't wait for old tabs to close.
  self.skipWaiting();
});

/* ---- Activate: claim clients + purge old caches ---- */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    Promise.all([
      // Take control of all clients immediately (REQ-051).
      self.clients.claim(),
      // Delete any cache that doesn't match the current version.
      caches.keys().then((keys) => {
        return Promise.all(
          keys
            .filter((key) => key.startsWith('dragon-vault-') && key !== CACHE_STATIC)
            .map((key) => caches.delete(key))
        );
      }),
    ])
  );
});

/* ---- Fetch: route based on request type and URL ---- */
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Only handle same-origin requests.
  if (url.origin !== self.location.origin) return;

  const path = url.pathname;

  // ---- Network-only for authenticated API endpoints (REQ-050) ----
  if (NEVER_CACHE_PREFIXES.some((prefix) => path.startsWith(prefix))) {
    // No fallback — these endpoints are useless offline.
    // cache: 'no-store' bypasses the browser HTTP cache so PUT-then-GET
    // always returns the latest rowVersion (prevents spurious 412 on edits).
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  // ---- Navigation requests: network-first, fall back to offline shell ----
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstNavigation(request));
    return;
  }

  // ---- Static assets: cache-first (REQ-049) ----
  if (STATIC_EXTENSIONS.test(path)) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // ---- Everything else: network-first with cache fallback ----
  event.respondWith(networkFirst(request));
});

/* ---- Strategy: cache-first ---- */
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_STATIC);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // If both cache and network fail, return a simple fallback.
    return new Response('Resource unavailable', { status: 503 });
  }
}

/* ---- Strategy: network-first ---- */
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_STATIC);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response('Resource unavailable', { status: 503 });
  }
}

/* ---- Strategy: network-first for navigation with offline shell ---- */
async function networkFirstNavigation(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_STATIC);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Try cache first, then show offline shell (REQ-049).
    const cached = await caches.match(request);
    if (cached) return cached;

    // Offline shell: simple HTML message. The vault is a zero-knowledge
    // app — you can't do anything useful offline anyway.
    return new Response(
      `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Dragon Vault — Offline</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #000;
      color: #fff;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100dvh;
      text-align: center;
      padding: 2rem;
    }
    h1 { font-size: 1.75rem; font-weight: 540; margin-bottom: 1rem; }
    p { font-size: 1rem; font-weight: 320; opacity: 0.8; max-width: 24rem; line-height: 1.45; }
  </style>
</head>
<body>
  <h1>Dragon Vault</h1>
  <p>You're offline — the vault needs the network to unlock.</p>
</body>
</html>`,
      {
        status: 503,
        statusText: 'Service Unavailable',
        headers: new Headers({ 'Content-Type': 'text/html; charset=utf-8' }),
      }
    );
  }
}
