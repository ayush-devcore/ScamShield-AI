const CACHE_VERSION = "scamshield-static-v1";
const SHELL_CACHE = "scamshield-shell-v1";
const SHELL_FILES = [
  "/",
  "/offline.html",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/icon-maskable-512.png",
  "/icons/apple-touch-icon.png",
];
const API_PREFIXES = ["/api/", "/auth/", "/scans/", "/dashboard", "/reports", "/notifications", "/preferences/", "/activity"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => cache.addAll(SHELL_FILES)),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys
        .filter((key) => key.startsWith("scamshield-") && ![SHELL_CACHE, CACHE_VERSION].includes(key))
        .map((key) => caches.delete(key)),
    )).then(() => self.clients.claim()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || request.headers.has("authorization")) return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) return;
  if (request.headers.get("accept")?.includes("application/json")) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(async () =>
        (await caches.match("/offline.html")) || Response.error(),
      ),
    );
    return;
  }

  const staticAsset = ["script", "style", "image", "font"].includes(request.destination)
    || url.pathname.startsWith("/privacy-tools/");
  if (!staticAsset) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_VERSION);
    const cached = await cache.match(request);
    if (cached) return cached;
    const response = await fetch(request);
    if (response.ok && response.type === "basic") {
      await cache.put(request, response.clone());
    }
    return response;
  })());
});
