const CACHE_VERSION = "messis-pwa-v3";

const STATIC_CACHE =
    `${CACHE_VERSION}-static`;

const RUNTIME_CACHE =
    `${CACHE_VERSION}-runtime`;

const OFFLINE_URL =
    "/static/pwa/offline.html";

const PRECACHE_URLS = [
    OFFLINE_URL,
    "/static/pwa/icon-192.png",
    "/static/pwa/icon-512.png",
    "/static/pwa/offline-entry-queue.js",
    "/static/pwa/manifest.webmanifest"
];

self.addEventListener(
    "install",
    event => {
        event.waitUntil(
            caches
                .open(STATIC_CACHE)
                .then(cache =>
                    cache.addAll(
                        PRECACHE_URLS
                    )
                )
                .then(() =>
                    self.skipWaiting()
                )
        );
    }
);

self.addEventListener(
    "activate",
    event => {
        event.waitUntil(
            caches
                .keys()
                .then(keys =>
                    Promise.all(
                        keys
                            .filter(
                                key =>
                                    key !== STATIC_CACHE
                                    && key !== RUNTIME_CACHE
                            )
                            .map(
                                key =>
                                    caches.delete(key)
                            )
                    )
                )
                .then(() =>
                    self.clients.claim()
                )
        );
    }
);

function isSafeStaticRequest(request) {
    const url = new URL(
        request.url
    );

    return (
        request.method === "GET"
        && url.origin === self.location.origin
        && (
            url.pathname.startsWith(
                "/static/"
            )
            || url.pathname ===
                "/manifest.webmanifest"
        )
    );
}

async function cacheFirst(request) {
    const cached =
        await caches.match(request);

    if (cached) {
        return cached;
    }

    const response =
        await fetch(request);

    if (
        response
        && response.ok
    ) {
        const cache =
            await caches.open(
                RUNTIME_CACHE
            );

        cache.put(
            request,
            response.clone()
        );
    }

    return response;
}

async function networkFirstPage(request) {
    try {
        return await fetch(request);
    } catch (error) {
        const cached =
            await caches.match(request);

        if (cached) {
            return cached;
        }

        return caches.match(
            OFFLINE_URL
        );
    }
}

self.addEventListener(
    "fetch",
    event => {
        const request =
            event.request;

        if (
            request.method !== "GET"
        ) {
            return;
        }

        if (
            request.mode === "navigate"
        ) {
            event.respondWith(
                networkFirstPage(request)
            );

            return;
        }

        if (
            isSafeStaticRequest(request)
        ) {
            event.respondWith(
                cacheFirst(request)
            );
        }
    }
);

self.addEventListener(
    "message",
    event => {
        if (
            event.data
            && event.data.type
                === "SKIP_WAITING"
        ) {
            self.skipWaiting();
        }
    }
);
