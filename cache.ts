const CACHE_TTL = 86400; // 24 hours

export async function cacheRequestData(key: Request, data: string) {
  const cache = (caches as unknown as { default: Cache }).default;

  const response = new Response(data, {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${CACHE_TTL}`,
    },
  });
  await cache.put(key, response);
}

export async function invalidateCache(key: Request) {
  const cache = (caches as unknown as { default: Cache }).default;
  await cache.delete(key);
}
