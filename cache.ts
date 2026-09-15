import { CACHE_TTL_SECONDS } from "./constants";

export async function cacheRequestData(key: Request, data: string, ttl: number = CACHE_TTL_SECONDS) {
  const cache = (caches as unknown as { default: Cache }).default;

  const response = new Response(data, {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${ttl}`,
    },
  });
  await cache.put(key, response);
}

export async function invalidateCache(key: Request) {
  try {
    const cache = (caches as unknown as { default: Cache }).default;
    await cache.delete(key);
  }
  catch (err) {
    console.error(`Failed to invalidate cache key='${key.url}'`, err);
  }
}
