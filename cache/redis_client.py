"""
Redis client with automatic reconnection and graceful fallback.
If Redis is unavailable, the app still works — just uncached.
"""
import redis
import json
import logging

from config import REDIS_URL

logger = logging.getLogger(__name__)

# ── Connection ────────────────────────────────────────────
_redis_client = None


def _get_redis():
    """Lazy-init Redis connection with reconnect logic."""
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            logger.warning("Redis connection lost, reconnecting…")
            _redis_client = None

    if not REDIS_URL:
        logger.info("REDIS_URL not set — caching disabled")
        return None

    try:
        _redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        _redis_client.ping()
        logger.info("✅ Redis connected")
        return _redis_client
    except Exception as e:
        logger.error(f"❌ Redis connection failed: {e}")
        _redis_client = None
        return None


# ── Public helpers ────────────────────────────────────────

def get_cache(key: str):
    """Return cached JSON value or None."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if raw is not None:
            return json.loads(raw)
    except Exception as e:
        logger.error(f"Cache GET error [{key}]: {e}")
    return None


def set_cache(key: str, value, ttl: int = 60):
    """Store a JSON-serialisable value with TTL in seconds."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(key, ttl, json.dumps(value, default=str))
    except Exception as e:
        logger.error(f"Cache SET error [{key}]: {e}")


def invalidate(pattern: str):
    """Delete all keys matching a pattern (e.g. 'questions:*')."""
    r = _get_redis()
    if r is None:
        return
    try:
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match=pattern, count=100)
            if keys:
                r.delete(*keys)
            if cursor == 0:
                break
    except Exception as e:
        logger.error(f"Cache INVALIDATE error [{pattern}]: {e}")


def delete_key(key: str):
    """Delete a single cache key."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(key)
    except Exception as e:
        logger.error(f"Cache DELETE error [{key}]: {e}")


def incr_with_ttl(key: str, ttl: int) -> int:
    """Increment a counter, setting TTL on first creation. Returns new count."""
    r = _get_redis()
    if r is None:
        return 0
    try:
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, remaining = pipe.execute()
        if remaining == -1:  # key exists but no TTL (just created)
            r.expire(key, ttl)
        return count
    except Exception as e:
        logger.error(f"Cache INCR error [{key}]: {e}")
        return 0


def publish(channel: str, data: dict):
    """Publish a message to a Redis Pub/Sub channel."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.publish(channel, json.dumps(data, default=str))
    except Exception as e:
        logger.error(f"Pub/Sub PUBLISH error [{channel}]: {e}")


def get_pubsub():
    """Return a Redis PubSub object for subscribing."""
    r = _get_redis()
    if r is None:
        return None
    try:
        return r.pubsub()
    except Exception as e:
        logger.error(f"Pub/Sub GET error: {e}")
        return None


def redis_available() -> bool:
    """Check if Redis is reachable."""
    r = _get_redis()
    return r is not None
