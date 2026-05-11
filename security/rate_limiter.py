"""
Redis-based rate limiter using sliding window counters.
Protects auth endpoints, question creation, and forum chat from abuse.
Falls back to allowing requests if Redis is unavailable.
"""
from functools import wraps
from flask import request, jsonify
import logging

from cache.redis_client import incr_with_ttl
from cache.cache_keys import rate_limit as rl_key

logger = logging.getLogger(__name__)


def check_rate_limit(endpoint: str, identifier: str, max_attempts: int, window_seconds: int) -> bool:
    """
    Check if the identifier has exceeded the rate limit.
    Returns True if ALLOWED, False if RATE LIMITED.
    """
    key = rl_key(endpoint, identifier)
    count = incr_with_ttl(key, window_seconds)

    if count == 0:
        # Redis unavailable — fail open (allow)
        return True

    if count > max_attempts:
        logger.warning(f"Rate limit hit: {endpoint} by {identifier} ({count}/{max_attempts})")
        return False

    return True


def rate_limit(max_attempts: int, window_seconds: int, key_func=None):
    """
    Decorator for rate-limiting Flask endpoints.

    Args:
        max_attempts: Maximum allowed requests within the window.
        window_seconds: Window duration in seconds.
        key_func: Optional function(request) -> str to derive the rate limit key.
                  Defaults to client IP address.

    Usage:
        @app.route("/api/login", methods=["POST"])
        @rate_limit(5, 300)  # 5 attempts per 5 minutes
        def login():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if key_func:
                identifier = key_func(request)
            else:
                identifier = request.remote_addr or "unknown"

            endpoint_name = request.endpoint or f.__name__

            if not check_rate_limit(endpoint_name, identifier, max_attempts, window_seconds):
                return jsonify({
                    "success": False,
                    "message": "Too many requests. Please try again later.",
                }), 429

            return f(*args, **kwargs)
        return wrapped
    return decorator
