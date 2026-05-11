"""
Request timing middleware.
Logs every request's duration and flags slow requests (>500ms).
"""
import time
import logging
from flask import request, g

logger = logging.getLogger(__name__)


def register_timing_middleware(app):
    """
    Register before_request / after_request hooks on the Flask app.
    Call this once during app setup.
    """

    @app.before_request
    def start_timer():
        g.start_time = time.perf_counter()

    @app.after_request
    def log_request_time(response):
        if not hasattr(g, "start_time"):
            return response

        elapsed_ms = (time.perf_counter() - g.start_time) * 1000
        status = response.status_code
        method = request.method
        path = request.path

        # Skip noisy health checks and SSE streams
        if path in ("/health",) or "text/event-stream" in (response.content_type or ""):
            return response

        flag = "⚠️ SLOW" if elapsed_ms > 500 else "✅"
        logger.info(f"{flag} {method} {path} → {status} ({elapsed_ms:.1f}ms)")

        # Add timing header for frontend debugging
        response.headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"

        return response
