"""
Gunicorn production configuration for Render deployment.
Uses threaded workers (gthread) to support SSE connections.
"""
import multiprocessing
import os

# ── Bind ──────────────────────────────────────────────────
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# ── Workers ───────────────────────────────────────────────
# Render free tier has limited memory, so cap workers
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
threads = 2
worker_class = "gthread"  # Required for SSE support

# ── Timeouts ──────────────────────────────────────────────
timeout = 120              # SSE connections need longer timeout
keepalive = 5
graceful_timeout = 30

# ── Memory management ────────────────────────────────────
max_requests = 1000        # Restart workers periodically
max_requests_jitter = 50   # Add jitter to prevent thundering herd

# ── Preload ───────────────────────────────────────────────
preload_app = True         # Load app before forking workers (saves memory)

# ── Logging ───────────────────────────────────────────────
accesslog = "-"            # Log to stdout
errorlog = "-"
loglevel = "info"
