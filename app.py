"""
askUNI Backend — Application Factory
=====================================
This is the main entry point. The 1,800-line monolith has been refactored into:
  - routes/     → Blueprint-based route handlers
  - services/   → Business logic (batched queries, caching)
  - cache/      → Redis client + cache key management
  - database/   → Supabase client singleton
  - auth/       → JWT utilities + middleware
  - realtime/   → SSE manager + Redis Pub/Sub
  - security/   → Rate limiting
  - utils/      → Helpers + logging middleware
"""
import logging
from flask import Flask, request
from flask_cors import CORS

from config import ALLOWED_ORIGINS, ENV

# ── Configure logging ─────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Create Flask app ──────────────────────────────────────
app = Flask(__name__)

# ── CORS ──────────────────────────────────────────────────
CORS(
    app,
    supports_credentials=True,
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)


@app.after_request
def apply_cors(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# ── Register performance logging middleware ───────────────
from utils.logging_middleware import register_timing_middleware
register_timing_middleware(app)

# ── Register Blueprints ───────────────────────────────────
from routes.health_routes import health_bp
from routes.auth_routes import auth_bp
from routes.profile_routes import profile_bp
from routes.question_routes import question_bp
from routes.forum_routes import forum_bp

app.register_blueprint(health_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(question_bp)
app.register_blueprint(forum_bp)

# ── Start Redis Pub/Sub subscriber ────────────────────────
from sse.redis_pubsub import start_subscriber
try:
    start_subscriber()
    logger.info("🔄 Redis Pub/Sub subscriber started")
except Exception as e:
    logger.warning(f"Redis Pub/Sub not started (non-fatal): {e}")


# ── Startup banner ────────────────────────────────────────
logger.info("=" * 60)
logger.info("🚀 askUNI Backend — Production-Optimised")
logger.info(f"   Environment:  {ENV}")
logger.info(f"   Blueprints:   health, auth, profile, questions, forums")
logger.info(f"   Features:     Redis caching, SSE realtime, rate limiting")
logger.info("=" * 60)


# ── Development server ────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Server starting on http://127.0.0.1:5000")
    print("📊 Health check: http://127.0.0.1:5000/health")
    app.run(debug=True, host="0.0.0.0", port=5000)
