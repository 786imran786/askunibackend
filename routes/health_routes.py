"""
Health check endpoint.
"""
from flask import Blueprint, request, jsonify
from database.supabase_client import supabase
from cache.redis_client import redis_available
from sse.sse_manager import get_client_count
from config import SUPABASE_URL

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    try:
        env_loaded = SUPABASE_URL is not None

        db_status = False
        try:
            supabase.table("users").select("id").limit(1).execute()
            db_status = True
        except Exception as e:
            print("DB error:", e)

        redis_status = redis_available()

        return jsonify({
            "status": "ok",
            "message": "Backend is running successfully!",
            "env_loaded": env_loaded,
            "database_connected": db_status,
            "redis_connected": redis_status,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@health_bp.route("/api/sse/status", methods=["GET"])
def sse_status():
    """Debug endpoint: shows live SSE connection counts."""
    return jsonify({
        "status": "ok",
        "redis": redis_available(),
        "sse_connections": get_client_count(),
    })
