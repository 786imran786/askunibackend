"""
Authentication middleware and decorators.
"""
from functools import wraps
from flask import request, jsonify
from auth.jwt_utils import decode_jwt


def _extract_payload():
    """
    Try to extract JWT payload from (in priority order):
      1. Authorization: Bearer <token>
      2. auth_token cookie
    Returns payload dict or None.
    """
    # 1. Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_jwt(token)
        if payload:
            return payload

    # 2. Cookie
    cookie_token = request.cookies.get("auth_token")
    if cookie_token:
        payload = decode_jwt(cookie_token)
        if payload:
            return payload

    return None


def verify_jwt_from_request():
    """
    Convenience function for route handlers that want to manually
    check auth without using the decorator.
    Returns payload dict or None.
    """
    return _extract_payload()


def require_auth(f):
    """
    Decorator that enforces JWT authentication.
    Injects `payload` as the first argument to the wrapped function.

    Usage:
        @app.route("/api/protected")
        @require_auth
        def protected(payload):
            user_id = payload["user_id"]
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _extract_payload()
        if payload is None:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return f(payload, *args, **kwargs)
    return decorated
