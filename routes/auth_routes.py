"""
Authentication routes — Register, Login, OTP, Google OAuth, Password Reset.
Rate-limited and optimised with async email sending.
"""
from flask import Blueprint, request, jsonify, redirect, make_response
from passlib.hash import pbkdf2_sha256
import requests as http_requests

from database.supabase_client import supabase
from auth.jwt_utils import create_jwt, decode_jwt
from auth.middleware import verify_jwt_from_request
from services.email_service import send_otp_email, send_otp_email_sync
from utils.helpers import generate_otp, is_valid_lpu_email
from security.rate_limiter import rate_limit
from config import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
    FRONTEND_URL, ENV, IS_PROD,
    RATE_LIMIT_LOGIN, RATE_LIMIT_REGISTER, RATE_LIMIT_FORGOT_PW,
    RATE_LIMIT_OTP, RATE_LIMIT_RESEND_OTP,
)

auth_bp = Blueprint("auth", __name__)


# ======================================================
# 🔵 REGISTRATION
# ======================================================

@auth_bp.route("/api/register", methods=["POST"])
@rate_limit(*RATE_LIMIT_REGISTER)
def register():
    data = request.json
    fullname = data.get("fullname")
    email = data.get("email")
    password = data.get("password")

    if not all([fullname, email, password]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    # Check if user already exists
    existing = supabase.table("users").select("id").eq("email", email).execute()
    if existing.data:
        return jsonify({"success": False, "message": "Email already registered."})

    password_hash = pbkdf2_sha256.hash(password)
    otp = generate_otp()

    result = supabase.table("users").insert({
        "full_name": fullname,
        "email": email,
        "password_hash": password_hash,
        "is_verified": False,
        "otp": otp,
        "google_id": None,
    }).execute()

    # 🚀 Async email — API responds immediately
    send_otp_email(email, otp)

    user_id = result.data[0]["id"] if result.data else None
    token = create_jwt(user_id, email) if user_id else None

    return jsonify({
        "success": True,
        "message": "OTP sent to your email.",
        "token": token,
        "user_id": user_id,
    })


# ======================================================
# 🔵 OTP VERIFICATION
# ======================================================

@auth_bp.route("/api/verify-otp", methods=["POST"])
@rate_limit(*RATE_LIMIT_OTP)
def verify_otp():
    data = request.json
    email = data.get("email")
    otp_entered = data.get("otp")

    user = supabase.table("users").select("id, otp").eq("email", email).execute()
    if not user.data:
        return jsonify({"success": False, "message": "User not found."})

    if otp_entered != user.data[0]["otp"]:
        return jsonify({"success": False, "message": "Incorrect OTP."})

    supabase.table("users").update({"is_verified": True, "otp": None}).eq("email", email).execute()

    user_id = user.data[0]["id"]
    token = create_jwt(user_id, email)

    return jsonify({
        "success": True,
        "message": "OTP verified. Proceed to details page.",
        "token": token,
        "user_id": user_id,
    })


@auth_bp.route("/api/resend-otp", methods=["POST"])
@rate_limit(*RATE_LIMIT_RESEND_OTP)
def resend_otp():
    data = request.json
    email = data.get("email")

    user_query = supabase.table("users").select("id").eq("email", email).execute()
    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    otp = generate_otp()
    supabase.table("users").update({"otp": otp}).eq("email", email).execute()

    # 🚀 Async email
    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "New OTP sent successfully!"})


# ======================================================
# 🔵 LOGIN
# ======================================================

@auth_bp.route("/api/login", methods=["POST"])
@rate_limit(*RATE_LIMIT_LOGIN)
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user_query = supabase.table("users").select("id, email, full_name, password_hash, is_verified") \
        .eq("email", username).execute()

    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    user = user_query.data[0]

    if not pbkdf2_sha256.verify(password, user["password_hash"]):
        return jsonify({"success": False, "message": "Incorrect password."})

    if not user["is_verified"]:
        return jsonify({"success": False, "message": "Please verify your OTP first."})

    token = create_jwt(user["id"], user["email"])

    resp = make_response({
        "success": True,
        "user_id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
    })

    resp.set_cookie(
        "auth_token", token,
        httponly=True,
        secure=IS_PROD,
        samesite="None" if IS_PROD else "Lax",
        max_age=7 * 24 * 60 * 60,
    )

    return resp


# ======================================================
# 🔵 TOKEN VERIFICATION
# ======================================================

@auth_bp.route("/api/verify-token", methods=["POST"])
def verify_token():
    # 1. Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_jwt(token)
        if payload:
            return jsonify({"success": True, "user_id": payload["user_id"], "email": payload["email"]})

    # 2. Cookie
    cookie_token = request.cookies.get("auth_token")
    if cookie_token:
        payload = decode_jwt(cookie_token)
        if payload:
            return jsonify({"success": True, "user_id": payload["user_id"], "email": payload["email"]})

    # 3. Body (legacy)
    data = request.json if request.is_json else {}
    body_token = data.get("token")
    if body_token:
        payload = decode_jwt(body_token)
        if payload:
            return jsonify({"success": True, "user_id": payload["user_id"], "email": payload["email"]})

    return jsonify({"success": False, "message": "Token missing or invalid"}), 401


# ======================================================
# 🔵 GOOGLE OAuth
# ======================================================

@auth_bp.route("/auth/google")
def google_login():
    redirect_to = request.args.get("redirect_to", "")
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        f"&state={redirect_to}"
    )
    return redirect(google_auth_url)


@auth_bp.route("/auth/google/callback")
def google_callback():
    code = request.args.get("code")

    token_res = http_requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }).json()

    access_token = token_res.get("access_token")
    if not access_token:
        return "Google auth failed", 400

    userinfo = http_requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()

    email = userinfo["email"]
    google_id = userinfo["id"]
    name = userinfo["name"]

    state = request.args.get("state")
    base_redirect = state if state else f"{FRONTEND_URL}/home.html"
    separator = "&" if "?" in base_redirect else "?"

    user_query = supabase.table("users").select("id, email").eq("email", email).execute()

    if user_query.data:
        user = user_query.data[0]
        supabase.table("users").update({
            "google_id": google_id,
            "is_verified": True,
        }).eq("email", email).execute()

        token = create_jwt(user["id"], email)
        return redirect(f"{base_redirect}{separator}token={token}")
    else:
        result = supabase.table("users").insert({
            "email": email,
            "full_name": name,
            "google_id": google_id,
            "is_verified": True,
        }).execute()

        user_id = result.data[0]["id"]
        token = create_jwt(user_id, email)
        return redirect(f"{base_redirect}{separator}token={token}&new_user=true")


@auth_bp.route("/api/save-token-cookie", methods=["POST"])
def save_token_cookie():
    data = request.json
    token = data.get("token")

    resp = make_response({"success": True})
    resp.set_cookie(
        "auth_token", token,
        httponly=True,
        secure=IS_PROD,
        samesite="None" if IS_PROD else "Lax",
        max_age=7 * 24 * 60 * 60,
    )
    return resp


# ======================================================
# 🔵 PASSWORD RESET
# ======================================================

@auth_bp.route("/api/forgot-password", methods=["POST"])
@rate_limit(*RATE_LIMIT_FORGOT_PW)
def forgot_password():
    data = request.json
    email = data.get("email")

    user_query = supabase.table("users").select("id").eq("email", email).execute()
    if not user_query.data:
        return jsonify({"success": False, "message": "No account found with this email."})

    otp = generate_otp()
    supabase.table("users").update({"otp": otp}).eq("email", email).execute()

    # 🚀 Async email
    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "Password reset OTP sent to your email."})


@auth_bp.route("/api/verify-reset-otp", methods=["POST"])
@rate_limit(*RATE_LIMIT_OTP)
def verify_reset_otp():
    data = request.json
    email = data.get("email")
    otp_entered = data.get("otp")

    user_query = supabase.table("users").select("id, otp").eq("email", email).execute()
    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    if otp_entered != user_query.data[0]["otp"]:
        return jsonify({"success": False, "message": "Invalid OTP."})

    return jsonify({"success": True, "message": "OTP verified. Proceed to reset password."})


@auth_bp.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("new_password")

    password_hash = pbkdf2_sha256.hash(new_password)
    supabase.table("users").update({
        "password_hash": password_hash,
        "otp": None,
    }).eq("email", email).execute()

    return jsonify({"success": True, "message": "Password reset successful! You can login now."})


# ======================================================
# 🔵 LOGOUT
# ======================================================

@auth_bp.route("/api/logout", methods=["GET", "POST"])
def logout():
    try:
        resp = make_response(jsonify({"success": True, "message": "Logout successful"}))
        resp.set_cookie(
            "auth_token", "",
            expires=0,
            httponly=True,
            secure=IS_PROD,
            samesite="None" if IS_PROD else "Lax",
        )
        return resp
    except Exception as e:
        return jsonify({"success": False, "message": "Failed to log out"}), 500
