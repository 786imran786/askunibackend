from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256
import jwt
import os
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import re

# Supabase
from supabase import create_client

load_dotenv()

app = Flask(__name__)
CORS(
    app,
    supports_credentials=True,
    origins=["https://ask-uni.vercel.app"],
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "https://ask-uni.vercel.app"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response



# --- ENVIRONMENT VARIABLES ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SERVICE_ROLE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ======================================================
# 🌟 HELPER FUNCTIONS
# ======================================================

def generate_otp():
    return str(random.randint(100000, 999999))

# -----------------------------------------------------
# 📧 Brevo Email Sender (Universal OTP sender)
# -----------------------------------------------------
import os
import requests


def send_otp_email(email, otp):
    api_key = os.getenv("MJ_API_KEY")          # public key
    secret_key = os.getenv("MJ_SECRET_KEY")    # private key
    sender = os.getenv("MAILJET_SENDER")
    print("api key",api_key)
    print("secret_key",secret_key)
    print("sender",sender)
    url = "https://api.mailjet.com/v3.1/send"

    payload = {
        "Messages": [
            {
                "From": {
                    "Email": sender,
                    "Name": "ASK-UNI"
                },
                "To": [
                    {
                        "Email": email
                    }
                ],
                "Subject": "Your OTP for ASK-UNI Verification",
                "TextPart": f"Your OTP for ASK-UNI verification is: {otp}",
                "HTMLPart": f"<h2>Your OTP is <b>{otp}</b></h2>"
            }
        ]
    }

    try:
        response = requests.post(
            url,
            auth=(api_key, secret_key),   # ❤️ Mailjet Basic Auth
            json=payload
        )

        print("Mailjet Response:", response.status_code, response.text)

        return response.status_code == 200
    except Exception as e:
        print("Mailjet Error:", e)
        return False


    
def create_jwt(user_id, email):
    payload = {"user_id": user_id, "email": email, "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def verify_jwt(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None

    if not auth_header.startswith('Bearer '):
        return None

    token = auth_header.split(' ')[1]
    return decode_jwt(token)

def is_valid_lpu_email(email):
    """Check if email is a valid LPU college email"""
    lpu_patterns = [
        r'^[a-zA-Z0-9._%+-]+@lpu\.in$',
        r'^[a-zA-Z0-9._%+-]+@students\.lpu\.in$',
        r'^[a-zA-Z0-9._%+-]+@lpu\.co\.in$'
    ]

    for pattern in lpu_patterns:
        if re.match(pattern, email, re.IGNORECASE):
            return True
    return False


# ======================================================
# 🔵 MIDDLEWARE FOR CORS PREFLIGHT
# ======================================================

# ======================================================
# 🔵 HEALTH CHECK
# ======================================================

@app.route("/health", methods=["GET"])
def health_check():
    try:
        env_loaded = SUPABASE_URL is not None
        db_status = False
        try:
            test = supabase.table("users").select("*").limit(1).execute()
            db_status = True
        except Exception as e:
            print("DB error:", e)

        return jsonify({
            "status": "ok",
            "message": "Backend is running successfully!",
            "env_loaded": env_loaded,
            "database_connected": db_status
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ======================================================
# 🔵 AUTHENTICATION ENDPOINTS
# ======================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    fullname = data.get("fullname")
    email = data.get("email")
    password = data.get("password")

    # Check if user already exists
    existing = supabase.table("users").select("*").eq("email", email).execute()

    if existing.data:
        return jsonify({"success": False, "message": "Email already registered."})

    password_hash = pbkdf2_sha256.hash(password)
    otp = generate_otp()

    # Store user with is_verified=False
    result = supabase.table("users").insert({
        "full_name": fullname,
        "email": email,
        "password_hash": password_hash,
        "is_verified": False,
        "otp": otp,
        "google_id": None
    }).execute()

    # Send OTP email
    send_otp_email(email, otp)

    # Create token for immediate use
    user_id = result.data[0]["id"] if result.data else None
    token = create_jwt(user_id, email) if user_id else None

    return jsonify({
        "success": True,
        "message": "OTP sent to your email.",
        "token": token,
        "user_id": user_id
    })

@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = data.get("email")
    otp_entered = data.get("otp")

    user = supabase.table("users").select("*").eq("email", email).execute()

    if not user.data:
        return jsonify({"success": False, "message": "User not found."})

    db_otp = user.data[0]["otp"]

    if otp_entered != db_otp:
        return jsonify({"success": False, "message": "Incorrect OTP."})

    # Mark user as verified
    supabase.table("users").update({"is_verified": True, "otp": None}).eq("email", email).execute()

    # Create new token
    user_id = user.data[0]["id"]
    token = create_jwt(user_id, email)

    return jsonify({
        "success": True,
        "message": "OTP verified. Proceed to details page.",
        "token": token,
        "user_id": user_id
    })

@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    data = request.json
    email = data.get("email")

    # Check if user exists
    user_query = supabase.table("users").select("*").eq("email", email).execute()

    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    # Generate new OTP
    otp = generate_otp()

    # Update OTP in DB
    supabase.table("users").update({"otp": otp}).eq("email", email).execute()

    # Send OTP email
    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "New OTP sent successfully!"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user_query = supabase.table("users").select("*").eq("email", username).execute()

    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    user = user_query.data[0]

    if not pbkdf2_sha256.verify(password, user["password_hash"]):
        return jsonify({"success": False, "message": "Incorrect password."})

    if not user["is_verified"]:
        return jsonify({"success": False, "message": "Please verify your OTP first."})

    # JWT
    token = create_jwt(user["id"], user["email"])

    # 🔥 Set auth cookie (SAME as Google login)
    resp = make_response({
        "success": True,
        "user_id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"]
    })

    resp.set_cookie(
        "auth_token",
        token,
        httponly=True,
        secure=False,      # localhost only
        samesite="Lax",
        max_age=7 * 24 * 60 * 60
    )

    return resp

@app.route("/api/verify-token", methods=["POST"])
def verify_token():
    # 1️⃣ Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)
        if payload:
            return jsonify({
                "success": True,
                "user_id": payload["user_id"],
                "email": payload["email"]
            })

    # 2️⃣ Check HttpOnly cookie
    cookie_token = request.cookies.get("auth_token")
    if cookie_token:
        payload = decode_jwt(cookie_token)
        if payload:
            return jsonify({
                "success": True,
                "user_id": payload["user_id"],
                "email": payload["email"]
            })

    # 3️⃣ Optional: check token from body (old method)
    data = request.json if request.is_json else {}
    body_token = data.get("token")
    if body_token:
        payload = decode_jwt(body_token)
        if payload:
            return jsonify({
                "success": True,
                "user_id": payload["user_id"],
                "email": payload["email"]
            })

    # No valid token found
    return jsonify({"success": False, "message": "Token missing or invalid"}), 401


# ======================================================
# 🔵 GOOGLE AUTH
# ======================================================

@app.route("/auth/google")
def google_login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
    )
    return redirect(google_auth_url)

@app.route("/auth/google/callback")
def google_callback():
    code = request.args.get("code")
    import requests

    # Exchange code for token
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    token_res = requests.post(token_url, data=token_data).json()
    access_token = token_res.get("access_token")

    if not access_token:
        return "Google auth failed", 400

    # Get user info
    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    email = userinfo["email"]
    google_id = userinfo["id"]
    name = userinfo["name"]

    # Check if email already exists (normal or google)
    user_query = supabase.table("users").select("*").eq("email", email).execute()

    if user_query.data:
        # ⭐ Existing user (normal signup or google) → Link google_id
        user = user_query.data[0]

        supabase.table("users").update({
            "google_id": google_id,
            "is_verified": True   # Google always verifies email
        }).eq("email", email).execute()

        token = create_jwt(user["id"], email)

        return redirect(f"https://ask-uni.vercel.app/home.html?token={token}")

    else:
        # ⭐ First-time Google login → create user
        result = supabase.table("users").insert({
            "email": email,
            "full_name": name,
            "google_id": google_id,
            "is_verified": True
        }).execute()

        user_id = result.data[0]["id"]
        token = create_jwt(user_id, email)

        return redirect(f"https://ask-uni.vercel.app/detail.html?token={token}&new_user=true")

@app.route('/api/save-token-cookie', methods=['POST'])
def save_token_cookie():
    data = request.json
    token = data.get("token")

    resp = make_response({"success": True})
    resp.set_cookie(
    "auth_token",
    token,
    httponly=True,
    secure=False,       # ✔ localhost cannot use secure cookies
    samesite="Lax",     # ✔ lets cross-domain requests work locally
    max_age=7 * 24 * 60 * 60
    )

    return resp


# ======================================================
# 🔵 PASSWORD RESET
# ======================================================

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    user_query = supabase.table("users").select("*").eq("email", email).execute()

    if not user_query.data:
        return jsonify({"success": False, "message": "No account found with this email."})

    otp = generate_otp()

    # store OTP for password reset
    supabase.table("users").update({"otp": otp}).eq("email", email).execute()

    # send OTP
    send_otp_email(email, otp)

    return jsonify({"success": True, "message": "Password reset OTP sent to your email."})

@app.route("/api/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.json
    email = data.get("email")
    otp_entered = data.get("otp")

    user_query = supabase.table("users").select("*").eq("email", email).execute()

    if not user_query.data:
        return jsonify({"success": False, "message": "User not found."})

    db_otp = user_query.data[0]["otp"]

    if otp_entered != db_otp:
        return jsonify({"success": False, "message": "Invalid OTP."})

    return jsonify({"success": True, "message": "OTP verified. Proceed to reset password."})

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")
    new_password = data.get("new_password")

    password_hash = pbkdf2_sha256.hash(new_password)

    supabase.table("users").update({
        "password_hash": password_hash,
        "otp": None   # clear OTP
    }).eq("email", email).execute()

    return jsonify({"success": True, "message": "Password reset successful! You can login now."})


# ======================================================
# 🔵 COLLEGE EMAIL VERIFICATION
# ======================================================




# ======================================================
# 🔵 PROFILE MANAGEMENT ENDPOINTS
# ======================================================

@app.route("/api/save-personal-info", methods=["POST"])
def save_personal_info():
    # Verify JWT token
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    # Basic validation
    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

    # Validate required fields
    required_fields = ["full_name", "username", "email", "age", "gender"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required"})

    # Check if username is taken (excluding current user)
    existing_username = supabase.table("personal_info") \
        .select("*") \
        .eq("username", data.get("username")) \
        .neq("user_id", user_id) \
        .execute()

    if existing_username.data:
        return jsonify({"success": False, "message": "Username already taken"})

    try:
        # Insert or update personal info
        supabase.table("personal_info").upsert({
            "user_id": user_id,
            "full_name": data.get("full_name"),
            "username": data.get("username"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "age": data.get("age"),
            "gender": data.get("gender")
        }).execute()

        # Also update the main users table with name
        supabase.table("users").update({
            "full_name": data.get("full_name"),
            "username": data.get("username")
        }).eq("id", user_id).execute()

        return jsonify({"success": True, "message": "Personal info saved"})
    except Exception as e:
        print(f"Error saving personal info: {e}")
        return jsonify({"success": False, "message": "Failed to save personal info"}), 500
        
@app.route("/api/save-designation", methods=["POST"])
def save_designation():
    # Verify JWT token
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

    designation_type = data.get("designation_type")

    # Validate designation type
    if designation_type not in ["student", "faculty", "alumni"]:
        return jsonify({"success": False, "message": "Invalid designation type"})

    try:
        designation_data = {
            "user_id": user_id,
            "designation_type": designation_type,
        }

        # ------------------------------------------------------
        # STUDENT SECTION (College email optional)
        # ------------------------------------------------------
        if designation_type == "student":

            required_fields = [
                "registration_no",
                "program",
                "department",
                "current_year",
                "graduation_year"
            ]

            for field in required_fields:
                if not data.get(field):
                    return jsonify({
                        "success": False,
                        "message": f"{field.replace('_', ' ').title()} is required for students"
                    })

            designation_data.update({
                "registration_no": data.get("registration_no"),
                "program": data.get("program"),
                "department": data.get("department"),
                "current_year": data.get("current_year"),
                "graduation_year": data.get("graduation_year"),
            })

            # OPTIONAL college email
            college_email = data.get("college_email")

            if college_email:
                # Validate only if provided
                if not is_valid_lpu_email(college_email):
                    return jsonify({
                        "success": False,
                        "message": "Please enter a valid LPU college email"
                    })

                designation_data["college_email"] = college_email
                designation_data["is_college_email_verified"] = data.get(
                    "is_college_email_verified", False
                )

        # ------------------------------------------------------
        # FACULTY SECTION
        # ------------------------------------------------------
        elif designation_type == "faculty":
            required_fields = [
                "faculty_id",
                "faculty_department",
                "post",
                "courses_taught",
                "office_location",
                "experience"
            ]

            for field in required_fields:
                if not data.get(field):
                    return jsonify({
                        "success": False,
                        "message": f"{field.replace('_', ' ').title()} is required for faculty"
                    })

            designation_data.update({
                "faculty_id": data.get("faculty_id"),
                "faculty_department": data.get("faculty_department"),
                "post": data.get("post"),
                "courses_taught": data.get("courses_taught"),
                "office_location": data.get("office_location"),
                "experience": data.get("experience"),
                "research": data.get("research"),
            })

        # ------------------------------------------------------
        # ALUMNI SECTION
        # ------------------------------------------------------
        elif designation_type == "alumni":
            required_fields = [
                "graduation_year",
                "program",
                "department",
                "job_title",
                "company_name"
            ]

            for field in required_fields:
                if not data.get(field):
                    return jsonify({
                        "success": False,
                        "message": f"{field.replace('_', ' ').title()} is required for alumni"
                    })

            designation_data.update({
                "graduation_year": data.get("graduation_year"),
                "program": data.get("program"),
                "department": data.get("department"),
                "job_title": data.get("job_title"),
                "company_name": data.get("company_name"),
                "linkedin": data.get("linkedin"),
            })

        # ------------------------------------------------------
        # Save to DB
        # ------------------------------------------------------
        supabase.table("designation").upsert(designation_data).execute()

        return jsonify({"success": True, "message": "Designation saved successfully"})

    except Exception as e:
        print(f"Error saving designation: {e}")
        return jsonify({
            "success": False,
            "message": "Failed to save designation"
        }), 500

@app.route("/api/save-general-profile", methods=["POST"])
def save_general_profile():
    # Verify JWT token
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

    # Validate required fields
    required_fields = ["short_bio", "skills", "interests"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required"})

    try:
        supabase.table("general_profile").upsert({
            "user_id": user_id,
            "short_bio": data.get("short_bio"),
            "skills": data.get("skills"),
            "interests": data.get("interests"),
            "linkedin": data.get("linkedin"),
            "github": data.get("github"),
            "portfolio": data.get("portfolio")
        }).execute()

        return jsonify({"success": True, "message": "General profile saved"})
    except Exception as e:
        print(f"Error saving general profile: {e}")
        return jsonify({"success": False, "message": "Failed to save general profile"}), 500
@app.route("/api/save-profile-photo", methods=["POST"])
def save_profile_photo():
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    user_id = payload.get("user_id")
    photo_data = data.get("photo")

    if not photo_data:
        return jsonify({"success": False, "message": "Photo data missing"}), 400

    try:
        supabase.table("personal_info").upsert({
            "user_id": user_id,
            "profile_photo": photo_data
        }).execute()

        return jsonify({"success": True, "message": "Profile photo saved"})
    except Exception as e:
        print("Error saving profile photo:", e)
        return jsonify({"success": False, "message": "Failed to save profile photo"}), 500

@app.route('/api/send-college-otp', methods=['POST'])
def send_college_otp():
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    # Prefer the user_id from JWT to avoid mismatch
    user_id = payload.get("user_id")
    email = data.get("email")
    # allow optional client-provided user_id only as a fallback (less preferred)
    if not user_id:
        user_id = data.get("user_id")

    if not email or not user_id:
        return jsonify({"success": False, "message": "Email or user ID missing"}), 400

    if not is_valid_lpu_email(email):
        return jsonify({"success": False, "message": "Invalid LPU college email"}), 400

    try:
        # Check if email already verified by another user
        existing = supabase.table("designation") \
            .select("user_id,college_email,is_college_email_verified") \
            .eq("college_email", email) \
            .execute()

        # Debug log
        print("Existing check:", existing)

        if existing.data:
            # If the email belongs to the same user, let them re-verify
            if existing.data[0].get("user_id") != user_id and existing.data[0].get("is_college_email_verified"):
                return jsonify({
                    "success": False,
                    "message": "This college email is already verified by another account."
                }), 400

            if existing.data[0].get("user_id") != user_id:
                return jsonify({
                    "success": False,
                    "message": "This college email is already in use. Use a different email."
                }), 400

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Use upsert so the row is created if it doesn't exist
        upsert_payload = {
            "user_id": user_id,
            "college_email": email,
            "otp": otp,
            "otp_verified": False,
            "is_college_email_verified": False
        }

        upsert_res = supabase.table("designation").upsert(upsert_payload).execute()
        print("Upsert result:", upsert_res)

        # check for success / permission errors
        if getattr(upsert_res, "status_code", None) and upsert_res.status_code >= 400:
            print("Supabase upsert error:", upsert_res)
            return jsonify({"success": False, "message": "Failed to save OTP (db). Check permissions."}), 500

    except Exception as e:
        print("Error saving OTP:", e)
        return jsonify({"success": False, "message": "Failed to save OTP"}), 500

    # Send OTP email
    email_status = send_otp_email(email, otp)
    if not email_status:
        # optional: clear OTP if email failed
        try:
            supabase.table("designation").update({"otp": None}).eq("user_id", user_id).execute()
        except Exception as e:
            print("Failed to clear OTP after email failure:", e)
        return jsonify({"success": False, "message": "Failed to send OTP email"}), 500

    print("OTP email sent successfully:", otp)
    return jsonify({"success": True, "message": "OTP sent to your college email"})

@app.route('/api/verify-college-otp', methods=['POST'])
def verify_college_otp():
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.json
    # prefer JWT user_id again
    user_id = payload.get("user_id")
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp or not user_id:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    try:
        response = supabase.table("designation").select("*").eq("user_id", user_id).execute()
        print("Verify fetch:", response)

        if not response.data:
            return jsonify({"success": False, "message": "No OTP found. Please request a new one."}), 400

        record = response.data[0]

        if not record.get("otp"):
            return jsonify({"success": False, "message": "OTP not generated."}), 400

        if str(record["otp"]) != str(otp):
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        # Mark verified
        update_res = supabase.table("designation").update({
            "is_college_email_verified": True,
            "otp_verified": True,
            "otp": None
        }).eq("user_id", user_id).execute()
        print("Verify update:", update_res)

        return jsonify({"success": True, "message": "Email verified successfully"})
    except Exception as e:
        print("Error verifying OTP:", e)
        return jsonify({"success": False, "message": "Failed to verify OTP"}), 500


@app.route("/api/get-profile-data", methods=["GET"])
def get_profile_data():
    # Verify JWT token
    payload = verify_jwt(request)
    if not payload:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    user_id = payload.get("user_id")

    try:
        # Get personal info
        personal_info = supabase.table("personal_info") \
            .select("*") \
            .eq("user_id", user_id) \
            .execute()

        # Get designation
        designation = supabase.table("designation") \
            .select("*") \
            .eq("user_id", user_id) \
            .execute()

        # Get general profile
        general_profile = supabase.table("general_profile") \
            .select("*") \
            .eq("user_id", user_id) \
            .execute()

        # Get user info from main table
        user_info = supabase.table("users") \
            .select("email, full_name, created_at") \
            .eq("id", user_id) \
            .execute()

        response_data = {
            "success": True,
            "personal_info": personal_info.data[0] if personal_info.data else {},
            "designation": designation.data[0] if designation.data else {},
            "general_profile": general_profile.data[0] if general_profile.data else {},
            "user_info": user_info.data[0] if user_info.data else {}
        }

        return jsonify(response_data)
    except Exception as e:
        print(f"Error fetching profile data: {e}")
        return jsonify({"success": False, "message": "Failed to fetch profile data"}), 500


# ======================================================
# 🚀 START SERVER
# ======================================================

if __name__ == "__main__":
    # Create necessary tables if they don't exist
    # (In production, these should be set up via migrations)
    print("🚀 Server starting on http://127.0.0.1:5000")
    print("📊 Health check: http://127.0.0.1:5000/health")
    app.run(debug=True, host="0.0.0.0", port=5000)
