"""
Profile management routes — personal info, designation, general profile, photo.
"""
import random
from flask import Blueprint, request, jsonify

from database.supabase_client import supabase
from auth.middleware import require_auth, verify_jwt_from_request
from services.email_service import send_otp_email_sync
from utils.helpers import is_valid_lpu_email
from cache.redis_client import get_cache, set_cache, delete_key
from cache.cache_keys import user_profile
from config import CACHE_TTL_PROFILE

profile_bp = Blueprint("profile", __name__)


# ======================================================
# 🔵 SAVE PERSONAL INFO
# ======================================================

@profile_bp.route("/api/save-personal-info", methods=["POST"])
@require_auth
def save_personal_info(payload):
    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

    required_fields = ["full_name", "username", "email", "age", "gender"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required"})

    # Check username uniqueness
    existing_username = supabase.table("personal_info") \
        .select("user_id") \
        .eq("username", data.get("username")) \
        .neq("user_id", user_id) \
        .execute()

    if existing_username.data:
        return jsonify({"success": False, "message": "Username already taken"})

    try:
        supabase.table("personal_info").upsert({
            "user_id": user_id,
            "full_name": data.get("full_name"),
            "username": data.get("username"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "age": data.get("age"),
            "gender": data.get("gender"),
        }).execute()

        supabase.table("users").update({
            "full_name": data.get("full_name"),
            "username": data.get("username"),
        }).eq("id", user_id).execute()

        # Invalidate profile cache
        delete_key(user_profile(user_id))

        return jsonify({"success": True, "message": "Personal info saved"})
    except Exception as e:
        print(f"Error saving personal info: {e}")
        return jsonify({"success": False, "message": "Failed to save personal info"}), 500


# ======================================================
# 🔵 SAVE DESIGNATION
# ======================================================

@profile_bp.route("/api/save-designation", methods=["POST"])
@require_auth
def save_designation(payload):
    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

    designation_type = data.get("designation_type")
    if designation_type not in ["student", "faculty", "alumni"]:
        return jsonify({"success": False, "message": "Invalid designation type"})

    try:
        designation_data = {
            "user_id": user_id,
            "designation_type": designation_type,
        }

        # ── STUDENT ──────────────────────────────────────
        if designation_type == "student":
            required_fields = ["registration_no", "program", "department", "current_year", "graduation_year"]
            for field in required_fields:
                if not data.get(field):
                    return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required for students"})

            designation_data.update({
                "registration_no": data.get("registration_no"),
                "program": data.get("program"),
                "department": data.get("department"),
                "current_year": data.get("current_year"),
                "graduation_year": data.get("graduation_year"),
            })

            college_email = data.get("college_email")
            if college_email:
                if not is_valid_lpu_email(college_email):
                    return jsonify({"success": False, "message": "Please enter a valid LPU college email"})
                designation_data["college_email"] = college_email
                designation_data["is_college_email_verified"] = data.get("is_college_email_verified", False)

        # ── FACULTY ──────────────────────────────────────
        elif designation_type == "faculty":
            required_fields = ["faculty_id", "faculty_department", "post", "courses_taught", "office_location", "experience"]
            for field in required_fields:
                if not data.get(field):
                    return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required for faculty"})

            designation_data.update({
                "faculty_id": data.get("faculty_id"),
                "faculty_department": data.get("faculty_department"),
                "post": data.get("post"),
                "courses_taught": data.get("courses_taught"),
                "office_location": data.get("office_location"),
                "experience": data.get("experience"),
                "research": data.get("research"),
            })

        # ── ALUMNI ───────────────────────────────────────
        elif designation_type == "alumni":
            required_fields = ["graduation_year", "program", "department", "job_title", "company_name"]
            for field in required_fields:
                if not data.get(field):
                    return jsonify({"success": False, "message": f"{field.replace('_', ' ').title()} is required for alumni"})

            designation_data.update({
                "graduation_year": data.get("graduation_year"),
                "program": data.get("program"),
                "department": data.get("department"),
                "job_title": data.get("job_title"),
                "company_name": data.get("company_name"),
                "linkedin": data.get("linkedin"),
            })

        supabase.table("designation").upsert(designation_data).execute()
        delete_key(user_profile(user_id))

        return jsonify({"success": True, "message": "Designation saved successfully"})
    except Exception as e:
        print(f"Error saving designation: {e}")
        return jsonify({"success": False, "message": "Failed to save designation"}), 500


# ======================================================
# 🔵 SAVE GENERAL PROFILE
# ======================================================

@profile_bp.route("/api/save-general-profile", methods=["POST"])
@require_auth
def save_general_profile(payload):
    data = request.json
    user_id = data.get("user_id", payload.get("user_id"))

    if not user_id:
        return jsonify({"success": False, "message": "User ID missing"})

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
            "portfolio": data.get("portfolio"),
        }).execute()

        delete_key(user_profile(user_id))
        return jsonify({"success": True, "message": "General profile saved"})
    except Exception as e:
        print(f"Error saving general profile: {e}")
        return jsonify({"success": False, "message": "Failed to save general profile"}), 500


# ======================================================
# 🔵 SAVE PROFILE PHOTO
# ======================================================

@profile_bp.route("/api/save-profile-photo", methods=["POST"])
@require_auth
def save_profile_photo(payload):
    data = request.json
    user_id = payload.get("user_id")
    photo_data = data.get("photo")

    if not photo_data:
        return jsonify({"success": False, "message": "Photo data missing"}), 400

    try:
        supabase.table("personal_info").upsert({
            "user_id": user_id,
            "profile_photo": photo_data,
        }).execute()

        delete_key(user_profile(user_id))
        return jsonify({"success": True, "message": "Profile photo saved"})
    except Exception as e:
        print("Error saving profile photo:", e)
        return jsonify({"success": False, "message": "Failed to save profile photo"}), 500


# ======================================================
# 🔵 COLLEGE EMAIL OTP
# ======================================================

@profile_bp.route("/api/send-college-otp", methods=["POST"])
@require_auth
def send_college_otp(payload):
    user_id = payload.get("user_id")
    data = request.json
    email = data.get("email")

    if not email or not user_id:
        return jsonify({"success": False, "message": "Email or user ID missing"}), 400

    if not is_valid_lpu_email(email):
        return jsonify({"success": False, "message": "Invalid LPU college email"}), 400

    try:
        existing = supabase.table("designation") \
            .select("user_id, college_email, is_college_email_verified") \
            .eq("college_email", email) \
            .execute()

        if existing.data:
            if existing.data[0].get("user_id") != user_id and existing.data[0].get("is_college_email_verified"):
                return jsonify({"success": False, "message": "This college email is already verified by another account."}), 400
            if existing.data[0].get("user_id") != user_id:
                return jsonify({"success": False, "message": "This college email is already in use."}), 400

        otp = str(random.randint(100000, 999999))

        supabase.table("designation").upsert({
            "user_id": user_id,
            "college_email": email,
            "otp": otp,
            "otp_verified": False,
            "is_college_email_verified": False,
        }).execute()

    except Exception as e:
        print("Error saving OTP:", e)
        return jsonify({"success": False, "message": "Failed to save OTP"}), 500

    # Use sync email here because we need to clear OTP on failure
    email_status = send_otp_email_sync(email, otp)
    if not email_status:
        try:
            supabase.table("designation").update({"otp": None}).eq("user_id", user_id).execute()
        except Exception:
            pass
        return jsonify({"success": False, "message": "Failed to send OTP email"}), 500

    return jsonify({"success": True, "message": "OTP sent to your college email"})


@profile_bp.route("/api/verify-college-otp", methods=["POST"])
@require_auth
def verify_college_otp(payload):
    user_id = payload.get("user_id")
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    if not email or not otp or not user_id:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    try:
        response = supabase.table("designation").select("otp").eq("user_id", user_id).execute()

        if not response.data:
            return jsonify({"success": False, "message": "No OTP found. Please request a new one."}), 400

        record = response.data[0]

        if not record.get("otp"):
            return jsonify({"success": False, "message": "OTP not generated."}), 400

        if str(record["otp"]) != str(otp):
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        supabase.table("designation").update({
            "is_college_email_verified": True,
            "otp_verified": True,
            "otp": None,
        }).eq("user_id", user_id).execute()

        delete_key(user_profile(user_id))
        return jsonify({"success": True, "message": "Email verified successfully"})
    except Exception as e:
        print("Error verifying OTP:", e)
        return jsonify({"success": False, "message": "Failed to verify OTP"}), 500


# ======================================================
# 🔵 GET PROFILE DATA
# ======================================================

@profile_bp.route("/api/get-profile-data", methods=["GET"])
@require_auth
def get_profile_data(payload):
    user_id = payload.get("user_id")

    # Check cache first
    cache_key = user_profile(user_id)
    cached = get_cache(cache_key)
    if cached:
        return jsonify(cached)

    try:
        personal_info = supabase.table("personal_info").select("*").eq("user_id", user_id).execute()
        designation = supabase.table("designation").select("*").eq("user_id", user_id).execute()
        general_profile = supabase.table("general_profile").select("*").eq("user_id", user_id).execute()
        user_info = supabase.table("users").select("email, full_name, created_at").eq("id", user_id).execute()

        response_data = {
            "success": True,
            "personal_info": personal_info.data[0] if personal_info.data else {},
            "designation": designation.data[0] if designation.data else {},
            "general_profile": general_profile.data[0] if general_profile.data else {},
            "user_info": user_info.data[0] if user_info.data else {},
        }

        set_cache(cache_key, response_data, CACHE_TTL_PROFILE)
        return jsonify(response_data)
    except Exception as e:
        print(f"Error fetching profile data: {e}")
        return jsonify({"success": False, "message": "Failed to fetch profile data"}), 500
