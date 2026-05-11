"""
Forum routes — CRUD, join requests, messages (paginated + realtime), likes.
"""
from flask import Blueprint, request, jsonify

from database.supabase_client import supabase
from auth.middleware import require_auth
from services.forum_service import (
    check_membership,
    get_forum_messages,
    post_message,
    toggle_like,
)
from sse.sse_manager import create_forum_sse_response
from security.rate_limiter import rate_limit
from cache.redis_client import get_cache, set_cache, invalidate
from cache.cache_keys import forums_list
from config import RATE_LIMIT_FORUM_MSG, CACHE_TTL_FEED

forum_bp = Blueprint("forums", __name__)


# ======================================================
# 🔵 GET FORUMS
# ======================================================

@forum_bp.route("/api/forums", methods=["GET"])
@require_auth
def get_forums(payload):
    try:
        user_id = payload["user_id"]

        forums_query = supabase.table("forums") \
            .select("id, title, description, visibility, admin_id, created_at") \
            .order("created_at", desc=True) \
            .execute()
        forums_data = forums_query.data

        # Batch: get all members in one query
        members_query = supabase.table("forum_members") \
            .select("forum_id, user_id") \
            .execute()

        forum_members_map = {}
        user_joined_map = {}

        for m in members_query.data:
            fid = m["forum_id"]
            forum_members_map[fid] = forum_members_map.get(fid, 0) + 1
            if m["user_id"] == user_id:
                user_joined_map[fid] = True

        result = []
        for f in forums_data:
            fid = f["id"]
            f["members"] = forum_members_map.get(fid, 0)
            f["joined"] = user_joined_map.get(fid, False)
            result.append(f)

        return jsonify({"success": True, "forums": result})
    except Exception as e:
        print(f"Error fetching forums: {e}")
        return jsonify({"success": False, "message": "Failed to fetch forums"}), 500


# ======================================================
# 🔵 CREATE FORUM
# ======================================================

@forum_bp.route("/api/forums", methods=["POST"])
@require_auth
def create_forum(payload):
    data = request.json
    title = data.get("title")
    description = data.get("description")
    visibility = data.get("visibility")

    if not all([title, description, visibility]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    try:
        user_id = payload["user_id"]

        res = supabase.table("forums").insert({
            "title": title,
            "description": description,
            "visibility": visibility,
            "admin_id": user_id,
        }).execute()

        forum_id = res.data[0]["id"]

        supabase.table("forum_members").insert({
            "forum_id": forum_id,
            "user_id": user_id,
        }).execute()

        return jsonify({"success": True, "message": "Forum created successfully", "forum_id": forum_id})
    except Exception as e:
        print(f"Error creating forum: {e}")
        return jsonify({"success": False, "message": "Failed to create forum"}), 500


# ======================================================
# 🔵 JOIN FORUM
# ======================================================

@forum_bp.route("/api/forums/<int:forum_id>/join", methods=["POST"])
@require_auth
def join_forum(payload, forum_id):
    try:
        user_id = payload["user_id"]

        forum_res = supabase.table("forums").select("id, visibility").eq("id", forum_id).execute()
        if not forum_res.data:
            return jsonify({"success": False, "message": "Forum not found"}), 404

        forum = forum_res.data[0]

        if check_membership(forum_id, user_id):
            return jsonify({"success": False, "message": "Already joined"}), 400

        if forum["visibility"] == "global":
            supabase.table("forum_members").insert({
                "forum_id": forum_id,
                "user_id": user_id,
            }).execute()
            return jsonify({"success": True, "message": "Joined forum successfully", "status": "joined"})
        else:
            req_res = supabase.table("forum_requests") \
                .select("id") \
                .eq("forum_id", forum_id) \
                .eq("user_id", user_id) \
                .eq("status", "pending") \
                .execute()
            if req_res.data:
                return jsonify({"success": False, "message": "Request already pending"}), 400

            supabase.table("forum_requests").insert({
                "forum_id": forum_id,
                "user_id": user_id,
                "status": "pending",
            }).execute()
            return jsonify({"success": True, "message": "Join request sent to admin", "status": "pending"})
    except Exception as e:
        print(f"Error joining forum: {e}")
        return jsonify({"success": False, "message": "Failed to join forum"}), 500


# ======================================================
# 🔵 FORUM REQUESTS
# ======================================================

@forum_bp.route("/api/forums/requests", methods=["GET"])
@require_auth
def get_forum_requests(payload):
    try:
        user_id = payload["user_id"]

        my_forums = supabase.table("forums").select("id, title").eq("admin_id", user_id).execute()
        my_forum_ids = [f["id"] for f in my_forums.data]

        if not my_forum_ids:
            return jsonify({"success": True, "requests": []})

        requests_res = supabase.table("forum_requests") \
            .select("id, forum_id, user_id, status, users(full_name, email, profile_photo), forums(title)") \
            .in_("forum_id", my_forum_ids) \
            .eq("status", "pending") \
            .execute()

        result = []
        for req in requests_res.data:
            result.append({
                "id": req["id"],
                "forum_id": req["forum_id"],
                "forum_title": req["forums"]["title"] if req.get("forums") else "Unknown",
                "user_id": req["user_id"],
                "user_name": req["users"]["full_name"] if req.get("users") else "Unknown",
                "user_email": req["users"]["email"] if req.get("users") else "",
                "profile_photo": req["users"]["profile_photo"] if req.get("users") else "",
                "status": req["status"],
            })

        return jsonify({"success": True, "requests": result})
    except Exception as e:
        print(f"Error fetching requests: {e}")
        return jsonify({"success": False, "message": "Failed to fetch requests"}), 500


@forum_bp.route("/api/forums/requests/<int:request_id>", methods=["POST"])
@require_auth
def respond_forum_request(payload, request_id):
    data = request.json
    action = data.get("action")

    if action not in ["approve", "reject"]:
        return jsonify({"success": False, "message": "Invalid action"}), 400

    try:
        user_id = payload["user_id"]

        req_res = supabase.table("forum_requests") \
            .select("id, forum_id, user_id, forums(admin_id)") \
            .eq("id", request_id) \
            .execute()

        if not req_res.data:
            return jsonify({"success": False, "message": "Request not found"}), 404

        req = req_res.data[0]

        if req["forums"]["admin_id"] != user_id:
            return jsonify({"success": False, "message": "Forbidden"}), 403

        status = "approved" if action == "approve" else "rejected"
        supabase.table("forum_requests").update({"status": status}).eq("id", request_id).execute()

        if status == "approved":
            supabase.table("forum_members").upsert({
                "forum_id": req["forum_id"],
                "user_id": req["user_id"],
            }).execute()

        return jsonify({"success": True, "message": f"Request {status}"})
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"success": False, "message": "Failed to process request"}), 500


# ======================================================
# 🔵 FORUM MESSAGES (paginated)
# ======================================================

@forum_bp.route("/api/forums/<int:forum_id>/messages", methods=["GET"])
@require_auth
def get_messages(payload, forum_id):
    try:
        user_id = payload["user_id"]

        if not check_membership(forum_id, user_id):
            return jsonify({"success": False, "message": "Not a member of this forum"}), 403

        result = get_forum_messages(forum_id, user_id, request.args)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching messages: {e}")
        return jsonify({"success": False, "message": "Failed to fetch messages"}), 500


@forum_bp.route("/api/forums/<int:forum_id>/messages", methods=["POST"])
@require_auth
@rate_limit(*RATE_LIMIT_FORUM_MSG)
def post_message_route(payload, forum_id):
    data = request.json
    content = data.get("content")

    if not content:
        return jsonify({"success": False, "message": "Message content required"}), 400

    try:
        user_id = payload["user_id"]

        if not check_membership(forum_id, user_id):
            return jsonify({"success": False, "message": "Not a member"}), 403

        result = post_message(forum_id, user_id, content)
        return jsonify(result)
    except Exception as e:
        print(f"Error posting message: {e}")
        return jsonify({"success": False, "message": "Failed to post message"}), 500


# ======================================================
# 🔵 FORUM MESSAGE LIKES
# ======================================================

@forum_bp.route("/api/forums/messages/<int:message_id>/like", methods=["POST"])
@require_auth
def toggle_message_like(payload, message_id):
    try:
        user_id = payload["user_id"]
        result = toggle_like(message_id, user_id)
        return jsonify(result)
    except Exception as e:
        print(f"Error toggling like: {e}")
        return jsonify({"success": False, "message": "Failed to toggle like"}), 500


# ======================================================
# 🔵 FORUM SSE (realtime chat)
# ======================================================

@forum_bp.route("/api/forums/<int:forum_id>/sse", methods=["GET"])
def forum_sse_stream(forum_id):
    """SSE stream for realtime forum chat messages."""
    return create_forum_sse_response(forum_id)
