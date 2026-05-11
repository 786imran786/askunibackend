"""
Question, Answer, Vote, and Tag routes.
Uses the optimised question_service for batched queries and caching.
"""
from flask import Blueprint, request, jsonify

from database.supabase_client import supabase
from auth.middleware import require_auth, verify_jwt_from_request
from services.question_service import (
    get_questions_feed,
    get_my_questions,
    get_my_answered_questions,
    get_question_detail,
    invalidate_question_caches,
)
from services.image_service import upload_file
from sse.sse_manager import broadcast_global, create_sse_response
from security.rate_limiter import rate_limit
from cache.redis_client import get_cache, set_cache, invalidate
from cache.cache_keys import all_tags, INVALIDATE_TAGS
from config import RATE_LIMIT_CREATE_Q, CACHE_TTL_TAGS

question_bp = Blueprint("questions", __name__)


# ======================================================
# 🔵 SSE STREAM ENDPOINT
# ======================================================

@question_bp.route("/api/sse/feed", methods=["GET"])
def sse_feed():
    """SSE stream for realtime feed updates (new questions, answers, votes)."""
    return create_sse_response()


# ======================================================
# 🔵 GET QUESTIONS (FEED)
# ======================================================

@question_bp.route("/api/questions", methods=["GET"])
def get_questions():
    try:
        result = get_questions_feed(request.args)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching questions: {e}")
        return jsonify({"success": False, "message": "Failed to fetch questions"}), 500


# ======================================================
# 🔵 GET MY QUESTIONS
# ======================================================

@question_bp.route("/api/my-questions", methods=["GET"])
@require_auth
def get_my_questions_route(payload):
    user_id = payload["user_id"] if isinstance(payload, dict) else payload
    try:
        result = get_my_questions(user_id, request.args)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching my questions: {e}")
        return jsonify({"success": False, "message": "Failed to fetch my questions"}), 500


# ======================================================
# 🔵 GET MY ANSWERS
# ======================================================

@question_bp.route("/api/my-answers", methods=["GET"])
@require_auth
def get_my_answers_route(payload):
    user_id = payload["user_id"] if isinstance(payload, dict) else payload
    try:
        result = get_my_answered_questions(user_id, request.args)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching my answers: {e}")
        return jsonify({"success": False, "message": "Failed to fetch my answers"}), 500


# ======================================================
# 🔵 GET QUESTION DETAIL
# ======================================================

@question_bp.route("/api/questions/<question_id>", methods=["GET"])
def get_question_detail_route(question_id):
    try:
        result = get_question_detail(question_id)
        if result is None:
            return jsonify({"success": False, "message": "Question not found"}), 404
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching question: {e}")
        return jsonify({"success": False, "message": "Failed to fetch question"}), 500


# ======================================================
# 🔵 CREATE QUESTION
# ======================================================

@question_bp.route("/api/questions", methods=["POST"])
@require_auth
@rate_limit(*RATE_LIMIT_CREATE_Q)
def create_question(payload):
    title = None
    content = None
    tags = []
    image_urls = []

    try:
        if request.is_json:
            data = request.json
            title = data.get("title")
            content = data.get("content")
            tags = data.get("tags", [])
        else:
            title = request.form.get("title")
            content = request.form.get("content")
            tags_str = request.form.get("tags")

            if tags_str:
                tags = [t.strip() for t in tags_str.split(",") if t.strip()]

            files = request.files.getlist("images")
            for file in files:
                if file.filename:
                    url = upload_file(file)
                    if url:
                        image_urls.append(url)

        if not title or not content:
            return jsonify({"success": False, "message": "Title and content are required"}), 400

        insert_data = {
            "user_id": payload["user_id"],
            "title": title,
            "content": content,
        }

        if image_urls:
            insert_data["images"] = image_urls

        question_result = supabase.table("questions").insert(insert_data).execute()

        if not question_result.data:
            return jsonify({"success": False, "message": "Failed to create question"}), 500

        question_id = question_result.data[0]["id"]
        question_created_at = question_result.data[0].get("created_at", "")

        # Add tags
        for tag_name in tags:
            tag_query = supabase.table("tags").select("id").eq("name", tag_name).execute()

            if tag_query.data:
                tag_id = tag_query.data[0]["id"]
            else:
                new_tag = supabase.table("tags").insert({
                    "name": tag_name,
                    "usage_count": 1,
                }).execute()
                tag_id = new_tag.data[0]["id"]

            supabase.table("question_tags").insert({
                "question_id": question_id,
                "tag_id": tag_id,
            }).execute()

        # 🚀 Invalidate caches & broadcast SSE
        # Include enough data so the frontend can render immediately
        user_res = supabase.table("personal_info") \
            .select("full_name, profile_photo") \
            .eq("user_id", payload["user_id"]).execute()
        author_name = user_res.data[0]["full_name"] if user_res.data else "Anonymous"

        invalidate_question_caches()
        invalidate(INVALIDATE_TAGS)
        broadcast_global("new_question", {
            "question_id": question_id,
            "title": title,
            "content": content,
            "tags": tags,
            "author": {"full_name": author_name, "profile_photo": "", "is_verified": False},
            "images": image_urls,
            "created_at": question_created_at,
            "upvotes": 0,
            "downvotes": 0,
            "answer_count": 0,
        })

        return jsonify({
            "success": True,
            "message": "Question created successfully",
            "question_id": question_id,
        })
    except Exception as e:
        print(f"Error creating question: {e}")
        return jsonify({"success": False, "message": "Failed to create question"}), 500


# ======================================================
# 🔵 CREATE ANSWER
# ======================================================

@question_bp.route("/api/questions/<question_id>/answers", methods=["POST"])
@require_auth
def create_answer(payload, question_id):
    content = None
    image_urls = []

    try:
        if request.is_json:
            data = request.json
            content = data.get("content")
        else:
            content = request.form.get("content")
            files = request.files.getlist("images")
            for file in files:
                if file.filename:
                    url = upload_file(file)
                    if url:
                        image_urls.append(url)

        if not content:
            return jsonify({"success": False, "message": "Content is required"}), 400

        question_query = supabase.table("questions").select("id").eq("id", question_id).execute()
        if not question_query.data:
            return jsonify({"success": False, "message": "Question not found"}), 404

        insert_data = {
            "question_id": question_id,
            "user_id": payload["user_id"],
            "content": content,
        }

        if image_urls:
            insert_data["images"] = image_urls

        answer_result = supabase.table("answers").insert(insert_data).execute()

        if not answer_result.data:
            return jsonify({"success": False, "message": "Failed to create answer"}), 500

        # Invalidate caches & broadcast
        invalidate_question_caches(question_id)
        broadcast_global("new_answer", {
            "question_id": question_id,
            "answer_id": answer_result.data[0]["id"],
            "answer_count_delta": 1,   # frontend increments the count
        })

        return jsonify({
            "success": True,
            "message": "Answer posted successfully",
            "answer_id": answer_result.data[0]["id"],
        })
    except Exception as e:
        print(f"Error creating answer: {e}")
        return jsonify({"success": False, "message": "Failed to post answer"}), 500


# ======================================================
# 🔵 VOTE
# ======================================================

@question_bp.route("/api/vote", methods=["POST"])
@require_auth
def vote(payload):
    data = request.json
    target_type = data.get("target_type")
    target_id = data.get("target_id")
    vote_type = data.get("vote_type")

    if not all([target_type, target_id, vote_type]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    if target_type not in ["question", "answer"] or vote_type not in ["upvote", "downvote"]:
        return jsonify({"success": False, "message": "Invalid vote data"}), 400

    try:
        existing_vote = supabase.table("votes") \
            .select("id") \
            .eq("user_id", payload["user_id"]) \
            .eq("target_type", target_type) \
            .eq("target_id", target_id) \
            .execute()

        if existing_vote.data:
            supabase.table("votes") \
                .update({"vote_type": vote_type}) \
                .eq("id", existing_vote.data[0]["id"]) \
                .execute()
        else:
            supabase.table("votes").insert({
                "user_id": payload["user_id"],
                "target_type": target_type,
                "target_id": target_id,
                "vote_type": vote_type,
            }).execute()

        # Get updated counts (single query)
        votes_res = supabase.table("votes") \
            .select("vote_type") \
            .eq("target_type", target_type) \
            .eq("target_id", target_id) \
            .execute()

        upvotes = sum(1 for v in votes_res.data if v["vote_type"] == "upvote")
        downvotes = sum(1 for v in votes_res.data if v["vote_type"] == "downvote")

        # Invalidate caches & broadcast vote update to ALL users
        invalidate_question_caches(target_id if target_type == "question" else None)
        broadcast_global("vote_update", {
            "target_type": target_type,
            "target_id": target_id,
            "upvotes": upvotes,
            "downvotes": downvotes,
        })

        return jsonify({
            "success": True,
            "message": "Vote recorded",
            "upvotes": upvotes,
            "downvotes": downvotes,
        })
    except Exception as e:
        print(f"Error recording vote: {e}")
        return jsonify({"success": False, "message": "Failed to record vote"}), 500


# ======================================================
# 🔵 TAGS
# ======================================================

@question_bp.route("/api/tags", methods=["GET"])
def get_tags():
    try:
        cached = get_cache(all_tags())
        if cached:
            return jsonify(cached)

        tags_query = supabase.table("tags") \
            .select("id, name, usage_count") \
            .order("usage_count", desc=True) \
            .execute()

        result = {"success": True, "tags": tags_query.data}
        set_cache(all_tags(), result, CACHE_TTL_TAGS)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching tags: {e}")
        return jsonify({"success": False, "message": "Failed to fetch tags"}), 500
