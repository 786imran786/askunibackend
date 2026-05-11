"""
Forum business logic — messages with pagination, caching, and realtime pub/sub.
"""
from datetime import datetime
from database.supabase_client import supabase
from cache.redis_client import get_cache, set_cache, invalidate, publish
from cache import cache_keys
from config import CACHE_TTL_FORUM_MSG, FORUM_MSG_PAGE_SIZE, MAX_PAGE_SIZE


def _parse_pagination(args, default_limit=FORUM_MSG_PAGE_SIZE):
    try:
        page = max(1, int(args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        limit = min(MAX_PAGE_SIZE, max(1, int(args.get("limit", default_limit))))
    except (ValueError, TypeError):
        limit = default_limit
    return page, limit


def _pagination_meta(page, limit, total):
    total_pages = max(1, -(-total // limit))
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


def check_membership(forum_id, user_id) -> bool:
    """Check if user is a member of the forum."""
    res = supabase.table("forum_members") \
        .select("id") \
        .eq("forum_id", forum_id) \
        .eq("user_id", user_id) \
        .execute()
    return bool(res.data)


def get_forum_messages(forum_id, user_id, args) -> dict:
    """Get paginated forum messages with likes info."""
    page, limit = _parse_pagination(args)

    cache_key = cache_keys.forum_messages(forum_id, page)
    cached = get_cache(cache_key)
    if cached:
        # We still need to compute likedByMe per-user, so we augment cached data
        # Actually for simplicity and correctness, we skip cache when user-specific data is needed
        # OR we cache the base data and overlay user-specific data
        pass  # Fall through to fetch — user-specific likes make caching tricky
        # TODO: cache base messages, overlay user-likes separately

    # Count total
    count_query = supabase.table("forum_messages") \
        .select("id", count="exact") \
        .eq("forum_id", forum_id) \
        .execute()
    total = count_query.count if hasattr(count_query, 'count') and count_query.count else len(count_query.data)

    offset = (page - 1) * limit

    msg_res = supabase.table("forum_messages") \
        .select("id, content, created_at, user_id, users!forum_messages_user_id_fkey(full_name)") \
        .eq("forum_id", forum_id) \
        .order("created_at", desc=False) \
        .range(offset, offset + limit - 1) \
        .execute()

    msg_ids = [m["id"] for m in msg_res.data]

    # Batch: likes
    likes_map = {mid: 0 for mid in msg_ids}
    user_liked_map = {mid: False for mid in msg_ids}

    if msg_ids:
        likes_res = supabase.table("forum_message_likes") \
            .select("message_id, user_id") \
            .in_("message_id", msg_ids) \
            .execute()
        for like in likes_res.data:
            mid = like["message_id"]
            likes_map[mid] = likes_map.get(mid, 0) + 1
            if like["user_id"] == user_id:
                user_liked_map[mid] = True

    messages = []
    for m in msg_res.data:
        try:
            dt = datetime.fromisoformat(m["created_at"].replace("Z", "+00:00"))
            time_str = dt.strftime("%I:%M %p")
        except Exception:
            time_str = ""

        messages.append({
            "id": m["id"],
            "text": m["content"],
            "author": m["users"]["full_name"] if m.get("users") else "Unknown",
            "authorId": m["user_id"],
            "time": time_str,
            "likes": likes_map.get(m["id"], 0),
            "likedByMe": user_liked_map.get(m["id"], False),
        })

    return {
        "success": True,
        "messages": messages,
        "pagination": _pagination_meta(page, limit, total),
    }


def post_message(forum_id, user_id, content) -> dict:
    """Insert a message and broadcast via Redis Pub/Sub."""
    res = supabase.table("forum_messages").insert({
        "forum_id": forum_id,
        "user_id": user_id,
        "content": content,
    }).execute()

    if not res.data:
        return {"success": False, "message": "Failed to send message"}

    msg = res.data[0]

    # Get author name for the broadcast payload
    user_res = supabase.table("users") \
        .select("full_name") \
        .eq("id", user_id) \
        .execute()
    author_name = user_res.data[0]["full_name"] if user_res.data else "Unknown"

    # Broadcast to Redis for SSE
    publish(f"sse:forum:{forum_id}:message", {
        "id": msg["id"],
        "text": content,
        "author": author_name,
        "authorId": user_id,
        "forum_id": forum_id,
        "time": datetime.utcnow().strftime("%I:%M %p"),
    })

    # Invalidate message cache for this forum
    invalidate(cache_keys.invalidate_forum_messages(forum_id))

    return {"success": True, "message": "Message sent"}


def toggle_like(message_id, user_id) -> dict:
    """Toggle a like on a forum message."""
    like_res = supabase.table("forum_message_likes") \
        .select("id") \
        .eq("message_id", message_id) \
        .eq("user_id", user_id) \
        .execute()

    if like_res.data:
        supabase.table("forum_message_likes") \
            .delete() \
            .eq("message_id", message_id) \
            .eq("user_id", user_id) \
            .execute()
        action = "unliked"
    else:
        supabase.table("forum_message_likes").insert({
            "message_id": message_id,
            "user_id": user_id,
        }).execute()
        action = "liked"

    return {"success": True, "action": action}
