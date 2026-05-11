"""
Question & Answer business logic.

KEY OPTIMIZATION: Replaces the original N+1 `enrich_questions_data()` which
made 4 DB calls PER question (answers, tags, upvotes, downvotes) with batched
queries that fetch everything in ~5 total queries regardless of how many
questions are on the page.
"""
from database.supabase_client import supabase
from cache.redis_client import get_cache, set_cache, invalidate, delete_key
from cache import cache_keys
from config import (
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE,
    CACHE_TTL_FEED, CACHE_TTL_QUESTION,
)


# ── Pagination helper ────────────────────────────────────

def _parse_pagination(args):
    """Extract page & limit from request.args, with sane defaults."""
    try:
        page = max(1, int(args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        limit = min(MAX_PAGE_SIZE, max(1, int(args.get("limit", DEFAULT_PAGE_SIZE))))
    except (ValueError, TypeError):
        limit = DEFAULT_PAGE_SIZE
    return page, limit


def _pagination_meta(page: int, limit: int, total: int) -> dict:
    """Build pagination metadata dict."""
    total_pages = max(1, -(-total // limit))  # ceil division
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


# ── Batch enrichment (replaces N+1) ──────────────────────

def _enrich_questions_batch(questions_data: list) -> list:
    """
    Given a list of raw question rows (with joined users),
    enrich them with answer_count, tags, upvotes, downvotes,
    profile_photo, and verification status — all in BATCH.

    BEFORE: 4 queries × N questions = O(N) round-trips
    AFTER:  5 queries total = O(1) round-trips
    """
    if not questions_data:
        return []

    question_ids = [q["id"] for q in questions_data]
    user_ids = list(set(
        q["users"]["id"]
        for q in questions_data
        if q.get("users") and "id" in q["users"]
    ))

    # ── 1. Batch: answer counts ──────────────────────────
    # We fetch all answers for these questions and count in Python
    # (Supabase REST doesn't support GROUP BY + count per group)
    answers_res = supabase.table("answers") \
        .select("question_id") \
        .in_("question_id", question_ids) \
        .execute()

    answer_counts = {}
    for a in answers_res.data:
        qid = a["question_id"]
        answer_counts[qid] = answer_counts.get(qid, 0) + 1

    # ── 2. Batch: tags ───────────────────────────────────
    tags_res = supabase.table("question_tags") \
        .select("question_id, tags(name)") \
        .in_("question_id", question_ids) \
        .execute()

    tags_map = {}  # question_id -> [tag_name, ...]
    for t in tags_res.data:
        qid = t["question_id"]
        tag_name = t.get("tags", {}).get("name", "")
        if tag_name:
            tags_map.setdefault(qid, []).append(tag_name)

    # ── 3. Batch: all votes for these questions ──────────
    votes_res = supabase.table("votes") \
        .select("target_id, vote_type") \
        .eq("target_type", "question") \
        .in_("target_id", question_ids) \
        .execute()

    upvote_counts = {}
    downvote_counts = {}
    for v in votes_res.data:
        tid = v["target_id"]
        if v["vote_type"] == "upvote":
            upvote_counts[tid] = upvote_counts.get(tid, 0) + 1
        else:
            downvote_counts[tid] = downvote_counts.get(tid, 0) + 1

    # ── 4. Batch: author profiles ────────────────────────
    user_profiles = {}
    user_verifications = {}
    if user_ids:
        p_info = supabase.table("personal_info") \
            .select("user_id, profile_photo") \
            .in_("user_id", user_ids) \
            .execute()
        for p in p_info.data:
            user_profiles[p["user_id"]] = p.get("profile_photo")

        d_info = supabase.table("designation") \
            .select("user_id, is_college_email_verified") \
            .in_("user_id", user_ids) \
            .execute()
        for d in d_info.data:
            user_verifications[d["user_id"]] = d.get("is_college_email_verified", False)

    # ── Assemble enriched list ───────────────────────────
    enriched = []
    for q in questions_data:
        author_data = q.get("users") or {}
        if author_data and "id" in author_data:
            author_data["profile_photo"] = user_profiles.get(author_data["id"])
            author_data["is_verified"] = user_verifications.get(author_data["id"], False)

        enriched.append({
            "id": q["id"],
            "title": q["title"],
            "content": q["content"],
            "created_at": q["created_at"],
            "images": q.get("images") or [],
            "author": author_data,
            "answer_count": answer_counts.get(q["id"], 0),
            "tags": tags_map.get(q["id"], []),
            "upvotes": upvote_counts.get(q["id"], 0),
            "downvotes": downvote_counts.get(q["id"], 0),
        })

    return enriched


# ── Public service functions ──────────────────────────────

def get_questions_feed(args) -> dict:
    """
    Fetch paginated questions feed with caching.
    Returns dict ready to be jsonified.
    """
    page, limit = _parse_pagination(args)

    # Check cache
    cache_key = cache_keys.questions_feed(page)
    cached = get_cache(cache_key)
    if cached:
        return cached

    offset = (page - 1) * limit

    # Count total
    count_query = supabase.table("questions") \
        .select("id", count="exact") \
        .execute()
    total = count_query.count if hasattr(count_query, 'count') and count_query.count else len(count_query.data)

    # Fetch page
    questions_query = supabase.table("questions") \
        .select("id, title, content, created_at, images, user_id, users(id, full_name, username)") \
        .order("created_at", desc=True) \
        .range(offset, offset + limit - 1) \
        .execute()

    questions = _enrich_questions_batch(questions_query.data)

    result = {
        "success": True,
        "questions": questions,
        "pagination": _pagination_meta(page, limit, total),
    }

    set_cache(cache_key, result, CACHE_TTL_FEED)
    return result


def get_my_questions(user_id, args) -> dict:
    """Fetch paginated questions authored by a specific user."""
    page, limit = _parse_pagination(args)

    cache_key = cache_keys.user_questions(user_id, page)
    cached = get_cache(cache_key)
    if cached:
        return cached

    offset = (page - 1) * limit

    count_query = supabase.table("questions") \
        .select("id", count="exact") \
        .eq("user_id", user_id) \
        .execute()
    total = count_query.count if hasattr(count_query, 'count') and count_query.count else len(count_query.data)

    questions_query = supabase.table("questions") \
        .select("id, title, content, created_at, images, user_id, users(id, full_name, username)") \
        .eq("user_id", user_id) \
        .order("created_at", desc=True) \
        .range(offset, offset + limit - 1) \
        .execute()

    questions = _enrich_questions_batch(questions_query.data)

    result = {
        "success": True,
        "questions": questions,
        "pagination": _pagination_meta(page, limit, total),
    }

    set_cache(cache_key, result, CACHE_TTL_FEED)
    return result


def get_my_answered_questions(user_id, args) -> dict:
    """Fetch questions that a user has answered."""
    page, limit = _parse_pagination(args)

    cache_key = cache_keys.user_answers(user_id, page)
    cached = get_cache(cache_key)
    if cached:
        return cached

    # Get all question_ids this user answered
    answers_query = supabase.table("answers") \
        .select("question_id") \
        .eq("user_id", user_id) \
        .execute()

    question_ids = list(set(a["question_id"] for a in answers_query.data))

    if not question_ids:
        return {"success": True, "questions": [], "pagination": _pagination_meta(1, limit, 0)}

    total = len(question_ids)

    # Paginate over the question_ids
    paginated_ids = question_ids[((page - 1) * limit):(page * limit)]

    if not paginated_ids:
        return {"success": True, "questions": [], "pagination": _pagination_meta(page, limit, total)}

    questions_query = supabase.table("questions") \
        .select("id, title, content, created_at, images, user_id, users(id, full_name, username)") \
        .in_("id", paginated_ids) \
        .order("created_at", desc=True) \
        .execute()

    questions = _enrich_questions_batch(questions_query.data)

    result = {
        "success": True,
        "questions": questions,
        "pagination": _pagination_meta(page, limit, total),
    }

    set_cache(cache_key, result, CACHE_TTL_FEED)
    return result


def get_question_detail(question_id) -> dict:
    """Fetch a single question with its answers, optimised."""
    cache_key = cache_keys.question_detail(question_id)
    cached = get_cache(cache_key)
    if cached:
        return cached

    # 1. Get question
    question_query = supabase.table("questions") \
        .select("id, title, content, created_at, images, views, user_id, users(id, full_name, username)") \
        .eq("id", question_id) \
        .execute()

    if not question_query.data:
        return None

    question = question_query.data[0]

    # 2. Increment view count (fire-and-forget, don't block response)
    try:
        supabase.table("questions") \
            .update({"views": (question.get("views") or 0) + 1}) \
            .eq("id", question_id) \
            .execute()
    except Exception:
        pass

    # 3. Get answers
    answers_query = supabase.table("answers") \
        .select("id, content, created_at, images, is_accepted, user_id, users(id, full_name, username)") \
        .eq("question_id", question_id) \
        .order("created_at", desc=True) \
        .execute()

    # 4. Collect all user IDs (question author + answer authors)
    user_ids = set()
    if question.get("users") and "id" in question["users"]:
        user_ids.add(question["users"]["id"])
    for a in answers_query.data:
        if a.get("users") and "id" in a["users"]:
            user_ids.add(a["users"]["id"])
    user_ids = list(user_ids)

    # 5. Batch: profiles + verification
    user_profiles = {}
    user_verifications = {}
    if user_ids:
        p_info = supabase.table("personal_info") \
            .select("user_id, profile_photo") \
            .in_("user_id", user_ids).execute()
        for p in p_info.data:
            user_profiles[p["user_id"]] = p.get("profile_photo")

        d_info = supabase.table("designation") \
            .select("user_id, is_college_email_verified") \
            .in_("user_id", user_ids).execute()
        for d in d_info.data:
            user_verifications[d["user_id"]] = d.get("is_college_email_verified", False)

    # 6. Enrich question author
    if question.get("users") and "id" in question["users"]:
        question["users"]["profile_photo"] = user_profiles.get(question["users"]["id"])
        question["users"]["is_verified"] = user_verifications.get(question["users"]["id"], False)

    # 7. Batch: all answer votes
    answer_ids = [a["id"] for a in answers_query.data]
    answer_upvotes = {}
    answer_downvotes = {}
    if answer_ids:
        a_votes_res = supabase.table("votes") \
            .select("target_id, vote_type") \
            .eq("target_type", "answer") \
            .in_("target_id", answer_ids) \
            .execute()
        for v in a_votes_res.data:
            if v["vote_type"] == "upvote":
                answer_upvotes[v["target_id"]] = answer_upvotes.get(v["target_id"], 0) + 1
            else:
                answer_downvotes[v["target_id"]] = answer_downvotes.get(v["target_id"], 0) + 1

    # 8. Build answers list
    answers = []
    for a in answers_query.data:
        author_data = a.get("users") or {}
        if author_data and "id" in author_data:
            author_data["profile_photo"] = user_profiles.get(author_data["id"])
            author_data["is_verified"] = user_verifications.get(author_data["id"], False)

        answers.append({
            "id": a["id"],
            "content": a["content"],
            "created_at": a["created_at"],
            "images": a.get("images") or [],
            "author": author_data,
            "is_accepted": a["is_accepted"],
            "upvotes": answer_upvotes.get(a["id"], 0),
            "downvotes": answer_downvotes.get(a["id"], 0),
        })

    # 9. Tags
    tags_query = supabase.table("question_tags") \
        .select("tags(name)") \
        .eq("question_id", question_id) \
        .execute()

    # 10. Question votes
    q_votes_res = supabase.table("votes") \
        .select("vote_type") \
        .eq("target_type", "question") \
        .eq("target_id", question_id) \
        .execute()
    q_upvotes = sum(1 for v in q_votes_res.data if v["vote_type"] == "upvote")
    q_downvotes = sum(1 for v in q_votes_res.data if v["vote_type"] == "downvote")

    result = {
        "success": True,
        "question": {
            "id": question["id"],
            "title": question["title"],
            "content": question["content"],
            "created_at": question["created_at"],
            "images": question.get("images") or [],
            "author": question["users"],
            "views": (question.get("views") or 0) + 1,
            "tags": [t["tags"]["name"] for t in tags_query.data if t.get("tags")],
            "upvotes": q_upvotes,
            "downvotes": q_downvotes,
        },
        "answers": answers,
    }

    set_cache(cache_key, result, CACHE_TTL_QUESTION)
    return result


# ── Cache invalidation triggers ───────────────────────────

def invalidate_question_caches(question_id=None):
    """Call after creating/editing a question or adding an answer/vote."""
    invalidate(cache_keys.INVALIDATE_QUESTIONS)
    invalidate(cache_keys.INVALIDATE_USER_QUESTIONS)
    invalidate(cache_keys.INVALIDATE_USER_ANSWERS)
    if question_id:
        delete_key(cache_keys.question_detail(question_id))
