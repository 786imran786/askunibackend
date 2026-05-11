"""
Centralised cache key patterns.
Keeps key naming consistent and makes invalidation straightforward.
"""


# ── Questions ─────────────────────────────────────────────
def questions_feed(page: int) -> str:
    return f"questions:feed:page:{page}"

def question_detail(question_id) -> str:
    return f"question:{question_id}"

def user_questions(user_id, page: int) -> str:
    return f"user:{user_id}:questions:page:{page}"

def user_answers(user_id, page: int) -> str:
    return f"user:{user_id}:answers:page:{page}"


# ── Tags ──────────────────────────────────────────────────
def all_tags() -> str:
    return "tags:all"


# ── Forums ────────────────────────────────────────────────
def forum_messages(forum_id, page: int) -> str:
    return f"forum:{forum_id}:messages:page:{page}"

def forums_list() -> str:
    return "forums:list"


# ── Profile ───────────────────────────────────────────────
def user_profile(user_id) -> str:
    return f"user:{user_id}:profile"


# ── Rate Limiting ─────────────────────────────────────────
def rate_limit(endpoint: str, identifier: str) -> str:
    return f"ratelimit:{endpoint}:{identifier}"


# ── Invalidation patterns ────────────────────────────────
INVALIDATE_QUESTIONS = "questions:*"
INVALIDATE_USER_QUESTIONS = "user:*:questions:*"
INVALIDATE_USER_ANSWERS = "user:*:answers:*"
INVALIDATE_TAGS = "tags:*"

def invalidate_forum_messages(forum_id) -> str:
    return f"forum:{forum_id}:messages:*"

def invalidate_question(question_id) -> str:
    return f"question:{question_id}"

def invalidate_user_profile(user_id) -> str:
    return f"user:{user_id}:profile"
