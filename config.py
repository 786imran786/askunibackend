"""
Central configuration for askUNI backend.
Loads all environment variables and provides typed config access.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Supabase ──────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SERVICE_ROLE_KEY")      # service-role key

# ── JWT ───────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

# ── Google OAuth ──────────────────────────────────────────
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

# ── Frontend ──────────────────────────────────────────────
FRONTEND_URL = os.getenv("FRONTEND_URL")
ENV = os.getenv("ENV", "development")
IS_PROD = ENV == "production"

# ── Redis ─────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "")

# ── Email (Mailjet) ──────────────────────────────────────
MJ_API_KEY = os.getenv("MJ_API_KEY")
MJ_SECRET_KEY = os.getenv("MJ_SECRET_KEY")
MAILJET_SENDER = os.getenv("MAILJET_SENDER")

# ── CORS ──────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "https://ask-uni.vercel.app",
    "https://www.ask-uni.vercel.app",
    "http://localhost:8081",
    "http://localhost:19000",
    "http://localhost:19006",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]

# ── Pagination defaults ──────────────────────────────────
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
FORUM_MSG_PAGE_SIZE = 50

# ── Cache TTLs (seconds) ─────────────────────────────────
CACHE_TTL_FEED = 60           # questions feed
CACHE_TTL_QUESTION = 120      # single question detail
CACHE_TTL_PROFILE = 300       # user profile data
CACHE_TTL_TAGS = 600          # tags list
CACHE_TTL_FORUM_MSG = 30      # forum messages

# ── Rate Limits (attempts, window_seconds) ────────────────
RATE_LIMIT_LOGIN = (5, 300)           # 5 per 5 min
RATE_LIMIT_REGISTER = (3, 600)        # 3 per 10 min
RATE_LIMIT_FORGOT_PW = (3, 900)       # 3 per 15 min
RATE_LIMIT_OTP = (5, 300)             # 5 per 5 min
RATE_LIMIT_RESEND_OTP = (3, 300)      # 3 per 5 min
RATE_LIMIT_FORUM_MSG = (30, 60)       # 30 per 1 min
RATE_LIMIT_CREATE_Q = (5, 600)        # 5 per 10 min
