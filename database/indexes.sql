-- ================================================================
-- askUNI – Performance Indexes
-- Run this in Supabase Dashboard → SQL Editor (one-time)
-- All indexes are idempotent (IF NOT EXISTS)
-- ================================================================

-- ── Questions ────────────────────────────────────────────
-- Speeds up: feed ordering, user-specific question lists
CREATE INDEX IF NOT EXISTS idx_questions_created_at
    ON questions (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_questions_user_id
    ON questions (user_id);

-- ── Answers ──────────────────────────────────────────────
-- Speeds up: answer count per question, user answer lists
CREATE INDEX IF NOT EXISTS idx_answers_question_id
    ON answers (question_id);

CREATE INDEX IF NOT EXISTS idx_answers_user_id
    ON answers (user_id);

-- ── Votes ────────────────────────────────────────────────
-- Speeds up: vote aggregation queries (the hottest path)
-- Composite index matches the exact query pattern:
--   WHERE target_type = ? AND target_id = ? AND vote_type = ?
CREATE INDEX IF NOT EXISTS idx_votes_target
    ON votes (target_type, target_id, vote_type);

-- Speeds up: "did this user already vote?" checks
CREATE INDEX IF NOT EXISTS idx_votes_user_target
    ON votes (user_id, target_type, target_id);

-- ── Tags ─────────────────────────────────────────────────
-- Speeds up: tag lookup per question
CREATE INDEX IF NOT EXISTS idx_question_tags_question_id
    ON question_tags (question_id);

CREATE INDEX IF NOT EXISTS idx_question_tags_tag_id
    ON question_tags (tag_id);

-- ── Forum Messages ──────────────────────────────────────
-- Speeds up: message retrieval ordered by time
CREATE INDEX IF NOT EXISTS idx_forum_messages_forum_id
    ON forum_messages (forum_id, created_at);

-- ── Forum Members ───────────────────────────────────────
-- Speeds up: membership checks (is user in this forum?)
CREATE INDEX IF NOT EXISTS idx_forum_members_forum_user
    ON forum_members (forum_id, user_id);

-- ── Forum Requests ──────────────────────────────────────
-- Speeds up: pending request lookups per forum
CREATE INDEX IF NOT EXISTS idx_forum_requests_forum_status
    ON forum_requests (forum_id, status);

-- ── Users ────────────────────────────────────────────────
-- Speeds up: login, registration duplicate check
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (email);

-- ── Personal Info ───────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_personal_info_user_id
    ON personal_info (user_id);

-- ── Designation ─────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_designation_user_id
    ON designation (user_id);

-- ── General Profile ─────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_general_profile_user_id
    ON general_profile (user_id);

-- ── Forum Message Likes ─────────────────────────────────
-- Speeds up: like count + "did I like?" checks
CREATE INDEX IF NOT EXISTS idx_forum_message_likes_message
    ON forum_message_likes (message_id, user_id);
