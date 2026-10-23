-- Small key/value state such as the Telegram update offset.
CREATE TABLE kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

-- Telegram updates are stored here in the same transaction that advances the
-- offset, then processed and deleted.
CREATE TABLE telegram_inbox (
    update_id   INTEGER PRIMARY KEY,
    payload     TEXT NOT NULL,
    received_at INTEGER NOT NULL
) STRICT;

-- Notification outbox. One row per message to deliver.
CREATE TABLE notifications (
    id              TEXT PRIMARY KEY,
    consumer        TEXT NOT NULL,
    destination     TEXT NOT NULL,
    chat_id         INTEGER NOT NULL,
    thread_id       INTEGER,
    body_html       TEXT NOT NULL,
    severity        TEXT,
    source          TEXT,
    dedupe_key      TEXT,
    request_hash    TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'sending', 'sent', 'failed')),
    -- Long bodies are sent as several messages; this many were delivered.
    parts_sent      INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    lease_until     INTEGER,
    uncertain       INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX notifications_dedupe ON notifications (consumer, dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX notifications_due ON notifications (state, next_attempt_at);

-- Media jobs from the API or Telegram.
CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    owner_kind      TEXT NOT NULL CHECK (owner_kind IN ('api', 'telegram')),
    owner_id        TEXT NOT NULL,
    idempotency_key TEXT,
    request_hash    TEXT,
    action          TEXT NOT NULL,
    options         TEXT NOT NULL,
    source_kind     TEXT NOT NULL CHECK (source_kind IN ('url', 'upload', 'telegram_file')),
    source_ref      TEXT NOT NULL,
    media_index     INTEGER,
    destination     TEXT,
    chat_id         INTEGER,
    thread_id       INTEGER,
    reply_to        INTEGER,
    status_message  INTEGER,
    state           TEXT NOT NULL CHECK (state IN ('queued', 'resolving', 'downloading', 'processing',
                                                   'delivering', 'completed', 'failed', 'cancelled')),
    detail          TEXT,
    error_code      TEXT,
    error_message   TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    lease_owner     TEXT,
    lease_until     INTEGER,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    source_path     TEXT,
    source_size     INTEGER,
    source_sha256   TEXT,
    result_path     TEXT,
    result_size     INTEGER,
    result_sha256   TEXT,
    result_type     TEXT,
    input_bytes     INTEGER,
    reserved_bytes  INTEGER NOT NULL DEFAULT 0,
    delivery_uncertain INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    completed_at    INTEGER,
    expires_at      INTEGER
) STRICT;
CREATE UNIQUE INDEX jobs_idempotency ON jobs (owner_kind, owner_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX jobs_runnable ON jobs (state, lease_until);

-- One row per FFmpeg-service attempt (SDS §6.8).
CREATE TABLE remote_attempts (
    idempotency_key TEXT PRIMARY KEY,
    job_id          TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    step            TEXT NOT NULL,
    attempt         INTEGER NOT NULL,
    instance_id     TEXT,
    remote_job_id   TEXT,
    state           TEXT NOT NULL CHECK (state IN ('submitting', 'submitted', 'completed', 'failed', 'lost')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX remote_attempts_job ON remote_attempts (job_id);

-- Remote jobs whose DELETE has not reached 204 yet.
CREATE TABLE remote_cleanup (
    remote_job_id TEXT PRIMARY KEY,
    attempts      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
) STRICT;

-- Inline-button bindings; callback_data carries only the token.
CREATE TABLE callback_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    chat_id    INTEGER NOT NULL,
    thread_id  INTEGER,
    message_id INTEGER NOT NULL,
    action     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX callback_tokens_expiry ON callback_tokens (expires_at);

-- FFmpeg metadata results keyed by input SHA-256.
CREATE TABLE metadata_cache (
    sha256     TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
