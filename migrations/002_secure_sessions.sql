CREATE TABLE IF NOT EXISTS pack_auth_sessions (
    session_hash BYTEA PRIMARY KEY,
    jti UUID NOT NULL UNIQUE REFERENCES pack_auth_packs(jti),
    wallet TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pack_sessions_expires ON pack_auth_sessions(expires_at);
