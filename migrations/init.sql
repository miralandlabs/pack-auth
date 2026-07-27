-- pack-auth canonical schema
-- Apply manually: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/init.sql

CREATE TABLE IF NOT EXISTS pack_auth_services (
    service_id TEXT PRIMARY KEY,
    merchant_wallet TEXT NOT NULL,
    service_url TEXT NOT NULL,
    resources_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb,
    pack_bundles JSONB,
    category TEXT,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pack_services_wallet ON pack_auth_services(merchant_wallet);
CREATE INDEX IF NOT EXISTS idx_pack_services_marketplace ON pack_auth_services(updated_at DESC, service_id) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_pack_services_tags ON pack_auth_services USING GIN(tags) WHERE status='active';

CREATE TABLE IF NOT EXISTS pack_auth_packs (
    jti UUID PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES pack_auth_services(service_id),
    payer TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    total_uses BIGINT NOT NULL CHECK(total_uses > 0),
    used_uses BIGINT NOT NULL DEFAULT 0 CHECK(used_uses >= 0 AND used_uses <= total_uses),
    resources JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pack_packs_service_issued ON pack_auth_packs(service_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_pack_packs_payer_issued ON pack_auth_packs(payer, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_pack_packs_revoked ON pack_auth_packs(service_id, revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS pack_auth_consumptions (
    consumption_id UUID PRIMARY KEY,
    jti UUID NOT NULL REFERENCES pack_auth_packs(jti),
    idempotency_key TEXT NOT NULL,
    resource TEXT NOT NULL,
    remaining_after BIGINT NOT NULL CHECK(remaining_after >= 0),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(jti, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_pack_consumptions_jti_time ON pack_auth_consumptions(jti, consumed_at DESC);

CREATE TABLE IF NOT EXISTS pack_auth_nonces (
    wallet TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(wallet, nonce)
);
CREATE INDEX IF NOT EXISTS idx_pack_nonces_expires ON pack_auth_nonces(expires_at);

CREATE TABLE IF NOT EXISTS pack_auth_signing_keys (
    kid TEXT PRIMARY KEY,
    public_jwk JSONB NOT NULL,
    active_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ
);
