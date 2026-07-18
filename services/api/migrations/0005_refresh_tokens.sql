-- Refresh tokens: only the SHA-256 hash is stored (never the token). Rotation chains
-- allow reuse-detection — replaying a rotated token revokes the whole chain.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    device_id  uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    parent_id  uuid REFERENCES refresh_tokens,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_account_idx ON refresh_tokens (account_id);

-- Per-account TOTP brute-force lockout state.
CREATE TABLE IF NOT EXISTS totp_lockouts (
    account_id     uuid PRIMARY KEY REFERENCES accounts ON DELETE CASCADE,
    failed_count   int NOT NULL DEFAULT 0,
    locked_until   timestamptz
);
