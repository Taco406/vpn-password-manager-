-- Attack monitor (v0.1.41): a durable log of security-relevant auth outcomes and an
-- optional temporary IP ban list. Column names avoid the schema-guard words
-- (password/secret/…) — nothing here is sensitive: no tokens, no plaintext.

CREATE TABLE IF NOT EXISTS security_events (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The account the event relates to, when known (many failures are pre-auth ⇒ NULL).
    account_id uuid REFERENCES accounts ON DELETE CASCADE,
    -- login_ok | login_fail_bootstrap | google_reject | totp_fail | totp_lockout |
    -- refresh_reuse | rate_limited | banned_block | device_new
    kind       text NOT NULL CHECK (char_length(kind) <= 40),
    -- The caller's IP (the real peer address). NULL only under the test harness.
    ip         inet,
    -- Short, non-sensitive context (e.g. the rate-limited action name).
    detail     text CHECK (detail IS NULL OR char_length(detail) <= 200),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_events_created_idx ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS security_events_ip_idx ON security_events (ip, created_at DESC);

-- Temporary IP bans (opt-in auto-ban + the manual "block this IP" button). Rows with a
-- NULL `until` are permanent (manual bans); expired rows are ignored and swept lazily.
CREATE TABLE IF NOT EXISTS banned_ips (
    ip         inet PRIMARY KEY,
    reason     text CHECK (reason IS NULL OR char_length(reason) <= 200),
    until      timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
