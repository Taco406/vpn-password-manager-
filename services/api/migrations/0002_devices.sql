-- Device registry. iOS devices pin a P-256 public key from the pairing ceremony.
CREATE TABLE IF NOT EXISTS devices (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    name           text NOT NULL CHECK (char_length(name) <= 64),
    platform       text NOT NULL CHECK (platform IN ('windows','macos','linux','ios')),
    status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','revoked')),
    -- SEC1 uncompressed P-256 point (65 bytes), pinned; iOS companions only.
    phone_pub_p256 bytea CHECK (phone_pub_p256 IS NULL OR octet_length(phone_pub_p256) = 65),
    push_token     text CHECK (push_token IS NULL OR char_length(push_token) <= 512),
    approved_by    uuid REFERENCES devices,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_account_idx ON devices (account_id);
