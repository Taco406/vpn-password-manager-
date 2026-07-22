-- One-time device-enrollment codes ("scan the QR on your desktop"). A signed-in device mints a
-- code; a NEW device redeems it once, within minutes, to enroll on the SAME account — so a phone
-- can onboard by scanning a QR instead of hand-typing a server token. Only a hash of the code is
-- stored (the code itself travels in the QR); redeeming grants a session, never key material.
CREATE TABLE IF NOT EXISTS enroll_codes (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    code_hash  bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '5 minutes',
    used_at    timestamptz
);
CREATE INDEX IF NOT EXISTS enroll_codes_account_idx ON enroll_codes (account_id);
