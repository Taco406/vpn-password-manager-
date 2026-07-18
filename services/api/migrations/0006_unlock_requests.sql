-- Unlock/new-device approval relay. Request and response payloads are opaque E2E
-- ciphertext (pinned pairing channel) — the server only moves and expires them.
CREATE TABLE IF NOT EXISTS unlock_requests (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id        uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    desktop_device_id uuid NOT NULL REFERENCES devices,
    phone_device_id   uuid NOT NULL REFERENCES devices,
    kind              text NOT NULL CHECK (kind IN ('unlock','new_device')),
    request_payload   bytea NOT NULL CHECK (octet_length(request_payload) <= 4096),
    response_payload  bytea CHECK (response_payload IS NULL OR octet_length(response_payload) <= 4096),
    state             text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','denied','expired')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL DEFAULT now() + interval '2 minutes'
);
CREATE INDEX IF NOT EXISTS unlock_requests_account_idx ON unlock_requests (account_id, state);
