-- File-transfer relay ("send to my devices"). The stored blob is opaque E2E ciphertext, sealed
-- under the account's vault key — the server only moves, size-caps, and expires it, and can never
-- read the file, its name, or any key. Column names avoid the schema-guard words (0007); nothing
-- here is sensitive (there is deliberately NO cleartext filename — the real name is sealed in the
-- blob, so the inbox shows only size + sender + time until a device downloads and decrypts it).
CREATE TABLE IF NOT EXISTS file_transfers (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    sender_device_id    uuid NOT NULL REFERENCES devices,
    -- NULL = any of the account's devices may claim it (a personal drop); else a specific device.
    recipient_device_id uuid REFERENCES devices,
    -- Cleartext plaintext size for the inbox display + quota accounting (the ciphertext length
    -- already approximates this, so it leaks nothing new).
    size_bytes          bigint NOT NULL CHECK (size_bytes >= 0),
    -- 25 MiB ciphertext ceiling — under the 32 MiB vault ceiling, sized for the recommended Nanode.
    ciphertext          bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 26214400),
    state               text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','expired')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL DEFAULT now() + interval '24 hours'
);
CREATE INDEX IF NOT EXISTS file_transfers_account_idx ON file_transfers (account_id, state);
