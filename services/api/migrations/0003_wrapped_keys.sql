-- Wrapped vault-key blobs (opaque SNTL envelopes, D7). The server can never unwrap
-- these: it holds no KEK material. Length bounds keep them small and opaque.
--   wrapper_type: 1=platform, 2=phone, 3=recovery
CREATE TABLE IF NOT EXISTS wrapped_keys (
    account_id   uuid NOT NULL REFERENCES accounts ON DELETE CASCADE,
    wrapper_type smallint NOT NULL CHECK (wrapper_type IN (1,2,3)),
    device_id    uuid REFERENCES devices ON DELETE CASCADE,
    -- Stored key column so (account, wrapper_type, device) is unique even when
    -- device_id is NULL (platform/recovery wrappers are not device-scoped).
    device_key   uuid GENERATED ALWAYS AS
                     (COALESCE(device_id, '00000000-0000-0000-0000-000000000000'::uuid)) STORED,
    -- 80 bytes (platform/phone, no params) .. 512 bytes ceiling.
    blob         bytea NOT NULL CHECK (octet_length(blob) BETWEEN 80 AND 512),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, wrapper_type, device_key)
);
