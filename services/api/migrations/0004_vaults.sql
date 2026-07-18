-- The vault: one opaque ciphertext blob per account plus a monotonic version counter.
-- Version monotonicity is a DB-level guarantee (D9): a client cannot roll the vault
-- back or skip versions even if it misbehaves.
CREATE TABLE IF NOT EXISTS vaults (
    account_id uuid PRIMARY KEY REFERENCES accounts ON DELETE CASCADE,
    version    bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    -- 32 bytes (empty sealed doc) .. 32 MiB ceiling.
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 32 AND 33554432),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES devices
);

CREATE OR REPLACE FUNCTION vault_version_monotonic() RETURNS trigger AS $$
BEGIN
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'vault version must increment by exactly 1 (old=%, new=%)',
            OLD.version, NEW.version
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_vault_version ON vaults;
CREATE TRIGGER trg_vault_version
    BEFORE UPDATE ON vaults
    FOR EACH ROW EXECUTE FUNCTION vault_version_monotonic();
