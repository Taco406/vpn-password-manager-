-- Accounts. The only server-side secret is the TOTP secret, stored encrypted under
-- a server key (D8) — it protects the account/2FA, never the vault.
CREATE TABLE IF NOT EXISTS accounts (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    google_sub        text NOT NULL UNIQUE,
    email             text NOT NULL,
    -- AES-256-GCM ciphertext of the TOTP secret; bounded so no large blob can hide.
    totp_secret_enc   bytea CHECK (totp_secret_enc IS NULL OR octet_length(totp_secret_enc) <= 256),
    totp_confirmed_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);
