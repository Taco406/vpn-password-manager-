-- One personal server = ONE account. Marks the account the built-in (bootstrap) login binds to,
-- so every sign-in path — Google, bootstrap token, join codes, phones — lands on the same
-- account_id instead of silently splitting into "bootstrap:local" vs the Google account (the root
-- cause of "0 passwords synced" on a second device). At most one account can hold the flag.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_bootstrap_owner boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS accounts_one_bootstrap_owner
    ON accounts (is_bootstrap_owner) WHERE is_bootstrap_owner;
-- Existing personal servers: the synthetic bootstrap account (if any) is the owner.
UPDATE accounts SET is_bootstrap_owner = true WHERE google_sub = 'bootstrap:local';
