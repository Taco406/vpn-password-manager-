-- Master-password sign-in (the ONE login): the account stores the public Argon2 salt and the
-- SHA-256 of the client's HKDF login proof. The proof is derived from the password's KEK with a
-- one-way step, so the server can verify the password without ever being able to unwrap the
-- vault key — sign-in stays zero-knowledge.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS pw_auth_salt bytea;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS pw_auth_hash bytea;
