-- Allow wrapper_type 4 (Wrapper D — a user master password) so the password-wrapped vault key can
-- be escrowed here, enabling "sign in + master password" unlock on a new device. Still fully opaque:
-- the server holds no KEK and can never unwrap it (D7). Idempotent.
ALTER TABLE wrapped_keys DROP CONSTRAINT IF EXISTS wrapped_keys_wrapper_type_check;
ALTER TABLE wrapped_keys
    ADD CONSTRAINT wrapped_keys_wrapper_type_check CHECK (wrapper_type IN (1, 2, 3, 4));
