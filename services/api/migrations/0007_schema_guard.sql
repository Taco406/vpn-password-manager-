-- Zero-knowledge schema guard (D7). Fails the migration if any column could plausibly
-- hold a plaintext secret. A secret-ish column name is allowed ONLY when it is an
-- explicitly-encrypted `*_enc` column or an opaque `bytea` blob. This runs at migrate
-- time AND is re-asserted by an integration test (schema_guard).
DO $$
DECLARE
    offending text;
BEGIN
    SELECT string_agg(table_name || '.' || column_name, ', ')
    INTO offending
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND column_name ~* '(password|secret|passphrase|private_key|plaintext)'
      AND column_name NOT LIKE '%\_enc'
      AND data_type <> 'bytea';

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'zero-knowledge violation: plaintext-suspect column(s): %', offending
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$;
