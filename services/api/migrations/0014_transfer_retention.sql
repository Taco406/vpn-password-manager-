-- File-transfer retention controls (space management). The sender chooses, per transfer, whether
-- it is deleted the moment a device downloads it, expires after N days (the existing behaviour,
-- now with a caller-chosen TTL), or is kept permanently ("filed" — no auto-expiry, bounded only by
-- the account storage quota). Both columns are additive and defaulted so every existing transfer
-- keeps its current behaviour (TTL expiry, no delete-on-download). The blob stays opaque ciphertext.
ALTER TABLE file_transfers ADD COLUMN IF NOT EXISTS delete_on_download boolean NOT NULL DEFAULT false;
ALTER TABLE file_transfers ADD COLUMN IF NOT EXISTS permanent boolean NOT NULL DEFAULT false;
