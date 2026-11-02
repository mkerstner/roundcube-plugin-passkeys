ALTER TABLE passkeys_credentials ADD COLUMN stale smallint NOT NULL DEFAULT 0;
