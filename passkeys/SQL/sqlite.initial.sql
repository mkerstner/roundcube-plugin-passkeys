-- Roundcube passkeys plugin - initial schema (SQLite)

CREATE TABLE passkeys_credentials (
    credential_id  varchar(255) NOT NULL PRIMARY KEY,
    user_id        integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    public_key     text NOT NULL,
    sign_count     integer NOT NULL DEFAULT 0,
    aaguid         varchar(36) DEFAULT NULL,
    label          varchar(128) DEFAULT NULL,
    transports     varchar(64) DEFAULT NULL,
    prf_supported  tinyint NOT NULL DEFAULT 0,
    wrapped_secret text DEFAULT NULL,
    wrap_iv        varchar(32) DEFAULT NULL,
    created        datetime NOT NULL,
    last_used      datetime DEFAULT NULL
);

CREATE INDEX ix_passkeys_user_id ON passkeys_credentials(user_id);
