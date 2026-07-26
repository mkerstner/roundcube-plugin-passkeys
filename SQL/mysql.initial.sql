-- Roundcube passkeys plugin - initial schema (MySQL / MariaDB)

CREATE TABLE `passkeys_credentials` (
    `credential_id`  varchar(255)     NOT NULL,
    `user_id`        int(10) UNSIGNED NOT NULL,
    `public_key`     text             NOT NULL,
    `sign_count`     int(10) UNSIGNED NOT NULL DEFAULT 0,
    `aaguid`         varchar(36)      DEFAULT NULL,
    `label`          varchar(128)     DEFAULT NULL,
    `transports`     varchar(64)      DEFAULT NULL,
    `prf_supported`  tinyint(1)       NOT NULL DEFAULT 0,
    `wrapped_secret` text             DEFAULT NULL,
    `wrap_iv`        varchar(32)      DEFAULT NULL,
    `created`        datetime         NOT NULL,
    `last_used`      datetime         DEFAULT NULL,
    PRIMARY KEY (`credential_id`),
    CONSTRAINT `user_id_fk_passkeys` FOREIGN KEY (`user_id`)
        REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE,
    INDEX `user_passkeys_index` (`user_id`)
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
