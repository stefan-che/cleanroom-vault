-- cleanroom-vault: storage for keyPart1 (the "remote half" of every per-record AES key).
--
-- This file is the ONLY canonical vault schema. It is idempotent and is applied in two ways:
--   * bare metal: replace CHANGE_ME with a strong password, then `sudo mysql < db.sql`;
--   * docker:     tron-cleanroom/docker/docker-compose.yml mounts this file into the
--                 `app-mysql-key-storage` container; its init script substitutes CHANGE_ME with
--                 DB_PASSWORD_KEY_STORAGE on the first start (empty data directory only).
-- Database name `encryptor` and user `enc_user` are fixed; the DSN in config.json must match.

CREATE DATABASE IF NOT EXISTS encryptor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Host '%': clients in containers connect from a bridge address, never from 127.0.0.1, so a
-- user bound to '127.0.0.1' gets "ERROR 1130 Host is not allowed". Do not publish the vault
-- port to the outside world; on bare metal with a networked MySQL, narrow '%' to the
-- encryptor host's address.
--
-- mysql_native_password: the Go MySQL driver fails the caching_sha2_password handshake over a
-- non-TLS connection. MySQL 8.4 ships the plugin disabled — start the server with
-- --mysql-native-password=ON (the docker stack does).
-- Least privilege: the tool only ever needs SELECT and INSERT.
CREATE USER IF NOT EXISTS 'enc_user'@'%' IDENTIFIED WITH mysql_native_password BY 'CHANGE_ME';
GRANT SELECT, INSERT ON encryptor.* TO 'enc_user'@'%';
FLUSH PRIVILEGES;
USE encryptor;

-- Column names are historical:
--   encrypted       = matchingString (random lookup id, plaintext base64)
--   salt            = keyPart1 (base64, first 16 bytes of the AES-256 record key)
--   key_fingerprint = hex(sha256(master key)) that sealed this record (drives key rotation)
CREATE TABLE IF NOT EXISTS wallet_keys
(
    salt            varchar(255) not null,
    encrypted       varchar(512) not null,
    key_fingerprint varchar(64)  null,
    constraint wallet_keys_salt_unique unique (salt),
    index wallet_keys_encrypted_index (encrypted),
    index wallet_keys_key_fingerprint_index (key_fingerprint)
) collate = utf8mb4_unicode_ci;

-- --- Upgrading a table created without key_fingerprint ---
-- Get the fingerprint of the master key that sealed the existing rows:
--   ./encryptor key_fingerprint
-- A DEFAULT backfills every existing row in one statement and also tags rows written by an
-- older binary that does not know the column yet. The current binary always writes the
-- fingerprint explicitly, so the DEFAULT can be dropped once the upgrade is complete.
--
-- ALTER TABLE wallet_keys
--   ADD COLUMN key_fingerprint varchar(64) NOT NULL DEFAULT '<fingerprint>';
-- CREATE INDEX wallet_keys_key_fingerprint_index ON wallet_keys (key_fingerprint);
-- ALTER TABLE wallet_keys ALTER COLUMN key_fingerprint DROP DEFAULT;

-- DSN format for config.json (encrypt it with ./encryptor encrypt_bd before storing):
--   enc_user:<password>@tcp(<vault-host>:3306)/encryptor
--   docker stack: enc_user:<password>@tcp(app-mysql-key-storage:3306)/encryptor
