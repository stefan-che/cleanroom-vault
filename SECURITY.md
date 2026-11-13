# Security — cleanroom-vault

**Reporting a security issue.** Use the single channel of the stack: [tron-cleanroom SECURITY.md](https://github.com/stefan-che/tron-cleanroom/blob/main/SECURITY.md). Report privately via [GitHub security advisories](https://github.com/stefan-che/tron-cleanroom/security/advisories/new), not in a public issue.

## Built-in protection

- **Split keys:** a random AES-256 key per record, split in two: one half in the vault database, the other with the caller.
- **KEK-wrapped master key:** the master key is never in code. It sits in `config.json`, wrapped by a KEK kept in a separate `kek` file. Vault DSNs are encrypted with the master key.
- **Refuses to start without its keys:** a missing or empty `kek` or an empty `master_key` stops the process before any database connection. There is no default key.
- **Key rotation:** master-key rotation by fingerprint with `previous_keys`, with no downtime; KEK rotation re-wraps the config only ([MAINTENANCE.md](MAINTENANCE.md)).
- **Append-only vault:** the vault database user has `SELECT` and `INSERT` only.
- **Integrity check:** every record carries `hash = sha256(plaintext)`; the caller compares it with `sha256(result)` after decryption.

## Production hardening checklist

- Keep the application database and the vault — and their backups — on separate hosts with separate credentials.
- Use TLS for the connection to the vault database and keep the vault port on a private network.
- Set file permissions `600` on `kek` and `config.json`, owned by the service user.
- Generate the KEK and master key as random 32-byte values (`openssl rand -base64 32`) and store a copy of the master key offline.
- Rotate the master key and the KEK on a schedule ([MAINTENANCE.md](MAINTENANCE.md)); remove an old key from `previous_keys` once its records are retired.
- Run the encryptor on a dedicated host that only the calling service can reach, and protect it like a signing service.
- Compare `sha256(result)` with the stored `hash` on every decrypt.
