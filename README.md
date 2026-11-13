# cleanroom-vault — split-key vault for per-payment wallet keys

[![CI](https://github.com/stefan-che/cleanroom-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/stefan-che/cleanroom-vault/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Part of the **tron-cleanroom** stack (required component: key vault) → [overview](https://github.com/stefan-che/tron-cleanroom) · [architecture](https://github.com/stefan-che/tron-cleanroom/blob/main/ARCHITECTURE.md) · [full-stack quickstart](https://github.com/stefan-che/tron-cleanroom/blob/main/docs/QUICKSTART.md).
> Siblings: [cleanroom-watcher](https://github.com/stefan-che/cleanroom-watcher) · [tally-bot](https://github.com/stefan-che/tally-bot).

**Status:** Production-proven: built and run in production as the processing stack of WOL, a Dubai OTC desk, 2022–2026.

**Role in crypto hygiene:** cleanroom-vault keeps the keys of thousands of per-payment transit wallets sealed, which makes per-payment isolation safe at scale.

A small Go CLI (~470 lines of Go plus tests, two dependencies). It seals each private key with its own random AES-256 key and splits that key in two: one half goes to a separate vault database, the other half goes back to the caller. One leaked database, backup, config file or source tree is not enough to recover a key.

## The problem

One fresh wallet per payment means thousands of hot private keys. The usual ways to store them each have a single point of failure:

- **Unencrypted or reversible in the app database.** One SQL dump or leaked backup drains every wallet.
- **Encrypted with a key from the app config or env.** Database and config sit on the same server and land in the same backup.
- **Encrypted with a key compiled into the code.** The key lives in git, in every build and on every laptop, and cannot be rotated cheaply.

## How it works

```
                     encrypt(privateKey)
                            │
        random AES-256 key = keyPart1 (16 B) ‖ keyPart2 (16 B)
        random lookup id   = matchingString (16 B)
                            │
     ┌──────────────────────┴──────────────────────────┐
     ▼  CALLER HALF (your app database)                ▼  VAULT HALF (separate MySQL)
  key    = AES-CFB(privateKey, keyPart1‖keyPart2)    wallet_keys row:
  secret = keyPart2                                    matchingString → keyPart1
  salt   = matchingString sealed by the master key     + fingerprint of the master key
  hash   = sha256(privateKey)
                            │
         master key + vault DSNs live in config.json,
         wrapped by the KEK, a separate file `kek` (chmod 600) next to the binary
```

- **Per-record key.** Every `encrypt` call creates a new key and lookup id. Nothing is reused.
- **Sealed link.** Only the master key turns `salt` back into the vault row id.
- **Refuses to start without its keys.** No `kek`, empty `kek` or empty `master_key`: the process exits before it opens a database connection. There is no default key.
- **Rotation.** Each vault row stores the fingerprint of the master key that sealed it. Old keys stay in `previous_keys`, so the master key can be rotated with no downtime. Rotating the KEK only re-wraps `config.json`. Recipes: [MAINTENANCE.md](MAINTENANCE.md).
- **Append-only vault.** The vault user only has `SELECT` and `INSERT`.

## Threat model: "the attacker has X; can they decrypt?"

| Attacker obtains | Can decrypt? | Why |
|---|---|---|
| Dump / backup of the **vault MySQL** | **No** | Only `keyPart1` halves and random ids. No ciphertexts, no `keyPart2`. |
| Dump / backup of the **app database** (`key`, `salt`, `secret`, `hash`) | **No** | Only `keyPart2`. `keyPart1` sits in another database, behind a `salt` that only the master key opens. |
| **Source code, git history, a built binary** | **No** | No key material is compiled in. Keys come from `config.json` + `kek` at runtime. |
| **`config.json`** alone | **No** | `master_key` is wrapped by the KEK, which is not in the file; every DSN is encrypted with the master key. |
| **`kek`** alone | **No** | Unwraps nothing without `config.json`. |
| `config.json` + `kek` (the encryptor host files) | **No** | Gives the master key and vault access, but not the caller's `key` + `secret`. |
| A former master key, after rotation | Only records it sealed | Each row is bound to its key by fingerprint. Drop an old key from `previous_keys` once its records are retired. |

**Scope:** the scheme protects data at rest and leaked copies: backups, dumps, snapshots, repositories and single servers.

**Hardening:** keep the application database and the vault (and their backups) on separate hosts with separate credentials; keep `kek` and `config.json` readable only by the service user; use TLS to the vault database; run the encryptor on a dedicated host that only the calling service can reach. Full checklist: [SECURITY.md](SECURITY.md).

## Quickstart

With tron-cleanroom, `make bootstrap` in `tron-cleanroom/docker` builds the binary, creates the vault and generates `kek` + `config.json` (see the [full-stack quickstart](https://github.com/stefan-che/tron-cleanroom/blob/main/docs/QUICKSTART.md)). On its own:

```bash
git clone https://github.com/stefan-che/cleanroom-vault && cd cleanroom-vault
go test -v ./...                    # round trip and rotation, in-memory vault, no MySQL needed
go build -o ./encryptor .
# then: vault DB, kek, master key, DSN -> docs/SETUP.md (8 steps)
./encryptor encrypt 3 "my-private-key-hex"
```

Requirements: Go 1.22+ (or Docker), MySQL 5.7+/8.x, `openssl`.

## Use it alone

cleanroom-vault knows nothing about TRON or payments. It seals any string, so any service that can run a subprocess and read JSON can use it for secrets of its own. The contract:

- `encryptor encrypt [conn 1-5] <plaintext>` → `{"key","salt","secret","hash"}`. Store all four plus the connection number (default `3`).
- `encryptor decrypt [conn 1-5] <key> <secret> <salt>` → `{"result"}`. Compare `sha256(result)` with `hash`.
- Failure: `Error code N` on stderr and a non-zero exit. Missing arguments give empty stdout with exit 0, so treat empty output as an error.
- Run it from the directory that holds `config.json`; `kek` is read from the binary's directory.

## Documentation

- [docs/SETUP.md](docs/SETUP.md): bare-metal setup, commands, configuration, schema, build.
- [MAINTENANCE.md](MAINTENANCE.md): health check, backup, upgrade, KEK and master-key rotation, error codes.
- [SECURITY.md](SECURITY.md): reporting, built-in protection, production hardening checklist.
- [db.sql](db.sql): the only vault schema.

Naming: the binary and the vault database are still called `encryptor`; the names are kept for compatibility with existing deployments.

Contributions: no external process yet; open an issue first.

## License

Licensed under the MIT License — see [LICENSE](LICENSE).

Dependencies: [`go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql), [`golang.org/x/crypto/pbkdf2`](https://pkg.go.dev/golang.org/x/crypto/pbkdf2).
