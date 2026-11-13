# CLAUDE.md — cleanroom-vault

Technical guide for engineers and AI agents. Product overview and threat model: [README.md](README.md).
Operator recipes: [MAINTENANCE.md](MAINTENANCE.md).

## What this is
A single-binary Go CLI (`package main`, module `github.com/stefan-che/cleanroom-vault`, Go 1.22) that seals wallet private keys
with a split per-record AES-256 key: half in a dedicated vault MySQL, half returned to the caller.
The linking master key is KEK-wrapped in `config.json`; the KEK is a file next to the binary.
Stateless between calls: one process per operation, arguments in, JSON on stdout.

## How it fits the stack
Part of a self-hosted crypto payment stack:
- [`tron-cleanroom`](https://github.com/stefan-che/tron-cleanroom) — the **only caller**. When it generates a transit
  wallet it runs `enc/encryptor encrypt <connect> <privateKey>` (working dir = `enc/`, see
  `app/Services/Wallet/KeyManager.php`) and stores `key`, `salt`, `secret`, `hash` and the
  connection number (`connect_type`) on the wallet row. To sign a sweep it runs
  `decrypt <connect> <key> <secret> <salt>` (`Wallet::decPrivateKeyFromManager`). It also uses
  `encrypt_bd` for its own backup copies.
- [`cleanroom-watcher`](https://github.com/stefan-che/cleanroom-watcher) — TRON scanner; does not talk to this tool.

## File map
| File | Contents |
|---|---|
| `main.go` | CLI dispatch (`main`), KEK resolution, key loading, encrypt/decrypt core, AES helpers, MySQL access |
| `config.go` | `Config` struct and `readConfig()` (reads `./config.json` from the working directory) |
| `main_test.go` | Unit tests; vault replaced by an in-memory map |
| `db.sql` | Vault schema (`wallet_keys`), least-privilege user, upgrade snippet for `key_fingerprint` |
| `config.json.example` | Config skeleton with placeholders |
| `MAINTENANCE.md` | Backup, upgrade, KEK / master-key rotation, error table |

## Key functions (`main.go`)
| Function | Role |
|---|---|
| `main()` | `readConfig()` first, then switch on `os.Args[1]`: `encrypt`, `decrypt`, `encrypt_bd`, `decrypt_bdd`, `wrap_key`, `key_fingerprint`. Missing args → silent return. Default connection `"3"`. |
| `resolveKEK()` | Reads `kek` from `filepath.Dir(os.Executable())`, trims it; missing/empty → `Error code 6`. |
| `loadKeys()` | Unwraps `master_key` → `currentKey`; builds `allKeys = [current, previous_keys...]`. Empty `master_key` → `Error code 7`. Always called before `initDBConnection`. |
| `fingerprint(key)` | `hex(sha256(key))`, stored per vault row. |
| `initDBConnection(n)` | Decrypts `connectN` with the master key, `sql.Open("mysql", dsn)`. |
| `encrypt(plaintext)` | New `keyPart1`, `keyPart2` (16 B each) and `matchingString` (16 B) → stores `(matchingString, keyPart1, fingerprint(currentKey))` via `storeKeyPart` → AES-256-CFB with random IV. Returns `(salt, secret, key)`. |
| `decryptWithKeys(...)` | For each key in `allKeys`: unseal `salt` → `matchingString` → `loadKeyPart` → skip on miss or fingerprint mismatch → decrypt. Returns `(plaintext, ok)`. |
| `decrypt(...)` | CLI wrapper: `ok=false` → `Error code 5`. |
| `aesEncrypt` / `aesDecrypt` | Wrapping primitive: PBKDF2-SHA256(password, salt=password, 4096 iters, 32 B) + AES-CFB, base64 output. Used for KEK→master key, master key→`salt`, master key→DSNs. |
| `storeKeyPart` / `loadKeyPart` | Package-level function variables pointing at `saveKeyPartToRemoteDB` / `getKeyPartFromRemoteDB`; tests swap them. |

## Data contracts
- `encrypt` stdout: `{"key","salt","secret","hash"}` — all strings; `hash = sha256(plaintext)` hex.
- `decrypt` stdout: `{"result"}`.
- Vault row (`wallet_keys`): `encrypted = matchingString` (base64), `salt = keyPart1` (base64,
  unique), `key_fingerprint` (hex, 64). Names are historical — do not rename, existing
  deployments depend on them.
- `config.json`: `master_key`, `previous_keys[]` (KEK-wrapped), `connect1..5` (master-key-encrypted DSNs).

## Error codes
All via `log.Fatal` → stderr, exit 1.

| Code | Where | Meaning |
|---|---|---|
| 1 | `readConfig` | `config.json` missing in working dir |
| 2 | `readConfig` | `config.json` invalid JSON |
| 3 | `initDBConnection` | `sql.Open` failed |
| 4 | `saveKeyPartToRemoteDB` | INSERT failed |
| 5 | `getKeyPartFromRemoteDB`, `decrypt` | vault SELECT error, or no key in `allKeys` matched |
| 6 | `resolveKEK` | KEK file missing / empty |
| 7 | `loadKeys` | `master_key` empty |
| `Invalid connection number` | `initDBConnection` | connection not in 1–5 |

## Invariants — keep them
- **No key material in code.** Keys come only from `config.json` + `kek`. Test fixtures are
  obviously fake strings.
- **Fail-closed order:** `readConfig` → `loadKeys` (KEK) → `initDBConnection`. Never open the
  vault before the keys are loaded; never fall back to a default key.
- **Wire format is frozen.** `aesEncrypt`/`aesDecrypt` and the record cipher are what existing
  `salt`, `connect*` and `key` values were produced with. Changing them breaks every stored record.
  A new scheme needs a new, versioned code path plus migration — not an in-place edit.
- **Vault is append-only.** Only `INSERT` and `SELECT`; the DB user has no other grants.
- **Fingerprint written explicitly** on every insert.
- Output contract (JSON field names, default connection `3`) is consumed by `tron-cleanroom`.

## Recipes
**Run checks.**
```bash
docker run --rm -v "$PWD":/src -w /src golang:1.22 sh -c "go build ./... && go vet ./... && go test -v ./..."
```

**Add a test.** Call `newMemDB(t)` (swaps the vault for a map and restores it in `t.Cleanup`),
`setKeys(current, previous...)` to emulate `master_key` / `previous_keys`, then use `encrypt` and
`decryptWithKeys`. Existing tests: fingerprint stability, AES round trip, wrong-key rejection,
full encrypt/decrypt, rotation keeps old records, dropping an old key breaks old records,
per-record fingerprint.

**Add a CLI command.** New `case` in `main()`; call `loadKeys()` if it needs the master key and
`initDBConnection` + `defer db.Close()` if it needs the vault; print JSON to stdout; use a new
`Error code N` for fatal paths and add it to the tables here and in `MAINTENANCE.md`.

**Add a vault slot.** Add `ConnectN` to `Config` (`config.go`), a `case "N"` in
`initDBConnection`, and a key in `config.json.example`.

**Rotate keys.** Operator procedure in `MAINTENANCE.md` (KEK: re-wrap only; master key: move to
`previous_keys`, re-encrypt DSNs). Code needs no change.

## Conventions
- Single package `main`; comments and messages are in English.
- `gofmt`; no new dependencies without a reason.
- Secrets (`config.json`, `kek`) and binaries are git-ignored.
