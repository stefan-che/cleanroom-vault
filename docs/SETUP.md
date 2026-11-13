# Setup and reference — `encryptor`

Bare-metal setup, command reference, configuration, schema and build. Overview and threat model: [README](../README.md). Rotation, backup and error codes: [MAINTENANCE.md](../MAINTENANCE.md).

## With Docker and tron-cleanroom

You do not need the steps below. `make bootstrap` in `tron-cleanroom/docker` builds the binary (`make enc`), creates the vault container from [`db.sql`](../db.sql) and generates `kek` + `config.json` (`make enc-init`). Walkthrough: [full-stack quickstart](https://github.com/stefan-che/tron-cleanroom/blob/main/docs/QUICKSTART.md).

## Bare metal

Requirements: Go 1.22+ (or Docker), MySQL 5.7+/8.x (8.4: start with `--mysql-native-password=ON`), `openssl`.

```bash
# 1. Build (Linux binary; or use Docker, see "Build" below)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ./encryptor .

# 2. Vault database: edit the CHANGE_ME password in db.sql first
sudo mysql < db.sql

# 3. KEK: a file named `kek` next to the binary, readable only by the service user
openssl rand -base64 32 > kek && chmod 600 kek

# 4. Config skeleton (must be valid JSON before any command runs)
cp config.json.example config.json

# 5. Master key: generate, keep a copy OFFLINE (password manager / safe), wrap it with the KEK
MASTER=$(openssl rand -base64 32)
./encryptor wrap_key "$MASTER"        # paste the output into "master_key"

# 6. Vault DSN: encrypt it with the master key, paste into "connect3" (the default slot)
./encryptor encrypt_bd "enc_user:<password>@tcp(127.0.0.1:3306)/encryptor"

# 7. Sanity check: prints a 64-hex fingerprint of the master key; note it down
./encryptor key_fingerprint

# 8. Round trip
./encryptor encrypt 3 "my-private-key-hex"
./encryptor decrypt 3 "<key>" "<secret>" "<salt>"
```

Run every command **from the binary's directory**: `config.json` is read from the working directory and `kek` from the directory of the executable.

On a networked MySQL, narrow the `enc_user@'%'` host in `db.sql` to the encryptor host, keep the vault port on a private network and enable TLS in the DSN (for example `...?tls=true`).

## Commands

### Encrypt

```bash
./encryptor encrypt <plaintext>                 # vault connection 3 (default)
./encryptor encrypt <connection 1-5> <plaintext>
```

```json
{"key": "<ciphertext>", "salt": "<sealed lookup id>", "secret": "<keyPart2>", "hash": "<sha256 of plaintext>"}
```

Store all four fields **plus the connection number** in your application record.

### Decrypt

```bash
./encryptor decrypt <key> <secret> <salt>                    # connection 3
./encryptor decrypt <connection 1-5> <key> <secret> <salt>
```

```json
{"result": "<plaintext>"}
```

Verify integrity on every decrypt: compare `sha256(result)` with the stored `hash`.

### Administrative commands

| Command | What it does | Needs |
|---|---|---|
| `wrap_key <master-key>` | Wraps a master key with the KEK → value for `master_key` / `previous_keys` | `kek` |
| `encrypt_bd <string>` | Encrypts a string (e.g. a DSN) with the current master key → value for `connectN` | `kek`, `master_key` |
| `decrypt_bdd <string>` | Reverses `encrypt_bd` (to inspect or migrate a DSN) | `kek`, `master_key` |
| `key_fingerprint` | Prints `sha256(master key)`: health check and value for schema migration | `kek`, `master_key` |

Success: JSON / value on stdout, exit 0. Failure: `Error code N` on stderr, exit 1 (codes in [MAINTENANCE.md](../MAINTENANCE.md#error-codes)). Missing arguments or an unknown command do **not** fail: the process prints nothing (or `...`) and exits 0. Treat output that is not the expected JSON as an error.

### Calling from an application

A standard process call: arguments in, JSON out. Example from tron-cleanroom (PHP, Symfony Process):

```php
$process = new Process([$dir.'encryptor', 'encrypt', $connect, $privateKey]);
$process->setWorkingDirectory($dir);   // where config.json lives
$process->mustRun();
$enc = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);
// store $enc['key'], $enc['salt'], $enc['secret'], $enc['hash'], $connect
```

The plaintext is passed as a process argument: run the encryptor on a dedicated host that only the calling service can access.

## Configuration

`config.json` (never commit it; it is in `.gitignore`). Template: [`config.json.example`](../config.json.example).

| Field | Content |
|---|---|
| `master_key` | Current master key, wrapped with the KEK (`wrap_key`) |
| `previous_keys` | Earlier master keys, wrapped with the KEK, so old records still decrypt after rotation. `[]` if none. |
| `connect1` … `connect5` | Vault MySQL DSNs `user:pass@tcp(host:3306)/db`, encrypted with the master key (`encrypt_bd`). Up to five vaults (e.g. per environment or shard); `3` is the default. |

`kek`: one line, the KEK itself; mode `0600`; same directory as the binary. There is no environment-variable override.

## Database schema

Table `wallet_keys` (full script in [`db.sql`](../db.sql)). Column names are historical:

| Column | Holds |
|---|---|
| `encrypted` | `matchingString`, the random lookup id (indexed) |
| `salt` | `keyPart1`, base64 (unique) |
| `key_fingerprint` | `sha256(master key)` that sealed the row, hex |

The vault DB user needs only `SELECT` and `INSERT`. The tool never updates or deletes rows. Upgrading a table created without `key_fingerprint`: see the comment block at the end of `db.sql`.

## Build

```bash
# Native
go build -o ./encryptor .

# Linux release binary from any OS via Docker
docker run --rm -v "$PWD":/src -w /src -e GOOS=linux -e GOARCH=amd64 -e CGO_ENABLED=0 golang:1.25 \
  go build -trimpath -ldflags="-s -w" -o ./encryptor .

# Tests (no MySQL needed: the vault is replaced by an in-memory map)
go test -v ./...
```

## Dependencies

- [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql): MySQL driver
- [`golang.org/x/crypto/pbkdf2`](https://pkg.go.dev/golang.org/x/crypto/pbkdf2): key derivation for wrapping
