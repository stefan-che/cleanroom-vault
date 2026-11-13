# Operations runbook — `encryptor`

Copy-paste recipes for the operator. Each section is self-contained.

**One rule for everything:** run commands **from the directory that holds the binary**
(`encryptor`, `config.json` and `kek` live together):

```bash
cd /path/to/encryptor
```

> `kek` and `config.json` are secrets. Without them the data can **never** be decrypted again.
> Do not delete them without a fresh backup and never publish them (git, chats, tickets, mail).

## Contents

- [Health check](#health-check)
- [Backup](#backup)
- [Upgrade the binary](#upgrade-the-binary)
- [Rotate the KEK](#rotate-the-kek)
- [Rotate the master key](#rotate-the-master-key)
- [Error codes](#error-codes)
- [Never do this](#never-do-this)

---

## Health check

```bash
./encryptor key_fingerprint
```

- A 64-character hex string → **all good**. Record it; compare after every change.
- `Error code 6` → no `kek` file next to the binary (or it is empty).
- `Error code 7` → `master_key` in `config.json` is empty.

---

## Backup

Regularly, and always before any change below. Store copies **off this host**.

```bash
cp kek          /secure/location/kek.backup
cp config.json  /secure/location/config.json.backup
mysqldump -u enc_user -p -h 127.0.0.1 encryptor > /secure/location/encryptor-db.sql
```

Also keep the **plaintext master key** in an offline secret store (password manager, safe).
It is required to rotate the KEK.

---

## Upgrade the binary

Only the `encryptor` file changes. `kek`, `config.json` and the database stay as they are.

```bash
# 0. Backup (see above)
# 1. Build the new version
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ./encryptor .
# 2. Replace the old binary in place (keep kek and config.json next to it)
# 3. Verify — must print the same fingerprint as before
./encryptor key_fingerprint
```

---

## Rotate the KEK

**When:** the `kek` file may have been exposed. Safe operation: the master key and the database
do not change, only the wrapping. **Requires** the plaintext master key from offline storage.

```bash
# 1. Backup
cp kek /secure/location/kek.backup
cp config.json /secure/location/config.json.backup

# 2. Record the current fingerprint
./encryptor key_fingerprint

# 3. New KEK
openssl rand -base64 32 > ./kek
chmod 600 ./kek

# 4. Re-wrap the master key with the new KEK
./encryptor wrap_key '<plaintext-master-key>'
```

Put the output into `config.json` → `master_key`. For every entry in `previous_keys`, run
`./encryptor wrap_key '<that-plaintext-key>'` and replace it as well.

```bash
# 5. Verify — must match the fingerprint from step 2
./encryptor key_fingerprint
```

---

## Rotate the master key

**When:** the master key may have been exposed, or on a scheduled rotation. Take a full backup
first. The vault DSNs (`connect1`–`connect5`) are encrypted with the **current** master key, so
they are re-encrypted as part of the procedure. Old records keep decrypting through
`previous_keys`.

```bash
# 1. Full backup, including the database
cp kek /secure/location/kek.backup
cp config.json /secure/location/config.json.backup
mysqldump -u enc_user -p -h 127.0.0.1 encryptor > /secure/location/encryptor-db.sql

# 2. While the old key is current — decrypt every filled connectN
./encryptor decrypt_bdd '<value of connectN>'
#    keep the DSNs in a temporary protected file

# 3. New master key — store it offline
openssl rand -base64 32
```

4. Edit `config.json`:
   - move the **old** `master_key` value into `previous_keys`;
   - wrap the **new** key and put the result into `master_key`:
     ```bash
     ./encryptor wrap_key '<new-master-key>'
     ```
   Result: `master_key` = new, `previous_keys` = `["<old wrapped>", ...]`.

5. Re-encrypt every DSN from step 2 with the new key and put each into its `connectN`:
   ```bash
   ./encryptor encrypt_bd '<dsn>'
   ```

6. Optional — if the table still carries a column `DEFAULT` from a schema upgrade, point it to the
   new key:
   ```bash
   ./encryptor key_fingerprint     # prints the NEW fingerprint
   ```
   ```sql
   ALTER TABLE wallet_keys ALTER COLUMN key_fingerprint SET DEFAULT '<new-fingerprint>';
   ```

7. Verify: `key_fingerprint` prints the new value, an **old** record still decrypts and a new
   `encrypt` → `decrypt` round trip works. Then delete the temporary DSN file.

Remove an old key from `previous_keys` only after every record it sealed has been retired.

---

## Error codes

All errors are printed to stderr and the process exits non-zero.

| Message | Meaning | Action |
|---|---|---|
| `Error code 1` | `config.json` not found | run from the directory that contains `config.json` |
| `Error code 2` | `config.json` is not valid JSON | restore from backup |
| `Error code 3` | cannot open the vault DB driver | check the `connectN` DSN |
| `Error code 4` | cannot write to the vault | check MySQL availability and the user's `INSERT` grant |
| `Error code 5` | cannot decrypt the record / vault read failed | wrong input, or the sealing key is missing from `master_key` / `previous_keys` |
| `Error code 6` | KEK not found | check `ls -l ./kek` next to the binary; it must be non-empty |
| `Error code 7` | `master_key` is empty | insert the wrapped master key or restore from backup |
| `Invalid connection number` | connection number outside 1–5 | use 1–5 |

---

## Never do this

- Delete or overwrite `kek` / `config.json` without a fresh backup.
- Publish `kek` or `config.json` anywhere.
- Rotate the master key without a full backup.
- Move the binary to another directory without moving `kek` with it.
- Hand-edit `master_key`, `previous_keys` or `connect*` with anything other than the output of
  `wrap_key` / `encrypt_bd`.
