package main

import "testing"

// Fixtures. testK0 / testK1 are dummy test master keys (used nowhere outside tests).
// testK0Fingerprint is the expected fingerprint of testK0 (hex SHA-256), in the same
// format that `./encryptor key_fingerprint` prints for the db.sql migration.
const (
	testK0            = "TestMasterKey_v0_fixture_not_a_real_secret"
	testK0Fingerprint = "f0d9b4bbb63f229304b85b4af1c9327474e3f48e90496f0ce307d597d688c1d7"
	testK1            = "TestMasterKey_v1_fixture_not_a_real_secret"
)

// memRow is a row of the in-memory stand-in for the wallet_keys table.
type memRow struct {
	keyPart     string
	fingerprint string
}

// newMemDB swaps the DB access points for an in-memory map so the real
// encrypt/decryptWithKeys run without MySQL. Restores the real functions after the test.
func newMemDB(t *testing.T) map[string]memRow {
	t.Helper()
	store := map[string]memRow{}
	storeKeyPart = func(matchingString, keyPart, keyFingerprint string) {
		store[matchingString] = memRow{keyPart: keyPart, fingerprint: keyFingerprint}
	}
	loadKeyPart = func(matchingString string) (string, string, bool) {
		r, ok := store[matchingString]
		return r.keyPart, r.fingerprint, ok
	}
	t.Cleanup(func() {
		storeKeyPart = saveKeyPartToRemoteDB
		loadKeyPart = getKeyPartFromRemoteDB
	})
	return store
}

// setKeys sets the current key and the iteration order (current, then previous).
func setKeys(current string, previous ...string) {
	currentKey = current
	allKeys = append([]string{current}, previous...)
}

func TestFingerprintIsStable(t *testing.T) {
	got := fingerprint(testK0)
	if got != testK0Fingerprint {
		t.Fatalf("K0 fingerprint = %s, want %s (fingerprint must be deterministic)", got, testK0Fingerprint)
	}
	if len(got) != 64 {
		t.Fatalf("fingerprint length %d, want 64 hex characters", len(got))
	}
	if fingerprint(testK0) == fingerprint(testK1) {
		t.Fatal("different keys produced the same fingerprint")
	}
}

func TestAESRoundTrip(t *testing.T) {
	for _, plaintext := range []string{"1 2 3", "", "private key ☺", "user:pass@tcp(127.0.0.1:3306)/db"} {
		enc := aesEncrypt(plaintext, testK0)
		if dec := aesDecrypt(enc, testK0); dec != plaintext {
			t.Errorf("round-trip: got %q, want %q", dec, plaintext)
		}
	}
}

func TestAESWrongKeyDoesNotRecover(t *testing.T) {
	enc := aesEncrypt("1 2 3", testK0)
	if dec := aesDecrypt(enc, testK1); dec == "1 2 3" {
		t.Fatal("decrypting with a foreign key returned the plaintext: the key does not protect the data")
	}
}

// Base case: encrypt "1 2 3" and immediately decrypt it with the same key.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	newMemDB(t)
	setKeys(testK0)

	salt, secret, ct := encrypt("1 2 3")

	got, ok := decryptWithKeys(ct, secret, salt)
	if !ok {
		t.Fatal("freshly encrypted value did not decrypt with the current key")
	}
	if got != "1 2 3" {
		t.Fatalf("got %q, want %q", got, "1 2 3")
	}
}

// Rotation: the old key moves to previous_keys; old records must stay readable,
// new ones are created with the new key.
func TestRotationKeepsOldRecordsReadable(t *testing.T) {
	newMemDB(t)

	// Record created with the old key K0.
	setKeys(testK0)
	oldSalt, oldSecret, oldCt := encrypt("1 2 3")

	// Rotation: current key is K1, K0 moves to previous_keys.
	setKeys(testK1, testK0)

	// The old record is still readable (via previous_keys + fingerprint matching).
	got, ok := decryptWithKeys(oldCt, oldSecret, oldSalt)
	if !ok || got != "1 2 3" {
		t.Fatalf("old record unreadable after rotation: ok=%v got=%q", ok, got)
	}

	// A new record is created with K1 and is readable too.
	newSalt, newSecret, newCt := encrypt("4 5 6")
	got, ok = decryptWithKeys(newCt, newSecret, newSalt)
	if !ok || got != "4 5 6" {
		t.Fatalf("new record (K1) unreadable: ok=%v got=%q", ok, got)
	}
}

// Negative check: if the old key is dropped from the config (not kept in
// previous_keys), records encrypted with it can no longer be decrypted.
func TestDroppingOldKeyBreaksOldRecords(t *testing.T) {
	newMemDB(t)

	setKeys(testK0)
	oldSalt, oldSecret, oldCt := encrypt("1 2 3")

	// Rotation without keeping K0 in previous_keys: new key only.
	setKeys(testK1)

	if _, ok := decryptWithKeys(oldCt, oldSecret, oldSalt); ok {
		t.Fatal("old-key record decrypted without K0: backward compatibility check is broken")
	}
}

// The per-record fingerprint identifies the right key: even when both keys are known,
// the one that actually sealed the record is chosen (matchingString + fingerprint match).
func TestFingerprintStoredPerRecord(t *testing.T) {
	store := newMemDB(t)

	setKeys(testK0)
	salt, _, _ := encrypt("1 2 3")

	ms := decryptMatchingString(salt) // recover matchingString with the current key
	row, ok := store[ms]
	if !ok {
		t.Fatal("record not found by matchingString")
	}
	if row.fingerprint != testK0Fingerprint {
		t.Fatalf("record fingerprint is %s, want K0 fingerprint %s", row.fingerprint, testK0Fingerprint)
	}
}
