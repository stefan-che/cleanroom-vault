package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/pbkdf2"
)

const (
	keySize    = 32
	iterations = 4096

	// kekEnv is an optional KEK override via an environment variable (handy for one-off
	// runs/containers). kekFileName is the fixed name of the KEK file next to the binary:
	// a persistent source that survives logout and reboot. File mode is 0600.
	kekEnv      = "ENCRYPTOR_KEK"
	kekFileName = "kek"
)

var db *sql.DB

// currentKey is the decrypted current master key.
// allKeys is the current key plus previous_keys, in the order tried during decryption.
var (
	currentKey string
	allKeys    []string
)

// storeKeyPart/loadKeyPart are the DB access points, kept in variables so tests can
// substitute an in-memory store for MySQL. In normal operation they point to the
// real functions; the binary's behavior is unchanged.
var (
	storeKeyPart = saveKeyPartToRemoteDB
	loadKeyPart  = getKeyPartFromRemoteDB
)

func main() {
	if len(os.Args) < 2 {
		return
	}

	readConfig()

	action := os.Args[1]

	switch action {
	case "encrypt":
		if len(os.Args) < 3 {
			return
		}

		connection := "3"
		input := ""

		if len(os.Args) == 3 {
			input = os.Args[2]
		} else if len(os.Args) >= 4 {
			connection = os.Args[2]
			input = os.Args[3]
		}

		loadKeys()

		initDBConnection(connection)
		defer db.Close()

		encryptedMatchingString, keyPart2, encryptedText := encrypt(input)

		result := map[string]string{
			"key":    encryptedText,           // private_key
			"salt":   encryptedMatchingString, // private_key_salt
			"secret": keyPart2,                // private_key_secret
			"hash":   createHash(input),       //private_key_hash
		}

		jsonResult, _ := json.Marshal(result)
		fmt.Println(string(jsonResult))

	case "decrypt":
		if len(os.Args) < 5 {
			return
		}

		connection := "3"
		encryptedText := ""
		secret := ""
		encryptedSalt := ""

		if len(os.Args) == 5 {
			encryptedText = os.Args[2]
			secret = os.Args[3]
			encryptedSalt = os.Args[4]
		} else if len(os.Args) >= 6 {
			connection = os.Args[2]
			encryptedText = os.Args[3]
			secret = os.Args[4]
			encryptedSalt = os.Args[5]
		}

		loadKeys()

		initDBConnection(connection)
		defer db.Close()

		decrypted := decrypt(encryptedText, secret, encryptedSalt)

		result := map[string]string{
			"result": decrypted,
		}
		jsonResult, _ := json.Marshal(result)
		fmt.Println(string(jsonResult))

	case "test":
		loadKeys()
		test()

	case "encrypt_bd":
		if len(os.Args) < 3 {
			return
		}
		loadKeys()
		input := os.Args[2]
		enc := encryptMatchingString(input)
		fmt.Print(enc)

	case "decrypt_bdd":
		if len(os.Args) < 3 {
			return
		}
		loadKeys()
		input := os.Args[2]
		dec := decryptMatchingString(input)
		fmt.Print(dec)

	case "wrap_key":
		// Wraps a master key with the KEK for insertion into config.json
		// (master_key / previous_keys fields). The DB is not used.
		if len(os.Args) < 3 {
			return
		}
		fmt.Print(aesEncrypt(os.Args[2], resolveKEK()))

	case "key_fingerprint":
		// Prints the fingerprint of the current master key, for the db.sql migration.
		loadKeys()
		fmt.Print(fingerprint(currentKey))

	default:
		fmt.Println("...")
	}
}

// resolveKEK returns the wrapping key from the kek file next to the binary (persistent source).
// The ENCRYPTOR_KEK environment override is intentionally disabled.
// A missing KEK is fatal (fail-closed): the master key cannot be decrypted without it.
func resolveKEK() string {
	if path := kekFilePath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if kek := strings.TrimSpace(string(data)); kek != "" {
				return kek
			}
		}
	}
	log.Fatal("Error code 6")
	return ""
}

// kekFilePath returns the path to the KEK file next to the executable (same directory).
func kekFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), kekFileName)
}

// loadKeys decrypts the master key and previous keys from config.json using the KEK
// and populates currentKey/allKeys. Must be called after readConfig().
func loadKeys() {
	kek := resolveKEK()

	if appConfig.MasterKey == "" {
		log.Fatal("Error code 7")
	}
	currentKey = aesDecrypt(appConfig.MasterKey, kek)

	allKeys = make([]string, 0, 1+len(appConfig.PreviousKeys))
	allKeys = append(allKeys, currentKey)
	for _, enc := range appConfig.PreviousKeys {
		if enc == "" {
			continue
		}
		allKeys = append(allKeys, aesDecrypt(enc, kek))
	}
}

// fingerprint is a one-way key fingerprint (hex SHA-256) stored in the DB so that
// decryption can tell which key sealed a record. It does not reveal the key itself.
func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func initDBConnection(connection string) {
	var dataSourceName string

	switch connection {
	case "1":
		dataSourceName = decryptMatchingString(appConfig.Connect1)
	case "2":
		dataSourceName = decryptMatchingString(appConfig.Connect2)
	case "3":
		dataSourceName = decryptMatchingString(appConfig.Connect3)
	case "4":
		dataSourceName = decryptMatchingString(appConfig.Connect4)
	case "5":
		dataSourceName = decryptMatchingString(appConfig.Connect5)
	default:
		log.Fatal("Invalid connection number")
	}

	var err error
	db, err = sql.Open("mysql", dataSourceName)
	if err != nil {
		log.Fatal("Error code 3")
	}
}

func test() {
	for i := 0; i < 500_000; i++ {
		originalText, err := generateRandomString(20, 100)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate random string: %v", err))
		}

		originalHash := createHash(originalText)

		encryptedMatchingString, keyPart2, encryptedText := encrypt(originalText)

		decryptedText := decrypt(encryptedText, keyPart2, encryptedMatchingString)

		decryptedHash := createHash(decryptedText)

		if originalHash != decryptedHash {
			fmt.Printf("Error %d: texts do not match\n", i)
			fmt.Printf("original: %s\n", originalText)
			fmt.Printf("decrypted: %s\n", decryptedText)
			return
		}

		if (i+1)%100 == 0 {
			fmt.Printf("Completed %d iterations\n", i+1)
		}
	}

	fmt.Println("Done")
}

func createHash(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateRandomString(minLength, maxLength int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	length, err := rand.Int(rand.Reader, big.NewInt(int64(maxLength-minLength+1)))
	if err != nil {
		return "", err
	}
	actualLength := int(length.Int64()) + minLength

	b := make([]byte, actualLength)
	for i := range b {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[randomIndex.Int64()]
	}
	return string(b), nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encrypt(plaintext string) (string, string, string) {
	keyPart1, _ := generateRandomBytes(keySize / 2)
	keyPart2, _ := generateRandomBytes(keySize / 2)

	matchingString, _ := generateRandomBytes(16)
	matchingStringBase64 := base64.StdEncoding.EncodeToString(matchingString)

	encryptedMatchingString := encryptMatchingString(matchingStringBase64)

	storeKeyPart(matchingStringBase64, base64.StdEncoding.EncodeToString(keyPart1), fingerprint(currentKey))

	fullKey := append(keyPart1, keyPart2...)

	block, _ := aes.NewCipher(fullKey)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return encryptedMatchingString, //private_key_salt
		base64.StdEncoding.EncodeToString(keyPart2), //private_key_secret
		base64.StdEncoding.EncodeToString(ciphertext) //private_key
}

func decrypt(encryptedText, keyPart2, encryptedMatchingString string) string {
	result, ok := decryptWithKeys(encryptedText, keyPart2, encryptedMatchingString)
	if !ok {
		log.Fatal("Error code 5")
	}
	return result
}

// decryptWithKeys is the decryption core that tries keys in order (current, then previous):
// the salt was encrypted with whichever key was current at encryption time. The record is
// looked up by matchingString, and the fingerprint in the DB confirms the key is correct.
// Returns ok=false if no key matched (instead of exiting the process), which lets tests
// cover the rotation logic and distinguish "did not decrypt" from a fatal error.
func decryptWithKeys(encryptedText, keyPart2, encryptedMatchingString string) (string, bool) {
	for _, key := range allKeys {
		matchingString := aesDecrypt(encryptedMatchingString, key)

		keyPart1Base64, keyFingerprint, ok := loadKeyPart(matchingString)
		if !ok {
			continue
		}
		if keyFingerprint != "" && keyFingerprint != fingerprint(key) {
			continue
		}

		keyPart1, _ := base64.StdEncoding.DecodeString(keyPart1Base64)
		keyPart2Bytes, _ := base64.StdEncoding.DecodeString(keyPart2)

		fullKey := append(keyPart1, keyPart2Bytes...)

		ciphertext, _ := base64.StdEncoding.DecodeString(encryptedText)
		block, _ := aes.NewCipher(fullKey)
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(ciphertext, ciphertext)

		return string(ciphertext), true
	}

	return "", false
}

// aesEncrypt/aesDecrypt implement the shared PBKDF2(password,password)+AES-CFB scheme.
// The password (master key or KEK) is always passed as a parameter; no keys live in code.
func aesEncrypt(plaintext, password string) string {
	key := pbkdf2.Key([]byte(password), []byte(password), iterations, keySize, sha256.New)
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func aesDecrypt(encrypted, password string) string {
	key := pbkdf2.Key([]byte(password), []byte(password), iterations, keySize, sha256.New)
	ciphertext, _ := base64.StdEncoding.DecodeString(encrypted)
	block, _ := aes.NewCipher(key)
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}

func encryptMatchingString(matchingString string) string {
	return aesEncrypt(matchingString, currentKey)
}

func decryptMatchingString(encryptedMatchingString string) string {
	return aesDecrypt(encryptedMatchingString, currentKey)
}

func saveKeyPartToRemoteDB(matchingString, keyPart, keyFingerprint string) {
	_, err := db.Exec("INSERT INTO wallet_keys (encrypted, salt, key_fingerprint) VALUES (?, ?, ?)", matchingString, keyPart, keyFingerprint)
	if err != nil {
		log.Fatal("Error code 4")
	}
}

// getKeyPartFromRemoteDB returns keyPart1 and the record's key fingerprint. ok=false if
// the record does not exist (needed for key iteration in decrypt; a miss must not kill the process).
func getKeyPartFromRemoteDB(matchingString string) (string, string, bool) {
	var salt string
	var keyFingerprint sql.NullString
	err := db.QueryRow("SELECT salt, key_fingerprint FROM wallet_keys WHERE encrypted = ?", matchingString).Scan(&salt, &keyFingerprint)
	if err == sql.ErrNoRows {
		return "", "", false
	}
	if err != nil {
		log.Fatal("Error code 5")
	}
	return salt, keyFingerprint.String, true
}
