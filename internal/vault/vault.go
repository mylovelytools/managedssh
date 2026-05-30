package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/mylovelytools/managedssh/internal/fsutil"
)

const (
	verifierPlaintext = "managedssh-vault-ok"
	argonTime         = 3
	argonMemory       = 128 * 1024
	argonThreads      = 4
	argonKeyLen       = 32
	saltLen           = 16
)

// AAD context tags prevent ciphertext from being transplanted between roles.
var (
	aadVaultVerifier = []byte("managedssh:vault-verifier")
	aadHostPassword  = []byte("managedssh:host-password")
)

var ErrWrongPassword = errors.New("incorrect master key")

type meta struct {
	Salt     []byte `json:"salt"`
	Nonce    []byte `json:"nonce"`
	Verifier []byte `json:"verifier"`
}

func Dir() (string, error) {
	// Respect XDG_CONFIG_HOME if set, otherwise fall back to ~/.config
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome != "" {
		return filepath.Join(configHome, "managedssh"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "managedssh"), nil
}

func metaPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.json"), nil
}

func Exists() (bool, error) {
	p, err := metaPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func encryptBytes(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func decryptBytes(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// Create initialises a new vault with the given master password and
// returns the derived 256-bit encryption key.
func Create(password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := deriveKey([]byte(password), salt)
	nonce, ciphertext, err := encryptBytes(key, []byte(verifierPlaintext), aadVaultVerifier)
	if err != nil {
		return nil, err
	}

	m := meta{Salt: salt, Nonce: nonce, Verifier: ciphertext}

	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	p, err := metaPath()
	if err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fsutil.AtomicWrite(p, data, 0600); err != nil {
		return nil, err
	}

	return key, nil
}

// Unlock verifies the master password against the stored vault and
// returns the derived encryption key on success.
func Unlock(password string) ([]byte, error) {
	p, err := metaPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return UnlockWithMetaJSON(password, data)
}

// UnlockWithMetaJSON verifies a master password against vault metadata bytes
// and returns the derived encryption key on success.
func UnlockWithMetaJSON(password string, data []byte) ([]byte, error) {
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	key := deriveKey([]byte(password), m.Salt)
	plain, err := decryptBytes(key, m.Nonce, m.Verifier, aadVaultVerifier)
	if err != nil {
		return nil, ErrWrongPassword
	}
	if string(plain) != verifierPlaintext {
		return nil, ErrWrongPassword
	}
	return key, nil
}

// Encrypt encrypts arbitrary data with the given key using the
// host-password AAD context. The nonce is prepended to the ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	nonce, ct, err := encryptBytes(key, plaintext, aadHostPassword)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// Decrypt decrypts a blob previously produced by Encrypt.
func Decrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], aadHostPassword)
}

// ZeroKey overwrites a key slice with zeros (best-effort in Go).
func ZeroKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
