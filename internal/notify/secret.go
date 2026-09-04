package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const notificationKeySize = 32

var (
	ErrKeyUnavailable = errors.New("notification encryption key is unavailable")
	ErrKeyInvalid     = errors.New("notification encryption key is invalid")
	ErrKeyPermissions = errors.New("notification encryption key permissions are unsafe")
)

// DefaultKeyPath keeps the generated key beside the database so a normal
// ./data bind mount contains all state needed for an appliance deployment.
func DefaultKeyPath(database string) string {
	if database == "" || database == ":memory:" {
		return ""
	}
	return filepath.Join(filepath.Dir(database), "notification.key")
}

func loadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrKeyUnavailable
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrKeyUnavailable
		}
		return nil, fmt.Errorf("read notification key: %w", err)
	}
	// Only owner-readable regular files are accepted. In particular, reject
	// group/other access and executable bits even when the process runs as
	// root; the key is a credential-equivalent secret.
	perm := info.Mode().Perm()
	if !info.Mode().IsRegular() || (perm != 0o400 && perm != 0o600) {
		return nil, ErrKeyPermissions
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read notification key: %w", err)
	}
	if len(raw) != notificationKeySize {
		trimmed := strings.TrimSpace(string(raw))
		if len(trimmed) != notificationKeySize*2 {
			return nil, ErrKeyInvalid
		}
		decoded, decodeErr := hex.DecodeString(trimmed)
		if decodeErr != nil || len(decoded) != notificationKeySize {
			return nil, ErrKeyInvalid
		}
		raw = decoded
	}
	return append([]byte(nil), raw...), nil
}

func createKey(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrKeyUnavailable
	}
	key := make([]byte, notificationKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func sealURL(key []byte, id, url string) (nonce, ciphertext []byte, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, []byte(url), associatedData(id))
	return nonce, ciphertext, nil
}

func openURL(key []byte, id string, nonce, ciphertext []byte) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	if len(nonce) != aead.NonceSize() {
		return "", ErrKeyInvalid
	}
	plain, err := aead.Open(nil, nonce, ciphertext, associatedData(id))
	if err != nil {
		return "", ErrKeyInvalid
	}
	return string(plain), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != notificationKeySize {
		return nil, ErrKeyInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKeyInvalid
	}
	return cipher.NewGCM(block)
}

func associatedData(id string) []byte {
	return []byte("edgewatch/notification/v1/" + id)
}
