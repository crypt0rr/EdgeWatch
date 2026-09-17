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

// ValidateKeyFile verifies an explicitly configured notification key during
// daemon startup. The notifier still keeps its lazy default-key generation
// behavior, but an operator-managed path must be present, private, and a
// correctly sized raw or hexadecimal key before the process starts.
func ValidateKeyFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return ErrKeyUnavailable
	}
	_, err := loadKey(strings.TrimSpace(path))
	return err
}

func createKey(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrKeyUnavailable
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	key := make([]byte, notificationKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	// Never write directly to the published path. A crash after create but
	// before the write used to leave a zero-byte key that permanently looked
	// like an operator-managed invalid key on the next start. Link publishes the
	// fully synced inode without replacing a key another process won the race to
	// create.
	// CreateTemp supplies an exclusive, unpredictable name in the same
	// directory. The same-directory placement is required for an atomic link
	// publish and avoids collisions between simultaneous first starts.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, err
	}
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(key); err != nil {
		cleanup()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := os.Link(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	_ = os.Remove(tmpName)
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return key, nil
}

// removeInterruptedKey removes only an empty auto-generated key. Non-empty
// invalid files are deliberately left untouched so an operator can recover or
// replace them explicitly rather than having EdgeWatch destroy credential
// material.
func removeInterruptedKey(path string, expectedSize int64) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != expectedSize {
		return ErrKeyInvalid
	}
	return os.Remove(path)
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
