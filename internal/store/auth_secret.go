package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	authKeySize    = 32
	authCiphertext = "ew1:"
)

var (
	ErrAuthKeyUnavailable = errors.New("authentication encryption key is unavailable")
	ErrAuthKeyInvalid     = errors.New("authentication encryption key is invalid")
	ErrAuthKeyPermissions = errors.New("authentication encryption key permissions are unsafe")
	ErrTOTPSecretLocked   = errors.New("TOTP secret cannot be decrypted")
)

func defaultAuthKeyPath(database string) string {
	if database == "" || isSQLiteMemoryPath(database) {
		return ""
	}
	return filepath.Join(filepath.Dir(database), "auth.key")
}

func loadAuthKey(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrAuthKeyUnavailable
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrAuthKeyUnavailable
		}
		return nil, fmt.Errorf("read authentication key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrAuthKeyInvalid
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrAuthKeyPermissions
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authentication key: %w", err)
	}
	if len(raw) != authKeySize {
		trimmed := []byte(strings.TrimSpace(string(raw)))
		if len(trimmed) == authKeySize*2 {
			decoded, decodeErr := hexDecode(trimmed)
			if decodeErr == nil {
				raw = decoded
			} else {
				raw = trimmed
			}
		} else {
			raw = trimmed
		}
	}
	if len(raw) == authKeySize*2 {
		decoded, decodeErr := hexDecode(raw)
		if decodeErr == nil {
			raw = decoded
		}
	}
	if len(raw) != authKeySize {
		return nil, ErrAuthKeyInvalid
	}
	return raw, nil
}

func hexDecode(raw []byte) ([]byte, error) {
	out := make([]byte, len(raw)/2)
	for i := range out {
		hi, ok := hexNibble(raw[i*2])
		lo, okLo := hexNibble(raw[i*2+1])
		if !ok || !okLo {
			return nil, ErrAuthKeyInvalid
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(v byte) (byte, bool) {
	switch {
	case v >= '0' && v <= '9':
		return v - '0', true
	case v >= 'a' && v <= 'f':
		return v - 'a' + 10, true
	case v >= 'A' && v <= 'F':
		return v - 'A' + 10, true
	default:
		return 0, false
	}
}

func createAuthKey(path string) ([]byte, error) {
	if path == "" {
		return nil, ErrAuthKeyUnavailable
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	key := make([]byte, authKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) authKeyForWrite() ([]byte, error) {
	key, err := loadAuthKey(s.authKeyPath)
	if errors.Is(err, ErrAuthKeyUnavailable) && s.authAutoKey {
		key, err = createAuthKey(s.authKeyPath)
		if errors.Is(err, os.ErrExist) {
			key, err = loadAuthKey(s.authKeyPath)
		}
	}
	return key, err
}

func (s *Store) sealTOTPSecret(secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	key, err := s.authKeyForWrite()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), []byte("edgewatch-totp-v1"))
	encoded := make([]byte, 0, len(nonce)+len(ciphertext))
	encoded = append(encoded, nonce...)
	encoded = append(encoded, ciphertext...)
	return authCiphertext + base64.RawStdEncoding.EncodeToString(encoded), nil
}

func (s *Store) openTOTPSecret(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, authCiphertext) {
		// v0.3/v0.4 records used plaintext TOTP seeds. GetAdmin returns the
		// legacy value and rewrites it through sealTOTPSecret so an existing
		// installation is upgraded on its first authenticated read.
		return stored, nil
	}
	key, err := loadAuthKey(s.authKeyPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	encoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, authCiphertext))
	if err != nil || len(encoded) < gcm.NonceSize() {
		return "", fmt.Errorf("%w: malformed ciphertext", ErrTOTPSecretLocked)
	}
	plain, err := gcm.Open(nil, encoded[:gcm.NonceSize()], encoded[gcm.NonceSize():], []byte("edgewatch-totp-v1"))
	if err != nil {
		return "", fmt.Errorf("%w: authentication failed", ErrTOTPSecretLocked)
	}
	return string(plain), nil
}
