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
	authKeySize = 32
	// authCiphertext is the legacy format. It remains readable so upgrades do
	// not lock administrators out of TOTP, but all new writes use the owner-
	// bound v2 format below.
	authCiphertext     = "ew1:"
	authCiphertextV2   = "ew2:"
	totpOwnerAADPrefix = "edgewatch-totp-v2:"
)

var (
	ErrAuthKeyUnavailable = errors.New("authentication encryption key is unavailable")
	ErrAuthKeyInvalid     = errors.New("authentication encryption key is invalid")
	ErrAuthKeyPermissions = errors.New("authentication encryption key permissions are unsafe")
	ErrTOTPSecretLocked   = errors.New("TOTP secret cannot be decrypted")
	// ErrPasswordChangedDuringLogin tells the authentication layer that a
	// concurrent login or password-management request won the conditional
	// upgrade race. The caller may safely re-read and verify the current hash;
	// it must not report a valid password as a generic storage failure.
	ErrPasswordChangedDuringLogin = errors.New("password changed during login")
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

// ValidateAuthKeyFile verifies an explicitly configured authentication key
// before the web server starts. The default key is still created lazily when
// TOTP is first enabled; this helper is only for operator-managed paths.
func ValidateAuthKeyFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return ErrAuthKeyUnavailable
	}
	_, err := loadAuthKey(strings.TrimSpace(path))
	return err
}

func hexDecode(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, ErrAuthKeyInvalid
	}
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
	// Keep the old helper available to compatibility callers and migration
	// tests. Production save paths use sealTOTPSecretForOwner so the stable user
	// identity is authenticated with the ciphertext.
	return s.sealTOTPSecretVersion("", secret, false)
}

func (s *Store) sealTOTPSecretForOwner(owner, secret string) (string, error) {
	if strings.TrimSpace(owner) == "" {
		return "", errors.New("TOTP secret owner is required")
	}
	return s.sealTOTPSecretVersion(owner, secret, true)
}

func (s *Store) sealTOTPSecretVersion(owner, secret string, bindOwner bool) (string, error) {
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
	aad, prefix := []byte("edgewatch-totp-v1"), authCiphertext
	if bindOwner {
		aad, prefix = []byte(totpOwnerAADPrefix+owner), authCiphertextV2
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), aad)
	encoded := make([]byte, 0, len(nonce)+len(ciphertext))
	encoded = append(encoded, nonce...)
	encoded = append(encoded, ciphertext...)
	return prefix + base64.RawStdEncoding.EncodeToString(encoded), nil
}

func (s *Store) openTOTPSecret(stored string) (string, error) {
	secret, _, err := s.openTOTPSecretForOwner("", stored)
	return secret, err
}

// openTOTPSecretForOwner returns whether the value was successfully decoded
// from a legacy/plaintext format and should be rewritten in the owner-bound
// v2 format. A v2 value is authenticated against owner, so copying encrypted
// data between users fails closed even when the database key is shared.
func (s *Store) openTOTPSecretForOwner(owner, stored string) (string, bool, error) {
	if stored == "" {
		return "", false, nil
	}
	if !strings.HasPrefix(stored, authCiphertext) && !strings.HasPrefix(stored, authCiphertextV2) {
		// v0.3/v0.4 records used plaintext TOTP seeds. GetAdmin returns the
		// legacy value and rewrites it through sealTOTPSecretForOwner so an
		// existing installation is upgraded on its first authenticated read.
		return stored, true, nil
	}
	prefix, aad := authCiphertext, []byte("edgewatch-totp-v1")
	legacy := true
	if strings.HasPrefix(stored, authCiphertextV2) {
		prefix = authCiphertextV2
		if strings.TrimSpace(owner) == "" {
			return "", false, fmt.Errorf("%w: owner is unavailable", ErrTOTPSecretLocked)
		}
		aad = []byte(totpOwnerAADPrefix + owner)
		legacy = false
	}
	key, err := loadAuthKey(s.authKeyPath)
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false, fmt.Errorf("%w: %v", ErrTOTPSecretLocked, err)
	}
	encoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil || len(encoded) < gcm.NonceSize() {
		return "", false, fmt.Errorf("%w: malformed ciphertext", ErrTOTPSecretLocked)
	}
	plain, err := gcm.Open(nil, encoded[:gcm.NonceSize()], encoded[gcm.NonceSize():], aad)
	if err != nil {
		return "", false, fmt.Errorf("%w: authentication failed", ErrTOTPSecretLocked)
	}
	return string(plain), legacy, nil
}
