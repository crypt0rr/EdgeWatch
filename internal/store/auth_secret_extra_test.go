package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthKeyHexDecodeRejectsMalformedInput(t *testing.T) {
	decoded, err := hexDecode([]byte("00aF10"))
	if err != nil || string(decoded) != string([]byte{0, 0xaf, 0x10}) {
		t.Fatalf("hex decode = %x, %v", decoded, err)
	}
	for _, input := range []string{"0", "0g", "xyz"} {
		if _, err := hexDecode([]byte(input)); !errors.Is(err, ErrAuthKeyInvalid) {
			t.Fatalf("hex decode %q error = %v", input, err)
		}
	}
	for _, input := range []byte{'0', '9', 'a', 'f', 'A', 'F', 'x'} {
		value, ok := hexNibble(input)
		if input == 'x' {
			if ok || value != 0 {
				t.Fatalf("invalid nibble %q = %d, %v", input, value, ok)
			}
			continue
		}
		if !ok {
			t.Fatalf("valid nibble %q was rejected", input)
		}
	}
}

func TestLoadAuthKeyFormatsAndPermissions(t *testing.T) {
	if _, err := loadAuthKey(""); !errors.Is(err, ErrAuthKeyUnavailable) {
		t.Fatalf("empty auth key error = %v", err)
	}
	if err := ValidateAuthKeyFile(""); !errors.Is(err, ErrAuthKeyUnavailable) {
		t.Fatalf("empty configured auth key error = %v", err)
	}
	if _, err := loadAuthKey(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrAuthKeyUnavailable) {
		t.Fatalf("missing auth key error = %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "auth.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("ab", authKeySize)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthKey(keyPath); !errors.Is(err, ErrAuthKeyPermissions) {
		t.Fatalf("unsafe auth key permissions = %v", err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := loadAuthKey(keyPath)
	if err != nil || len(key) != authKeySize || key[0] != 0xab {
		t.Fatalf("hex auth key = %x, %v", key, err)
	}
	if err := ValidateAuthKeyFile(keyPath); err != nil {
		t.Fatalf("valid configured auth key rejected: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthKey(keyPath); !errors.Is(err, ErrAuthKeyInvalid) {
		t.Fatalf("short auth key error = %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthKey(keyPath); !errors.Is(err, ErrAuthKeyInvalid) {
		t.Fatalf("directory auth key error = %v", err)
	}
}

func TestExplicitAuthKeyPathDisablesAutomaticGeneration(t *testing.T) {
	s := &Store{authKeyPath: "default", authAutoKey: true}
	s.SetAuthKeyPath("  /tmp/operator-auth.key  ")
	if s.authKeyPath != "/tmp/operator-auth.key" || s.authAutoKey {
		t.Fatalf("explicit auth key path = %q, auto=%v", s.authKeyPath, s.authAutoKey)
	}
	s.SetAuthKeyPath("   ")
	if s.authKeyPath != "/tmp/operator-auth.key" || s.authAutoKey {
		t.Fatalf("blank auth key path changed selection = %q, auto=%v", s.authKeyPath, s.authAutoKey)
	}
}
