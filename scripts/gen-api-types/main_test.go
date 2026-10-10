package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/apitypes"
	"github.com/crypt0rr/edgewatch/internal/web"
)

// The committed declarations are the ones that the command writes, so a
// change of a response struct without them fails here as it fails in CI.
func TestCommittedAPITypesAreCurrent(t *testing.T) {
	t.Parallel()
	want, err := apitypes.Generate(web.ResponseTypes())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(output)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date; run go run ./scripts/gen-api-types from the repository root and commit it", output)
	}
}

func TestRunWritesTheDeclarations(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "api-types.ts")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if status := run([]string{"-o", path}, web.ResponseTypes(), &stderr); status != 0 {
		t.Fatalf("run = %d: %s", status, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := apitypes.Generate(web.ResponseTypes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || stderr.Len() != 0 {
		t.Fatalf("run wrote %q and reported %q", got, stderr.String())
	}
}

func TestRunRefusesInvalidArgumentsAndReportsFailures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, test := range []struct {
		name   string
		args   []string
		types  []apitypes.Type
		status int
		want   string
	}{
		{"unknown flag", []string{"-unknown"}, web.ResponseTypes(), 2, "flag provided but not defined"},
		{"argument", []string{"extra"}, web.ResponseTypes(), 2, "takes no arguments"},
		{"invalid type", []string{"-o", filepath.Join(dir, "invalid.ts")}, []apitypes.Type{{Name: "Number", Value: 1}}, 1, "is not a named struct"},
		{"missing directory", []string{"-o", filepath.Join(dir, "missing", "api-types.ts")}, web.ResponseTypes(), 1, "run it from the repository root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if status := run(test.args, test.types, &stderr); status != test.status || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("run(%q) = %d %q, want %d and %q", test.args, status, stderr.String(), test.status, test.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "invalid.ts")); !os.IsNotExist(err) {
		t.Fatalf("a failed generation wrote a file: %v", err)
	}
}
