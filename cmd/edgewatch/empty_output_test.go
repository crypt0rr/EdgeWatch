package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// status and history print empty lists, not null, for a business unit
// without jobs or history, as the web API does, so a script can iterate
// the output of a new unit.
func TestStatusAndHistoryPrintEmptyListsForAUnitWithoutJobs(t *testing.T) {
	database := storetest.FreshPath(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000300','Empty','empty',?,?)`, stamp, stamp); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(filepath.Dir(database), "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := func(t *testing.T, args ...string) string {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error {
			return run(append(args, "--config", configPath, "--output", "json"))
		})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return strings.TrimSpace(stdout)
	}
	for _, unit := range []struct {
		name string
		args []string
	}{
		{name: "default unit of a fresh database"},
		{name: "new unit", args: []string{"--tenant", "empty"}},
	} {
		t.Run(unit.name, func(t *testing.T) {
			if got := cli(t, append([]string{"status"}, unit.args...)...); got != "[]" {
				t.Fatalf("status printed %q, want []", got)
			}
			var history map[string]json.RawMessage
			out := cli(t, append([]string{"history"}, unit.args...)...)
			if err := json.Unmarshal([]byte(out), &history); err != nil {
				t.Fatalf("history printed %q: %v", out, err)
			}
			for _, key := range []string{"scans", "events"} {
				if got := string(history[key]); got != "[]" {
					t.Fatalf("history %s = %s, want []", key, got)
				}
			}
		})
	}
}
