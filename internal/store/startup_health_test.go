package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ReadStartupHealth reports a database that the starting daemon has not
// created, or whose startup it has not recorded, as not recorded, without
// opening a database that does not exist or is still empty. Once the
// daemon has recorded its migration, it reads the health as the daemon
// reports it, through a handle that writes nothing.
func TestReadStartupHealth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.db")
	if _, err := ReadStartupHealth(ctx, missing); !errors.Is(err, ErrStartupNotRecorded) {
		t.Errorf("missing database = %v, want ErrStartupNotRecorded", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("reading a missing database created it: %v", err)
	}
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStartupHealth(ctx, empty); !errors.Is(err, ErrStartupNotRecorded) {
		t.Errorf("empty database = %v, want ErrStartupNotRecorded", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(empty + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("reading an empty database left %s: %v", suffix, err)
		}
	}
	if _, err := ReadStartupHealth(ctx, ""); err == nil {
		t.Error("an empty path was read")
	}
	if _, err := ReadStartupHealth(ctx, dir); err == nil || errors.Is(err, ErrStartupNotRecorded) {
		t.Errorf("a directory = %v, want an open error", err)
	}

	s := openTestStore(t)
	if _, err := s.DB.Exec(`DELETE FROM startup_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStartupHealth(ctx, s.Path); !errors.Is(err, ErrStartupNotRecorded) {
		t.Errorf("no startup row = %v, want ErrStartupNotRecorded", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO startup_state(id,state,phase,started_at,updated_at,progress,total) VALUES(1,'migrating','schema',?,?,3,4)`, now, now); err != nil {
		t.Fatal(err)
	}
	health, err := ReadStartupHealth(ctx, s.Path)
	if err != nil || health.Status != "starting" || health.Phase != "schema" || health.Progress != 3 || health.Total != 4 {
		t.Errorf("migrating = %+v, %v", health, err)
	}
	if _, err := s.DB.Exec(`DROP TABLE startup_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStartupHealth(ctx, s.Path); !errors.Is(err, ErrStartupNotRecorded) {
		t.Errorf("no startup table = %v, want ErrStartupNotRecorded", err)
	}
}
