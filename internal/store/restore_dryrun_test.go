package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A dry run must predict the real restore: it runs the same refusal checks and
// staged validation, reports every refusal as unsafe, and leaves the source and
// destination directories exactly as it found them. Each case then runs the
// real restore on the same inputs to prove the two paths agree.
func TestDryRunRestorePredictsRestoreOutcome(t *testing.T) {
	// Migrate each fixture once and copy it per case; the cases only differ in
	// what they change afterwards.
	templates := t.TempDir()
	sourceTemplate := filepath.Join(templates, "source.db")
	destinationTemplate := filepath.Join(templates, "destination.db")
	createRestoreFixture(t, sourceTemplate, "source")
	addRestorePendingDelivery(t, sourceTemplate, "backup-destination")
	createRestoreFixture(t, destinationTemplate, "destination")
	validSource := func(t *testing.T, path string) {
		copyRestoreFixture(t, sourceTemplate, path)
	}
	validDestination := func(t *testing.T, path string) {
		copyRestoreFixture(t, destinationTemplate, path)
	}
	cases := []struct {
		name        string
		source      func(*testing.T, string)
		destination func(*testing.T, string)
		options     RestoreOptions
		wantErr     error
		wantText    string
	}{
		{name: "valid source", source: validSource, destination: validDestination},
		{
			name:   "active daemon without sidecars",
			source: validSource,
			destination: func(t *testing.T, path string) {
				validDestination(t, path)
				owner, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.AcquireDaemonLease(context.Background(), "daemon-probe"); err != nil {
					owner.Close()
					t.Fatal(err)
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrRestoreDaemonLive,
		},
		{
			name: "foreign source",
			source: func(t *testing.T, path string) {
				raw, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := raw.Exec(`CREATE TABLE unrelated(x)`); err != nil {
					raw.Close()
					t.Fatal(err)
				}
				if err := raw.Close(); err != nil {
					t.Fatal(err)
				}
			},
			destination: validDestination,
			wantText:    "not an EdgeWatch database",
		},
		{
			name: "newer schema source",
			source: func(t *testing.T, path string) {
				validSource(t, path)
				raw, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := raw.Exec(`PRAGMA user_version = 999`); err != nil {
					raw.Close()
					t.Fatal(err)
				}
				if err := raw.Close(); err != nil {
					t.Fatal(err)
				}
			},
			destination: validDestination,
			wantText:    "unsupported schema version",
		},
		{
			name:   "destination sidecars",
			source: validSource,
			destination: func(t *testing.T, path string) {
				validDestination(t, path)
				if err := os.WriteFile(path+"-wal", []byte("stale WAL"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrRestoreSidecars,
		},
		{
			name:   "unreadable destination",
			source: validSource,
			destination: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("not a usable EdgeWatch database"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrRestoreDestinationUnreadable,
		},
		{
			name:   "unreadable destination with explicit recovery",
			source: validSource,
			destination: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("not a usable EdgeWatch database"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			options: RestoreOptions{AllowUnreadableDestination: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			sourceDir, destinationDir := filepath.Join(root, "backups"), filepath.Join(root, "data")
			for _, dir := range []string{sourceDir, destinationDir} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			source := filepath.Join(sourceDir, "edgewatch-backup.db")
			destination := filepath.Join(destinationDir, "edgewatch.db")
			tc.source(t, source)
			tc.destination(t, destination)
			sourceEntries := restoreDirEntries(t, sourceDir)
			destinationEntries := restoreDirEntries(t, destinationDir)
			sourceDigest, err := fileDigest(source)
			if err != nil {
				t.Fatal(err)
			}
			destinationDigest, err := fileDigest(destination)
			if err != nil {
				t.Fatal(err)
			}

			dryRun, dryErr := DryRunRestore(ctx, source, destination, tc.options)
			assertRestoreOutcome(t, "dry run", dryErr, tc.wantErr, tc.wantText)
			if dryRun.Safe != (dryErr == nil) {
				t.Fatalf("dry run safe = %v with error %v", dryRun.Safe, dryErr)
			}
			if dryErr != nil && dryRun.Refusal != dryErr.Error() {
				t.Fatalf("dry run refusal = %q, want %q", dryRun.Refusal, dryErr.Error())
			}
			if dryErr == nil {
				if dryRun.Refusal != "" || dryRun.SourceSchemaVersion != schemaVersion {
					t.Fatalf("safe dry run = %#v", dryRun)
				}
				if dryRun.PendingDeliveriesPolicy != PendingDeliveriesQuarantine || dryRun.PendingDeliveriesAffected != 1 {
					t.Fatalf("dry run pending deliveries = %q/%d, want quarantine/1", dryRun.PendingDeliveriesPolicy, dryRun.PendingDeliveriesAffected)
				}
			}
			if dryRun.SourcePath != source || dryRun.DestinationPath != destination {
				t.Fatalf("dry run paths = %q -> %q", dryRun.SourcePath, dryRun.DestinationPath)
			}
			// The staged copy lives in a private directory that is removed again;
			// nothing may appear next to the source or the destination.
			if got := restoreDirEntries(t, sourceDir); !slices.Equal(got, sourceEntries) {
				t.Fatalf("dry run changed the source directory: %v -> %v", sourceEntries, got)
			}
			if got := restoreDirEntries(t, destinationDir); !slices.Equal(got, destinationEntries) {
				t.Fatalf("dry run changed the destination directory: %v -> %v", destinationEntries, got)
			}
			if got, err := fileDigest(source); err != nil || got != sourceDigest {
				t.Fatalf("dry run changed the source: %v", err)
			}
			if got, err := fileDigest(destination); err != nil || got != destinationDigest {
				t.Fatalf("dry run changed the destination: %v", err)
			}

			result, restoreErr := Restore(ctx, source, destination, tc.options)
			assertRestoreOutcome(t, "restore", restoreErr, tc.wantErr, tc.wantText)
			if restoreErr != nil {
				if got, err := fileDigest(destination); err != nil || got != destinationDigest {
					t.Fatalf("refused restore changed the destination: %v", err)
				}
				return
			}
			if result.PendingDeliveriesAffected != dryRun.PendingDeliveriesAffected {
				t.Fatalf("restore pending deliveries = %d, dry run predicted %d", result.PendingDeliveriesAffected, dryRun.PendingDeliveriesAffected)
			}
			if got, err := readRestoreValue(destination); err != nil || got != "source" {
				t.Fatalf("restored value = %q, %v; want source", got, err)
			}
		})
	}
}

func assertRestoreOutcome(t *testing.T, label string, err, wantErr error, wantText string) {
	t.Helper()
	switch {
	case wantErr == nil && wantText == "":
		if err != nil {
			t.Fatalf("%s error = %v, want success", label, err)
		}
	case wantErr != nil:
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s error = %v, want %v", label, err, wantErr)
		}
	default:
		if err == nil || !strings.Contains(err.Error(), wantText) {
			t.Fatalf("%s error = %v, want %q", label, err, wantText)
		}
	}
}

// copyRestoreFixture copies a closed fixture database. A cleanly closed store
// leaves no sidecars, so the main file is the complete database.
func copyRestoreFixture(t *testing.T, from, to string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(from + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture %s has a %s sidecar: %v", from, suffix, err)
		}
	}
	contents, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func restoreDirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
