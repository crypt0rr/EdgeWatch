package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const restoreSignalChildEnv = "EDGEWATCH_RESTORE_SIGNAL_TEST_CHILD"

// TestRestoreSignalChild is run in a subprocess so the regression test can
// send SIGINT without risking termination of the main test process.
func TestRestoreSignalChild(t *testing.T) {
	if os.Getenv(restoreSignalChildEnv) != "1" {
		return
	}
	configPath := os.Getenv("EDGEWATCH_RESTORE_SIGNAL_CONFIG")
	sourcePath := os.Getenv("EDGEWATCH_RESTORE_SIGNAL_SOURCE")
	err := run([]string{"restore", "--config", configPath, "--from", sourcePath, "--output", "json"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("restore error = %v, want context.Canceled", err)
	}
}

func TestRestoreCommandTerminationSignalsRemoveStagingCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("restore command signal handling is exercised on Unix")
	}

	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	source := filepath.Join(dir, "source.db")
	createCLIStoreFixture(t, source, "source")
	createCLIStoreFixture(t, database, "destination")

	// Keep the copy active long enough to deliver a deterministic interrupt
	// after stageRestore has created its private directory.
	sourceStore, err := store.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceStore.DB.Exec(`CREATE TABLE restore_signal_payload (payload BLOB NOT NULL)`); err != nil {
		sourceStore.Close()
		t.Fatal(err)
	}
	if _, err := sourceStore.DB.Exec(`INSERT INTO restore_signal_payload(payload) VALUES (zeroblob(134217728))`); err != nil {
		sourceStore.Close()
		t.Fatal(err)
	}
	if err := sourceStore.Close(); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}

	for _, termination := range []struct {
		name   string
		signal os.Signal
	}{
		{name: "SIGINT", signal: os.Interrupt},
		{name: "SIGTERM", signal: syscall.SIGTERM},
	} {
		termination := termination
		t.Run(termination.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestRestoreSignalChild$")
			command.Env = append(os.Environ(),
				restoreSignalChildEnv+"=1",
				"EDGEWATCH_RESTORE_SIGNAL_CONFIG="+configPath,
				"EDGEWATCH_RESTORE_SIGNAL_SOURCE="+source,
			)
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()

			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			interrupted := false
			for !interrupted {
				entries, readErr := os.ReadDir(dir)
				if readErr != nil {
					_ = command.Process.Kill()
					<-done
					t.Fatalf("read restore directory: %v", readErr)
				}
				for _, entry := range entries {
					if entry.IsDir() && strings.HasPrefix(entry.Name(), ".edgewatch-restore-") {
						if err := command.Process.Signal(termination.signal); err != nil {
							_ = command.Process.Kill()
							<-done
							t.Fatalf("send %s to restore process: %v", termination.name, err)
						}
						interrupted = true
						break
					}
				}
				if interrupted {
					break
				}
				select {
				case processErr := <-done:
					t.Fatalf("restore process exited before staging began: %v\nstdout: %s\nstderr: %s", processErr, stdout.String(), stderr.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatal("restore process did not create a staging directory")
				default:
					time.Sleep(time.Millisecond)
				}
			}

			select {
			case processErr := <-done:
				if processErr != nil {
					entries, _ := os.ReadDir(dir)
					var staging []string
					for _, entry := range entries {
						if entry.IsDir() && strings.HasPrefix(entry.Name(), ".edgewatch-restore-") {
							staging = append(staging, entry.Name())
						}
					}
					t.Fatalf("interrupted restore process error = %v; remaining staging directories = %v\nstdout: %s\nstderr: %s", processErr, staging, stdout.String(), stderr.String())
				}
			case <-time.After(15 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Fatalf("restore process did not stop promptly after %s", termination.name)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), ".edgewatch-restore-") {
					t.Errorf("interrupted restore left staging directory %q", entry.Name())
				}
			}
			after, err := os.ReadFile(database)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("interrupted restore changed the destination database")
			}
		})
	}
}
