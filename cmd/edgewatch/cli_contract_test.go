package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// captureCLIOutput runs fn with the process stdout and stderr redirected, so a
// test can assert which stream a command writes its result and logs to.
func captureCLIOutput(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	originalStdout, originalStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() { os.Stdout, os.Stderr = originalStdout, originalStderr })
	t.Cleanup(restore)
	var stdout, stderr bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&stdout, stdoutReader) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&stderr, stderrReader) }()
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	runErr := fn()
	restore()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	wg.Wait()
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	return stdout.String(), stderr.String(), runErr
}

// writeFakeNmap writes a stand-in scanner that reports a version and prints
// fixed XML for 192.0.2.10:1, or fails every scan when fail is set.
func writeFakeNmap(t *testing.T, dir string, fail bool) string {
	t.Helper()
	path := filepath.Join(dir, "fake-nmap")
	if fail {
		path += "-failing"
	}
	scan := `printf '%s' '<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="1"><state state="open" reason="syn-ack"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'`
	if fail {
		scan = "echo 'scanner failure' >&2\nexit 1"
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Nmap version 7.95'; exit 0; fi\n" + scan + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func managedCLIJob(name string) config.Job {
	return config.NormalizeJob(config.Job{
		Name: name, Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.10"},
		TCP: &config.Protocol{Ports: "1", Mode: "connect"}, Timeout: config.Duration(time.Minute), Timing: "balanced",
	})
}

const legacyCLIJobsYAML = "jobs:\n  - name: legacy-yaml\n    schedule: \"0 * * * *\"\n    timezone: UTC\n    targets: [192.0.2.20]\n    tcp:\n      ports: \"1\"\n      mode: connect\n"

// A dry run must fail exactly when the real restore would refuse, so that
// "restore --dry-run && restore" is safe to automate, and it must still print
// a single JSON document that explains the refusal.
func TestRunRestoreDryRunExitsNonZeroWhenRestoreWouldBeRefused(t *testing.T) {
	activeDaemon := func(t *testing.T, database string) {
		owner, err := store.Open(database)
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
	}
	foreignSource := func(t *testing.T, source string) {
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}
		raw, err := sql.Open("sqlite", source)
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
	}
	for _, tc := range []struct {
		name        string
		source      func(*testing.T, string)
		destination func(*testing.T, string)
		wantErr     error
		refusal     string
	}{
		{name: "active daemon", destination: activeDaemon, wantErr: store.ErrRestoreDaemonLive, refusal: "daemon is active"},
		{name: "foreign source", source: foreignSource, refusal: "not an EdgeWatch database"},
		{
			name: "destination sidecars",
			destination: func(t *testing.T, database string) {
				if err := os.WriteFile(database+"-wal", []byte("stale WAL"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: store.ErrRestoreSidecars,
			refusal: "sidecars are present",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "edgewatch.db")
			configPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(dir, "source.db")
			createCLIStoreFixture(t, source, "source")
			createCLIStoreFixture(t, database, "destination")
			if tc.source != nil {
				tc.source(t, source)
			}
			if tc.destination != nil {
				tc.destination(t, database)
			}
			before := snapshotCLIFile(t, database)
			stdout, _, err := captureCLIOutput(t, func() error {
				return run([]string{"restore", "--config", configPath, "--from", source, "--dry-run", "--output", "json"})
			})
			if err == nil {
				t.Fatalf("unsafe dry run exited zero; stdout=%s", stdout)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("dry run error = %v, want %v", err, tc.wantErr)
			}
			if !json.Valid([]byte(stdout)) {
				t.Fatalf("dry run stdout is not a single JSON document: %q", stdout)
			}
			var report struct {
				Safe    bool   `json:"safe"`
				Refusal string `json:"refusal"`
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatal(err)
			}
			if report.Safe || !strings.Contains(report.Refusal, tc.refusal) {
				t.Fatalf("dry run report = %+v, want unsafe with refusal containing %q", report, tc.refusal)
			}
			assertCLIFileUnchanged(t, database, before)
			// The real restore refuses the same inputs.
			if err := run([]string{"restore", "--config", configPath, "--from", source, "--output", "json"}); err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("restore error = %v, want refusal containing %q", err, tc.refusal)
			}
		})
	}
}

// With --output json, stdout carries exactly one JSON document. Application
// startup warnings, such as the inactive legacy YAML jobs notice, go to stderr.
func TestRunJSONOutputKeepsApplicationLogsOnStderr(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(context.Background(), managedCLIJob("managed")); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"+legacyCLIJobsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	nmap := writeFakeNmap(t, dir, false)
	for _, args := range [][]string{
		{"baseline", "reset", "--job", "managed"},
		{"scan", "--job", "managed", "--nmap", nmap},
	} {
		args = append(args, "--config", configPath, "--output", "json")
		stdout, stderr, err := captureCLIOutput(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("%v: %v (stderr=%s)", args, err, stderr)
		}
		if !json.Valid([]byte(stdout)) {
			t.Fatalf("%v stdout is not a single JSON document: %q", args, stdout)
		}
		if !strings.Contains(stderr, "legacy YAML jobs are inactive") {
			t.Fatalf("%v stderr = %q, want the legacy jobs warning", args, stderr)
		}
	}
}

// Container runtimes collect the daemon's structured log from stdout. One-shot
// commands print their result there, so their diagnostics use stderr.
func TestOnlyDaemonLogsToStdout(t *testing.T) {
	if commandLogWriter("daemon") != io.Writer(os.Stdout) {
		t.Fatal("daemon log output moved away from stdout")
	}
	for _, cmd := range []string{"scan", "baseline", "notify", "status", "history", "backup", "verify", "health", "admin"} {
		if commandLogWriter(cmd) != io.Writer(os.Stderr) {
			t.Fatalf("%s logs to stdout", cmd)
		}
	}
}

// status must not advertise a next run for a job the daemon will not schedule,
// and each row states why.
func TestRunStatusReportsJobStateAndSchedulesOnlyActiveJobs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateJob(ctx, managedCLIJob("active-job")); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err := s.CreateJobWithEnabled(ctx, managedCLIJob("paused-job"), false); err != nil {
		s.Close()
		t.Fatal(err)
	}
	archived, err := s.CreateJob(ctx, managedCLIJob("archived-job"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.SetJobArchived(ctx, archived.ID, true); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"+legacyCLIJobsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"active-job": "scheduled", "paused-job": "paused", "archived-job": "archived", "legacy-yaml": "legacy"}
	for _, output := range []string{"json", "text"} {
		stdout, _, err := captureCLIOutput(t, func() error {
			return run([]string{"status", "--config", configPath, "--output", output})
		})
		if err != nil {
			t.Fatalf("%s status: %v", output, err)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
			t.Fatalf("%s status output %q: %v", output, stdout, err)
		}
		if len(rows) != len(want) {
			t.Fatalf("%s status rows = %v", output, rows)
		}
		for _, row := range rows {
			name, _ := row["name"].(string)
			if row["state"] != want[name] {
				t.Fatalf("%s status %s state = %v, want %s", output, name, row["state"], want[name])
			}
			nextRun, hasNextRun := row["next_run"].(string)
			if scheduled := want[name] == "scheduled"; scheduled != (hasNextRun && nextRun != "") {
				t.Fatalf("%s status %s next_run = %v; only scheduled jobs have one", output, name, row["next_run"])
			}
		}
	}
}

// A host CLI scan mutates scan history, baselines, incidents, and the outbox,
// so it leaves the same security audit trail as the web run action.
func TestRunScanRecordsHostAuditEntry(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	database := filepath.Join(dir, "edgewatch.db")
	s, err := store.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.CreateJob(ctx, managedCLIJob("managed"))
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := func(job, nmap string) error {
		_, _, err := captureCLIOutput(t, func() error {
			return run([]string{"scan", "--config", configPath, "--job", job, "--nmap", nmap, "--output", "json"})
		})
		return err
	}
	if err := scan("managed", writeFakeNmap(t, dir, false)); err != nil {
		t.Fatalf("successful scan: %v", err)
	}
	if err := scan("managed", writeFakeNmap(t, dir, true)); err == nil {
		t.Fatal("failing scanner did not fail the scan")
	}
	if err := scan("missing", writeFakeNmap(t, dir, false)); err == nil {
		t.Fatal("unknown job unexpectedly scanned")
	}

	reader, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rows, err := reader.DB.QueryContext(ctx, `SELECT action,actor_username,detail FROM security_audit WHERE action='scan.run_requested' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var action, actor, detail string
		if err := rows.Scan(&action, &actor, &detail); err != nil {
			t.Fatal(err)
		}
		if actor != "host-cli" || strings.Contains(detail, "192.0.2.10") {
			t.Fatalf("unsafe scan audit row: actor=%q detail=%q", actor, detail)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantDetails := []string{"job=" + record.ID + " status=success", "job=" + record.ID + " status=failed"}
	if strings.Join(details, "\n") != strings.Join(wantDetails, "\n") {
		t.Fatalf("scan audit details = %q, want %q", details, wantDetails)
	}
}
