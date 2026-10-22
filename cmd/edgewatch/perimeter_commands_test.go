package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func newPerimeterCLIStore(t *testing.T) (string, string) {
	t.Helper()
	database := storetest.FreshPath(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.ExecContext(context.Background(), `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,?,?,?,?)`, otherTenantID, "Other", "other", stamp, stamp); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("database: "+database+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return database, configPath
}

func seedPerimeterCLI(t *testing.T, database, tenantID string, entries ...store.PerimeterEntry) {
	t.Helper()
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	scope := store.DefaultTenantScope()
	if tenantID != store.DefaultTenantID {
		var scopeErr error
		scope, scopeErr = s.TenantScopeByID(context.Background(), tenantID)
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
	}
	if _, err := s.Tenant(scope).DeclarePerimeterSeeds(context.Background(), entries, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
}

func TestPerimeterListIsTenantScopedAndReadOnly(t *testing.T) {
	database, configPath := newPerimeterCLIStore(t)
	seedPerimeterCLI(t, database, store.DefaultTenantID, store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "192.0.2.0/24", Label: "default-only"})
	seedPerimeterCLI(t, database, otherTenantID, store.PerimeterEntry{Kind: store.PerimeterKindAuthorized, Value: "198.51.100.0/24", Label: "other-only"})

	s, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit`).Scan(&before); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"perimeter", "list", "--tenant", "other", "--output", "json", "--config", configPath})
	})
	if err != nil {
		t.Fatalf("perimeter list: %v", err)
	}
	var got []store.PerimeterSeed
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("list JSON %q: %v", stdout, err)
	}
	if len(got) != 1 || got[0].Kind != store.PerimeterKindAuthorized || got[0].Value != "198.51.100.0/24" || got[0].Label != "other-only" {
		t.Fatalf("listed ranges = %+v, want only the other unit's authorized range", got)
	}
	if strings.Contains(stdout, "default-only") || strings.Contains(stdout, "192.0.2.0/24") {
		t.Fatalf("list output crossed tenant scope: %s", stdout)
	}
	textOutput, _, err := captureCLIOutput(t, func() error {
		return run([]string{"perimeter", "list", "--tenant", "other", "--config", configPath})
	})
	if err != nil || !strings.Contains(textOutput, "authorized 198.51.100.0/24 other-only") || strings.Contains(textOutput, "default-only") {
		t.Fatalf("text list output = %q, err=%v", textOutput, err)
	}

	s, err = store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var after int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("read-only list wrote %d audit rows; before=%d after=%d", after-before, before, after)
	}
}

func TestPerimeterDeclareIsIdempotentAndAudited(t *testing.T) {
	database, configPath := newPerimeterCLIStore(t)
	declaration := "\r192.0.2.17/24 edge router\r\r198.51.100.7\r"
	inputPath := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(inputPath, []byte(declaration), 0o600); err != nil {
		t.Fatal(err)
	}

	runDeclare := func(from string) store.PerimeterDeclareResult {
		t.Helper()
		stdout, _, err := captureCLIOutput(t, func() error {
			return run([]string{"perimeter", "declare", "--tenant", "other", "--kind", "prefix", "--from", from, "--config", configPath, "--output", "json"})
		})
		if err != nil {
			t.Fatalf("perimeter declare --from %s: %v", from, err)
		}
		var result store.PerimeterDeclareResult
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			t.Fatalf("declare JSON %q: %v", stdout, err)
		}
		return result
	}

	if got := runDeclare(inputPath); got != (store.PerimeterDeclareResult{Created: 2}) {
		t.Fatalf("first declare = %+v, want two created", got)
	}

	// The same input through standard input is wholly skipped on repetition.
	stdinFile, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdinFile.WriteString(declaration); err != nil {
		stdinFile.Close()
		t.Fatal(err)
	}
	if _, err := stdinFile.Seek(0, 0); err != nil {
		stdinFile.Close()
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = stdinFile
	t.Cleanup(func() { os.Stdin = originalStdin })
	stdout, _, err := captureCLIOutput(t, func() error {
		return run([]string{"perimeter", "declare", "--tenant", "other", "--kind", "prefix", "--from", "-", "--config", configPath, "--output", "json"})
	})
	if err != nil {
		t.Fatalf("perimeter declare from standard input: %v", err)
	}
	if err := stdinFile.Close(); err != nil {
		t.Fatal(err)
	}
	var repeated store.PerimeterDeclareResult
	if err := json.Unmarshal([]byte(stdout), &repeated); err != nil {
		t.Fatalf("repeated declare JSON %q: %v", stdout, err)
	}
	if repeated != (store.PerimeterDeclareResult{Skipped: 2}) {
		t.Fatalf("repeated declare = %+v, want both entries skipped", repeated)
	}

	s, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var seeds, audits, wrongActors int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM perimeter_seeds WHERE tenant_id=?`, otherTenantID).Scan(&seeds); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='perimeter.seeds_added'`, otherTenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='perimeter.seeds_added' AND (actor_username<>'host-cli' OR actor_kind<>'host')`, otherTenantID).Scan(&wrongActors); err != nil {
		t.Fatal(err)
	}
	if seeds != 2 || audits != 2 || wrongActors != 0 {
		t.Fatalf("stored seeds=%d audits=%d with wrong actor=%d; want 2, 2, 0", seeds, audits, wrongActors)
	}
	var createdBy string
	if err := s.DB.QueryRow(`SELECT created_by FROM perimeter_seeds WHERE tenant_id=? AND value='192.0.2.0/24'`, otherTenantID).Scan(&createdBy); err != nil {
		t.Fatal(err)
	}
	if createdBy != "host-cli" {
		t.Fatalf("created_by = %q, want host-cli", createdBy)
	}
}

func TestPerimeterDeclareRefusalIsAtomicAndDoesNotEchoInput(t *testing.T) {
	database, configPath := newPerimeterCLIStore(t)
	inputPath := filepath.Join(t.TempDir(), "private-ranges.txt")
	input := "192.0.2.0/24 PRIVATE-LABEL\n127.0.0.1 HIGHLY-SENSITIVE-LABEL\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := captureCLIOutput(t, func() error {
		return run([]string{"perimeter", "declare", "--tenant", "other", "--kind", "prefix", "--from", inputPath, "--config", configPath})
	})
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("refused declaration error = %v, want line-specific loopback refusal", err)
	}
	for _, secret := range []string{"192.0.2.0/24", "127.0.0.1", "PRIVATE-LABEL", "HIGHLY-SENSITIVE-LABEL", inputPath} {
		if strings.Contains(err.Error()+stdout+stderr, secret) {
			t.Errorf("refusal echoed submitted value or path %q: err=%v stdout=%q stderr=%q", secret, err, stdout, stderr)
		}
	}
	if stdout != "" {
		t.Fatalf("refused declaration printed success output: %q", stdout)
	}

	s, err := store.OpenReadOnlyExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var seeds, audits int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM perimeter_seeds WHERE tenant_id=?`, otherTenantID).Scan(&seeds); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE tenant_id=? AND action='perimeter.seeds_added'`, otherTenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if seeds != 0 || audits != 0 {
		t.Fatalf("refused declaration wrote seeds=%d audits=%d; want no writes", seeds, audits)
	}
}

func TestPerimeterCommandContract(t *testing.T) {
	for _, test := range []struct {
		args  []string
		want  []string
		avoid []string
	}{
		{args: []string{"perimeter", "list", "--help"}, want: []string{"Usage: edgewatch perimeter list", "--tenant", "--output"}, avoid: []string{"--kind", "--from"}},
		{args: []string{"perimeter", "declare", "--help"}, want: []string{"Usage: edgewatch perimeter declare", "--tenant", "--kind", "--from\tinput file, or - to read standard input", "--config"}, avoid: []string{"--job", "--password-file"}},
	} {
		stdout, _, err := captureCLIOutput(t, func() error { return run(test.args) })
		if err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		for _, want := range test.want {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v help lacks %q: %s", test.args, want, stdout)
			}
		}
		for _, unwanted := range test.avoid {
			if strings.Contains(stdout, unwanted) {
				t.Errorf("%v help contains unrelated %q: %s", test.args, unwanted, stdout)
			}
		}
	}

	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"perimeter", "list"}, want: "require --tenant SLUG"},
		{args: []string{"perimeter", "list", "--tenant", "other", "--kind", "prefix"}, want: "--kind does not apply to perimeter list"},
		{args: []string{"perimeter", "declare", "--tenant", "other", "--kind", "asn", "--from", "-"}, want: "--kind must be prefix or authorized"},
		{args: []string{"perimeter", "declare", "--tenant", "other", "--kind", "prefix"}, want: "--from is required"},
	} {
		if err := run(test.args); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%v error = %v, want %q", test.args, err, test.want)
		}
	}
	if err := run([]string{"perimeter", "unknown"}); err == nil || !strings.Contains(err.Error(), "expected: perimeter list or perimeter declare") {
		t.Errorf("unknown perimeter action error = %v, want a usage error", err)
	}

}

func TestPerimeterListTextEmptyAndReadError(t *testing.T) {
	database, _ := newPerimeterCLIStore(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tenant := s.Tenant(store.DefaultTenantScope())

	stdout, _, err := captureCLIOutput(t, func() error {
		return listPerimeter(context.Background(), tenant, "text")
	})
	if err != nil || !strings.Contains(stdout, "No declared perimeter ranges.") {
		t.Fatalf("empty text list = %q, err=%v", stdout, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := listPerimeter(ctx, tenant, "text"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled list error = %v, want context.Canceled", err)
	}
}

func TestPerimeterDeclareInputErrorsAndTextSummary(t *testing.T) {
	database, _ := newPerimeterCLIStore(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tenant := s.Tenant(store.DefaultTenantScope())

	missingPath := filepath.Join(t.TempDir(), "private-path-secret", "ranges.txt")
	err = declarePerimeter(context.Background(), tenant, store.PerimeterKindPrefix, missingPath, strings.NewReader(""), "text")
	if err == nil || err.Error() != "could not open perimeter declaration input" || strings.Contains(err.Error(), missingPath) {
		t.Fatalf("missing input error = %v, want a generic path-free error", err)
	}

	oversized := strings.Repeat("PRIVATE-CONTENT", maxPerimeterInputLineBytes/len("PRIVATE-CONTENT")+2)
	err = declarePerimeter(context.Background(), tenant, store.PerimeterKindPrefix, "-", strings.NewReader(oversized), "text")
	if err == nil || err.Error() != "could not read perimeter declaration input" || strings.Contains(err.Error(), "PRIVATE-CONTENT") {
		t.Fatalf("oversized input error = %v, want a generic value-free error", err)
	}

	err = declarePerimeter(context.Background(), tenant, store.PerimeterKindPrefix, "-", strings.NewReader("\r\n  \n"), "json")
	if err == nil || !strings.Contains(err.Error(), "declare between 1 and 256 entries") {
		t.Fatalf("empty declaration error = %v, want the bounded entry-count refusal", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = declarePerimeter(ctx, tenant, store.PerimeterKindPrefix, "-", strings.NewReader("192.0.2.0/24 private-label\n"), "json")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled declaration error = %v, want context.Canceled", err)
	}

	stdout, _, err := captureCLIOutput(t, func() error {
		return declarePerimeter(context.Background(), tenant, store.PerimeterKindPrefix, "-", strings.NewReader("192.0.2.0/24\n"), "text")
	})
	if err != nil || !strings.Contains(stdout, "Declared 1 new range.") {
		t.Fatalf("text declaration summary = %q, err=%v", stdout, err)
	}
}

func TestPerimeterDeclareCancellationInterruptsOpenInput(t *testing.T) {
	database, _ := newPerimeterCLIStore(t)
	s, err := store.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tenant := s.Tenant(store.DefaultTenantScope())

	pipeReader, pipeWriter := io.Pipe()
	input := &perimeterBlockingPipeReader{PipeReader: pipeReader, readStarted: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- declarePerimeter(ctx, tenant, store.PerimeterKindPrefix, "-", input, "json")
	}()

	completed := false
	defer func() {
		cancel()
		_ = pipeWriter.Close()
		_ = input.Close()
		if !completed {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("perimeter declaration reader did not stop after test cleanup")
			}
		}
	}()

	select {
	case <-input.readStarted:
	case <-time.After(time.Second):
		t.Fatal("perimeter declaration did not start reading the open input")
	}

	started := time.Now()
	cancel()
	select {
	case err := <-done:
		completed = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled declaration error = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("canceled declaration returned after %s, want within one second", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled declaration kept waiting on open input")
	}
}

type perimeterBlockingPipeReader struct {
	*io.PipeReader
	readStarted chan struct{}
	once        sync.Once
}

func (r *perimeterBlockingPipeReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.readStarted) })
	return r.PipeReader.Read(p)
}

type perimeterChunkReader struct {
	chunks []string
}

func (r *perimeterChunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if r.chunks[0] == "" {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func TestParsePerimeterDeclarationHandlesSplitLineEndings(t *testing.T) {
	input := &perimeterChunkReader{chunks: []string{
		"192.0.2.0/24\r",
		"\n198.51.100.0/24\r",
		"\n2001:db8::/32",
	}}
	entries, lineNumbers, err := parsePerimeterDeclaration(input, store.PerimeterKindPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || len(lineNumbers) != 3 {
		t.Fatalf("parsed %d entries on %d lines, want three", len(entries), len(lineNumbers))
	}
	for i, want := range []string{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"} {
		if entries[i].Value != want || lineNumbers[i] != i+1 {
			t.Errorf("entry %d = %+v on line %d, want %q on line %d", i, entries[i], lineNumbers[i], want, i+1)
		}
	}
}

func TestPerimeterDeclareSummary(t *testing.T) {
	for _, test := range []struct {
		result store.PerimeterDeclareResult
		want   string
	}{
		{result: store.PerimeterDeclareResult{Skipped: 2}, want: "No new ranges were declared; 2 already-declared entries were skipped."},
		{result: store.PerimeterDeclareResult{Created: 1}, want: "Declared 1 new range."},
		{result: store.PerimeterDeclareResult{Created: 2}, want: "Declared 2 new ranges."},
		{result: store.PerimeterDeclareResult{Created: 1, Skipped: 1}, want: "Declared 1 new range; 1 already-declared entry was skipped."},
	} {
		if got := perimeterDeclareSummary(test.result); got != test.want {
			t.Errorf("perimeterDeclareSummary(%+v) = %q, want %q", test.result, got, test.want)
		}
	}
}

func TestParsePerimeterDeclarationEnforcesBatchLimit(t *testing.T) {
	input := strings.Repeat("192.0.2.0/24\n", store.MaxPerimeterEntriesPerRequest+1)
	if _, _, err := parsePerimeterDeclaration(strings.NewReader(input), store.PerimeterKindPrefix); err == nil || !strings.Contains(err.Error(), "1 and 256 entries") {
		t.Fatalf("257-entry input error = %v, want a bounded declaration refusal", err)
	}
}
