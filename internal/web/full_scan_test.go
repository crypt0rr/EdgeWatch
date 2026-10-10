package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// decodedScanResponse is the GET /scans/{id} response as releases before
// the verbatim writer built it: the decoded scan, encoded by writeJSON.
func decodedScanResponse(t *testing.T, ts *store.TenantStore, id string) *httptest.ResponseRecorder {
	t.Helper()
	scan, err := ts.GetScan(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, map[string]any{"scan": scan})
	return recorder
}

func getFullScan(server *Server, id string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	server.getScan(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+id, nil), defaultTenantStore(server), id)
	return recorder
}

// fullScanFixture returns a successful scan of record with evidence that
// exercises the encoder: HTML characters, non-ASCII text, a fractional
// latency, maps, host states and target failures.
func fullScanFixture(record store.JobRecord, id string, changes []model.Change) model.Scan {
	when := time.Date(2026, 10, 1, 12, 30, 45, 123456789, time.UTC)
	snapshot := runtimeTestSnapshot(3, 2)
	snapshot.Hosts[0].LatencyMS = 0.4271
	snapshot.Hosts[0].Hostnames = []model.Hostname{{Name: "café.example", Type: "PTR"}}
	snapshot.Hosts[1].Protocols[0].Ports[0].Service.ExtraInfo = `<b>"admin" & co</b>`
	snapshot.Hosts[1].Protocols[0].NSEArgs = map[string]string{"z": "last", "a": "first"}
	return model.Scan{ID: id, JobID: record.ID, JobRevision: record.Revision, Job: record.Job.Name, StartedAt: when, FinishedAt: when.Add(time.Minute), Status: "success", NmapVersion: "7.95", ScannerEngine: "nmap", ConfigHash: record.Job.SecurityHash(), BaselineScanID: "baseline", BaselineConfigHash: record.Job.SecurityHash(), Comparison: model.ScanComparisonCompared, Changes: changes, Snapshot: snapshot}
}

func TestFullScanResponseMatchesTheDecodedScanByteForByte(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	record := runtimeTestJob(t, db, "full-scan-bytes")
	changes := []model.Change{{Key: "port|198.18.0.1|tcp|1000", Kind: "port", Severity: "critical", Target: "198.18.0.1", Protocol: "tcp", Port: 1000, Old: "not-open", New: "open"}}
	failed := fullScanFixture(record, "full-scan-failed", nil)
	failed.Status, failed.Error, failed.Snapshot = "failed", "nmap exited <1>", model.Snapshot{}
	for _, scan := range []model.Scan{fullScanFixture(record, "full-scan-changes", changes), fullScanFixture(record, "full-scan-no-changes", nil), failed} {
		if err := db.System().SaveScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		got, want := getFullScan(server, scan.ID), decodedScanResponse(t, defaultTenantStore(server), scan.ID)
		if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
			t.Errorf("%s: GET /scans/{id} = %d\n%s\nwant\n%s", scan.ID, got.Code, got.Body.String(), want.Body.String())
		}
		for _, header := range []string{"Content-Type", "Cache-Control"} {
			if got.Header().Get(header) != want.Header().Get(header) {
				t.Errorf("%s: %s = %q, want %q", scan.ID, header, got.Header().Get(header), want.Header().Get(header))
			}
		}
	}
}

// TestFullScanResponseDecodesStoredValuesItCannotWriteVerbatim answers a
// row whose snapshot or changes EdgeWatch would not have written as the
// decoding path did, and a row it cannot decode with not found.
func TestFullScanResponseDecodesStoredValuesItCannotWriteVerbatim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	record := runtimeTestJob(t, db, "full-scan-stored")
	for index, stored := range []struct {
		snapshot, changes string
		found             bool
	}{
		{`null`, `[]`, true},
		{` {"units":[],"scopes":null} `, `null`, true},
		{`{"units":[],"scopes":null}`, ` [ ] `, true},
		{`{"units":[],"scopes":null}`, ``, true},
		{`{"units":[],"scopes":null}`, `[{"key":"a","kind":"port","severity":"info","target":"198.18.0.1"}]`, true},
		{`{"units":`, `[]`, false},
		{`[]`, `[]`, false},
		{`{"units":[],"scopes":null}`, `{"key":"a"}`, false},
		{`{"units":[],"scopes":null}`, `[{"key":`, false},
	} {
		id := fmt.Sprintf("full-scan-stored-%d", index)
		if err := db.System().SaveScan(ctx, fullScanFixture(record, id, nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.ExecContext(ctx, `UPDATE scans SET snapshot_json=?,changes_json=? WHERE id=?`, []byte(stored.snapshot), []byte(stored.changes), id); err != nil {
			t.Fatal(err)
		}
		got := getFullScan(server, id)
		if !stored.found {
			if got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), `"scan"`) {
				t.Errorf("snapshot %q, changes %q: GET /scans/{id} = %d: %s", stored.snapshot, stored.changes, got.Code, got.Body.String())
			}
			continue
		}
		if want := decodedScanResponse(t, defaultTenantStore(server), id); got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
			t.Errorf("snapshot %q, changes %q: GET /scans/{id} = %d\n%s\nwant\n%s", stored.snapshot, stored.changes, got.Code, got.Body.String(), want.Body.String())
		}
	}
	if got := getFullScan(server, "missing-scan"); got.Code != http.StatusNotFound {
		t.Errorf("missing scan = %d: %s", got.Code, got.Body.String())
	}
}

// countingResponseWriter discards a response body and counts its bytes, so
// that measuring a handler's allocations leaves out a buffered body.
type countingResponseWriter struct {
	header  http.Header
	status  int
	written int
	failAt  int
}

func (w *countingResponseWriter) Header() http.Header { return w.header }

func (w *countingResponseWriter) WriteHeader(status int) { w.status = status }

func (w *countingResponseWriter) Write(data []byte) (int, error) {
	if w.failAt > 0 && w.written+len(data) > w.failAt {
		return 0, fmt.Errorf("client went away")
	}
	w.written += len(data)
	return len(data), nil
}

// TestFullScanResponseHoldsALargeSnapshotOnce writes a 50 MB stored
// snapshot while allocating little more than the driver's copy of it. The
// decoding path allocated several times the snapshot's size. The test is
// not parallel, so that other tests do not count towards the allocations
// it measures.
func TestFullScanResponseHoldsALargeSnapshotOnce(t *testing.T) {
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	record := runtimeTestJob(t, db, "full-scan-large")
	scan := fullScanFixture(record, "full-scan-large", nil)
	if err := db.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	const size = 50 << 20
	host := `{"address":"198.18.0.1","status":"up","protocols":[{"protocol":"tcp","scanned_ports":"1-1024","scanned_port_count":1024,"service_detection":true,"ports":[{"port":443,"state":"open","service":{"name":"https","product":"nginx"}}]}]}`
	var snapshot bytes.Buffer
	snapshot.Grow(size + len(host))
	snapshot.WriteString(`{"units":[],"scopes":null,"hosts":[`)
	for snapshot.Len() < size {
		snapshot.WriteString(host)
		snapshot.WriteByte(',')
	}
	snapshot.WriteString(host + `]}`)
	if _, err := db.DB.ExecContext(ctx, `UPDATE scans SET snapshot_json=? WHERE id=?`, snapshot.Bytes(), scan.ID); err != nil {
		t.Fatal(err)
	}
	stored := snapshot.Len()
	snapshot = bytes.Buffer{}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scan.ID, nil)
	writer := &countingResponseWriter{header: http.Header{}}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	server.getScan(writer, request, defaultTenantStore(server), scan.ID)
	runtime.ReadMemStats(&after)
	if writer.status != http.StatusOK || writer.written < stored {
		t.Fatalf("GET /scans/{id} = %d with %d bytes for a %d byte snapshot", writer.status, writer.written, stored)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > uint64(stored)+uint64(stored)/4 {
		t.Fatalf("GET /scans/{id} allocated %d bytes for a %d byte snapshot", allocated, stored)
	}
	t.Logf("GET /scans/{id} allocated %d bytes for a %d byte snapshot", allocated, stored)
}

// TestFullScanResponsesWaitForASlot holds every full-result slot, so a
// request waits and gives up when its client does. Once a slot is free, a
// request is answered, and an interrupted response frees its slot again.
func TestFullScanResponsesWaitForASlot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	record := runtimeTestJob(t, db, "full-scan-slots")
	if err := db.System().SaveScan(ctx, fullScanFixture(record, "full-scan-slots", nil)); err != nil {
		t.Fatal(err)
	}
	if got := getFullScan(server, "full-scan-slots"); got.Code != http.StatusOK {
		t.Fatalf("GET /scans/{id} = %d", got.Code)
	}
	for range maxConcurrentFullScans {
		server.fullScanSlots <- struct{}{}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	waiting := httptest.NewRecorder()
	server.getScan(waiting, httptest.NewRequest(http.MethodGet, "/api/v1/scans/full-scan-slots", nil).WithContext(canceled), defaultTenantStore(server), "full-scan-slots")
	if waiting.Body.Len() != 0 || waiting.Header().Get("Content-Type") != "" {
		t.Fatalf("request without a slot wrote %q", waiting.Body.String())
	}
	<-server.fullScanSlots
	if got := getFullScan(server, "full-scan-slots"); got.Code != http.StatusOK {
		t.Fatalf("GET /scans/{id} after a slot was freed = %d", got.Code)
	}

	// A client that goes away during the response gets nothing more, and
	// the slot is released.
	failing := &countingResponseWriter{header: http.Header{}, failAt: 16}
	server.getScan(failing, httptest.NewRequest(http.MethodGet, "/api/v1/scans/full-scan-slots", nil), defaultTenantStore(server), "full-scan-slots")
	if failing.status != http.StatusOK || failing.written > 16 {
		t.Fatalf("interrupted GET /scans/{id} = %d with %d bytes", failing.status, failing.written)
	}
	if got := getFullScan(server, "full-scan-slots"); got.Code != http.StatusOK {
		t.Fatalf("GET /scans/{id} after an interrupted response = %d", got.Code)
	}
}
