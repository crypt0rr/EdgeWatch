package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestQueueAndDeliverGenericWebhook(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsed.Host + "/edgewatch?disabletls=yes&template=json"
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	notifier, err := New(db, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", Job: "public", ScanID: "scan-1", Message: "one change", CreatedAt: time.Now(), Changes: []model.Change{{Target: "example.com", Protocol: "tcp", Port: 443, Old: "not-open", New: "open", Severity: "critical"}}}
	if err := notifier.Queue(context.Background(), []model.Event{event}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("received %d webhook calls", calls.Load())
	}
	due, err := db.DueDeliveries(context.Background(), 10)
	if err != nil || len(due) != 0 {
		t.Fatalf("delivery remains due: %#v %v", due, err)
	}
}

func TestInvalidURLDoesNotLeakSecret(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = New(db, []string{"unknown://super-secret@example.invalid/path"})
	if err == nil {
		t.Fatal("invalid URL accepted")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}
