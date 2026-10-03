package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestIncidentActionsWakeDeliveryWorker(t *testing.T) {
	deliveries := make(chan string, 4)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		select {
		case deliveries <- string(body):
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	parsedWebhook, err := url.Parse(webhook.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://" + parsedWebhook.Host + "/edgewatch?disabletls=yes&template=json"

	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	server := newRoutingTestServer(t, db, destination)
	disabled := false
	server.App.Config.Updates.Enabled = &disabled
	job := config.NormalizeJob(config.Job{
		Name:     "incident-delivery-wake",
		Schedule: "0 0 1 1 *",
		Timezone: "UTC",
		Targets:  []string{"127.0.0.1"},
		TCP:      &config.Protocol{Ports: "1-65535", Mode: "connect", Engine: config.EngineNmap},
	})
	record, err := defaultTenant(db).CreateJob(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	acceptedChange := model.Change{
		Key: "port|127.0.0.1|tcp|443", Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 443,
		Old: "not-open", New: "open", Severity: "critical",
	}
	suppressedChange := model.Change{
		Key: "port|127.0.0.1|tcp|80", Kind: "port", Target: "127.0.0.1", Protocol: "tcp", Port: 80,
		Old: "not-open", New: "open", Severity: "critical",
	}
	_, err = db.System().UpdateRuntime(ctx, record.ID, func(state *model.JobState) ([]model.Event, error) {
		state.Baseline = &model.Snapshot{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1-65535"}}}
		if state.Incidents == nil {
			state.Incidents = make(map[string]model.Incident)
		}
		now := time.Now().UTC()
		for _, change := range []model.Change{acceptedChange, suppressedChange} {
			state.Incidents[change.Key] = model.Incident{Change: change, ScanID: "incident-action-scan", OpenedAt: now, LastSeenAt: now}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.App.Notifier.Queue(ctx, []model.Event{{Type: "delivery-wake-primer", Job: job.Name, Message: "delivery worker ready", CreatedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}

	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- server.App.Daemon(daemonCtx) }()
	defer func() {
		cancelDaemon()
		select {
		case err := <-daemonDone:
			if err != nil && err != context.Canceled {
				t.Errorf("daemon stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("delivery worker daemon did not stop after cancellation")
		}
	}()

	waitForDelivery := func(t *testing.T, label string) {
		t.Helper()
		select {
		case body := <-deliveries:
			var payload struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				t.Fatalf("decode %s delivery %q: %v", label, body, err)
			}
			if strings.TrimSpace(payload.Message) == "" {
				t.Fatalf("%s delivery had an empty message: %s", label, body)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s notification was not delivered promptly", label)
		}
	}
	waitForDelivery(t, "startup primer")

	for _, action := range []struct {
		name   string
		change model.Change
	}{
		{name: "accept", change: acceptedChange},
		{name: "suppress", change: suppressedChange},
	} {
		t.Run(action.name, func(t *testing.T) {
			body, err := json.Marshal(incidentActionRequest{Key: action.change.Key, ExpectedChange: &action.change})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			path := record.ID + "/incidents/" + action.name
			server.jobRoute(response, scanHandlerRequest(http.MethodPost, "/api/v1/jobs/"+path, string(body)), admin, defaultTenantStore(server), path)
			if response.Code != http.StatusNoContent {
				t.Fatalf("%s incident = %d: %s", action.name, response.Code, response.Body.String())
			}
			waitForDelivery(t, action.name)
		})
	}
}
