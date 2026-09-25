package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type routingJobResponse struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Job      struct {
		NotificationDestinations []string `json:"notification_destinations"`
	} `json:"job"`
	MissingNotificationDestinations []string `json:"missing_notification_destinations"`
}

func routingRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9100"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func decodeRoutingJob(t *testing.T, response *httptest.ResponseRecorder) routingJobResponse {
	t.Helper()
	var job routingJobResponse
	if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode job response %s: %v", response.Body.String(), err)
	}
	return job
}

func routingJobUpdateBody(schedule string, revision int64, selection []string) string {
	encoded, _ := json.Marshal(selection)
	return fmt.Sprintf(`{"name":"routed","schedule":%q,"timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect","engine":"nmap"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1,"max_expanded_hosts":256,"revision":%d,"notification_destinations":%s}`, schedule, revision, encoded)
}

func TestDeletingManagedDestinationUnblocksJobEdits(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	created := httptest.NewRecorder()
	server.createNotificationDestination(created, routingRequest(t, http.MethodPost, "/api/v1/notifications/destinations", `{"name":"Ops","url":"generic://localhost/ops?disabletls=yes","password":"administrator password"}`), admin)
	if created.Code != http.StatusCreated {
		t.Fatalf("create destination = %d: %s", created.Code, created.Body.String())
	}
	var destination struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &destination); err != nil {
		t.Fatal(err)
	}
	createdJob := httptest.NewRecorder()
	server.createJob(createdJob, routingRequest(t, http.MethodPost, "/api/v1/jobs", `{"name":"routed","schedule":"0 * * * *","timezone":"UTC","targets":["127.0.0.1"],"tcp":{"ports":"1","mode":"connect","engine":"nmap"},"timeout":"1m","timing":"balanced","baseline_samples":1,"change_confirmations":1,"max_expanded_hosts":256,"notification_destinations":["`+destination.ID+`"]}`), admin)
	if createdJob.Code != http.StatusCreated {
		t.Fatalf("create job = %d: %s", createdJob.Code, createdJob.Body.String())
	}
	job := decodeRoutingJob(t, createdJob)
	routing := httptest.NewRecorder()
	server.updateNotificationRouting(routing, routingRequest(t, http.MethodPut, "/api/v1/notifications/update-routing", `{"destinations":["`+destination.ID+`"],"password":"administrator password"}`), admin)
	if routing.Code != http.StatusOK {
		t.Fatalf("update routing = %d: %s", routing.Code, routing.Body.String())
	}

	deleted := httptest.NewRecorder()
	server.notificationDestinationRoute(deleted, routingRequest(t, http.MethodDelete, "/api/v1/notifications/destinations/"+destination.ID, fmt.Sprintf(`{"password":"administrator password","revision":%d}`, destination.Revision)), admin, destination.ID)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete destination = %d: %s", deleted.Code, deleted.Body.String())
	}
	broadcastJobUpdate := false
	for _, message := range server.history {
		if strings.Contains(string(message.payload), `"type":"job.updated"`) && strings.Contains(string(message.payload), job.ID) {
			broadcastJobUpdate = true
		}
	}

	loaded := httptest.NewRecorder()
	server.jobRoute(loaded, routingRequest(t, http.MethodGet, "/api/v1/jobs/"+job.ID, ""), admin, job.ID)
	if loaded.Code != http.StatusOK {
		t.Fatalf("get job = %d: %s", loaded.Code, loaded.Body.String())
	}
	current := decodeRoutingJob(t, loaded)
	if current.Job.NotificationDestinations == nil || len(current.Job.NotificationDestinations) != 0 || current.Revision != job.Revision+1 || len(current.MissingNotificationDestinations) != 0 {
		t.Fatalf("job after destination delete = %#v", current)
	}
	updated := httptest.NewRecorder()
	server.jobRoute(updated, routingRequest(t, http.MethodPut, "/api/v1/jobs/"+job.ID, routingJobUpdateBody("30 * * * *", current.Revision, current.Job.NotificationDestinations)), admin, job.ID)
	if updated.Code != http.StatusOK {
		t.Fatalf("schedule-only edit after destination delete = %d: %s", updated.Code, updated.Body.String())
	}
	state, err := db.GetApplicationUpdateState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.UpdateNotificationDestinationsConfigured || len(state.UpdateNotificationDestinations) != 0 {
		t.Fatalf("update routing after destination delete = %#v", state)
	}
	if !broadcastJobUpdate {
		t.Fatal("destination delete did not announce the job routing change to open consoles")
	}
}

// newRoutingTestServer starts a server on an existing database with the
// supplied deployment URLs, as a daemon restart with an edited config.yaml does.
func newRoutingTestServer(t *testing.T, db *store.Store, urls ...string) *Server {
	t.Helper()
	cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(24 * time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"}, Notifications: config.Notifications{URLs: urls}}
	a, err := app.New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(a, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestJobAPIReportsRoutingToRotatedDeploymentDestination(t *testing.T) {
	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "routed", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", Engine: "nmap"}, Timeout: config.Duration(time.Minute), Timing: "balanced", Baseline: config.Baseline{Samples: 1}, Change: config.Change{Confirmations: 1}}))
	if err != nil {
		t.Fatal(err)
	}
	oldURL := "generic://localhost/hook?token=old-secret&disabletls=yes&template=json"
	newRoutingTestServer(t, db, oldURL)
	frozen, err := db.GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldSelector := frozen.Job.NotificationDestinations[0]

	newURL := "generic://localhost/hook?token=new-secret&disabletls=yes&template=json"
	server := newRoutingTestServer(t, db, newURL)
	newSelector := server.App.Notifier.LegacySelection()[0]
	if newSelector == oldSelector {
		t.Fatalf("changed deployment URL kept selector %q", oldSelector)
	}
	loaded := httptest.NewRecorder()
	server.jobRoute(loaded, routingRequest(t, http.MethodGet, "/api/v1/jobs/"+record.ID, ""), admin, record.ID)
	current := decodeRoutingJob(t, loaded)
	if loaded.Code != http.StatusOK || strings.Join(current.MissingNotificationDestinations, ",") != oldSelector || strings.Join(current.Job.NotificationDestinations, ",") != oldSelector {
		t.Fatalf("job after URL rotation = %d %#v, want missing %q", loaded.Code, current, oldSelector)
	}
	listed := httptest.NewRecorder()
	server.listJobs(listed, routingRequest(t, http.MethodGet, "/api/v1/jobs", ""))
	var list struct {
		Jobs []routingJobResponse `json:"jobs"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &list); err != nil || len(list.Jobs) != 1 || strings.Join(list.Jobs[0].MissingNotificationDestinations, ",") != oldSelector {
		t.Fatalf("job list after URL rotation = %s (%v)", listed.Body.String(), err)
	}
	for _, body := range []string{loaded.Body.String(), listed.Body.String()} {
		if strings.Contains(body, "secret") || strings.Contains(body, "generic://") {
			t.Fatalf("job response exposed a destination URL: %s", body)
		}
	}

	// The console drops the unresolved selector and opts into the new
	// destination; the server accepts that save and stops reporting it.
	updated := httptest.NewRecorder()
	server.jobRoute(updated, routingRequest(t, http.MethodPut, "/api/v1/jobs/"+record.ID, routingJobUpdateBody("30 * * * *", current.Revision, []string{newSelector})), admin, record.ID)
	if updated.Code != http.StatusOK {
		t.Fatalf("repair save = %d: %s", updated.Code, updated.Body.String())
	}
	repaired := decodeRoutingJob(t, updated)
	if strings.Join(repaired.Job.NotificationDestinations, ",") != newSelector || len(repaired.MissingNotificationDestinations) != 0 {
		t.Fatalf("repaired job = %#v", repaired)
	}
}

func TestJobAPIShowsLegacyDeploymentDigestAsCurrentSelector(t *testing.T) {
	ctx := context.Background()
	_, db, admin := newUsersTestServer(t)
	url := "generic://localhost/hook?token=legacy&disabletls=yes&template=json"
	digest := sha256.Sum256([]byte(url))
	legacySelector := "file:" + hex.EncodeToString(digest[:])
	record, err := db.CreateJob(ctx, config.NormalizeJob(config.Job{Name: "legacy-digest", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"127.0.0.1"}, TCP: &config.Protocol{Ports: "1", Mode: "connect", Engine: "nmap"}, Timeout: config.Duration(time.Minute), Timing: "balanced", NotificationDestinations: []string{legacySelector}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetApplicationUpdateDestinations(ctx, []string{legacySelector}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	server := newRoutingTestServer(t, db, url)
	currentSelector := server.App.Notifier.LegacySelection()[0]
	loaded := httptest.NewRecorder()
	server.jobRoute(loaded, routingRequest(t, http.MethodGet, "/api/v1/jobs/"+record.ID, ""), admin, record.ID)
	job := decodeRoutingJob(t, loaded)
	if loaded.Code != http.StatusOK || strings.Join(job.Job.NotificationDestinations, ",") != currentSelector || len(job.MissingNotificationDestinations) != 0 {
		t.Fatalf("legacy digest job = %d %#v, want selector %q", loaded.Code, job, currentSelector)
	}
	if strings.Contains(loaded.Body.String(), legacySelector) {
		t.Fatalf("job response exposed the legacy URL digest: %s", loaded.Body.String())
	}
	listed := httptest.NewRecorder()
	server.listNotificationDestinations(listed, routingRequest(t, http.MethodGet, "/api/v1/notifications/destinations", ""))
	var destinations struct {
		UpdateRouting struct {
			Destinations []string `json:"destinations"`
		} `json:"update_routing"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &destinations); err != nil || strings.Join(destinations.UpdateRouting.Destinations, ",") != currentSelector {
		t.Fatalf("update routing with legacy digest = %s (%v)", listed.Body.String(), err)
	}
}
