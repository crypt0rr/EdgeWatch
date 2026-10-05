package app

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func routingTestJob(name string) config.Job {
	return config.NormalizeJob(config.Job{
		Name:     name,
		Schedule: "0 * * * *",
		Timezone: "UTC",
		Targets:  []string{"127.0.0.1"},
		TCP:      &config.Protocol{Ports: "1", Mode: "connect"},
		Timeout:  config.Duration(time.Minute),
		Timing:   "balanced",
	})
}

func routingTestConfig(database string, urls ...string) *config.Config {
	return &config.Config{
		Version: 1, Database: database, Retention: config.Duration(24 * time.Hour),
		Scheduler:     config.Scheduler{MaxConcurrent: 1},
		Web:           config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{URLs: urls},
	}
}

func TestNewFreezesPausedManagedDestinationsWithoutDroppingThem(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	notifier, err := notify.New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	tn := notifier.Tenant(defaultTenant(s))
	first, err := tn.CreateManagedWithAudit(ctx, "First", "generic://localhost/first?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := tn.CreateManagedWithAudit(ctx, "Second", "generic://localhost/second?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	record, err := defaultTenant(s).CreateJob(ctx, routingTestJob("legacy-paused-startup"))
	if err != nil || record.Job.NotificationDestinations != nil {
		t.Fatalf("create nil-routed job = %#v, %v; want legacy nil routing", record, err)
	}
	paused := false
	pausedFirst, err := tn.UpdateManagedWithAudit(ctx, first.ID, first.Revision, first.Name, nil, &paused, store.AuditEntry{})
	if err != nil || pausedFirst.Enabled {
		t.Fatalf("pause First = %+v, %v", pausedFirst, err)
	}

	app, err := New(routingTestConfig(s.Path), s, "missing-nmap", slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	job, err := defaultTenant(s).GetJob(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantSelection := []string{first.ID, second.ID}
	slices.Sort(wantSelection)
	if job.Job.NotificationDestinations == nil || !slices.Equal(job.Job.NotificationDestinations, wantSelection) {
		t.Fatalf("job routing after startup freeze = %v; want paused First retained in %v", job.Job.NotificationDestinations, wantSelection)
	}
	tn = app.Notifier.Tenant(defaultTenant(s))
	keys, err := tn.QueueDestinationsForJob(ctx, job.Job)
	if err != nil || !slices.Equal(keys, []string{"managed:" + second.ID + ":1"}) {
		t.Fatalf("queue while First is paused = %v, %v; want only Second", keys, err)
	}
	enabled := true
	resumedFirst, err := tn.UpdateManagedWithAudit(ctx, first.ID, pausedFirst.Revision, first.Name, nil, &enabled, store.AuditEntry{})
	if err != nil || !resumedFirst.Enabled {
		t.Fatalf("resume First = %+v, %v", resumedFirst, err)
	}
	keys, err = tn.QueueDestinationsForJob(ctx, job.Job)
	wantKeys := []string{"managed:" + first.ID + ":3", "managed:" + second.ID + ":1"}
	slices.Sort(wantKeys)
	if err != nil || !slices.Equal(keys, wantKeys) {
		t.Fatalf("queue after First resumes = %v, %v; want %v", keys, err, wantKeys)
	}
}

func TestNewReportsJobsRoutedToRotatedDeploymentDestination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rotated, err := defaultTenant(s).CreateJob(ctx, routingTestJob("rotated-routing"))
	if err != nil {
		t.Fatal(err)
	}
	archived, err := defaultTenant(s).CreateJob(ctx, routingTestJob("archived-rotated-routing"))
	if err != nil {
		t.Fatal(err)
	}
	silentJob := routingTestJob("silent-routing")
	silentJob.NotificationDestinations = []string{}
	silent, err := defaultTenant(s).CreateJob(ctx, silentJob)
	if err != nil {
		t.Fatal(err)
	}

	oldURL := "generic://localhost/hook?token=old-secret&disabletls=yes&template=json"
	var firstLogs bytes.Buffer
	if _, err := New(routingTestConfig(s.Path, oldURL), s, "missing-nmap", slog.New(slog.NewTextHandler(&firstLogs, nil))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(firstLogs.String(), "no longer exist") {
		t.Fatalf("startup reported missing destinations before the URL changed: %s", firstLogs.String())
	}
	frozen, err := defaultTenant(s).GetJob(ctx, rotated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(frozen.Job.NotificationDestinations) != 1 || !strings.HasPrefix(frozen.Job.NotificationDestinations[0], "file:") {
		t.Fatalf("startup did not freeze the deployment selector: %#v", frozen.Job.NotificationDestinations)
	}
	oldSelector := frozen.Job.NotificationDestinations[0]
	if err := defaultTenant(s).SetJobArchived(ctx, archived.ID, true); err != nil {
		t.Fatal(err)
	}

	newURL := "generic://localhost/hook?token=new-secret&disabletls=yes&template=json"
	var logs bytes.Buffer
	if _, err := New(routingTestConfig(s.Path, newURL), s, "missing-nmap", slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	output := logs.String()
	var warning string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "no longer exist") {
			warning = line
		}
	}
	if warning == "" {
		t.Fatalf("startup did not warn about jobs routed to a removed destination: %s", output)
	}
	if !strings.Contains(warning, "rotated-routing") || !strings.Contains(warning, rotated.ID) {
		t.Fatalf("warning does not name the affected job: %s", warning)
	}
	if strings.Contains(warning, "silent-routing") || strings.Contains(warning, silent.ID) || strings.Contains(warning, archived.ID) {
		t.Fatalf("warning names jobs that do not need attention: %s", warning)
	}
	for _, secret := range []string{"old-secret", "new-secret", "generic://", oldSelector} {
		if strings.Contains(output, secret) {
			t.Fatalf("startup log exposed %q: %s", secret, output)
		}
	}
}

func TestMissingNotificationDestinationCheckDoesNotBlockStartup(t *testing.T) {
	t.Parallel()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	notifier, err := notify.New(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	reportMissingNotificationDestinations(context.Background(), s, notifier, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "notification routing check failed") {
		t.Fatalf("failed routing check was not logged: %s", logs.String())
	}
}

func TestNewDoesNotReportCurrentNotificationRouting(t *testing.T) {
	t.Parallel()
	s, err := store.Open(storetest.FreshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := defaultTenant(s).CreateJob(context.Background(), routingTestJob("current-routing")); err != nil {
		t.Fatal(err)
	}
	url := "generic://localhost/hook?token=current&disabletls=yes&template=json"
	for range 2 {
		var logs bytes.Buffer
		if _, err := New(routingTestConfig(s.Path, url), s, "missing-nmap", slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "no longer exist") {
			t.Fatalf("startup reported current routing as missing: %s", logs.String())
		}
	}
}
