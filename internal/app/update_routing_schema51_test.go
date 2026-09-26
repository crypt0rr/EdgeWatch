package app

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

// downgradeToSchema50 moves the update routing and the public status page
// back to their schema-50 locations and removes what schema 51 adds, as a
// database written by the previous release has it.
func downgradeToSchema50(t *testing.T, database string) {
	t.Helper()
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, statement := range []string{
		"DROP INDEX security_audit_tenant_time",
		"DROP INDEX security_audit_platform_time",
		"ALTER TABLE security_audit DROP COLUMN tenant_id",
		"ALTER TABLE security_audit DROP COLUMN actor_kind",
		"ALTER TABLE security_audit DROP COLUMN category",
		"ALTER TABLE setup_tokens DROP COLUMN purpose",
		`CREATE TABLE public_dashboard (id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0, title TEXT NOT NULL DEFAULT 'EdgeWatch public status', introduction TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)`,
		`INSERT INTO public_dashboard(id,enabled,title,introduction,updated_at) SELECT 1,enabled,title,introduction,updated_at FROM public_dashboards`,
		"DROP TABLE public_dashboards",
		`UPDATE application_update_state SET notification_destinations_json=(SELECT update_destinations_json FROM tenants WHERE id='` + store.DefaultTenantID + `') WHERE id=1`,
		"DROP TABLE tenants",
		"PRAGMA user_version=50",
	} {
		if _, err := raw.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// Update alerts reach the same destinations after the upgrade to schema 51,
// once each: every enabled destination while the routing was never
// configured, the selection when it was, and none when it was silenced.
func TestUpdateAlertsReachTheSameDestinationsAfterSchema51(t *testing.T) {
	for _, tc := range []struct {
		name string
		// selection picks the update routing; nil leaves it unconfigured.
		selection func(operations, security string) []string
		want      int
	}{
		{name: "unconfigured routing", want: 2},
		{name: "configured routing", selection: func(_, security string) []string { return []string{security} }, want: 1},
		{name: "silenced routing", selection: func(string, string) []string { return []string{} }, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := filepath.Join(t.TempDir(), "edgewatch.db")
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			cfg := &config.Config{Version: 1, Database: database, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}}

			previous, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			before, err := New(cfg, previous, "missing-nmap", logger)
			if err != nil {
				previous.Close()
				t.Fatal(err)
			}
			var ids []string
			for _, name := range []string{"Operations", "Security", "Paused"} {
				destination, err := before.Notifier.CreateManaged(ctx, name, "generic://127.0.0.1:9/"+name+"?disabletls=yes&template=json", name != "Paused")
				if err != nil {
					previous.Close()
					t.Fatal(err)
				}
				ids = append(ids, destination.ID)
			}
			var want []string
			if tc.selection == nil {
				want, err = before.Notifier.QueueDestinations(ctx)
			} else {
				selection := tc.selection(ids[0], ids[1])
				if err := previous.SetApplicationUpdateDestinations(ctx, selection, store.AuditEntry{}); err != nil {
					previous.Close()
					t.Fatal(err)
				}
				want, err = before.Notifier.QueueDestinationsForSelection(ctx, selection)
			}
			if err != nil {
				previous.Close()
				t.Fatal(err)
			}
			if len(want) != tc.want {
				previous.Close()
				t.Fatalf("destinations before the upgrade = %v, want %d", want, tc.want)
			}
			if err := previous.Close(); err != nil {
				t.Fatal(err)
			}
			downgradeToSchema50(t, database)

			upgraded, err := store.Open(database)
			if err != nil {
				t.Fatal(err)
			}
			defer upgraded.Close()
			a, err := New(cfg, upgraded, "missing-nmap", logger)
			if err != nil {
				t.Fatal(err)
			}
			a.Version = "v1.0.0"
			a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.1.0"}}}
			a.runUpdateCheck(ctx)

			events, err := upgraded.ListEvents(ctx, "", 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Type != "application-update-available" {
				t.Fatalf("update events = %#v", events)
			}
			rows, err := upgraded.DB.QueryContext(ctx, `SELECT destination,COUNT(*) FROM outbox WHERE sent_at IS NULL GROUP BY destination ORDER BY destination`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			got := []string{}
			for rows.Next() {
				var destination string
				var count int
				if err := rows.Scan(&destination, &count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("update alert queued %d times for %s", count, destination)
				}
				got = append(got, destination)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("update alert destinations after the upgrade = %v, want %v", got, want)
			}
		})
	}
}
