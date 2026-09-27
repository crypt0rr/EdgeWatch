package app

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
	"github.com/crypt0rr/edgewatch/internal/updatecheck"
)

// Update alerts follow the default tenant's routing exactly as they did
// before tenants existed: every enabled destination while the routing was
// never configured, the selection when it was, and none when it was
// silenced. A second tenant, with destinations and routing of its own, does
// not change that: its own copy of the alert goes to its own destination
// only, and its routing is left as it is.
func TestUpdateAlertsFollowTheDefaultTenantRouting(t *testing.T) {
	const otherTenantID = "00000000-0000-0000-0000-000000000200"
	for _, tc := range []struct {
		name string
		// selection picks the default tenant's routing; nil leaves it
		// unconfigured.
		selection func(operations, security string) []string
		want      func(operations, security string) []string
	}{
		{name: "unconfigured routing", want: func(operations, security string) []string { return []string{operations, security} }},
		{name: "configured routing", selection: func(_, security string) []string { return []string{security} }, want: func(_, security string) []string { return []string{security} }},
		{name: "silenced routing", selection: func(string, string) []string { return []string{} }, want: func(string, string) []string { return nil }},
	} {
		for _, second := range []bool{false, true} {
			name := tc.name + ", one tenant"
			if second {
				name = tc.name + ", two tenants"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				db, err := store.Open(storetest.FreshPath(t))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				cfg := &config.Config{Version: 1, Database: db.Path, Retention: config.Duration(time.Hour), Scheduler: config.Scheduler{MaxConcurrent: 1}}
				a, err := New(cfg, db, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
				if err != nil {
					t.Fatal(err)
				}
				own := db.Tenant(store.DefaultTenantScope())
				create := func(ts *store.TenantStore, name string, enabled bool) string {
					t.Helper()
					destination, err := a.Notifier.Tenant(ts).CreateManagedWithAudit(ctx, name, "generic://127.0.0.1:9/"+name+"?disabletls=yes&template=json", enabled, store.AuditEntry{Action: "notifications.created"})
					if err != nil {
						t.Fatal(err)
					}
					return destination.ID
				}
				operations, security := create(own, "Operations", true), create(own, "Security", true)
				create(own, "Paused", false)
				var other *store.TenantStore
				var otherDestination string
				if second {
					stamp := time.Now().UTC().Format(time.RFC3339Nano)
					if _, err := db.DB.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,created_at,updated_at) VALUES(?,'Other','other',?,?)`, otherTenantID, stamp, stamp); err != nil {
						t.Fatal(err)
					}
					scope, err := db.TenantScopeByID(ctx, otherTenantID)
					if err != nil {
						t.Fatal(err)
					}
					other = db.Tenant(scope)
					otherDestination = create(other, "Operations", true)
					if err := other.SetApplicationUpdateDestinations(ctx, []string{otherDestination}, store.AuditEntry{}); err != nil {
						t.Fatal(err)
					}
				}
				if tc.selection != nil {
					if err := own.SetApplicationUpdateDestinations(ctx, tc.selection(operations, security), store.AuditEntry{}); err != nil {
						t.Fatal(err)
					}
				}

				a.Version = "v1.0.0"
				a.ReleaseChecker = &fakeReleaseChecker{result: updatecheck.Result{Release: updatecheck.Release{Version: "v1.1.0"}}}
				a.runUpdateCheck(ctx)

				rows, err := db.DB.QueryContext(ctx, `SELECT destination,COUNT(*) FROM outbox WHERE sent_at IS NULL AND CAST(payload_json AS TEXT) LIKE '%application-update-available%' GROUP BY destination ORDER BY destination`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				var got []string
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
				var want []string
				for _, id := range tc.want(operations, security) {
					want = append(want, "managed:"+id+":1")
				}
				if other != nil {
					want = append(want, "managed:"+otherDestination+":1")
				}
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Fatalf("update alert destinations = %v, want %v", got, want)
				}
				if other != nil {
					var owner string
					if err := db.DB.QueryRowContext(ctx, `SELECT tenant_id FROM outbox WHERE destination=?`, "managed:"+otherDestination+":1").Scan(&owner); err != nil || owner != otherTenantID {
						t.Fatalf("the second tenant's update delivery belongs to %q, %v", owner, err)
					}
					routing, err := other.ApplicationUpdateRouting(ctx)
					if err != nil || !slices.Equal(routing.Destinations, []string{otherDestination}) {
						t.Fatalf("the second tenant's routing = %+v, %v", routing, err)
					}
				}
			})
		}
	}
}
