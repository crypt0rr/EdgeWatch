package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func init() {
	cases := map[string]tenantLeakCase{
		"CreateChangeWindow": {writes: true, run: func(t *testing.T, f tenantFixture) {
			ctx := context.Background()
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			for _, jobID := range []string{f.jobA, "00000000-0000-0000-0000-00000000dead"} {
				if _, err := f.store.Tenant(f.b).CreateChangeWindow(ctx, jobID, start, start.Add(time.Hour), false, "tenant boundary", "", "Operator"); !errors.Is(err, ErrNotFound) {
					t.Errorf("tenant B created a window on job %s: %v, want ErrNotFound", jobID, err)
				}
			}
			before := tenantJobDigest(t, f.store, f.a)
			window := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, start)
			if window.ID == "" || window.JobID != f.jobB {
				t.Fatalf("tenant B's window = %+v", window)
			}
			if tenantJobDigest(t, f.store, f.a) != before {
				t.Fatal("tenant B creating its own window changed tenant A's rows")
			}
		}},
		"ListChangeWindows": {writes: true, run: func(t *testing.T, f tenantFixture) {
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			a := createTenantWindow(t, f.store.Tenant(f.a), f.jobA, start)
			b := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, start)
			for _, check := range []struct {
				scope TenantScope
				jobID string
				want  string
			}{{f.a, f.jobA, a.ID}, {f.b, f.jobB, b.ID}} {
				windows, err := f.store.Tenant(check.scope).ListChangeWindows(context.Background(), check.jobID)
				if err != nil || len(windows) != 1 || windows[0].ID != check.want {
					t.Errorf("tenant %s list = %+v, %v; want only %s", check.scope.ID(), windows, err, check.want)
				}
			}
		}},
		"GetChangeWindow": {writes: true, run: func(t *testing.T, f tenantFixture) {
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			a := createTenantWindow(t, f.store.Tenant(f.a), f.jobA, start)
			b := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, start)
			for _, id := range []string{a.ID, "00000000-0000-0000-0000-00000000dead"} {
				if _, err := f.store.Tenant(f.b).GetChangeWindow(context.Background(), f.jobA, id); !errors.Is(err, ErrNotFound) {
					t.Errorf("tenant B read window %s: %v, want ErrNotFound", id, err)
				}
			}
			if got, err := f.store.Tenant(f.b).GetChangeWindow(context.Background(), f.jobB, b.ID); err != nil || got.ID != b.ID {
				t.Errorf("tenant B read its own window = %+v, %v", got, err)
			}
		}},
		"LatestChangeWindowSummaries": {writes: true, run: func(t *testing.T, f tenantFixture) {
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			a := createTenantWindow(t, f.store.Tenant(f.a), f.jobA, start)
			b := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, start)
			for _, check := range []struct {
				scope TenantScope
				jobID string
				want  string
			}{{f.a, f.jobA, a.ID}, {f.b, f.jobB, b.ID}} {
				got, err := f.store.Tenant(check.scope).LatestChangeWindowSummaries(context.Background(), true, time.Now().UTC())
				if err != nil || len(got) != 1 || got[check.jobID].ID != check.want {
					t.Errorf("tenant %s latest windows = %+v, %v; want only %s", check.scope.ID(), got, err, check.want)
				}
			}
		}},
		"CancelChangeWindow": {writes: true, run: func(t *testing.T, f tenantFixture) {
			ctx := context.Background()
			start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			a := createTenantWindow(t, f.store.Tenant(f.a), f.jobA, start)
			b := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, start)
			before := tenantJobDigest(t, f.store, f.a)
			if _, _, err := f.store.Tenant(f.b).CancelChangeWindow(ctx, f.jobA, a.ID, "actor", "Operator", nil, AuditEntry{}); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B cancelled tenant A's window: %v, want ErrNotFound", err)
			}
			if tenantJobDigest(t, f.store, f.a) != before {
				t.Fatal("tenant B's refused cancel changed tenant A's rows")
			}
			if _, changed, err := f.store.Tenant(f.b).CancelChangeWindow(ctx, f.jobB, b.ID, "actor", "Operator", nil, AuditEntry{}); err != nil || !changed {
				t.Errorf("tenant B cancelled its own window: changed %v, err %v", changed, err)
			}
		}},
		"ReviewChangeWindow": {writes: true, run: func(t *testing.T, f tenantFixture) {
			ctx := context.Background()
			a := createDueTenantWindow(t, f.store, f.store.Tenant(f.a), f.jobA, "a-change")
			b := createDueTenantWindow(t, f.store, f.store.Tenant(f.b), f.jobB, "b-change")
			before := tenantJobDigest(t, f.store, f.a)
			for _, id := range []string{a.ID, "00000000-0000-0000-0000-00000000dead"} {
				if _, err := f.store.Tenant(f.b).ReviewChangeWindow(ctx, f.jobA, id, 2, "reviewer", "Reviewer", AuditEntry{}); !errors.Is(err, ErrConflict) {
					t.Errorf("tenant B reviewed foreign/unknown window %s: %v, want indistinguishable ErrConflict", id, err)
				}
			}
			if tenantJobDigest(t, f.store, f.a) != before {
				t.Fatal("tenant B's refused review changed tenant A's rows")
			}
			if reviewed, err := f.store.Tenant(f.b).ReviewChangeWindow(ctx, f.jobB, b.ID, b.Revision, "reviewer", "Reviewer", AuditEntry{}); err != nil || reviewed.ReviewState != "reviewed" {
				t.Errorf("tenant B reviewed its own window = %+v, %v", reviewed, err)
			}
		}},
		"ExpireChangeWindow": {writes: true, run: func(t *testing.T, f tenantFixture) {
			ctx := context.Background()
			a := createTenantWindow(t, f.store.Tenant(f.a), f.jobA, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
			b := createTenantWindow(t, f.store.Tenant(f.b), f.jobB, time.Now().UTC().Add(2*time.Hour).Truncate(time.Second))
			end := sqliteTimestamp(time.Now().UTC().Add(-time.Second).Truncate(time.Second))
			for _, window := range []ChangeWindow{a, b} {
				if _, err := f.store.DB.ExecContext(ctx, `UPDATE change_windows SET start_at=?,end_at=? WHERE id=?`, end, end, window.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := tenantJobDigest(t, f.store, f.a)
			if _, _, err := f.store.Tenant(f.b).ExpireChangeWindow(ctx, a.ID, func() time.Time { return time.Now().UTC() }, nil); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B expired tenant A's window: %v, want ErrNotFound", err)
			}
			if tenantJobDigest(t, f.store, f.a) != before {
				t.Fatal("tenant B's refused expiry changed tenant A's rows")
			}
			if _, changed, err := f.store.Tenant(f.b).ExpireChangeWindow(ctx, b.ID, func() time.Time { return time.Now().UTC() }, nil); err != nil || !changed {
				t.Errorf("tenant B expired its own window: changed %v, err %v", changed, err)
			}
		}},
	}
	for name, leak := range cases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

func createTenantWindow(t *testing.T, ts *TenantStore, jobID string, start time.Time) ChangeWindow {
	t.Helper()
	window, err := ts.CreateChangeWindow(context.Background(), jobID, start, start.Add(time.Hour), false, "tenant boundary", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	return window
}

func createDueTenantWindow(t *testing.T, s *Store, ts *TenantStore, jobID, key string) ChangeWindow {
	t.Helper()
	ctx := context.Background()
	window, err := ts.CreateChangeWindow(ctx, jobID, time.Time{}, time.Now().UTC().Add(time.Hour), true, "tenant review", "actor", "Operator")
	if err != nil {
		t.Fatal(err)
	}
	event := model.Event{Type: "changes-detected", JobID: jobID, Job: "edge", ScanID: "tenant-review-" + key, Message: "test", CreatedAt: time.Now().UTC(), TenantID: ts.scope.ID(), Changes: []model.Change{{Key: key, Kind: "port", Target: "192.0.2.10", Port: 443}}}
	if err := s.System().QueueEvent(ctx, "tenant-review-"+key, event); err != nil {
		t.Fatal(err)
	}
	closed, changed, err := ts.CancelChangeWindow(ctx, jobID, window.ID, "actor", "Operator", nil, AuditEntry{})
	if err != nil || !changed || closed.ReviewState != "due" {
		t.Fatalf("close tenant test window = %+v, changed %v, err %v", closed, changed, err)
	}
	return closed
}
