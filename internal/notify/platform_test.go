package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// platformActorID is the platform administrator that the platform tests
// act as.
const platformActorID = "00000000-0000-0000-0000-00000000fa01"

// addPlatformAdmin adds an enabled platform administrator in SQL.
func addPlatformAdmin(t *testing.T, db *store.Store) store.AuditEntry {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.DB.Exec(`INSERT INTO users(id,tenant_id,username,display_name,role,password_hash,enabled,created_at,updated_at) VALUES(?,NULL,'platform','platform',?,'hash',1,?,?)`, platformActorID, store.RolePlatformAdmin, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return store.AuditEntry{ActorUserID: platformActorID, ActorUsername: "platform"}
}

// The platform sees only its own destinations: it creates, lists, updates
// and deletes them, and its routing selects only them. A unit's destination
// and a deployment destination are not found, exactly as unknown ones, and
// no view carries a URL.
func TestPlatformNotifierManagesOnlyPlatformDestinations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	notifier, db, ownTenant, otherTenant := twoTenantNotifier(t)
	audit := addPlatformAdmin(t, db)
	platform := notifier.Platform(db.Platform())
	own, err := notifier.Tenant(ownTenant).CreateManagedWithAudit(ctx, "unit-ops", "generic://localhost/unit?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := notifier.Tenant(otherTenant).CreateManagedWithAudit(ctx, "other-ops", "generic://localhost/other?disabletls=yes", true, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}

	for _, refused := range []struct{ name, url string }{{"", "generic://localhost/x"}, {"alerts", ""}, {"alerts", "not a url"}} {
		if _, err := platform.CreateManagedWithAudit(ctx, refused.name, refused.url, true, audit); err == nil {
			t.Errorf("create %q with %q succeeded", refused.name, refused.url)
		}
	}
	if _, err := platform.CreateManagedWithAudit(ctx, "alerts", "generic://localhost/platform-secret?disabletls=yes", true, store.AuditEntry{}); !errors.Is(err, store.ErrAccountNotPermitted) {
		t.Fatalf("create without a platform actor = %v", err)
	}
	created, err := platform.CreateManagedWithAudit(ctx, " alerts ", "generic://localhost/platform-secret?disabletls=yes", true, audit)
	if err != nil || created.Name != "alerts" || created.Source != "web" || created.Revision != 1 || created.Locked {
		t.Fatalf("created platform destination = %+v, %v", created, err)
	}
	views, status, err := platform.Destinations(ctx)
	if err != nil || len(views) != 1 || views[0].ID != created.ID || status["managed"] != 1 || status["active"] != 1 || status["deployment"] != 0 {
		t.Fatalf("platform destinations = %+v, status %v, %v", views, status, err)
	}
	for _, view := range views {
		if strings.Contains(view.Name+view.Provider+view.ErrorCode, "platform-secret") {
			t.Fatalf("a platform view carries the URL: %+v", view)
		}
	}
	if unitViews, err := notifier.Tenant(ownTenant).Destinations(ctx); err != nil || len(unitViews) != 1 || unitViews[0].ID != own.ID {
		t.Fatalf("unit destinations = %+v, %v", unitViews, err)
	}

	if err := platform.ValidateDestinationSelection(ctx, []string{created.ID}); err != nil {
		t.Fatalf("platform selection = %v", err)
	}
	for _, foreign := range []string{own.ID, other.ID, "file:deployment", "", "00000000-0000-0000-0000-00000000dead"} {
		if err := platform.ValidateDestinationSelection(ctx, []string{foreign}); !errors.Is(err, ErrInvalidDestinationSelection) {
			t.Errorf("platform selection of %q = %v", foreign, err)
		}
	}

	for _, foreign := range []string{own.ID, other.ID} {
		if _, err := platform.UpdateManagedWithAudit(ctx, foreign, 1, "renamed", nil, nil, audit); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("platform update of %s = %v", foreign, err)
		}
		if err := platform.DeleteManagedWithAudit(ctx, foreign, 1, audit); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("platform delete of %s = %v", foreign, err)
		}
	}
	if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, 1, "", nil, nil, audit); err != nil {
		t.Fatalf("update that keeps the name = %v", err)
	}
	disabled := false
	renamed, err := platform.UpdateManagedWithAudit(ctx, created.ID, 2, "alerts renamed", nil, &disabled, audit)
	if err != nil || renamed.Name != "alerts renamed" || renamed.Enabled || renamed.Revision != 3 {
		t.Fatalf("renamed platform destination = %+v, %v", renamed, err)
	}
	invalid := "not a url"
	if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, 3, "alerts renamed", &invalid, nil, audit); err == nil {
		t.Fatal("an invalid URL was accepted")
	}
	if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, 3, strings.Repeat("n", 101), nil, nil, audit); err == nil {
		t.Fatal("a long name was accepted")
	}
	replacement, enabled := "generic://localhost/replacement?disabletls=yes", true
	updated, err := platform.UpdateManagedWithAudit(ctx, created.ID, 3, "alerts renamed", &replacement, &enabled, audit)
	if err != nil || !updated.Enabled || updated.Revision != 4 {
		t.Fatalf("platform destination with a new URL = %+v, %v", updated, err)
	}
	if err := platform.DeleteManagedWithAudit(ctx, created.ID, 4, audit); err != nil {
		t.Fatal(err)
	}
	if views, _, err := platform.Destinations(ctx); err != nil || len(views) != 0 {
		t.Fatalf("platform destinations after the delete = %+v, %v", views, err)
	}
	if unitViews, err := notifier.Tenant(otherTenant).Destinations(ctx); err != nil || len(unitViews) != 1 || unitViews[0].ID != other.ID {
		t.Fatalf("unit destinations after the platform's changes = %+v, %v", unitViews, err)
	}
}

// A locked platform destination can be renamed and paused, but enabling it
// again needs a key that opens it.
func TestPlatformNotifierLockedDestination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	audit := addPlatformAdmin(t, db)
	platform := notifier.Platform(db.Platform())
	created, err := platform.CreateManagedWithAudit(ctx, "alerts", "generic://localhost/platform?disabletls=yes", false, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE managed_notifications SET ciphertext=x'00' WHERE id=?`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, 1, "renamed", nil, nil, audit); err != nil {
		t.Fatalf("rename a locked destination = %v", err)
	}
	enabled := true
	if _, err := platform.UpdateManagedWithAudit(ctx, created.ID, 2, "renamed", nil, &enabled, audit); !errors.Is(err, ErrManagedNotificationLocked) {
		t.Fatalf("enable a locked destination = %v", err)
	}
	if _, err := platform.UpdateManagedWithAudit(ctx, "00000000-0000-0000-0000-00000000dead", 1, "renamed", nil, nil, audit); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update an unknown destination = %v", err)
	}
}
