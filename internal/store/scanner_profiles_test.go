package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestBuiltinScannerProfilesForwardUpgrade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()

	current, err := defaultTenant(s).GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 1 {
		t.Fatalf("initial built-in revision = %d, want 1", current.Revision)
	}

	// Simulate a database that still has the previous built-in definition in
	// its current row while the running binary now carries a newer definition.
	legacy := current.Definition
	legacy.Description = "legacy Naabu defaults"
	legacyRaw, err := json.Marshal(config.NormalizeScannerProfile(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scanner_profiles SET definition_json=?,description=? WHERE id=?`, legacyRaw, legacy.Description, BuiltinNaabuProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scanner_profile_revisions SET definition_json=? WHERE profile_id=? AND revision=?`, legacyRaw, BuiltinNaabuProfileID, current.Revision); err != nil {
		t.Fatal(err)
	}

	if err := ensureBuiltinScannerProfiles(s.DB); err != nil {
		t.Fatal(err)
	}
	upgraded, err := defaultTenant(s).GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Revision != 2 || upgraded.Definition.Description != config.BuiltinNaabuProfile().Description {
		t.Fatalf("upgraded built-in = %#v, want revision 2 with current definition", upgraded)
	}
	historical, err := defaultTenant(s).GetScannerProfileRevision(ctx, BuiltinNaabuProfileID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if historical.Definition.Description != legacy.Description {
		t.Fatalf("historical built-in revision was replaced: got %q, want %q", historical.Definition.Description, legacy.Description)
	}

	if err := ensureBuiltinScannerProfiles(s.DB); err != nil {
		t.Fatal(err)
	}
	unchanged, err := defaultTenant(s).GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Revision != upgraded.Revision {
		t.Fatalf("unchanged built-in revision advanced from %d to %d", upgraded.Revision, unchanged.Revision)
	}
}

// The built-in seeding reads and writes only the built-in rows, whose
// tenant_id is NULL. It repairs a missing current revision of a built-in,
// and it refuses to seed over a tenant's profile that holds a built-in ID
// instead of taking that profile over.
func TestBuiltinScannerProfileSeedingTouchesOnlyBuiltinRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scanner_profile_revisions WHERE profile_id=?`, BuiltinNmapProfileID); err != nil {
		t.Fatal(err)
	}
	if err := ensureBuiltinScannerProfiles(s.DB); err != nil {
		t.Fatal(err)
	}
	revisions, err := defaultTenant(s).ListScannerProfileRevisions(ctx, BuiltinNmapProfileID)
	if err != nil || len(revisions) != 1 || revisions[0].Revision != 1 {
		t.Fatalf("repaired built-in revisions = %+v, %v", revisions, err)
	}

	// A tenant's profile that holds the built-in ID stops the seeding, which
	// leaves the profile as it was.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM scanner_profiles WHERE id=?`, BuiltinNmapProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO scanner_profiles(id,tenant_id,name,definition_json,built_in,created_at,updated_at) VALUES(?,?,'Tenant profile','{}',0,'2026-09-27T00:00:00Z','2026-09-27T00:00:00Z')`, BuiltinNmapProfileID, DefaultTenantID); err != nil {
		t.Fatal(err)
	}
	if err := ensureBuiltinScannerProfiles(s.DB); err == nil || !strings.Contains(err.Error(), "conflicts with the built-in profile") {
		t.Fatalf("seeding over a tenant's profile = %v", err)
	}
	var name, definition string
	var builtIn, revisionRows int
	if err := s.DB.QueryRowContext(ctx, `SELECT name,definition_json,built_in,(SELECT COUNT(*) FROM scanner_profile_revisions WHERE profile_id=?) FROM scanner_profiles WHERE id=?`, BuiltinNmapProfileID, BuiltinNmapProfileID).Scan(&name, &definition, &builtIn, &revisionRows); err != nil {
		t.Fatal(err)
	}
	if name != "Tenant profile" || definition != "{}" || builtIn != 0 || revisionRows != 0 {
		t.Fatalf("the tenant's profile changed: %q %q built-in %d, %d revisions", name, definition, builtIn, revisionRows)
	}

	// A revision is recorded only for a built-in row.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertBuiltinProfileRevisionTx(ctx, tx, BuiltinNmapProfileID, 2, []byte("{}"), "2026-09-27T00:00:00Z"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revision of a tenant's profile = %v, want ErrNotFound", err)
	}
}

func TestCurrentScannerProfileRevisionsReturnsCurrentRowsAndReportsFailures(t *testing.T) {
	t.Parallel()
	t.Run("current revisions", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		revisions, err := defaultTenant(s).CurrentScannerProfileRevisions(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(revisions) == 0 {
			t.Fatal("built-in scanner profile revisions were not returned")
		}
		for id, revision := range revisions {
			if id == "" || revision < 1 {
				t.Fatalf("invalid scanner profile revision: %q=%d", id, revision)
			}
		}
	})
	t.Run("query failure", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		if _, err := s.DB.ExecContext(ctx, `DROP TABLE scanner_profiles`); err != nil {
			t.Fatal(err)
		}
		if _, err := defaultTenant(s).CurrentScannerProfileRevisions(ctx); err == nil {
			t.Fatal("expected missing scanner profile table to fail")
		}
	})
	t.Run("scan failure", func(t *testing.T) {
		s := openTestStore(t)
		ctx := context.Background()
		if _, err := s.DB.ExecContext(ctx, `UPDATE scanner_profiles SET revision='not-a-number' WHERE id=?`, BuiltinNmapProfileID); err != nil {
			t.Fatal(err)
		}
		if _, err := defaultTenant(s).CurrentScannerProfileRevisions(ctx); err == nil {
			t.Fatal("expected malformed scanner profile revision to fail scanning")
		}
	})
}

func TestScannerProfilesSeedAndRevisionLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	profiles, err := defaultTenant(s).ListScannerProfiles(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 2 {
		t.Fatalf("built-in scanner profiles were not seeded: %#v", profiles)
	}
	builtin, err := defaultTenant(s).GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil || !builtin.BuiltIn || builtin.Definition.Engine != config.EngineNaabuNmap || builtin.Definition.Naabu.Rate != 1000 {
		t.Fatalf("Naabu built-in profile = %#v, %v", builtin, err)
	}

	created, err := defaultTenant(s).CreateScannerProfile(ctx, "Test Nmap", "test", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.BuiltIn || created.Archived {
		t.Fatalf("created profile metadata = %#v", created)
	}
	updatedDefinition := config.ScannerProfile{Engine: config.EngineNmap, Description: "updated"}
	updated, err := defaultTenant(s).UpdateScannerProfile(ctx, created.ID, 1, "Test Nmap", "updated", updatedDefinition, "admin")
	if err != nil || updated.Revision != 2 || updated.Definition.Description != "updated" {
		t.Fatalf("updated profile = %#v, %v", updated, err)
	}
	historical, err := defaultTenant(s).GetScannerProfileRevision(ctx, created.ID, 1)
	if err != nil || historical.Revision != 1 || historical.Definition.Description != "" {
		t.Fatalf("historical profile revision = %#v, %v", historical, err)
	}
	if _, err := defaultTenant(s).GetScannerProfileRevision(ctx, created.ID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile revision error = %v", err)
	}
	if _, err := defaultTenant(s).UpdateScannerProfile(ctx, created.ID, 1, "Test Nmap", "stale", updatedDefinition, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale profile update error = %v", err)
	}
	if err := defaultTenant(s).SetScannerProfileArchived(ctx, created.ID, true, 2, "admin"); err != nil {
		t.Fatal(err)
	}
	archived, err := defaultTenant(s).GetScannerProfile(ctx, created.ID)
	if err != nil || !archived.Archived || archived.Revision != 3 {
		t.Fatalf("archived profile = %#v, %v", archived, err)
	}
	if err := defaultTenant(s).SetScannerProfileArchived(ctx, created.ID, false, 3, "admin"); err != nil {
		t.Fatal(err)
	}
	restored, err := defaultTenant(s).GetScannerProfile(ctx, created.ID)
	if err != nil || restored.Archived || restored.Revision != 4 {
		t.Fatalf("restored profile = %#v, %v", restored, err)
	}
	revisions, err := defaultTenant(s).ListScannerProfileRevisions(ctx, created.ID)
	if err != nil || len(revisions) != 4 || revisions[0].Revision != 4 {
		t.Fatalf("profile revisions = %#v, %v", revisions, err)
	}
	if _, err := defaultTenant(s).ListScannerProfileRevisions(ctx, "missing-profile"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown profile revision lookup error = %v", err)
	}
}

func TestListScannerProfilesReportIsolatesInvalidDefinitions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()

	created, err := defaultTenant(s).CreateScannerProfile(ctx, "Corruptible", "test", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE scanner_profiles SET definition_json=? WHERE id=?`, []byte(`{"engine":`), created.ID); err != nil {
		t.Fatal(err)
	}

	result, err := defaultTenant(s).ListScannerProfilesReport(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) < 2 {
		t.Fatalf("valid profiles were hidden by corrupt row: %#v", result)
	}
	if len(result.Invalid) != 1 || result.Invalid[0].ID != created.ID || result.Invalid[0].Name != created.Name {
		t.Fatalf("invalid profile report = %#v", result.Invalid)
	}
	if result.Invalid[0].Error == "" || len(result.Invalid[0].Error) > 256 {
		t.Fatalf("invalid profile error was not bounded: %#v", result.Invalid[0])
	}
}
