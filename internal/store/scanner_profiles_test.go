package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

func TestBuiltinScannerProfilesForwardUpgrade(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()

	current, err := s.GetScannerProfile(ctx, BuiltinNaabuProfileID)
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
	upgraded, err := s.GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Revision != 2 || upgraded.Definition.Description != config.BuiltinNaabuProfile().Description {
		t.Fatalf("upgraded built-in = %#v, want revision 2 with current definition", upgraded)
	}
	historical, err := s.GetScannerProfileRevision(ctx, BuiltinNaabuProfileID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if historical.Definition.Description != legacy.Description {
		t.Fatalf("historical built-in revision was replaced: got %q, want %q", historical.Definition.Description, legacy.Description)
	}

	if err := ensureBuiltinScannerProfiles(s.DB); err != nil {
		t.Fatal(err)
	}
	unchanged, err := s.GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Revision != upgraded.Revision {
		t.Fatalf("unchanged built-in revision advanced from %d to %d", upgraded.Revision, unchanged.Revision)
	}
}

func TestScannerProfilesSeedAndRevisionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	profiles, err := s.ListScannerProfiles(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 2 {
		t.Fatalf("built-in scanner profiles were not seeded: %#v", profiles)
	}
	builtin, err := s.GetScannerProfile(ctx, BuiltinNaabuProfileID)
	if err != nil || !builtin.BuiltIn || builtin.Definition.Engine != config.EngineNaabuNmap || builtin.Definition.Naabu.Rate != 1000 {
		t.Fatalf("Naabu built-in profile = %#v, %v", builtin, err)
	}

	created, err := s.CreateScannerProfile(ctx, "Test Nmap", "test", config.ScannerProfile{Engine: config.EngineNmap}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || created.BuiltIn || created.Archived {
		t.Fatalf("created profile metadata = %#v", created)
	}
	updatedDefinition := config.ScannerProfile{Engine: config.EngineNmap, Description: "updated"}
	updated, err := s.UpdateScannerProfile(ctx, created.ID, 1, "Test Nmap", "updated", updatedDefinition, "admin")
	if err != nil || updated.Revision != 2 || updated.Definition.Description != "updated" {
		t.Fatalf("updated profile = %#v, %v", updated, err)
	}
	historical, err := s.GetScannerProfileRevision(ctx, created.ID, 1)
	if err != nil || historical.Revision != 1 || historical.Definition.Description != "" {
		t.Fatalf("historical profile revision = %#v, %v", historical, err)
	}
	if _, err := s.GetScannerProfileRevision(ctx, created.ID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile revision error = %v", err)
	}
	if _, err := s.UpdateScannerProfile(ctx, created.ID, 1, "Test Nmap", "stale", updatedDefinition, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale profile update error = %v", err)
	}
	if err := s.SetScannerProfileArchived(ctx, created.ID, true, 2, "admin"); err != nil {
		t.Fatal(err)
	}
	archived, err := s.GetScannerProfile(ctx, created.ID)
	if err != nil || !archived.Archived || archived.Revision != 3 {
		t.Fatalf("archived profile = %#v, %v", archived, err)
	}
	if err := s.SetScannerProfileArchived(ctx, created.ID, false, 3, "admin"); err != nil {
		t.Fatal(err)
	}
	restored, err := s.GetScannerProfile(ctx, created.ID)
	if err != nil || restored.Archived || restored.Revision != 4 {
		t.Fatalf("restored profile = %#v, %v", restored, err)
	}
	revisions, err := s.ListScannerProfileRevisions(ctx, created.ID)
	if err != nil || len(revisions) != 4 || revisions[0].Revision != 4 {
		t.Fatalf("profile revisions = %#v, %v", revisions, err)
	}
	if _, err := s.ListScannerProfileRevisions(ctx, "missing-profile"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown profile revision lookup error = %v", err)
	}
}
