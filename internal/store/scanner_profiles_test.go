package store

import (
	"context"
	"errors"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
)

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
