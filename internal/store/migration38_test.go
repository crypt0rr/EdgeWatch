package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigration38RetiresUnsaltedRecoveryCodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery-migration.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	_, err = s.DB.ExecContext(ctx, `
INSERT INTO recovery_codes(id_hash,user_id) VALUES('legacy-unsalted','user-1'),('v2$YWJjZGVmZ2hpamtsbW5vcA$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff','user-1');
PRAGMA user_version = 37;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE id_hash='legacy-unsalted'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy recovery code count = %d, want 0", count)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE substr(id_hash,1,3)='v2$'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("v2 recovery code count = %d, want 1", count)
	}
	var detail string
	if err := s.DB.QueryRowContext(ctx, `SELECT detail FROM security_audit WHERE action='auth.legacy_recovery_codes_retired'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if detail != "retired=1" {
		t.Fatalf("retirement audit detail = %q, want retired=1", detail)
	}
	var audits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.legacy_recovery_codes_retired'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `PRAGMA user_version = 37`); err != nil {
		t.Fatal(err)
	}
	if err := migrateContext(ctx, s.DB); err != nil {
		t.Fatal(err)
	}
	var repeatedAudits int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_audit WHERE action='auth.legacy_recovery_codes_retired'`).Scan(&repeatedAudits); err != nil {
		t.Fatal(err)
	}
	if repeatedAudits != audits {
		t.Fatalf("retirement audit rows after repeat migration = %d, want %d", repeatedAudits, audits)
	}
	var version int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
}
