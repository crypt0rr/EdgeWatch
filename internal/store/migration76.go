package store

// migration76Statements adds the perimeter: the address space that each
// business unit declares it owns (kind prefix) or may scan (kind
// authorized). The kind asn and the source and adopted_from columns are
// accepted now so that a later ASN watch, which adopts announced space, needs
// no rebuild of the table. The UNIQUE constraint's index serves the lookups
// by tenant and by tenant and kind, so the table has no other index, and
// tenant_id cannot change once a row is written.
func migration76Statements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS perimeter_seeds (
 id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL REFERENCES tenants(id),
 kind TEXT NOT NULL CHECK(kind IN ('prefix','authorized','asn')),
 value TEXT NOT NULL CHECK(length(value) BETWEEN 1 AND 64),
 label TEXT NOT NULL DEFAULT '',
 source TEXT NOT NULL DEFAULT 'declared' CHECK(source IN ('declared','adopted')),
 adopted_from TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 created_by TEXT NOT NULL DEFAULT '',
 UNIQUE(tenant_id, kind, value))`,
		`CREATE TRIGGER IF NOT EXISTS perimeter_seeds_tenant_immutable BEFORE UPDATE OF tenant_id ON perimeter_seeds BEGIN
 SELECT RAISE(ABORT, 'perimeter_seeds.tenant_id cannot be changed');
END`,
	}
}
