package store

import (
	"context"
	"sort"
	"testing"
)

// TestTenancyRegistry checks tenancyTables against the schema of a freshly
// migrated database. The tenant fixture is one, with rows added, and its
// copy is shared because opening a database is the slow part of the test.
func TestTenancyRegistry(t *testing.T) {
	s := newTenantFixture(t).store
	t.Run("covers the schema", func(t *testing.T) { assertTenancyRegistryCoversTheSchema(t, s) })
	t.Run("is consistent", func(t *testing.T) { assertTenancyRegistryIsConsistent(t, s) })
}

// assertTenancyRegistryCoversTheSchema checks that every table, virtual
// table, index, and trigger is classified in tenancyTables, directly or
// through its table, and that every entry names a table that exists.
func assertTenancyRegistryCoversTheSchema(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	rows, err := s.DB.QueryContext(ctx, `SELECT type,name,tbl_name FROM sqlite_master WHERE type IN ('table','view','index','trigger') ORDER BY type,name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tables := map[string]bool{}
	type object struct{ kind, name, table string }
	var dependents []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.table); err != nil {
			t.Fatal(err)
		}
		if o.kind == "table" || o.kind == "view" {
			tables[o.name] = true
			continue
		}
		dependents = append(dependents, o)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := tenancyTables[name]; !ok {
			t.Errorf("table %s has no entry in tenancyTables (internal/store/tenancy_tables.go). Classify who owns its rows: directTable when it has a tenant_id column, viaTable(parent) when each row belongs to a job, scan, account, or other tenant row, platformTable for platform data, systemTable for the daemon's bookkeeping, or sharedTable for reference data every tenant may read", name)
		}
	}
	for _, o := range dependents {
		if _, ok := tenancyTables[o.table]; !ok {
			t.Errorf("%s %s belongs to table %s, which has no entry in tenancyTables", o.kind, o.name, o.table)
		}
	}
	registered := make([]string, 0, len(tenancyTables))
	for name := range tenancyTables {
		registered = append(registered, name)
	}
	sort.Strings(registered)
	for _, name := range registered {
		if !tables[name] {
			t.Errorf("tenancyTables classifies %s, but the migrations create no such table; remove the entry", name)
		}
	}
}

// assertTenancyRegistryIsConsistent checks that the classification agrees
// with the schema: exactly the direct tables carry tenant_id, and each via
// table reaches a direct table through its parents.
func assertTenancyRegistryIsConsistent(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	names := make([]string, 0, len(tenancyTables))
	for name := range tenancyTables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tenancy := tenancyTables[name]
		var tenantColumn int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='tenant_id'`, name).Scan(&tenantColumn); err != nil {
			t.Fatal(err)
		}
		switch {
		case tenancy.class == tenancyDirect && tenantColumn == 0:
			t.Errorf("%s is classified direct but has no tenant_id column", name)
		case tenancy.class != tenancyDirect && tenantColumn != 0:
			t.Errorf("%s has a tenant_id column but is classified %s; classify it directTable", name, tenancy)
		case tenancy.class < tenancyDirect || tenancy.class > tenancyShared:
			t.Errorf("%s has no valid class", name)
		case tenancy.class != tenancyVia && tenancy.parent != "":
			t.Errorf("%s is classified %s but names parent %s", name, tenancy, tenancy.parent)
		}
		if tenancy.class != tenancyVia {
			continue
		}
		seen := map[string]bool{name: true}
		for current := tenancy; current.class == tenancyVia; {
			parent, ok := tenancyTables[current.parent]
			if !ok {
				t.Errorf("%s is classified via(%s), but %s has no entry in tenancyTables", name, current.parent, current.parent)
				break
			}
			if seen[current.parent] {
				t.Errorf("%s is classified via(%s), and its parents form a cycle", name, current.parent)
				break
			}
			seen[current.parent] = true
			if parent.class != tenancyVia && parent.class != tenancyDirect {
				t.Errorf("%s reaches its tenant through %s, which is classified %s instead of direct or via", name, current.parent, parent)
			}
			current = parent
		}
	}
}

func TestTenancyClassNames(t *testing.T) {
	for tenancy, want := range map[tableTenancy]string{
		directTable:         "direct",
		viaTable("jobs"):    "via(jobs)",
		platformTable:       "platform",
		systemTable:         "system",
		sharedTable:         "shared",
		{}:                  "unclassified",
		{class: 99}:         "unclassified",
		{class: tenancyVia}: "via()",
	} {
		if got := tenancy.String(); got != want {
			t.Errorf("%#v.String() = %q, want %q", tenancy, got, want)
		}
	}
	if !directTable.tenantData() || !viaTable("jobs").tenantData() || platformTable.tenantData() || systemTable.tenantData() || sharedTable.tenantData() {
		t.Fatal("only direct and via tables hold tenant data")
	}
}
