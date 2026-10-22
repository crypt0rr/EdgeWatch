package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The perimeter cases join tenantStoreLeakCases before any test runs, as the
// other slices' cases do.
func init() {
	for name, leak := range perimeterLeakCases {
		if _, duplicate := tenantStoreLeakCases[name]; duplicate {
			panic("two leak cases for TenantStore." + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

func prefixEntry(value, label string) PerimeterEntry {
	return PerimeterEntry{Kind: PerimeterKindPrefix, Value: value, Label: label}
}

func authorizedEntry(value, label string) PerimeterEntry {
	return PerimeterEntry{Kind: PerimeterKindAuthorized, Value: value, Label: label}
}

// perimeterRows renders the tenant's stored ranges as kind:value:label.
func perimeterRows(t *testing.T, s *Store, tenant string) []string {
	t.Helper()
	return queryStrings(t, s.DB, `SELECT kind||':'||value||':'||label FROM perimeter_seeds WHERE tenant_id=? ORDER BY kind,value`, tenant)
}

// perimeterAuditDetails returns the details of the tenant's audit records of
// the action, oldest first.
func perimeterAuditDetails(t *testing.T, s *Store, tenant, action string) []string {
	t.Helper()
	return queryStrings(t, s.DB, `SELECT detail FROM security_audit WHERE tenant_id=? AND action=? ORDER BY id`, tenant, action)
}

// declarePerimeter declares the entries and fails the test on an error.
func declarePerimeter(t *testing.T, ts *TenantStore, entries ...PerimeterEntry) PerimeterDeclareResult {
	t.Helper()
	result, err := ts.DeclarePerimeterSeeds(context.Background(), entries, AuditEntry{})
	if err != nil {
		t.Fatalf("declare %+v: %v", entries, err)
	}
	return result
}

// seedID returns the ID of the tenant's range with the value.
func seedID(t *testing.T, s *Store, tenant, value string) string {
	t.Helper()
	ids := queryStrings(t, s.DB, `SELECT id FROM perimeter_seeds WHERE tenant_id=? AND value=?`, tenant, value)
	if len(ids) != 1 {
		t.Fatalf("tenant %s has %d ranges %s", tenant, len(ids), value)
	}
	return ids[0]
}

// lineErrors returns the refused entries of a *PerimeterValidationError.
func lineErrors(t *testing.T, err error) []PerimeterLineError {
	t.Helper()
	var refused *PerimeterValidationError
	if !errors.As(err, &refused) || !errors.Is(err, ErrValidation) {
		t.Fatalf("error = %v, want a *PerimeterValidationError that matches ErrValidation", err)
	}
	if errors.Is(err, ErrPerimeterLimit) || errors.Is(err, ErrPerimeterEntryCount) {
		t.Fatalf("validation error %v matches another perimeter sentinel", err)
	}
	return refused.Entries
}

var perimeterLeakCases = map[string]tenantLeakCase{
	// Each unit lists its own ranges only, although both declare the same
	// value.
	"ListPerimeterSeeds": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		declarePerimeter(t, f.store.Tenant(f.a), prefixEntry("192.0.2.0/24", "alpha"))
		declarePerimeter(t, f.store.Tenant(f.b), prefixEntry("192.0.2.0/24", "bravo"), authorizedEntry("198.51.100.0/24", "bravo"))
		seeds, err := f.store.Tenant(f.b).ListPerimeterSeeds(ctx)
		if err != nil || len(seeds) != 2 {
			t.Fatalf("tenant B's ranges = %+v, %v", seeds, err)
		}
		for _, seed := range seeds {
			if seed.Label != "bravo" {
				t.Errorf("tenant B listed tenant A's range %+v", seed)
			}
		}
		seeds, err = f.store.Tenant(f.a).ListPerimeterSeeds(ctx)
		if err != nil || len(seeds) != 1 || seeds[0].Label != "alpha" || seeds[0].Value != "192.0.2.0/24" {
			t.Fatalf("tenant A's ranges = %+v, %v", seeds, err)
		}
	}},
	// Tenant A's range is not found through tenant B, with the same error as
	// an unknown ID.
	"GetPerimeterSeed": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		declarePerimeter(t, f.store.Tenant(f.a), prefixEntry("192.0.2.0/24", "alpha"))
		declarePerimeter(t, f.store.Tenant(f.b), prefixEntry("192.0.2.0/24", "bravo"))
		idA, idB := seedID(t, f.store, f.a.ID(), "192.0.2.0/24"), seedID(t, f.store, f.b.ID(), "192.0.2.0/24")
		seed, err := f.store.Tenant(f.b).GetPerimeterSeed(ctx, idA)
		_, unknownErr := f.store.Tenant(f.b).GetPerimeterSeed(ctx, "00000000-0000-0000-0000-00000000dead")
		if !errors.Is(err, ErrNotFound) || seed != (PerimeterSeed{}) || unknownErr == nil || err.Error() != unknownErr.Error() {
			t.Fatalf("tenant B read tenant A's range: %+v, %v; unknown ID: %v", seed, err, unknownErr)
		}
		if seed, err := f.store.Tenant(f.b).GetPerimeterSeed(ctx, idB); err != nil || seed.ID != idB || seed.Label != "bravo" {
			t.Fatalf("tenant B's own range = %+v, %v", seed, err)
		}
		if seed, err := f.store.Tenant(f.a).GetPerimeterSeed(ctx, idA); err != nil || seed.ID != idA || seed.Label != "alpha" {
			t.Fatalf("tenant A's own range = %+v, %v", seed, err)
		}
	}},
	// Tenant A's ranges neither refuse nor skip tenant B's declaration of
	// the same values, under either kind, and stay as they were.
	"DeclarePerimeterSeeds": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		declarePerimeter(t, f.store.Tenant(f.a), prefixEntry("192.0.2.0/24", "alpha"), authorizedEntry("198.51.100.0/24", "alpha"))
		before := perimeterRows(t, f.store, f.a.ID())
		auditBefore := perimeterAuditDetails(t, f.store, f.a.ID(), auditPerimeterSeedsAdded)
		result, err := f.store.Tenant(f.b).DeclarePerimeterSeeds(ctx, []PerimeterEntry{prefixEntry("192.0.2.0/24", "bravo"), prefixEntry("198.51.100.0/24", "bravo")}, AuditEntry{})
		if err != nil || result != (PerimeterDeclareResult{Created: 2}) {
			t.Fatalf("tenant B's declaration = %+v, %v; want both ranges created", result, err)
		}
		if after := perimeterRows(t, f.store, f.a.ID()); !reflect.DeepEqual(after, before) {
			t.Fatalf("tenant B's declaration changed tenant A's ranges: %q, want %q", after, before)
		}
		if after := perimeterAuditDetails(t, f.store, f.a.ID(), auditPerimeterSeedsAdded); !reflect.DeepEqual(after, auditBefore) {
			t.Fatalf("tenant B's declaration wrote tenant A's audit: %q", after)
		}
		if got := perimeterRows(t, f.store, f.b.ID()); !reflect.DeepEqual(got, []string{"prefix:192.0.2.0/24:bravo", "prefix:198.51.100.0/24:bravo"}) {
			t.Fatalf("tenant B's ranges = %q", got)
		}
	}},
	// Tenant B cannot remove tenant A's range: the ID is not found, and
	// nothing is removed or audited.
	"DeletePerimeterSeed": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		declarePerimeter(t, f.store.Tenant(f.a), prefixEntry("192.0.2.0/24", "alpha"))
		declarePerimeter(t, f.store.Tenant(f.b), prefixEntry("192.0.2.0/24", "bravo"))
		idA, idB := seedID(t, f.store, f.a.ID(), "192.0.2.0/24"), seedID(t, f.store, f.b.ID(), "192.0.2.0/24")
		before := perimeterRows(t, f.store, f.a.ID())
		if err := f.store.Tenant(f.b).DeletePerimeterSeed(ctx, idA, AuditEntry{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tenant B removed tenant A's range: %v", err)
		}
		if got := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit WHERE action=?`, auditPerimeterSeedRemoved); got != 0 {
			t.Fatalf("a refused removal wrote %d audit records", got)
		}
		if err := f.store.Tenant(f.b).DeletePerimeterSeed(ctx, idB, AuditEntry{}); err != nil {
			t.Fatalf("tenant B removes its own range: %v", err)
		}
		if after := perimeterRows(t, f.store, f.a.ID()); !reflect.DeepEqual(after, before) {
			t.Fatalf("tenant A's ranges after tenant B's removals = %q, want %q", after, before)
		}
		if got := perimeterAuditDetails(t, f.store, f.a.ID(), auditPerimeterSeedRemoved); len(got) != 0 {
			t.Fatalf("tenant B's removal was audited in tenant A: %q", got)
		}
	}},
	// Each unit reads the silence state of its own jobs only.
	"ListJobSilenceReferences": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		eligibleA := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		eligibleB := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		for job, eligible := range map[string]time.Time{f.jobA: eligibleA, f.jobB: eligibleB, f.archivedA: eligibleA, f.archivedB: eligibleB} {
			if _, err := f.store.DB.ExecContext(ctx, `INSERT INTO job_silence_state(job_id,eligible_at,updated_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET eligible_at=excluded.eligible_at,last_success_at=''`, job, sqliteTimestamp(eligible), sqliteTimestamp(eligible)); err != nil {
				t.Fatal(err)
			}
		}
		for scope, want := range map[TenantScope]map[string]time.Time{f.a: {f.jobA: eligibleA}, f.b: {f.jobB: eligibleB}} {
			got, err := f.store.Tenant(scope).ListJobSilenceReferences(ctx)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("tenant %s: silence references = %v, %v; want %v", scope.ID(), got, err, want)
			}
		}
	}},
}

// A declared value is stored in its canonical form: host bits masked, a bare
// address as a /32 or /128, IPv6 in its compressed lower-case text. Values
// and labels are trimmed, and each range records its source and its creator.
func TestDeclarePerimeterSeedsCanonicalizesValues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	before := time.Now().UTC().Add(-time.Second)
	result, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{
		prefixEntry("192.0.2.77/24", "  DC1 edge  "),
		prefixEntry(" 198.51.100.7 ", ""),
		authorizedEntry("2001:DB8:0:0:0:0:0:1/32", "cloud"),
		authorizedEntry("2001:db8:1::5", ""),
		prefixEntry("10.255.255.255/8", ""),
		authorizedEntry("2001:db8:ffff::/16", "provider"),
	}, AuditEntry{ActorUsername: "alice"})
	if err != nil || result != (PerimeterDeclareResult{Created: 6}) {
		t.Fatalf("declare = %+v, %v", result, err)
	}
	after := time.Now().UTC().Add(time.Second)
	seeds, err := ts.ListPerimeterSeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ kind, value, label string }{
		{PerimeterKindPrefix, "10.0.0.0/8", ""},
		{PerimeterKindPrefix, "192.0.2.0/24", "DC1 edge"},
		{PerimeterKindPrefix, "198.51.100.7/32", ""},
		{PerimeterKindAuthorized, "2001::/16", "provider"},
		{PerimeterKindAuthorized, "2001:db8::/32", "cloud"},
		{PerimeterKindAuthorized, "2001:db8:1::5/128", ""},
	}
	if len(seeds) != len(want) {
		t.Fatalf("ranges = %+v, want %d", seeds, len(want))
	}
	ids := map[string]bool{}
	for i, seed := range seeds {
		if seed.Kind != want[i].kind || seed.Value != want[i].value || seed.Label != want[i].label || seed.Source != "declared" || seed.AdoptedFrom != "" || seed.CreatedBy != "alice" || seed.CreatedAt.Before(before) || seed.CreatedAt.After(after) || seed.ID == "" || ids[seed.ID] {
			t.Errorf("range %d = %+v, want %+v declared by alice", i, seed, want[i])
		}
		ids[seed.ID] = true
		if got, err := ts.GetPerimeterSeed(ctx, seed.ID); err != nil || got != seed {
			t.Errorf("get range %s = %+v, %v; want %+v", seed.ID, got, err, seed)
		}
	}
}

// Every invalid entry of a declaration is refused with its index, its value
// as submitted, cut to 64 bytes, and a fixed reason, and nothing of the
// declaration is written, its valid entries included. The same valid
// entries, declared alone, are accepted.
func TestDeclarePerimeterSeedsRefusesEveryInvalidEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	valid := []PerimeterEntry{
		prefixEntry("10.0.0.0/8", ""),
		authorizedEntry("2001::/16", ""),
		prefixEntry("203.0.113.0/24", strings.Repeat("é", MaxPerimeterLabelRunes)),
		prefixEntry("169.253.255.0/24", ""),
		prefixEntry("126.0.0.0/8", ""),
		prefixEntry("128.0.0.0/8", ""),
		authorizedEntry("fe00::/16", ""),
		authorizedEntry("fec0::/16", ""),
		prefixEntry("::192.0.2.1", ""),
		prefixEntry("100.64.0.0/10", "shared address space"),
	}
	invalid := []struct {
		entry  PerimeterEntry
		reason string
	}{
		{PerimeterEntry{Value: "192.0.2.0/24"}, perimeterReasonKind},
		{PerimeterEntry{Kind: "owned", Value: "192.0.2.0/24"}, perimeterReasonKind},
		{PerimeterEntry{Kind: "Prefix", Value: "192.0.2.0/24"}, perimeterReasonKind},
		{PerimeterEntry{Kind: PerimeterKindASN, Value: "AS64500"}, perimeterReasonASN},
		{PerimeterEntry{Kind: PerimeterKindASN, Value: "192.0.2.0/24"}, perimeterReasonASN},
		{prefixEntry("edge.example.com", ""), perimeterReasonValue},
		{prefixEntry("10.0.0.1-10", ""), perimeterReasonValue},
		{authorizedEntry("AS64500", ""), perimeterReasonValue},
		{prefixEntry("", ""), perimeterReasonValue},
		{prefixEntry("   ", ""), perimeterReasonValue},
		{prefixEntry("192.0.2.0/33", ""), perimeterReasonValue},
		{prefixEntry("192.0.2.0/", ""), perimeterReasonValue},
		{prefixEntry("192.0.2.0/24/8", ""), perimeterReasonValue},
		{prefixEntry("300.1.1.1", ""), perimeterReasonValue},
		{prefixEntry("010.0.0.1", ""), perimeterReasonValue},
		{prefixEntry("2001:db8::/129", ""), perimeterReasonValue},
		{prefixEntry("fe80::1%eth0", ""), perimeterReasonZone},
		{prefixEntry("2001:db8::%eth0/64", ""), perimeterReasonZone},
		{authorizedEntry("2001:db8::1%25eth0", ""), perimeterReasonZone},
		{prefixEntry("::ffff:192.0.2.1", ""), perimeterReasonMapped},
		{prefixEntry("::ffff:192.0.2.0/120", ""), perimeterReasonMapped},
		{authorizedEntry("::ffff:0:0/96", ""), perimeterReasonMapped},
		{prefixEntry("::fffe:0:0/95", ""), perimeterReasonMapped},
		{prefixEntry("0.0.0.0", ""), perimeterReasonUnspecified},
		{prefixEntry("0.0.0.0/8", ""), perimeterReasonUnspecified},
		{prefixEntry("::", ""), perimeterReasonUnspecified},
		{prefixEntry("::/96", ""), perimeterReasonUnspecified},
		{prefixEntry("127.0.0.1", ""), perimeterReasonLoopback},
		{authorizedEntry("127.10.0.0/16", ""), perimeterReasonLoopback},
		{prefixEntry("::1", ""), perimeterReasonLoopback},
		{prefixEntry("224.0.0.0/4", ""), perimeterReasonMulticast},
		{prefixEntry("239.1.2.3", ""), perimeterReasonMulticast},
		{prefixEntry("ff02::1", ""), perimeterReasonMulticast},
		{prefixEntry("ff00::/16", ""), perimeterReasonMulticast},
		{prefixEntry("169.254.0.0/16", ""), perimeterReasonLinkLocal},
		{prefixEntry("169.254.169.254", ""), perimeterReasonLinkLocal},
		{prefixEntry("169.0.0.0/8", ""), perimeterReasonLinkLocal},
		{prefixEntry("fe80::/64", ""), perimeterReasonLinkLocal},
		{authorizedEntry("febf::/16", ""), perimeterReasonLinkLocal},
		{prefixEntry("10.0.0.0/7", ""), perimeterReasonIPv4Short},
		{prefixEntry("64.0.0.0/3", ""), perimeterReasonIPv4Short},
		{prefixEntry("2001::/15", ""), perimeterReasonIPv6Short},
		{prefixEntry("4000::/2", ""), perimeterReasonIPv6Short},
		// A short prefix that covers a special range gets that range's
		// reason.
		{prefixEntry("0.0.0.0/0", ""), perimeterReasonUnspecified},
		{prefixEntry("224.0.0.0/3", ""), perimeterReasonMulticast},
		{prefixEntry("::/0", ""), perimeterReasonUnspecified},
		{prefixEntry("fe80::/10", ""), perimeterReasonLinkLocal},
		{prefixEntry("ff00::/8", ""), perimeterReasonMulticast},
		{prefixEntry("203.0.113.0/24", strings.Repeat("é", MaxPerimeterLabelRunes+1)), perimeterReasonLabelLength},
		{prefixEntry("203.0.113.0/24", "edge\nrouter"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "edge\trouter"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "edge\x07router"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "\vstart"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "end\v"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "\fstart"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "end\f"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "edge\x7f"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "edge\u0085router"), perimeterReasonLabelControl},
		{prefixEntry("203.0.113.0/24", "edge\xff"), perimeterReasonLabelEncoding},
		{prefixEntry(strings.Repeat("a", 100), ""), perimeterReasonValue},
		{prefixEntry("x"+strings.Repeat("é", 40), ""), perimeterReasonValue},
	}
	entries := []PerimeterEntry{valid[0]}
	var want []PerimeterLineError
	for _, refused := range invalid {
		value := strings.TrimSpace(refused.entry.Value)
		if len(value) > 64 {
			value = value[:64]
			for !utf8.ValidString(value) {
				value = value[:len(value)-1]
			}
		}
		want = append(want, PerimeterLineError{Index: len(entries), Value: value, Reason: refused.reason})
		entries = append(entries, refused.entry)
	}
	entries = append(entries, valid[1:]...)
	_, err := ts.DeclarePerimeterSeeds(ctx, entries, AuditEntry{})
	got := lineErrors(t, err)
	if !reflect.DeepEqual(got, want) {
		for i := range max(len(got), len(want)) {
			var g, w PerimeterLineError
			if i < len(got) {
				g = got[i]
			}
			if i < len(want) {
				w = want[i]
			}
			if g != w {
				t.Errorf("refusal %d = %+v, want %+v", i, g, w)
			}
		}
		t.FailNow()
	}
	for _, refused := range got {
		if len(refused.Value) > 64 || !utf8.ValidString(refused.Value) {
			t.Errorf("refusal %d echoes %d bytes: %q", refused.Index, len(refused.Value), refused.Value)
		}
	}
	if got[len(got)-1].Value != "x"+strings.Repeat("é", 31) {
		t.Errorf("a long value is not cut at a character boundary: %q", got[len(got)-1].Value)
	}
	if rows := perimeterRows(t, s, DefaultTenantID); len(rows) != 0 {
		t.Fatalf("a refused declaration wrote %q", rows)
	}
	if audit := perimeterAuditDetails(t, s, DefaultTenantID, auditPerimeterSeedsAdded); len(audit) != 0 {
		t.Fatalf("a refused declaration was audited: %q", audit)
	}
	if result, err := ts.DeclarePerimeterSeeds(ctx, valid, AuditEntry{}); err != nil || result != (PerimeterDeclareResult{Created: len(valid)}) {
		t.Fatalf("the valid entries alone = %+v, %v", result, err)
	}
}

// A value may have one kind within a unit. A declaration that names a value
// under both kinds refuses each entry after the first kind, and a value that
// the unit holds under one kind refuses every entry of the other, listed
// beside every other refusal of the declaration; the value is compared in its
// canonical form. Nothing of a refused declaration is written.
func TestDeclarePerimeterSeedsRefusesTheOtherKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	_, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{
		prefixEntry("192.0.2.0/24", ""),
		authorizedEntry("192.0.2.9/24", ""),
		authorizedEntry("198.51.100.0/24", ""),
		prefixEntry("198.51.100.0/24", ""),
		prefixEntry("192.0.2.0/24", "again"),
		authorizedEntry("2001:db8::/32", "bad\x00label"),
		prefixEntry("2001:db8::/32", ""),
	}, AuditEntry{})
	want := []PerimeterLineError{
		{Index: 1, Value: "192.0.2.9/24", Reason: perimeterReasonOwned},
		{Index: 3, Value: "198.51.100.0/24", Reason: perimeterReasonAuthorized},
		{Index: 5, Value: "2001:db8::/32", Reason: perimeterReasonLabelControl},
		{Index: 6, Value: "2001:db8::/32", Reason: perimeterReasonAuthorized},
	}
	if got := lineErrors(t, err); !reflect.DeepEqual(got, want) {
		t.Fatalf("refusals within the declaration = %+v, want %+v", got, want)
	}
	if rows := perimeterRows(t, s, DefaultTenantID); len(rows) != 0 {
		t.Fatalf("a refused declaration wrote %q", rows)
	}

	declarePerimeter(t, ts, prefixEntry("192.0.2.0/24", "owned"), authorizedEntry("198.51.100.0/24", "partner"))
	_, err = ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{
		authorizedEntry("192.0.2.5/24", ""),
		prefixEntry("203.0.113.0/24", ""),
		prefixEntry(" 198.51.100.0/24", ""),
		authorizedEntry("192.0.2.0/24", ""),
	}, AuditEntry{})
	want = []PerimeterLineError{
		{Index: 0, Value: "192.0.2.5/24", Reason: perimeterReasonOwned},
		{Index: 2, Value: "198.51.100.0/24", Reason: perimeterReasonAuthorized},
		{Index: 3, Value: "192.0.2.0/24", Reason: perimeterReasonOwned},
	}
	if got := lineErrors(t, err); !reflect.DeepEqual(got, want) {
		t.Fatalf("refusals against the stored ranges = %+v, want %+v", got, want)
	}
	assertStored := func(step string) {
		t.Helper()
		if got := perimeterRows(t, s, DefaultTenantID); !reflect.DeepEqual(got, []string{"authorized:198.51.100.0/24:partner", "prefix:192.0.2.0/24:owned"}) {
			t.Fatalf("ranges after %s = %q", step, got)
		}
		if audit := perimeterAuditDetails(t, s, DefaultTenantID, auditPerimeterSeedsAdded); len(audit) != 1 {
			t.Fatalf("audit records after %s = %q, want only the first declaration's", step, audit)
		}
	}
	assertStored("the refused declaration")

	// A conflict with a stored range is reported beside the other refusals,
	// in the order of the declaration, each entry with one reason.
	for _, test := range []struct {
		name    string
		entries []PerimeterEntry
		want    []PerimeterLineError
	}{
		{
			name:    "beside an invalid value",
			entries: []PerimeterEntry{authorizedEntry("192.0.2.0/24", ""), prefixEntry("not-an-ip", "")},
			want: []PerimeterLineError{
				{Index: 0, Value: "192.0.2.0/24", Reason: perimeterReasonOwned},
				{Index: 1, Value: "not-an-ip", Reason: perimeterReasonValue},
			},
		},
		{
			name:    "beside a conflict within the declaration",
			entries: []PerimeterEntry{authorizedEntry("192.0.2.0/24", ""), prefixEntry("192.0.2.0/24", "")},
			want: []PerimeterLineError{
				{Index: 0, Value: "192.0.2.0/24", Reason: perimeterReasonOwned},
				{Index: 1, Value: "192.0.2.0/24", Reason: perimeterReasonAuthorized},
			},
		},
		{
			name: "interleaved with other refusals",
			entries: []PerimeterEntry{
				{Kind: PerimeterKindASN, Value: "AS64500"},
				prefixEntry("198.51.100.9/24", ""),
				prefixEntry("203.0.113.0/24", ""),
				prefixEntry("203.0.113.0/24", "bad\x00label"),
				authorizedEntry("192.0.2.1/24", ""),
				authorizedEntry("192.0.2.0/24", ""),
			},
			want: []PerimeterLineError{
				{Index: 0, Value: "AS64500", Reason: perimeterReasonASN},
				{Index: 1, Value: "198.51.100.9/24", Reason: perimeterReasonAuthorized},
				{Index: 3, Value: "203.0.113.0/24", Reason: perimeterReasonLabelControl},
				{Index: 4, Value: "192.0.2.1/24", Reason: perimeterReasonOwned},
				{Index: 5, Value: "192.0.2.0/24", Reason: perimeterReasonOwned},
			},
		},
	} {
		_, err := ts.DeclarePerimeterSeeds(ctx, test.entries, AuditEntry{})
		if got := lineErrors(t, err); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("%s: refusals = %+v, want %+v", test.name, got, test.want)
		}
		assertStored(test.name)
	}
}

// A value already declared under the same kind, stored or earlier in the
// declaration, is skipped rather than refused, and keeps its first label.
// Every declaration is audited with its counts by kind, including one that
// skipped all of its entries.
func TestDeclarePerimeterSeedsSkipsDuplicates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	for _, step := range []struct {
		entries []PerimeterEntry
		want    PerimeterDeclareResult
	}{
		{[]PerimeterEntry{prefixEntry("192.0.2.0/24", "edge"), prefixEntry("192.0.2.1/24", "repeat"), authorizedEntry("198.51.100.0/24", "partner")}, PerimeterDeclareResult{Created: 2, Skipped: 1}},
		{[]PerimeterEntry{prefixEntry("192.0.2.0/24", "renamed"), authorizedEntry("198.51.100.0/24", ""), prefixEntry("203.0.113.0/24", "lab")}, PerimeterDeclareResult{Created: 1, Skipped: 2}},
		{[]PerimeterEntry{prefixEntry("192.0.2.128/24", "")}, PerimeterDeclareResult{Skipped: 1}},
	} {
		if got, err := ts.DeclarePerimeterSeeds(ctx, step.entries, AuditEntry{}); err != nil || got != step.want {
			t.Fatalf("declare %+v = %+v, %v; want %+v", step.entries, got, err, step.want)
		}
	}
	if got := perimeterRows(t, s, DefaultTenantID); !reflect.DeepEqual(got, []string{"authorized:198.51.100.0/24:partner", "prefix:192.0.2.0/24:edge", "prefix:203.0.113.0/24:lab"}) {
		t.Fatalf("ranges = %q", got)
	}
	wantAudit := []string{
		"perimeter ranges declared: prefix 1 added, 1 skipped; authorized 1 added, 0 skipped",
		"perimeter ranges declared: prefix 1 added, 1 skipped; authorized 0 added, 1 skipped",
		"perimeter ranges declared: prefix 0 added, 1 skipped; authorized 0 added, 0 skipped",
	}
	if got := perimeterAuditDetails(t, s, DefaultTenantID, auditPerimeterSeedsAdded); !reflect.DeepEqual(got, wantAudit) {
		t.Fatalf("audit details = %q, want %q", got, wantAudit)
	}
}

// A declaration has between 1 and MaxPerimeterEntriesPerRequest entries.
func TestDeclarePerimeterSeedsBoundsTheEntries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	entries := make([]PerimeterEntry, MaxPerimeterEntriesPerRequest+1)
	for i := range entries {
		entries[i] = prefixEntry(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), "")
	}
	for _, refused := range [][]PerimeterEntry{nil, {}, entries} {
		_, err := ts.DeclarePerimeterSeeds(ctx, refused, AuditEntry{})
		var count *PerimeterEntryCountError
		if !errors.As(err, &count) || *count != (PerimeterEntryCountError{Count: len(refused), Limit: MaxPerimeterEntriesPerRequest}) || !errors.Is(err, ErrPerimeterEntryCount) || !errors.Is(err, ErrValidation) || errors.Is(err, ErrPerimeterLimit) {
			t.Fatalf("%d entries: error = %#v, want a *PerimeterEntryCountError", len(refused), err)
		}
	}
	if rows := perimeterRows(t, s, DefaultTenantID); len(rows) != 0 {
		t.Fatalf("a refused declaration wrote %d ranges", len(rows))
	}
	if result, err := ts.DeclarePerimeterSeeds(ctx, entries[:MaxPerimeterEntriesPerRequest], AuditEntry{}); err != nil || result.Created != MaxPerimeterEntriesPerRequest {
		t.Fatalf("declare %d entries = %+v, %v", MaxPerimeterEntriesPerRequest, result, err)
	}
}

// A unit holds at most MaxPerimeterRanges prefix and authorized ranges,
// counted after the insert, so skipped duplicates and ranges of the kind asn
// never count. A declaration that would exceed the limit writes nothing and
// reports the ranges held before it and those it would have created.
func TestDeclarePerimeterSeedsLimitsTheRanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	const held = MaxPerimeterRanges - 4
	stamp := sqliteTimestamp(time.Now())
	if _, err := s.DB.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<?2-1)
INSERT INTO perimeter_seeds(id,tenant_id,kind,value,created_at)
SELECT 'bulk-'||i,?1,CASE WHEN i%2=0 THEN 'prefix' ELSE 'authorized' END,'10.'||(i/256)||'.'||(i%256)||'.0/24',?3 FROM n`, DefaultTenantID, held, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO perimeter_seeds(id,tenant_id,kind,value,created_at) VALUES('asn',?,'asn','AS64500',?)`, DefaultTenantID, stamp); err != nil {
		t.Fatal(err)
	}
	stored := func() int {
		return countRows(t, s.DB, `SELECT COUNT(*) FROM perimeter_seeds WHERE tenant_id=? AND kind<>'asn'`, DefaultTenantID)
	}
	newEntries := func(from, count int) []PerimeterEntry {
		entries := make([]PerimeterEntry, count)
		for i := range entries {
			entries[i] = authorizedEntry(fmt.Sprintf("172.16.%d.0/24", from+i), "")
		}
		return entries
	}
	assertLimit := func(err error, held, created int) {
		t.Helper()
		var limit *PerimeterLimitError
		if !errors.As(err, &limit) || *limit != (PerimeterLimitError{Limit: MaxPerimeterRanges, Held: held, New: created}) || !errors.Is(err, ErrPerimeterLimit) || !errors.Is(err, ErrValidation) || errors.Is(err, ErrPerimeterEntryCount) {
			t.Fatalf("error = %#v, want a *PerimeterLimitError with %d held and %d new", err, held, created)
		}
	}

	_, err := ts.DeclarePerimeterSeeds(ctx, newEntries(0, 5), AuditEntry{})
	assertLimit(err, held, 5)
	if got := stored(); got != held {
		t.Fatalf("the refused declaration left %d ranges, want %d", got, held)
	}
	if audit := perimeterAuditDetails(t, s, DefaultTenantID, auditPerimeterSeedsAdded); len(audit) != 0 {
		t.Fatalf("the refused declaration was audited: %q", audit)
	}

	// Four new ranges reach the limit; the stored and repeated values beside
	// them are skipped and do not count.
	entries := append(newEntries(0, 4), prefixEntry("10.0.0.0/24", ""), authorizedEntry("10.0.1.0/24", ""), prefixEntry("10.0.2.9/24", ""), authorizedEntry("172.16.0.0/24", ""))
	if result, err := ts.DeclarePerimeterSeeds(ctx, entries, AuditEntry{}); err != nil || result != (PerimeterDeclareResult{Created: 4, Skipped: 4}) {
		t.Fatalf("declare up to the limit = %+v, %v", result, err)
	}
	if got := stored(); got != MaxPerimeterRanges {
		t.Fatalf("ranges at the limit = %d", got)
	}
	if result, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{prefixEntry("10.0.0.0/24", "")}, AuditEntry{}); err != nil || result != (PerimeterDeclareResult{Skipped: 1}) {
		t.Fatalf("declare a stored range at the limit = %+v, %v", result, err)
	}
	_, err = ts.DeclarePerimeterSeeds(ctx, newEntries(10, 1), AuditEntry{})
	assertLimit(err, MaxPerimeterRanges, 1)
	if got := stored(); got != MaxPerimeterRanges {
		t.Fatalf("ranges after the refused declaration = %d", got)
	}
}

// Each typed error matches its own sentinels and ErrValidation through any
// wrapping, and errors.As finds it.
func TestPerimeterErrorsMatchTheirSentinels(t *testing.T) {
	t.Parallel()
	for _, check := range []struct {
		err   error
		is    []error
		isNot []error
		as    func(error) bool
	}{
		{
			err:   &PerimeterValidationError{Entries: []PerimeterLineError{{Index: 2, Value: "x", Reason: perimeterReasonValue}}},
			is:    []error{ErrValidation},
			isNot: []error{ErrPerimeterLimit, ErrPerimeterEntryCount, ErrNotFound},
			as: func(err error) bool {
				var target *PerimeterValidationError
				return errors.As(err, &target) && len(target.Entries) == 1 && target.Entries[0].Index == 2
			},
		},
		{
			err:   &PerimeterLimitError{Limit: MaxPerimeterRanges, Held: 1000, New: 30},
			is:    []error{ErrValidation, ErrPerimeterLimit},
			isNot: []error{ErrPerimeterEntryCount, ErrNotFound},
			as: func(err error) bool {
				var target *PerimeterLimitError
				return errors.As(err, &target) && *target == PerimeterLimitError{Limit: MaxPerimeterRanges, Held: 1000, New: 30}
			},
		},
		{
			err:   &PerimeterEntryCountError{Count: 300, Limit: MaxPerimeterEntriesPerRequest},
			is:    []error{ErrValidation, ErrPerimeterEntryCount},
			isNot: []error{ErrPerimeterLimit, ErrNotFound},
			as: func(err error) bool {
				var target *PerimeterEntryCountError
				return errors.As(err, &target) && target.Count == 300
			},
		},
	} {
		for _, err := range []error{check.err, fmt.Errorf("declare: %w", check.err)} {
			for _, sentinel := range check.is {
				if !errors.Is(err, sentinel) {
					t.Errorf("%v does not match %v", err, sentinel)
				}
			}
			for _, sentinel := range check.isNot {
				if errors.Is(err, sentinel) {
					t.Errorf("%v matches %v", err, sentinel)
				}
			}
			if !check.as(err) {
				t.Errorf("errors.As does not find %T in %v", check.err, err)
			}
		}
	}
	if got := (&PerimeterEntryCountError{Count: 0, Limit: MaxPerimeterEntriesPerRequest}).Error(); got != "declare between 1 and 256 entries" {
		t.Errorf("entry count message = %q", got)
	}
}

// A declaration and a removal each write one data audit record in the
// store's unit, with the action and detail the store sets and the actor the
// caller names, whatever action or tenant the caller's entry names.
func TestPerimeterChangesAreAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	actor := AuditEntry{Action: "job.updated", ActorUsername: "alice", RequestID: "request-1", TenantID: secondTenantID}
	if _, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{prefixEntry("192.0.2.0/24", ""), authorizedEntry("2001:db8::/32", "")}, actor); err != nil {
		t.Fatal(err)
	}
	if err := ts.DeletePerimeterSeed(ctx, seedID(t, s, DefaultTenantID, "192.0.2.0/24"), actor); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, s.DB, `SELECT action||'|'||detail||'|'||category||'|'||COALESCE(tenant_id,'<null>')||'|'||actor_username||'|'||request_id FROM security_audit WHERE action LIKE 'perimeter.%' OR action='job.updated' ORDER BY id`)
	want := []string{
		"perimeter.seeds_added|perimeter ranges declared: prefix 1 added, 0 skipped; authorized 1 added, 0 skipped|data|" + DefaultTenantID + "|alice|request-1",
		"perimeter.seed_removed|perimeter range removed: prefix 192.0.2.0/24|data|" + DefaultTenantID + "|alice|request-1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit records = %q, want %q", got, want)
	}
	if got := perimeterRows(t, s, DefaultTenantID); !reflect.DeepEqual(got, []string{"authorized:2001:db8::/32:"}) {
		t.Fatalf("ranges after the removal = %q", got)
	}
}

// A range is never stored or removed without its audit record: when the
// record cannot be written, the declaration or removal rolls back.
func TestPerimeterChangesRollBackWithoutTheirAuditRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	declarePerimeter(t, ts, prefixEntry("192.0.2.0/24", "kept"))
	id := seedID(t, s, DefaultTenantID, "192.0.2.0/24")
	failStatement(t, s, "INSERT", "security_audit")
	if _, err := ts.DeclarePerimeterSeeds(ctx, []PerimeterEntry{prefixEntry("198.51.100.0/24", "")}, AuditEntry{}); !errors.Is(err, ErrAuditUnavailable) || errors.Is(err, ErrValidation) {
		t.Fatalf("declaration without its audit record = %v, want ErrAuditUnavailable", err)
	}
	if err := ts.DeletePerimeterSeed(ctx, id, AuditEntry{}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("removal without its audit record = %v, want ErrAuditUnavailable", err)
	}
	if got := perimeterRows(t, s, DefaultTenantID); !reflect.DeepEqual(got, []string{"prefix:192.0.2.0/24:kept"}) {
		t.Fatalf("ranges after the failed audit writes = %q", got)
	}
}

// An unknown ID is not found and changes nothing, and so is the ID of a range
// already removed.
func TestPerimeterSeedNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	declarePerimeter(t, ts, prefixEntry("192.0.2.0/24", ""))
	id := seedID(t, s, DefaultTenantID, "192.0.2.0/24")
	if err := ts.DeletePerimeterSeed(ctx, id, AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"", "00000000-0000-0000-0000-00000000dead", id} {
		if seed, err := ts.GetPerimeterSeed(ctx, missing); err != ErrNotFound || seed != (PerimeterSeed{}) {
			t.Errorf("get %q = %+v, %v; want ErrNotFound", missing, seed, err)
		}
		if err := ts.DeletePerimeterSeed(ctx, missing, AuditEntry{}); err != ErrNotFound {
			t.Errorf("delete %q = %v; want ErrNotFound", missing, err)
		}
	}
	if got := perimeterAuditDetails(t, s, DefaultTenantID, auditPerimeterSeedRemoved); len(got) != 1 {
		t.Fatalf("removal audit records = %q, want only the real removal's", got)
	}
}

// The ranges are listed in address order whatever order they were declared
// in: IPv4 before IPv6, the shorter of two prefixes at one address first,
// then by kind and ID, and values that are not CIDRs last.
func TestListPerimeterSeedsIsInAddressOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	declarePerimeter(t, ts,
		authorizedEntry("2001:db8::/48", ""),
		prefixEntry("192.0.2.0/25", ""),
		authorizedEntry("100.64.0.0/10", ""),
		prefixEntry("2001:db8::/32", ""),
		prefixEntry("9.0.0.0/8", ""),
		prefixEntry("192.0.2.0/24", ""),
		prefixEntry("10.0.0.0/8", ""),
	)
	stamp := sqliteTimestamp(time.Now())
	for _, row := range [][3]string{{"asn-a", "asn", "AS64500"}, {"asn-b", "asn", "AS1"}, {"a-prefix", "prefix", "198.51.100.0/24"}, {"z-authorized", "authorized", "198.51.100.0/24"}} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO perimeter_seeds(id,tenant_id,kind,value,created_at) VALUES(?,?,?,?,?)`, row[0], DefaultTenantID, row[1], row[2], stamp); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"prefix 9.0.0.0/8", "prefix 10.0.0.0/8", "authorized 100.64.0.0/10",
		"prefix 192.0.2.0/24", "prefix 192.0.2.0/25",
		"authorized 198.51.100.0/24", "prefix 198.51.100.0/24",
		"prefix 2001:db8::/32", "authorized 2001:db8::/48",
		"asn AS1", "asn AS64500",
	}
	for range 2 {
		seeds, err := ts.ListPerimeterSeeds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, len(seeds))
		for i, seed := range seeds {
			got[i] = seed.Kind + " " + seed.Value
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ranges = %q, want %q", got, want)
		}
	}
	empty, err := defaultTenantWithoutPerimeter(t).ListPerimeterSeeds(ctx)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("an empty perimeter = %#v, %v; want an empty list", empty, err)
	}
}

// defaultTenantWithoutPerimeter returns the default tenant of a new
// database.
func defaultTenantWithoutPerimeter(t *testing.T) *TenantStore {
	t.Helper()
	return defaultTenant(openTestStore(t))
}

// The silence reference of a job is the later of the eligible_at and
// last_success_at of its silence state, from which the watchdog measures it
// besides its creation. Archived jobs and jobs without a usable state are
// absent.
func TestListJobSilenceReferences(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	jobs := map[string]string{}
	for _, name := range []string{"created", "succeeded", "resumed", "archived", "stateless", "blank"} {
		record, err := ts.CreateJob(ctx, testJob(name))
		if err != nil {
			t.Fatal(err)
		}
		jobs[name] = record.ID
	}
	created, err := ts.GetJob(ctx, jobs["created"])
	if err != nil {
		t.Fatal(err)
	}
	eligible := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	success := eligible.Add(48 * time.Hour)
	resumed := success.Add(time.Hour)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`UPDATE job_silence_state SET eligible_at=?,last_success_at=? WHERE job_id=?`, []any{sqliteTimestamp(eligible), sqliteTimestamp(success), jobs["succeeded"]}},
		{`UPDATE job_silence_state SET eligible_at=?,last_success_at=? WHERE job_id=?`, []any{sqliteTimestamp(resumed), sqliteTimestamp(success), jobs["resumed"]}},
		{`UPDATE jobs SET archived=1,enabled=0 WHERE id=?`, []any{jobs["archived"]}},
		{`DELETE FROM job_silence_state WHERE job_id=?`, []any{jobs["stateless"]}},
		{`UPDATE job_silence_state SET eligible_at='',last_success_at='' WHERE job_id=?`, []any{jobs["blank"]}},
	} {
		if _, err := s.DB.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.query, err)
		}
	}
	got, err := ts.ListJobSilenceReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[jobs["succeeded"]].Equal(success) || !got[jobs["resumed"]].Equal(resumed) {
		t.Fatalf("silence references = %v", got)
	}
	// A new job is measured from its creation.
	if reference := got[jobs["created"]]; reference.Sub(created.CreatedAt).Abs() > time.Second {
		t.Fatalf("a new job's silence reference = %s, want its creation %s", reference, created.CreatedAt)
	}
	empty, err := defaultTenantWithoutPerimeter(t).ListJobSilenceReferences(ctx)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("a unit without jobs = %#v, %v; want an empty map", empty, err)
	}
}

// The ranges are part of a backup and come back with its restore.
func TestPerimeterSeedsSurviveBackupAndRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := openTestStore(t)
	ts := defaultTenant(s)
	declarePerimeter(t, ts, prefixEntry("192.0.2.0/24", "edge"), authorizedEntry("2001:db8::/32", "cloud"))
	want, err := ts.ListPerimeterSeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := s.Backup(ctx, filepath.Join(t.TempDir(), "perimeter-backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored.db")
	if _, err := Restore(ctx, backup, destination, RestoreOptions{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	got, err := defaultTenant(restored).ListPerimeterSeeds(ctx)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("restored ranges = %+v, %v; want %+v", got, err, want)
	}
}
