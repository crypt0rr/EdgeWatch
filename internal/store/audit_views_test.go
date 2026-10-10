package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The audit view case joins tenantStoreLeakCases before any test runs, so
// the completeness check and TestTenantStoreIsolation cover it.
func init() {
	for name, leak := range auditViewLeakCases {
		if _, exists := tenantStoreLeakCases[name]; exists {
			panic("duplicate tenant leak case " + name)
		}
		tenantStoreLeakCases[name] = leak
	}
}

// Client addresses of the seeded audit records.
const (
	auditUnitAIP    = "198.51.100.1"
	auditUnitBIP    = "198.51.100.2"
	auditPlatformIP = "203.0.113.9"
	auditUnknownIP  = "192.0.2.77"
)

// auditViewTime is the time of the first record that seedAuditViews writes;
// each later record is a minute newer.
var auditViewTime = time.Date(2026, 9, 21, 8, 0, 0, 0, time.UTC)

// auditViewSeed holds the IDs of the seeded audit records by label, and the
// labels in the order they were written.
type auditViewSeed struct {
	ids    map[string]int64
	labels []string
}

// of returns the IDs of the labelled records, in the order given.
func (seed auditViewSeed) of(t *testing.T, labels ...string) []int64 {
	t.Helper()
	ids := make([]int64, 0, len(labels))
	for _, label := range labels {
		id, ok := seed.ids[label]
		if !ok {
			t.Fatalf("no seeded audit record %q", label)
		}
		ids = append(ids, id)
	}
	return ids
}

// time returns the time that seedAuditViews gave the labelled record.
func (seed auditViewSeed) time(t *testing.T, label string) time.Time {
	t.Helper()
	for i, seeded := range seed.labels {
		if seeded == label {
			return auditViewTime.Add(time.Duration(i) * time.Minute)
		}
	}
	t.Fatalf("no seeded audit record %q", label)
	return time.Time{}
}

// seedAuditViews replaces the fixture's audit records with records of every
// category, in both tenants and in platform scope, by unit, platform, host,
// and system actors. The store's own writers record them, so each carries
// the tenant, actor kind, and category those writers give it; the test
// only moves each record to its own minute, in the order written, so the
// views list them in reverse. The platform administrator platformRoot is
// created along the way.
func seedAuditViews(t *testing.T, f tenantFixture) auditViewSeed {
	t.Helper()
	ctx := context.Background()
	if _, err := f.store.DB.Exec(`DELETE FROM security_audit`); err != nil {
		t.Fatal(err)
	}
	a, b, ps := f.store.Tenant(f.a), f.store.Tenant(f.b), f.store.Platform()
	now := time.Now().UTC()
	byPlatform := func(action, detail string) AuditEntry {
		return AuditEntry{Action: action, Detail: detail, ActorUserID: platformRoot, ActorUsername: platformRoot, SourceIP: auditPlatformIP, RequestID: "request-" + action}
	}
	steps := []struct {
		label string
		write func() error
	}{
		{"A login", func() error {
			return a.AuditEntry(ctx, AuditEntry{Action: "user.login", Detail: "signed in", ActorUserID: accountAdminA, ActorUsername: "admin-a", SourceIP: auditUnitAIP})
		}},
		{"A job", func() error {
			_, err := a.CreateJobWithEnabledAndAudit(ctx, testJob("audited"), true, AuditEntry{Action: "job.created", Detail: "job audited created", ActorUserID: accountAdminA, ActorUsername: "admin-a", SourceIP: auditUnitAIP})
			return err
		}},
		{"A backup", func() error {
			return a.AuditEntry(ctx, AuditEntry{Action: "database.backup", Detail: "output=backup.db", ActorUsername: "host-cli", ActorKind: AuditActorHost})
		}},
		{"platform setup token", func() error {
			return ps.IssuePlatformSetupToken(ctx, "platform-setup-hash", now.Add(time.Hour), now, false)
		}},
		{"platform login", func() error {
			insertTenantUser(t, f.store, platformRoot, nil, RolePlatformAdmin)
			return ps.AuditEntry(ctx, byPlatform("user.login", "signed in"))
		}},
		{"platform routing", func() error {
			return ps.AuditEntry(ctx, byPlatform("notifications.update_routing", "platform update routing changed"))
		}},
		{"B login", func() error {
			return b.AuditEntry(ctx, AuditEntry{Action: "user.login", Detail: "signed in", ActorUserID: accountAdminB, ActorUsername: "admin-b", SourceIP: auditUnitBIP, RequestID: "request-b-login"})
		}},
		{"B job", func() error {
			_, err := b.CreateJobWithEnabledAndAudit(ctx, testJob("audited"), true, AuditEntry{Action: "job.created", Detail: "job audited created", ActorUserID: accountAdminB, ActorUsername: "admin-b", SourceIP: auditUnitBIP})
			return err
		}},
		{"B reset", func() error {
			return ps.IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, "reset-link-hash", now, now.Add(time.Hour), byPlatform("user.password_reset_issued", "password reset issued for admin-b"))
		}},
		{"B capacity", func() error {
			return ps.SetTenantCapacity(ctx, secondTenantID, TenantCapacity{MaxConcurrentScans: ptrTo(1)}, testCapacityLimits, byPlatform("", ""))
		}},
		{"B throttled", func() error {
			return b.AuditEntry(ctx, AuditEntry{Action: "auth.rate_limited", Detail: "sign-in throttled"})
		}},
		{"B host reset", func() error {
			return b.AuditEntry(ctx, AuditEntry{Action: "user.password_reset", Detail: "password reset from host CLI", ActorUsername: "host-cli", ActorKind: AuditActorHost})
		}},
		{"A invite", func() error {
			_, err := ps.InviteUnitAdmin(ctx, DefaultTenantID, User{Username: "second-admin-a", DisplayName: "Second admin A"}, "invite-link-hash", now, now.Add(time.Hour), byPlatform("user.created", "user second-admin-a created"))
			return err
		}},
		{"platform failed login", func() error {
			return ps.AuditEntry(ctx, AuditEntry{Action: "auth.login_failed", Detail: "unknown account", SourceIP: auditUnknownIP})
		}},
	}
	seed := auditViewSeed{ids: map[string]int64{}}
	var last int64
	for i, step := range steps {
		if err := step.write(); err != nil {
			t.Fatalf("%s: %v", step.label, err)
		}
		var id int64
		var written int
		if err := f.store.DB.QueryRow(`SELECT COALESCE(MAX(id),0),COUNT(*) FROM security_audit WHERE id>?`, last).Scan(&id, &written); err != nil {
			t.Fatal(err)
		}
		if written != 1 {
			t.Fatalf("%s wrote %d audit records, want 1", step.label, written)
		}
		stamp := auditViewTime.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)
		if _, err := f.store.DB.Exec(`UPDATE security_audit SET created_at=? WHERE id=?`, stamp, id); err != nil {
			t.Fatal(err)
		}
		seed.ids[step.label], seed.labels, last = id, append(seed.labels, step.label), id
	}
	return seed
}

// auditIDs returns the IDs of the entries, in order.
func auditIDs(entries []AuditLogEntry) []int64 {
	ids := make([]int64, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}

// assertAuditPage checks that a page holds exactly the records with the IDs,
// in order, and is the last page.
func assertAuditPage(t *testing.T, name string, page AuditLogPage, err error, want []int64) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	if got := auditIDs(page.Entries); !reflect.DeepEqual(got, want) && (len(got) > 0 || len(want) > 0) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
	if page.NextBefore != 0 {
		t.Errorf("%s: next page after %d, want none", name, page.NextBefore)
	}
}

// auditEntry returns the entry with the ID.
func auditEntry(t *testing.T, page AuditLogPage, id int64) AuditLogEntry {
	t.Helper()
	for _, entry := range page.Entries {
		if entry.ID == id {
			return entry
		}
	}
	t.Fatalf("the page has no entry %d", id)
	return AuditLogEntry{}
}

// The unit and platform views show their own records only:
//
//   - a unit's view shows every record of the unit, including the platform
//     administrator's reset of its administrator and change of its
//     capacity, and never another unit's records or those in platform
//     scope;
//   - the platform view shows the records in platform scope and the
//     account and platform records of every unit, and never a unit's data
//     records, such as B's job.created; its unit filter keeps one unit's;
//   - the unit view hides the client address of a platform administrator's
//     action and shows only its own accounts' display names, while the
//     platform view shows both.
func TestAuditViewsShowTheirOwnRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	seed := seedAuditViews(t, f)
	unitA, errA := f.store.Tenant(f.a).AuditPage(ctx, AuditFilter{}, 0, 0)
	assertAuditPage(t, "unit A", unitA, errA, seed.of(t, "A invite", "A backup", "A job", "A login"))
	unitB, errB := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, 0, 0)
	assertAuditPage(t, "unit B", unitB, errB, seed.of(t, "B host reset", "B throttled", "B capacity", "B reset", "B job", "B login"))
	platform, err := f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, 0, 0)
	assertAuditPage(t, "platform", platform, err, seed.of(t, "platform failed login", "A invite", "B host reset", "B throttled", "B capacity", "B reset", "B login", "platform routing", "platform login", "platform setup token", "A backup", "A login"))
	for tenant, want := range map[string][]int64{
		DefaultTenantID: seed.of(t, "A invite", "A backup", "A login"),
		secondTenantID:  seed.of(t, "B host reset", "B throttled", "B capacity", "B reset", "B login"),
		"missing":       nil,
	} {
		page, err := f.store.Platform().AuditPage(ctx, PlatformAuditFilter{TenantID: tenant}, 0, 0)
		assertAuditPage(t, "platform, unit "+tenant, page, err, want)
	}

	reset := AuditLogEntry{
		ID: seed.ids["B reset"], CreatedAt: seed.time(t, "B reset"), Action: "user.password_reset_issued", Category: auditCategoryAccount,
		ActorKind: AuditActorPlatform, ActorUserID: platformRoot, ActorUsername: platformRoot, Detail: "password reset issued for admin-b",
		RequestID: "request-user.password_reset_issued", TenantID: secondTenantID,
	}
	if got := auditEntry(t, unitB, reset.ID); got != reset {
		t.Errorf("unit B's reset entry = %+v, want %+v", got, reset)
	}
	reset.SourceIP, reset.ActorDisplayName = auditPlatformIP, platformRoot
	if got := auditEntry(t, platform, reset.ID); got != reset {
		t.Errorf("platform reset entry = %+v, want %+v", got, reset)
	}
	login := AuditLogEntry{
		ID: seed.ids["B login"], CreatedAt: seed.time(t, "B login"), Action: "user.login", Category: auditCategoryAccount,
		ActorKind: AuditActorUnit, ActorUserID: accountAdminB, ActorUsername: "admin-b", ActorDisplayName: "admin-b", Detail: "signed in",
		RequestID: "request-b-login", SourceIP: auditUnitBIP, TenantID: secondTenantID,
	}
	for name, page := range map[string]AuditLogPage{"unit B": unitB, "platform": platform} {
		if got := auditEntry(t, page, login.ID); got != login {
			t.Errorf("%s: B's login entry = %+v, want %+v", name, got, login)
		}
	}
	type attribution struct{ tenant, kind, category string }
	for label, want := range map[string]attribution{
		"B capacity":            {secondTenantID, AuditActorPlatform, auditCategoryPlatform},
		"B job":                 {secondTenantID, AuditActorUnit, auditCategoryData},
		"B throttled":           {secondTenantID, AuditActorSystem, auditCategoryAccount},
		"B host reset":          {secondTenantID, AuditActorHost, auditCategoryAccount},
		"A backup":              {DefaultTenantID, AuditActorHost, auditCategoryPlatform},
		"A invite":              {DefaultTenantID, AuditActorPlatform, auditCategoryAccount},
		"platform setup token":  {"", AuditActorHost, auditCategoryAccount},
		"platform routing":      {"", AuditActorPlatform, auditCategoryData},
		"platform failed login": {"", AuditActorSystem, auditCategoryAccount},
	} {
		page := map[string]AuditLogPage{DefaultTenantID: unitA, secondTenantID: unitB, "": platform}[want.tenant]
		got := auditEntry(t, page, seed.ids[label])
		if (attribution{got.TenantID, got.ActorKind, got.Category}) != want {
			t.Errorf("%s: tenant %q, actor %q, category %q; want %+v", label, got.TenantID, got.ActorKind, got.Category, want)
		}
		// A unit's view shows neither the address nor the display name of
		// a platform administrator.
		if want.tenant != "" && got.ActorKind == AuditActorPlatform && (got.SourceIP != "" || got.ActorDisplayName != "") {
			t.Errorf("%s: the unit view shows the platform administrator's address %q and name %q", label, got.SourceIP, got.ActorDisplayName)
		}
	}
	if got := auditEntry(t, platform, seed.ids["platform failed login"]); got.SourceIP != auditUnknownIP {
		t.Errorf("platform view address of a failed sign-in = %q", got.SourceIP)
	}
}

// insertAuditRow writes an audit record directly in SQL and returns its ID.
// A nil tenant writes it in platform scope.
func insertAuditRow(t *testing.T, s *Store, tenant any, action, createdAt string) int64 {
	t.Helper()
	result, err := s.DB.Exec(`INSERT INTO security_audit(action,detail,created_at,tenant_id,actor_kind,category) VALUES(?,'',?,?,?,?)`, action, createdAt, tenant, AuditActorSystem, auditCategory(action))
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// auditRow is a record that a pagination test wrote, with its time as
// stored.
type auditRow struct {
	id        int64
	createdAt string
}

// newestFirst returns the IDs of the rows in the order of the views.
func newestFirst(rows []auditRow) []int64 {
	sorted := append([]auditRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].createdAt != sorted[j].createdAt {
			return sorted[i].createdAt > sorted[j].createdAt
		}
		return sorted[i].id > sorted[j].id
	})
	ids := make([]int64, 0, len(sorted))
	for _, row := range sorted {
		ids = append(ids, row.id)
	}
	return ids
}

// walkAuditPages reads a view page by page until its last page. Each page
// but the last is full, and names its last entry as the next position.
// between runs after the first page.
func walkAuditPages(t *testing.T, name string, limit int, read func(before int64) (AuditLogPage, error), between func()) []int64 {
	t.Helper()
	var ids []int64
	var before int64
	for pages := 0; ; pages++ {
		if pages > 1_000 {
			t.Fatalf("%s: the pages do not end", name)
		}
		page, err := read(before)
		if err != nil {
			t.Fatalf("%s: page after %d: %v", name, before, err)
		}
		ids = append(ids, auditIDs(page.Entries)...)
		if page.NextBefore == 0 {
			if len(page.Entries) > limit {
				t.Fatalf("%s: the last page holds %d entries, more than %d", name, len(page.Entries), limit)
			}
			return ids
		}
		if len(page.Entries) != limit || page.NextBefore != page.Entries[limit-1].ID {
			t.Fatalf("%s: a page of %d entries names %d as the next position", name, len(page.Entries), page.NextBefore)
		}
		before = page.NextBefore
		if pages == 0 && between != nil {
			between()
		}
	}
}

// Keyset pagination is stable: walking a view page by page returns each of
// its records once, newest first by time and then by ID, even when many
// share a time, when the IDs do not follow the times, when the view merges
// records in platform scope with the units' records, and when records are
// written between two pages; a record newer than the walk's position stays
// out of it. The page size defaults to 50 and is clamped to 200, and a
// position that is not a record of the view is not found.
func TestAuditViewPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	if _, err := f.store.DB.Exec(`DELETE FROM security_audit`); err != nil {
		t.Fatal(err)
	}
	stamp := func(second int) string {
		return time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC).Add(time.Duration(second) * time.Second).Format(time.RFC3339Nano)
	}
	actions := []string{"user.login", "job.created", "database.backup", "scan.run_requested"}
	var unitB, unitA, platform []auditRow
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 360 {
		// The times repeat, and they run against the IDs.
		createdAt := stamp((i * 37) % 97)
		var tenant any
		switch i % 6 {
		case 0, 1, 2, 3:
			tenant = secondTenantID
		case 4:
			tenant = DefaultTenantID
		}
		action := actions[i%len(actions)]
		result, err := tx.Exec(`INSERT INTO security_audit(action,detail,created_at,tenant_id,actor_kind,category) VALUES(?,'',?,?,?,?)`, action, createdAt, tenant, AuditActorSystem, auditCategory(action))
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		row := auditRow{id, createdAt}
		switch tenant {
		case secondTenantID:
			unitB = append(unitB, row)
		case DefaultTenantID:
			unitA = append(unitA, row)
		}
		if tenant == nil || auditCategory(action) != auditCategoryData {
			platform = append(platform, row)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if len(unitB) <= AuditPageMaxLimit {
		t.Fatalf("unit B has %d records; the clamp needs more than %d", len(unitB), AuditPageMaxLimit)
	}

	unitView := func(scope TenantScope, limit int) func(int64) (AuditLogPage, error) {
		return func(before int64) (AuditLogPage, error) {
			return f.store.Tenant(scope).AuditPage(ctx, AuditFilter{}, before, limit)
		}
	}
	platformView := func(limit int) func(int64) (AuditLogPage, error) {
		return func(before int64) (AuditLogPage, error) {
			return f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, before, limit)
		}
	}
	// Account records written after the first page: the newer ones stay
	// out of the walk, and the older one follows at its place.
	var newer, older []auditRow
	writeDuringWalk := func(tenant any) func() {
		return func() {
			newer, older = nil, nil
			for second := 200; second < 203; second++ {
				newer = append(newer, auditRow{insertAuditRow(t, f.store, tenant, "user.logout", stamp(second)), stamp(second)})
			}
			older = append(older, auditRow{insertAuditRow(t, f.store, tenant, "user.logout", stamp(-1)), stamp(-1)})
		}
	}
	if got, want := walkAuditPages(t, "unit B", 7, unitView(f.b, 7), writeDuringWalk(secondTenantID)), newestFirst(append(unitB, older...)); !reflect.DeepEqual(got, want) {
		t.Errorf("unit B pages = %v\nwant %v", got, want)
	}
	unitB = append(append(unitB, older...), newer...)
	platform = append(append(platform, older...), newer...)
	if got, want := walkAuditPages(t, "platform", 11, platformView(11), writeDuringWalk(nil)), newestFirst(append(platform, older...)); !reflect.DeepEqual(got, want) {
		t.Errorf("platform pages = %v\nwant %v", got, want)
	}
	platform = append(append(platform, older...), newer...)
	if len(platform) <= AuditPageMaxLimit {
		t.Fatalf("the platform view has %d records; the clamp needs more than %d", len(platform), AuditPageMaxLimit)
	}
	// A page that ends with the view's oldest record is the last page.
	if got, want := walkAuditPages(t, "unit A", len(unitA)/2, unitView(f.a, len(unitA)/2), nil), newestFirst(unitA); len(unitA)%2 != 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("unit A in two pages = %v\nwant %v", got, want)
	}
	page, err := f.store.Tenant(f.a).AuditPage(ctx, AuditFilter{}, 0, len(unitA))
	assertAuditPage(t, "unit A in one page", page, err, newestFirst(unitA))

	for limit, want := range map[int]int{-3: 50, 0: 50, 1: 1, 50: 50, 199: 199, 200: 200, 201: 200, 1_000_000: 200} {
		unitPage, unitErr := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, 0, limit)
		platformPage, platformErr := f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, 0, limit)
		for name, check := range map[string]struct {
			page AuditLogPage
			err  error
			all  []auditRow
		}{"unit B": {unitPage, unitErr, unitB}, "platform": {platformPage, platformErr, platform}} {
			if check.err != nil || len(check.page.Entries) != want {
				t.Errorf("%s, limit %d: %d entries, %v; want %d", name, limit, len(check.page.Entries), check.err, want)
				continue
			}
			if all := newestFirst(check.all); !reflect.DeepEqual(auditIDs(check.page.Entries), all[:want]) || check.page.NextBefore != all[want-1] {
				t.Errorf("%s, limit %d: the page is not the newest %d records, or names %d as the next position", name, limit, want, check.page.NextBefore)
			}
		}
	}

	var dataB, accountB, platformScope int64
	for _, row := range unitB {
		if dataB == 0 && !containsID(platform, row.id) {
			dataB = row.id
		}
		if accountB == 0 && containsID(platform, row.id) {
			accountB = row.id
		}
	}
	for _, row := range platform {
		if !containsID(unitA, row.id) && !containsID(unitB, row.id) {
			platformScope = row.id
			break
		}
	}
	for name, read := range map[string]func() (AuditLogPage, error){
		"unit B after A's record": func() (AuditLogPage, error) {
			return f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, unitA[0].id, 10)
		},
		"unit B after a platform record": func() (AuditLogPage, error) {
			return f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, platformScope, 10)
		},
		"unit B after a missing record": func() (AuditLogPage, error) {
			return f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, 1_000_000, 10)
		},
		"platform after B's data record": func() (AuditLogPage, error) {
			return f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, dataB, 10)
		},
		"platform after a missing record": func() (AuditLogPage, error) {
			return f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, 1_000_000, 10)
		},
	} {
		if page, err := read(); !errors.Is(err, ErrNotFound) || page.Entries != nil || page.NextBefore != 0 {
			t.Errorf("%s = %d entries, %v; want ErrNotFound", name, len(page.Entries), err)
		}
	}
	if _, err := f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, accountB, 10); err != nil {
		t.Errorf("platform after B's account record: %v", err)
	}
	if _, err := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, -1, 10); !errors.Is(err, ErrValidation) {
		t.Errorf("unit B before -1: %v, want a validation error", err)
	}
	if _, err := f.store.Platform().AuditPage(ctx, PlatformAuditFilter{}, -1, 10); !errors.Is(err, ErrValidation) {
		t.Errorf("platform before -1: %v, want a validation error", err)
	}
}

func containsID(rows []auditRow, id int64) bool {
	for _, row := range rows {
		if row.id == id {
			return true
		}
	}
	return false
}

// The filters narrow both views: an action prefix, a time range, and an
// actor, alone or together, and the platform view's unit. An action prefix
// with anything but a-z, 0-9, '.', '_' and '-', or longer than 64
// characters, is a validation error. The platform view keeps a unit's data
// records out whatever the filter asks for.
func TestAuditViewFilters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	seed := seedAuditViews(t, f)
	unit := func(scope TenantScope, filter AuditFilter) (AuditLogPage, error) {
		return f.store.Tenant(scope).AuditPage(ctx, filter, 0, 0)
	}
	platform := func(filter PlatformAuditFilter) (AuditLogPage, error) {
		return f.store.Platform().AuditPage(ctx, filter, 0, 0)
	}
	for _, check := range []struct {
		name   string
		read   func() (AuditLogPage, error)
		labels []string
	}{
		{"unit B, user.", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{ActionPrefix: "user."}) }, []string{"B host reset", "B reset", "B login"}},
		{"unit B, user.password_reset", func() (AuditLogPage, error) {
			return unit(f.b, AuditFilter{ActionPrefix: "user.password_reset"})
		}, []string{"B host reset", "B reset"}},
		{"unit B, job", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{ActionPrefix: "job"}) }, []string{"B job"}},
		{"unit B, user.login exactly", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{ActionPrefix: "user.login"}) }, []string{"B login"}},
		{"platform, auth.", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: "auth."}})
		}, []string{"platform failed login", "B throttled"}},
		{"platform, job", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: "job"}})
		}, nil},
		{"platform, unit B, job.created", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: "job.created"}, TenantID: secondTenantID})
		}, nil},
		{"unit B, platform actor", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{ActorUserID: platformRoot}) }, []string{"B capacity", "B reset"}},
		{"unit A, platform actor", func() (AuditLogPage, error) { return unit(f.a, AuditFilter{ActorUserID: platformRoot}) }, []string{"A invite"}},
		{"unit B, B's administrator", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{ActorUserID: accountAdminB}) }, []string{"B job", "B login"}},
		{"unit A, B's administrator", func() (AuditLogPage, error) { return unit(f.a, AuditFilter{ActorUserID: accountAdminB}) }, nil},
		{"platform, platform actor", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActorUserID: platformRoot}})
		}, []string{"A invite", "B capacity", "B reset", "platform routing", "platform login"}},
		{"unit B, time range", func() (AuditLogPage, error) {
			return unit(f.b, AuditFilter{Since: seed.time(t, "B reset"), Until: seed.time(t, "B host reset")})
		}, []string{"B throttled", "B capacity", "B reset"}},
		{"unit B, since", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{Since: seed.time(t, "B throttled")}) }, []string{"B host reset", "B throttled"}},
		{"unit B, until", func() (AuditLogPage, error) { return unit(f.b, AuditFilter{Until: seed.time(t, "B job")}) }, []string{"B login"}},
		{"platform, time range", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{Since: seed.time(t, "platform login"), Until: seed.time(t, "B reset")}})
		}, []string{"B login", "platform routing", "platform login"}},
		{"platform, unit B, every filter", func() (AuditLogPage, error) {
			return platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: "user.", Since: seed.time(t, "B login"), Until: seed.time(t, "A invite"), ActorUserID: platformRoot}, TenantID: secondTenantID})
		}, []string{"B reset"}},
		{"unit B, every filter", func() (AuditLogPage, error) {
			return unit(f.b, AuditFilter{ActionPrefix: "user.", Since: seed.time(t, "B login"), Until: seed.time(t, "A invite"), ActorUserID: platformRoot})
		}, []string{"B reset"}},
	} {
		page, err := check.read()
		assertAuditPage(t, check.name, page, err, seed.of(t, check.labels...))
	}

	for _, prefix := range []string{"User.", "user*", "user%", "user?", "user[a]", "user login", "user.login;", "user'", "üser", "user\x00", strings.Repeat("a", auditActionPrefixMaxLength+1)} {
		if page, err := unit(f.b, AuditFilter{ActionPrefix: prefix}); !errors.Is(err, ErrValidation) || page.Entries != nil {
			t.Errorf("unit B, action prefix %q: %d entries, %v; want a validation error", prefix, len(page.Entries), err)
		}
		if page, err := platform(PlatformAuditFilter{AuditFilter: AuditFilter{ActionPrefix: prefix}}); !errors.Is(err, ErrValidation) || page.Entries != nil {
			t.Errorf("platform, action prefix %q: %d entries, %v; want a validation error", prefix, len(page.Entries), err)
		}
	}
	for _, prefix := range []string{strings.Repeat("a", auditActionPrefixMaxLength), "-", "_", "0.9"} {
		if _, err := unit(f.b, AuditFilter{ActionPrefix: prefix}); err != nil {
			t.Errorf("unit B, action prefix %q: %v", prefix, err)
		}
	}
}

// The time bounds match the stored times, which leave out the trailing
// zeros of their fraction, by the instant: a record at a whole second is in
// a range that starts at that second and not in one that ends there, and a
// record with a fraction falls in its own second. A bound with a fraction
// counts from the whole second before it.
func TestAuditViewTimeBoundsMatchStoredTimes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	if _, err := f.store.DB.Exec(`DELETE FROM security_audit`); err != nil {
		t.Fatal(err)
	}
	second := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	ids := map[string]int64{}
	for _, createdAt := range []string{"2026-09-22T09:59:59.999999999Z", "2026-09-22T10:00:00Z", "2026-09-22T10:00:00.5Z", "2026-09-22T10:00:00.51Z", "2026-09-22T10:00:01Z"} {
		ids[createdAt] = insertAuditRow(t, f.store, secondTenantID, "user.login", createdAt)
	}
	for _, check := range []struct {
		name         string
		since, until time.Time
		want         []string
	}{
		{"the second", second, second.Add(time.Second), []string{"2026-09-22T10:00:00.51Z", "2026-09-22T10:00:00.5Z", "2026-09-22T10:00:00Z"}},
		{"before the second", time.Time{}, second, []string{"2026-09-22T09:59:59.999999999Z"}},
		{"from the next second", second.Add(time.Second), time.Time{}, []string{"2026-09-22T10:00:01Z"}},
		{"a bound with a fraction", second.Add(700 * time.Millisecond), second.Add(1700 * time.Millisecond), []string{"2026-09-22T10:00:00.51Z", "2026-09-22T10:00:00.5Z", "2026-09-22T10:00:00Z"}},
		{"another zone", second.In(time.FixedZone("CEST", 2*60*60)), second.Add(time.Second).In(time.FixedZone("CEST", 2*60*60)), []string{"2026-09-22T10:00:00.51Z", "2026-09-22T10:00:00.5Z", "2026-09-22T10:00:00Z"}},
	} {
		want := make([]int64, 0, len(check.want))
		for _, createdAt := range check.want {
			want = append(want, ids[createdAt])
		}
		sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
		// The order within one second follows the stored text; see the
		// comment at the top of audit_views.go. Only which records match
		// matters here.
		for name, read := range map[string]func() (AuditLogPage, error){
			check.name: func() (AuditLogPage, error) {
				return f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{Since: check.since, Until: check.until}, 0, 0)
			},
			"platform, " + check.name: func() (AuditLogPage, error) {
				return f.store.Platform().AuditPage(ctx, PlatformAuditFilter{AuditFilter: AuditFilter{Since: check.since, Until: check.until}}, 0, 0)
			},
		} {
			page, err := read()
			got := auditIDs(page.Entries)
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			if err != nil || !reflect.DeepEqual(got, want) || page.NextBefore != 0 {
				t.Errorf("%s = %v, next %d, %v; want %v", name, got, page.NextBefore, err, want)
			}
		}
	}
}

// No audit view shows secret material in any category, from any writer:
// the URLs and nonces of notification destinations, including those
// imported from config.yaml, and the hashes of setup, activation, reset,
// and session tokens, CSRF tokens, and password hashes. The writers keep
// them out of the details, and the views read no column that holds them.
func TestAuditViewsShowNoSecretMaterial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	if _, err := f.store.DB.Exec(`DELETE FROM security_audit`); err != nil {
		t.Fatal(err)
	}
	a, b, ps := f.store.Tenant(f.a), f.store.Tenant(f.b), f.store.Platform()
	now := time.Now().UTC()
	const (
		createdURL  = "discord://created-url-secret@webhook-created"
		rotatedURL  = "discord://rotated-url-secret@webhook-rotated"
		importedURL = "discord://imported-url-secret@webhook-imported"
	)
	secrets := []string{
		createdURL, rotatedURL, importedURL, "url-secret", "discord://",
		"created-nonce-secret", "rotated-nonce-secret", "imported-nonce-secret", "imported-url-digest-secret",
		"invite-token-hash-secret", "reset-token-hash-secret", "setup-token-hash-secret", "session-token-hash-secret",
		"csrf-token-secret", "password-hash-secret",
	}
	// The fixture's own account secrets.
	for _, account := range tenantFixtureAccounts {
		secrets = append(secrets, "hash-"+account.username, "session-"+account.username, "csrf-"+account.username, "recovery-"+account.username, "invite-"+account.username)
	}
	byAdminB := func(action, detail string) AuditEntry {
		return AuditEntry{Action: action, Detail: detail, ActorUserID: accountAdminB, ActorUsername: "admin-b", SourceIP: auditUnitBIP}
	}
	destination, err := b.CreateManagedNotificationWithAudit(ctx, "", "audited", "discord", []byte(createdURL), []byte("created-nonce-secret"), true, byAdminB("notifications.created", "managed notification created"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpdateManagedNotificationWithAudit(ctx, destination.ID, destination.Revision, "audited", "discord", []byte(rotatedURL), []byte("rotated-nonce-secret"), true, byAdminB("notifications.updated", "managed notification updated: "+destination.ID)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetApplicationUpdateDestinations(ctx, []string{destination.ID}, byAdminB("notifications.update_routing", "application update notification routing changed")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.System().ImportDeploymentNotifications(ctx, []DeploymentNotificationImport{{LegacyHash: "imported-url-digest-secret", ID: "00000000-0000-0000-0000-00000000d001", Name: "imported", Provider: "discord", Ciphertext: []byte(importedURL), Nonce: []byte("imported-nonce-secret")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateUserWithInvite(ctx, User{Username: "invited-b", DisplayName: "Invited B", Role: RoleViewer}, "invite-token-hash-secret", now, now.Add(time.Hour), byAdminB("user.created", "user invited-b created by admin-b")); err != nil {
		t.Fatal(err)
	}
	operatorB := fixtureAccount(t, f, accountOperatorB)
	if err := f.store.CreateSignInSession(ctx, SignInSession{UserID: accountOperatorB, PasswordHash: operatorB.PasswordHash, Revision: operatorB.Revision, TOTPEnabled: operatorB.TOTPEnabled, Factor: NoSignInFactor, IDHash: "session-token-hash-secret", CSRF: "csrf-token-secret", Created: now, Expires: now.Add(time.Hour), Audit: AuditEntry{Action: "user.login", Detail: "signed in", ActorUserID: accountOperatorB, ActorUsername: "operator-b"}}); err != nil {
		t.Fatal(err)
	}
	if err := ps.IssuePlatformSetupToken(ctx, "setup-token-hash-secret", now.Add(time.Hour), now, false); err != nil {
		t.Fatal(err)
	}
	root, err := ps.CompletePlatformSetup(ctx, "setup-token-hash-secret", "root", "password-hash-secret", now)
	if err != nil {
		t.Fatal(err)
	}
	byRoot := func(action, detail string) AuditEntry {
		return AuditEntry{Action: action, Detail: detail, ActorUserID: root.ID, ActorUsername: root.Username, SourceIP: auditPlatformIP}
	}
	if err := ps.IssueUnitAdminPasswordReset(ctx, secondTenantID, accountAdminB, "reset-token-hash-secret", now, now.Add(time.Hour), byRoot("user.password_reset_issued", "password reset issued for admin-b")); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetTenantCapacity(ctx, secondTenantID, TenantCapacity{MaxConcurrentScans: ptrTo(2)}, testCapacityLimits, byRoot("", "")); err != nil {
		t.Fatal(err)
	}
	if err := a.AuditEntry(ctx, AuditEntry{Action: "database.backup", Detail: "output=backup.db", ActorUsername: "host-cli", ActorKind: AuditActorHost}); err != nil {
		t.Fatal(err)
	}

	pages := map[string]func(before int64) (AuditLogPage, error){
		"unit A": func(before int64) (AuditLogPage, error) { return a.AuditPage(ctx, AuditFilter{}, before, 5) },
		"unit B": func(before int64) (AuditLogPage, error) { return b.AuditPage(ctx, AuditFilter{}, before, 5) },
		"platform": func(before int64) (AuditLogPage, error) {
			return ps.AuditPage(ctx, PlatformAuditFilter{}, before, 5)
		},
		"platform, unit B": func(before int64) (AuditLogPage, error) {
			return ps.AuditPage(ctx, PlatformAuditFilter{TenantID: secondTenantID}, before, 5)
		},
	}
	categories := map[string]bool{}
	for name, read := range pages {
		var shown int
		for before := int64(0); ; {
			page, err := read(before)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for _, entry := range page.Entries {
				shown++
				categories[entry.Category] = true
				text := fmt.Sprintf("%#v", entry)
				for _, secret := range secrets {
					if strings.Contains(text, secret) {
						t.Errorf("%s: entry %d %s shows %q: %s", name, entry.ID, entry.Action, secret, text)
					}
				}
			}
			if before = page.NextBefore; before == 0 {
				break
			}
		}
		if shown == 0 {
			t.Errorf("%s shows no records", name)
		}
	}
	for _, category := range []string{auditCategoryAccount, auditCategoryPlatform, auditCategoryData} {
		if !categories[category] {
			t.Errorf("no view showed a record of the %s category", category)
		}
	}
	if total := countRows(t, f.store.DB, `SELECT COUNT(*) FROM security_audit`); total != 11 {
		t.Fatalf("the writers recorded %d audit records, want 11", total)
	}
}

// Neither view scans the audit table or sorts it:
//
//   - the unit view searches security_audit_tenant_time for the tenant and
//     reads it in the index's order, so it sorts nothing;
//   - the platform view searches security_audit_tenant_time for the records
//     in platform scope and walks security_audit_platform_time, which holds
//     only account and platform records, for the units' records. Each
//     branch reads in its index's order and stops after one page; only the
//     two pages are sorted to merge them. On the first page nothing bounds
//     the time, so SQLite prints the walk of the partial index as SCAN ...
//     USING INDEX; after a position or with a time range it is a SEARCH;
//   - with a unit, the platform view searches security_audit_tenant_time for
//     that unit, like the unit view;
//   - the display name is a lookup by account ID.
//
// The plans hold with and without every filter and a position.
func TestAuditViewQueryPlansUseIndexes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newTenantFixture(t)
	seed := seedAuditViews(t, f)
	filters := AuditFilter{ActionPrefix: "user.", Since: seed.time(t, "A login"), Until: seed.time(t, "platform failed login"), ActorUserID: platformRoot}
	const (
		tenantSearch        = "SEARCH a USING INDEX security_audit_tenant_time (tenant_id=?)"
		tenantRangeSearch   = "SEARCH a USING INDEX security_audit_tenant_time (tenant_id=? AND created_at>? AND created_at<?)"
		platformWalk        = "SCAN a USING INDEX security_audit_platform_time"
		platformRangeSearch = "SEARCH a USING INDEX security_audit_platform_time (created_at>? AND created_at<?)"
		platformAfterSearch = "SEARCH a USING INDEX security_audit_platform_time (created_at<?)"
		tenantAfterSearch   = "SEARCH a USING INDEX security_audit_tenant_time (tenant_id=? AND created_at<?)"
		accountLookup       = "SEARCH u USING INDEX sqlite_autoindex_users_1 (id=?) LEFT-JOIN"
	)
	unitCursor, platformCursor := seed.ids["B login"], seed.ids["platform login"]
	for _, check := range []struct {
		name  string
		build func() (string, []any, error)
		// reads are the plan's accesses to security_audit.
		reads []string
		merge bool
	}{
		{"unit", func() (string, []any, error) { return f.store.Tenant(f.b).auditPageQuery(ctx, AuditFilter{}, 0, 50) }, []string{tenantSearch}, false},
		{"unit after a position", func() (string, []any, error) {
			return f.store.Tenant(f.b).auditPageQuery(ctx, AuditFilter{}, unitCursor, 50)
		}, []string{tenantAfterSearch}, false},
		{"unit, filtered after a position", func() (string, []any, error) {
			return f.store.Tenant(f.b).auditPageQuery(ctx, filters, unitCursor, 50)
		}, []string{tenantRangeSearch}, false},
		{"platform", func() (string, []any, error) {
			return f.store.Platform().auditPageQuery(ctx, PlatformAuditFilter{}, 0, 50)
		}, []string{tenantSearch, platformWalk}, true},
		{"platform after a position", func() (string, []any, error) {
			return f.store.Platform().auditPageQuery(ctx, PlatformAuditFilter{}, platformCursor, 50)
		}, []string{tenantAfterSearch, platformAfterSearch}, true},
		{"platform, filtered after a position", func() (string, []any, error) {
			return f.store.Platform().auditPageQuery(ctx, PlatformAuditFilter{AuditFilter: filters}, platformCursor, 50)
		}, []string{tenantRangeSearch, platformRangeSearch}, true},
		{"platform, unit B", func() (string, []any, error) {
			return f.store.Platform().auditPageQuery(ctx, PlatformAuditFilter{TenantID: secondTenantID}, 0, 50)
		}, []string{tenantSearch}, false},
		{"platform, unit B, filtered after a position", func() (string, []any, error) {
			return f.store.Platform().auditPageQuery(ctx, PlatformAuditFilter{AuditFilter: filters, TenantID: secondTenantID}, platformCursor, 50)
		}, []string{tenantRangeSearch}, false},
	} {
		query, args, err := check.build()
		if err != nil {
			t.Fatalf("%s: %v", check.name, err)
		}
		plan := explainQueryPlanRows(t, f.store.DB, query, args...)
		t.Logf("%s: %v", check.name, plan)
		rows := make(map[int]queryPlanRow, len(plan))
		for _, row := range plan {
			rows[row.id] = row
		}
		var reads []string
		for _, row := range plan {
			switch detail := row.detail; {
			case strings.HasPrefix(detail, "SEARCH a ") || strings.HasPrefix(detail, "SCAN a"):
				reads = append(reads, detail)
			case strings.HasPrefix(detail, "SEARCH u ") || strings.HasPrefix(detail, "SCAN u"):
				if detail != accountLookup {
					t.Errorf("%s reads the accounts with %q", check.name, detail)
				}
			case strings.HasPrefix(detail, "SCAN "):
				// Only the output of a branch, at most one page, is read in
				// full.
				if !strings.HasPrefix(detail, "SCAN (subquery-") {
					t.Errorf("%s scans %q", check.name, detail)
				}
			case strings.Contains(detail, "TEMP B-TREE"):
				if !check.merge {
					t.Errorf("%s sorts its records: %q", check.name, detail)
				}
				for parent, ok := rows[row.parent]; ok; parent, ok = rows[parent.parent] {
					if strings.HasPrefix(parent.detail, "CO-ROUTINE") {
						t.Errorf("%s sorts inside a branch, so the branch reads every record it matches", check.name)
					}
				}
			}
		}
		sort.Strings(reads)
		want := append([]string(nil), check.reads...)
		sort.Strings(want)
		if !reflect.DeepEqual(reads, want) {
			t.Errorf("%s reads the audit with %q, want %q", check.name, reads, want)
		}
	}
}

var auditViewLeakCases = map[string]tenantLeakCase{
	// Each unit's view shows only its own records: B never sees A's, nor
	// those in platform scope, not even by naming one as its position or
	// filtering on A's actor, and A never sees B's.
	"AuditPage": {writes: true, run: func(t *testing.T, f tenantFixture) {
		ctx := context.Background()
		seed := seedAuditViews(t, f)
		for scope, labels := range map[TenantScope][]string{
			f.a: {"A invite", "A backup", "A job", "A login"},
			f.b: {"B host reset", "B throttled", "B capacity", "B reset", "B job", "B login"},
		} {
			page, err := f.store.Tenant(scope).AuditPage(ctx, AuditFilter{}, 0, AuditPageMaxLimit)
			assertAuditPage(t, "tenant "+scope.ID(), page, err, seed.of(t, labels...))
			for _, entry := range page.Entries {
				if entry.TenantID != scope.ID() {
					t.Errorf("tenant %s: entry %d belongs to %q", scope.ID(), entry.ID, entry.TenantID)
				}
			}
		}
		for _, label := range []string{"A login", "A job", "A invite", "platform login", "platform routing"} {
			if page, err := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, seed.ids[label], 10); !errors.Is(err, ErrNotFound) || page.Entries != nil {
				t.Errorf("tenant B after %s = %v, %v; want ErrNotFound", label, auditIDs(page.Entries), err)
			}
		}
		if page, err := f.store.Tenant(f.a).AuditPage(ctx, AuditFilter{}, seed.ids["B reset"], 10); !errors.Is(err, ErrNotFound) || page.Entries != nil {
			t.Errorf("tenant A after B's reset = %v, %v; want ErrNotFound", auditIDs(page.Entries), err)
		}
		page, err := f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{ActorUserID: accountAdminA}, 0, 0)
		assertAuditPage(t, "tenant B, A's administrator", page, err, nil)
		page, err = f.store.Tenant(f.b).AuditPage(ctx, AuditFilter{}, seed.ids["B job"], 0)
		assertAuditPage(t, "tenant B after its job", page, err, seed.of(t, "B login"))
	}},
}
