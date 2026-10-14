package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	eventHistoryFixtureJobs   = 10
	eventHistoryFixtureEvents = 2000
	eventHistoryFixtureBytes  = 8 << 10
)

func TestMigration72IndexesActualEventHistoryQueries(t *testing.T) {
	ctx := context.Background()
	f := newTenantFixture(t)
	db := f.store.DB

	// Reconstruct the event-index shape at schema 71. The other schema objects
	// are the current migrated template, and migration 72 touches only events.
	for _, index := range []string{eventsTenantHistoryIndex, eventsTenantJobHistoryIndex, eventsTenantJobIDHistoryIndex} {
		if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS `+index); err != nil {
			t.Fatalf("drop schema 72 index %s: %v", index, err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX events_tenant_id_time ON events(tenant_id,created_at DESC,id DESC)`); err != nil {
		t.Fatalf("restore schema 71 event index: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version=71`); err != nil {
		t.Fatal(err)
	}
	if err := runMigration(ctx, db, 72, []string{
		`DROP INDEX events_tenant_id_time`,
		`CREATE INDEX events_tenant_id_time ON events(missing_migration_column)`,
	}, false); err == nil {
		t.Fatal("schema 72 migration with an invalid replacement index succeeded")
	}
	if got := countRows(t, db, `PRAGMA user_version`); got != 71 {
		t.Fatalf("failed schema 72 migration advanced to schema %d", got)
	}
	if got := countRows(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='events_tenant_id_time'`); got != 1 {
		t.Fatalf("failed schema 72 migration left the schema 71 tenant index count at %d, want 1", got)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}

	ctxTenantA := f.store.Tenant(f.a)
	ctxTenantB := f.store.Tenant(f.b)
	jobs := make([]JobRecord, eventHistoryFixtureJobs)
	var err error
	for i := range jobs {
		name := fmt.Sprintf("event-history-%02d", i)
		jobs[i], err = ctxTenantA.CreateJob(ctx, testJob(name))
		if err != nil {
			t.Fatalf("create tenant A job %s: %v", name, err)
		}
	}
	otherTenantJob, err := ctxTenantB.CreateJob(ctx, testJob("event-history-00"))
	if err != nil {
		t.Fatalf("create same-name tenant B job: %v", err)
	}
	tieJob, err := ctxTenantA.CreateJob(ctx, testJob("event-history-ties"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO job_history_purges(tenant_id,job_id,phase,created_at,updated_at) VALUES(?,?,?,?,?)`, f.a.ID(), jobs[len(jobs)-1].ID, jobPurgePhaseEvents, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert active history purge marker: %v", err)
	}
	baseA, err := ctxTenantA.ListEventsPage(ctx, "", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	largeMessage := strings.Repeat("x", eventHistoryFixtureBytes)
	for i, job := range jobs {
		name := fmt.Sprintf("event-history-%02d", i)
		payload := eventHistoryFixturePayload(t, job.ID, name, largeMessage, stamp)
		insertEvents(t, ctx, db, f.a.ID(), job.ID, name, payload, stamp, eventHistoryFixtureEvents)
	}

	// Legacy config history is grouped by name even though it has no stable job
	// ID. A managed job with the same name in another tenant stays isolated.
	legacyPayload := eventHistoryFixturePayload(t, "", "event-history-00", "legacy config event", stamp.Add(time.Hour))
	insertEvents(t, ctx, db, f.a.ID(), "", "event-history-00", legacyPayload, stamp.Add(time.Hour), 1)
	otherPayload := eventHistoryFixturePayload(t, otherTenantJob.ID, "event-history-00", "other tenant", stamp.Add(time.Hour))
	insertEvents(t, ctx, db, f.b.ID(), otherTenantJob.ID, "event-history-00", otherPayload, stamp.Add(time.Hour), 1)
	tieStamp := stamp.Add(2 * time.Hour)
	for _, message := range []string{"tie-first", "tie-second"} {
		payload := eventHistoryFixturePayload(t, tieJob.ID, "event-history-ties", message, tieStamp)
		insertEvents(t, ctx, db, f.a.ID(), tieJob.ID, "event-history-ties", payload, tieStamp, 1)
	}

	// Build the schema 72 indexes against a representative, payload-heavy event
	// table. The migration WAL is measured independently of fixture insertion.
	truncateFixtureWAL(t, db)
	if err := applyMigration(ctx, db, 72, migration72Statements()); err != nil {
		t.Fatalf("apply schema 72: %v", err)
	}
	walBytes, err := walSize(f.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if walBytes > maxSchemaStepWALBytes {
		t.Fatalf("schema 72 WAL is %d bytes, above %d-byte migration budget", walBytes, maxSchemaStepWALBytes)
	}
	var indexBytes int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name IN (?,?,?)`, eventsTenantHistoryIndex, eventsTenantJobHistoryIndex, eventsTenantJobIDHistoryIndex).Scan(&indexBytes); err != nil {
		t.Fatalf("measure schema 72 event indexes: %v", err)
	}
	if got := countRows(t, db, `PRAGMA user_version`); got != 72 {
		t.Fatalf("schema version = %d, want 72", got)
	}
	if got := indexKeys(t, db, eventsTenantHistoryIndex); got != "tenant_id,created_at DESC,id DESC,job_id" {
		t.Fatalf("%s keys = %q", eventsTenantHistoryIndex, got)
	}
	if got := indexKeys(t, db, eventsTenantJobHistoryIndex); got != "tenant_id,job,created_at DESC,id DESC,job_id" {
		t.Fatalf("%s keys = %q", eventsTenantJobHistoryIndex, got)
	}
	if got := indexKeys(t, db, eventsTenantJobIDHistoryIndex); got != "tenant_id,job_id,created_at DESC,id DESC" {
		t.Fatalf("%s keys = %q", eventsTenantJobIDHistoryIndex, got)
	}
	t.Logf("schema 72 event-index migration WAL: %d bytes; new event indexes: %d bytes; seeded 10 jobs × %d events with at least %d payload bytes", walBytes, indexBytes, eventHistoryFixtureEvents, eventHistoryFixtureJobs*eventHistoryFixtureEvents*eventHistoryFixtureBytes)

	checkEventHistoryProductionPlans(t, db, f.a.ID(), jobs[0].ID, "event-history-00")

	all, err := ctxTenantA.ListEventsPage(ctx, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := baseA.Total + eventHistoryFixtureJobs*eventHistoryFixtureEvents - eventHistoryFixtureEvents + 3; all.Total != want || len(all.Items) != 10 {
		t.Fatalf("tenant A event page total/items = %d/%d, want %d/10", all.Total, len(all.Items), want)
	}
	byName, err := ctxTenantA.ListEventsPage(ctx, "event-history-00", 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	if byName.Total != eventHistoryFixtureEvents+1 || len(byName.Items) != 25 {
		t.Fatalf("same-name config event page total/items = %d/%d, want %d/25", byName.Total, len(byName.Items), eventHistoryFixtureEvents+1)
	}
	byID, err := ctxTenantA.ListJobEventsPage(ctx, jobs[0].ID, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	if byID.Total != eventHistoryFixtureEvents || len(byID.Items) != 25 {
		t.Fatalf("stable-ID event page total/items = %d/%d, want %d/25", byID.Total, len(byID.Items), eventHistoryFixtureEvents)
	}
	if purged, err := ctxTenantA.ListJobEventsPage(ctx, jobs[len(jobs)-1].ID, 10, 0); err != nil || purged.Total != 0 || len(purged.Items) != 0 {
		t.Fatalf("purging job history = total %d, items %d, err %v; want no visible history", purged.Total, len(purged.Items), err)
	}
	other, err := ctxTenantB.ListEventsPage(ctx, "event-history-00", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if other.Total != 1 || len(other.Items) != 1 || other.Items[0].Message != "other tenant" {
		t.Fatalf("same-name tenant B history = %#v (total %d), want only its own event", other.Items, other.Total)
	}
	tiePage, err := ctxTenantA.ListJobEventsPage(ctx, tieJob.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tiePage.Total != 2 || len(tiePage.Items) != 2 || tiePage.Items[0].Message != "tie-second" || tiePage.Items[1].Message != "tie-first" {
		t.Fatalf("equal-time history order = %#v, want descending event ID", tiePage.Items)
	}
	if countRows(t, db, `SELECT COUNT(*) FROM events WHERE tenant_id=? AND job_id=?`, f.a.ID(), jobs[len(jobs)-1].ID) != eventHistoryFixtureEvents {
		t.Fatal("history lookup changed or removed events while excluding a purging job")
	}
}

func eventHistoryFixturePayload(t *testing.T, jobID, job, message string, createdAt time.Time) []byte {
	t.Helper()
	_, payload, err := model.MarshalBoundedEvent(model.Event{Type: "event-history-fixture", JobID: jobID, Job: job, Message: message, CreatedAt: createdAt}, model.EventPayloadLimit)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func insertEvents(t *testing.T, ctx context.Context, db *sql.DB, tenantID, jobID, job string, payload []byte, start time.Time, count int) {
	t.Helper()
	stmt, err := db.PrepareContext(ctx, `INSERT INTO events(type,job,payload_json,created_at,job_id,tenant_id) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := range count {
		createdAt := sqliteTimestamp(start.Add(time.Duration(i) * time.Second))
		if _, err := stmt.ExecContext(ctx, "event-history-fixture", job, payload, createdAt, jobID, tenantID); err != nil {
			t.Fatalf("insert event %s/%s/%d: %v", tenantID, job, i, err)
		}
	}
}

func checkEventHistoryProductionPlans(t *testing.T, db *sql.DB, tenantID, jobID, job string) {
	t.Helper()
	from := eventsFromSQL
	queries := []struct {
		name          string
		count, page   string
		countArgs     []any
		pageArgs      []any
		pageIndexName string
	}{
		{name: "tenant all jobs", count: `SELECT COUNT(*) ` + from, page: `SELECT payload_json ` + from + ` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, countArgs: []any{tenantID}, pageArgs: []any{tenantID, 10, 25}, pageIndexName: eventsTenantHistoryIndex},
		{name: "tenant legacy job name", count: `SELECT COUNT(*) ` + from + ` AND job=?`, page: `SELECT payload_json ` + from + ` AND job=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, countArgs: []any{tenantID, job}, pageArgs: []any{tenantID, job, 10, 25}, pageIndexName: eventsTenantJobHistoryIndex},
		{name: "tenant stable job ID", count: `SELECT COUNT(*) ` + from + ` AND job_id=?`, page: `SELECT payload_json ` + from + ` AND job_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, countArgs: []any{tenantID, jobID}, pageArgs: []any{tenantID, jobID, 10, 25}, pageIndexName: eventsTenantJobIDHistoryIndex},
	}
	for _, query := range queries {
		countPlan := queryPlan(t, db, query.count, query.countArgs...)
		if !strings.Contains(countPlan, "USING COVERING INDEX") || strings.Contains(countPlan, "SCAN events") {
			t.Errorf("%s count plan is not index-only: %s", query.name, countPlan)
		}
		if query.name == "tenant legacy job name" && !strings.Contains(countPlan, eventsTenantJobHistoryIndex) {
			t.Errorf("%s count plan does not constrain the legacy name: %s", query.name, countPlan)
		}
		if query.name == "tenant stable job ID" && !strings.Contains(countPlan, eventsTenantJobIDHistoryIndex) {
			t.Errorf("%s count plan does not constrain the stable ID: %s", query.name, countPlan)
		}
		pagePlan := queryPlan(t, db, query.page, query.pageArgs...)
		if !strings.Contains(pagePlan, "USING INDEX "+query.pageIndexName) || strings.Contains(pagePlan, "TEMP B-TREE") {
			t.Errorf("%s page plan = %s; want ordered %s lookup", query.name, pagePlan, query.pageIndexName)
		}
		if err := assertPayloadReadAfterPageFilters(t, db, query.page, query.pageArgs...); err != nil {
			t.Errorf("%s page payload access: %v", query.name, err)
		}
		t.Logf("%s count plan: %s", query.name, countPlan)
		t.Logf("%s page plan: %s", query.name, pagePlan)
	}
}

type eventHistoryVDBEOp struct {
	addr, p1, p2, p3 int
	opcode           string
	p4               sql.NullString
	p5               int
	comment          sql.NullString
}

func assertPayloadReadAfterPageFilters(t *testing.T, db *sql.DB, query string, args ...any) error {
	t.Helper()
	var eventRoot int
	if err := db.QueryRow(`SELECT rootpage FROM sqlite_master WHERE type='table' AND name='events'`).Scan(&eventRoot); err != nil {
		return err
	}
	payloadColumn, err := func() (int, error) {
		columns, err := db.Query(`PRAGMA table_info(events)`)
		if err != nil {
			return -1, err
		}
		defer columns.Close()
		payloadColumn := -1
		for columns.Next() {
			var cid, notNull, primaryKey int
			var name, dataType string
			var defaultValue sql.NullString
			if err := columns.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				return -1, err
			}
			if name == "payload_json" {
				payloadColumn = cid
			}
		}
		if err := columns.Err(); err != nil {
			return -1, err
		}
		return payloadColumn, nil
	}()
	if err != nil {
		return err
	}
	if payloadColumn < 0 {
		return fmt.Errorf("events.payload_json column is missing")
	}
	ops, err := func() ([]eventHistoryVDBEOp, error) {
		rows, err := db.Query(`EXPLAIN `+query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ops []eventHistoryVDBEOp
		for rows.Next() {
			var op eventHistoryVDBEOp
			if err := rows.Scan(&op.addr, &op.opcode, &op.p1, &op.p2, &op.p3, &op.p4, &op.p5, &op.comment); err != nil {
				return nil, err
			}
			ops = append(ops, op)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return ops, nil
	}()
	if err != nil {
		return err
	}
	tableCursor := -1
	for _, op := range ops {
		if op.opcode == "OpenRead" && op.p2 == eventRoot {
			tableCursor = op.p1
			break
		}
	}
	if tableCursor < 0 {
		return fmt.Errorf("page bytecode does not open events table root %d", eventRoot)
	}
	var payloadAddr, resultAddr = -1, -1
	for _, op := range ops {
		if op.opcode == "Column" && op.p1 == tableCursor && op.p2 == payloadColumn {
			if payloadAddr >= 0 {
				return fmt.Errorf("page bytecode reads payload more than once")
			}
			payloadAddr = op.addr
		}
		if op.opcode == "ResultRow" {
			resultAddr = op.addr
		}
	}
	if payloadAddr < 0 || resultAddr <= payloadAddr {
		return fmt.Errorf("page bytecode lacks the events.payload_json fetch/result (payload=%d result=%d)", payloadAddr, resultAddr)
	}
	var skipsPurge, skipsOffset bool
	for _, op := range ops {
		if op.addr >= payloadAddr || op.p2 <= payloadAddr {
			continue
		}
		if op.opcode == "IfPos" {
			skipsOffset = true
		}
		if op.opcode == "If" || op.opcode == "IfNot" {
			skipsPurge = true
		}
	}
	if !skipsPurge || !skipsOffset {
		return fmt.Errorf("payload read at bytecode %d is not guarded by both purge and OFFSET branches (purge=%t offset=%t)", payloadAddr, skipsPurge, skipsOffset)
	}
	return nil
}
