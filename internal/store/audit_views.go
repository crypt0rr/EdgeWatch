package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// The audit views read security_audit, newest first, a page at a time:
//
//   - the unit view, TenantStore.AuditPage, shows the records of one tenant,
//     including a platform administrator's actions on the tenant's accounts,
//     which are recorded in the tenant with the platform actor kind;
//   - the platform view, PlatformStore.AuditPage, shows the records in
//     platform scope, which have no tenant, and the account and platform
//     records of every tenant, but never a tenant's data records.
//
// Both order the records by their time and then their ID, the order of the
// security_audit_tenant_time and security_audit_platform_time indexes, and
// page with a keyset: the ID of the last entry of a page names the position
// after which the next page starts. A page reads its records from an index
// in their order and stops one record after the page, so neither view
// counts the records or sorts the table. The stored times are RFC 3339
// without the trailing zeros of the fraction, and the indexes order them as
// text, so within one second a time whose fraction is a prefix of
// another's, such as .5 and .51, sorts after it; the order is still total,
// so the pages neither repeat nor skip a record. Details are returned as
// they were recorded; the writers keep URLs, scan targets, and tokens out
// of them.

// The page size of the audit views.
const (
	// AuditPageDefaultLimit is the number of entries in a page when the
	// caller asks for none.
	AuditPageDefaultLimit = 50
	// AuditPageMaxLimit is the most entries a page holds.
	AuditPageMaxLimit = 200
)

// auditActionPrefixMaxLength bounds the action prefix filter. The longest
// audit action is about half as long.
const auditActionPrefixMaxLength = 64

// auditActionPrefixPattern holds the characters of audit actions. None of
// them is special in a GLOB pattern, so a prefix that matches it is used as
// the start of the pattern as it is.
var auditActionPrefixPattern = regexp.MustCompile(`^[a-z0-9._-]*$`)

// AuditFilter narrows an audit view. A field left empty matches every
// record.
type AuditFilter struct {
	// ActionPrefix matches the records whose action starts with it, such as
	// "user." or "job.created". It may hold only a-z, 0-9, '.', '_' and '-';
	// anything else is a validation error.
	ActionPrefix string
	// Since and Until bound the time of a record: Since is inclusive and
	// Until exclusive. Both are compared at whole seconds, truncated,
	// because the stored times leave out trailing zeros of the fraction.
	Since time.Time
	Until time.Time
	// ActorUserID matches the records of one acting account.
	ActorUserID string
}

// PlatformAuditFilter narrows the platform audit view.
type PlatformAuditFilter struct {
	AuditFilter
	// TenantID limits the view to the account and platform records of one
	// tenant, which may be deleted. The records in platform scope have no
	// tenant, so they are left out too.
	TenantID string
}

// AuditLogEntry is one audit record as an audit view shows it.
type AuditLogEntry struct {
	ID        int64
	CreatedAt time.Time
	Action    string
	// Category is account, platform, or data; see auditCategory.
	Category string
	// ActorKind is AuditActorUnit, AuditActorHost, AuditActorSystem, or
	// AuditActorPlatform, and empty for a record written before schema 51.
	ActorKind     string
	ActorUserID   string
	ActorUsername string
	// ActorDisplayName is the current display name of the acting account,
	// when the account still exists and the view may show it: the unit view
	// shows only the display names of the tenant's own accounts, so it
	// leaves it empty for a platform administrator.
	ActorDisplayName string
	Detail           string
	RequestID        string
	// SourceIP is the client address of the request. The unit view leaves
	// it empty for a platform administrator's action; the platform view
	// shows it.
	SourceIP string
	// TenantID is the tenant the record belongs to, or empty for a record
	// in platform scope.
	TenantID string
}

// AuditLogPage is one page of an audit view, newest first.
type AuditLogPage struct {
	Entries []AuditLogEntry
	// NextBefore is the before argument that reads the next page, or 0 when
	// no older record matches.
	NextBefore int64
}

// auditPlatformCategoriesSQL selects the account and platform records. It is
// the WHERE clause of the security_audit_platform_time partial index,
// spelled the same way, so SQLite can use that index for it.
const auditPlatformCategoriesSQL = `a.category IN ('` + auditCategoryAccount + `','` + auditCategoryPlatform + `')`

// auditPageOrderSQL orders the records newest first, as the indexes do.
const auditPageOrderSQL = ` ORDER BY a.created_at DESC,a.id DESC LIMIT ?`

// auditRecordColumnsSQL are the audit columns of an entry, apart from the
// source address and the actor's display name.
const auditRecordColumnsSQL = `a.id,a.created_at,a.action,a.category,a.actor_kind,a.actor_user_id,a.actor_username,a.detail,a.request_id,COALESCE(a.tenant_id,'')`

// AuditPage returns a page of the tenant's audit records, newest first: its
// own accounts' and data records, and a platform administrator's actions on
// its accounts, but never another tenant's records or those in platform
// scope. before is 0 for the first page, or the NextBefore of the previous
// page; an ID that names no record of the tenant is ErrNotFound. limit is
// AuditPageDefaultLimit when it is not positive, and at most
// AuditPageMaxLimit. An invalid filter is a validation error.
func (ts *TenantStore) AuditPage(ctx context.Context, filter AuditFilter, before int64, limit int) (AuditLogPage, error) {
	if err := ts.ready(); err != nil {
		return AuditLogPage{}, err
	}
	limit = auditPageLimit(limit)
	query, args, err := ts.auditPageQuery(ctx, filter, before, limit)
	if err != nil {
		return AuditLogPage{}, err
	}
	return readAuditPage(ctx, ts.store.reader(), query, args, limit)
}

// auditPageQuery builds the statement and arguments of a unit view page.
// The tenant predicate selects the records, and the display name comes only
// from an account of the same tenant. The source address of a platform
// administrator's action stays in the database.
func (ts *TenantStore) auditPageQuery(ctx context.Context, filter AuditFilter, before int64, limit int) (string, []any, error) {
	filterSQL, args, err := auditFilterSQL(filter)
	if err != nil {
		return "", nil, err
	}
	cursorSQL, cursorArgs, err := auditCursor(before, func(id int64) *sql.Row {
		return ts.store.reader().QueryRowContext(ctx, `SELECT created_at FROM security_audit WHERE id=? AND tenant_id=?`, id, ts.scope.id)
	})
	if err != nil {
		return "", nil, err
	}
	args = append(append(append([]any{ts.scope.id}, args...), cursorArgs...), limit+1)
	return `SELECT ` + auditRecordColumnsSQL + `,CASE WHEN a.actor_kind='` + AuditActorPlatform + `' THEN '' ELSE a.source_ip END,COALESCE(u.display_name,'') ` +
		`FROM security_audit AS a LEFT JOIN users AS u ON u.id=a.actor_user_id AND u.tenant_id=a.tenant_id ` +
		`WHERE a.tenant_id=?` + filterSQL + cursorSQL + auditPageOrderSQL, args, nil
}

// AuditPage returns a page of the platform's audit records, newest first:
// the records in platform scope, and the account and platform records of
// every tenant, deleted ones included, but never a tenant's data records,
// such as those about jobs, scans, baselines, incidents, notification
// destinations, the public status page, or scanner profiles. It is a read
// across tenants by design, for the platform administrator, who manages
// the tenants' accounts but never sees their data. filter.TenantID limits
// it to one tenant's account and platform records. before and limit work as
// in TenantStore.AuditPage; before must name a record of this view.
func (ps *PlatformStore) AuditPage(ctx context.Context, filter PlatformAuditFilter, before int64, limit int) (AuditLogPage, error) {
	limit = auditPageLimit(limit)
	query, args, err := ps.auditPageQuery(ctx, filter, before, limit)
	if err != nil {
		return AuditLogPage{}, err
	}
	return readAuditPage(ctx, ps.store.reader(), query, args, limit)
}

// auditPageQuery builds the statement and arguments of a platform view
// page. SQLite can serve "no tenant or an account or platform category" from
// an index only by scanning the whole table, so the statement reads the
// records in platform scope from security_audit_tenant_time and the account
// and platform records of the tenants from security_audit_platform_time,
// each newest first and at most one page, and merges the two.
func (ps *PlatformStore) auditPageQuery(ctx context.Context, filter PlatformAuditFilter, before int64, limit int) (string, []any, error) {
	filterSQL, filterArgs, err := auditFilterSQL(filter.AuditFilter)
	if err != nil {
		return "", nil, err
	}
	cursorSQL, cursorArgs, err := auditCursor(before, func(id int64) *sql.Row {
		return ps.store.reader().QueryRowContext(ctx, `SELECT a.created_at FROM security_audit AS a WHERE a.id=? AND (a.tenant_id IS NULL OR `+auditPlatformCategoriesSQL+`)`, id)
	})
	if err != nil {
		return "", nil, err
	}
	branchArgs := append(append([]any(nil), filterArgs...), cursorArgs...)
	if filter.TenantID != "" {
		args := append(append([]any{filter.TenantID}, branchArgs...), limit+1)
		return `SELECT ` + auditRecordColumnsSQL + `,a.source_ip,COALESCE(u.display_name,'') ` +
			`FROM security_audit AS a LEFT JOIN users AS u ON u.id=a.actor_user_id ` +
			`WHERE a.tenant_id=? AND ` + auditPlatformCategoriesSQL + filterSQL + cursorSQL + auditPageOrderSQL, args, nil
	}
	branch := func(scope string) string {
		return `SELECT * FROM (SELECT a.id,a.created_at,a.action,a.category,a.actor_kind,a.actor_user_id,a.actor_username,a.detail,a.request_id,a.tenant_id,a.source_ip ` +
			`FROM security_audit AS a WHERE ` + scope + filterSQL + cursorSQL + auditPageOrderSQL + `)`
	}
	var args []any
	args = append(append(args, branchArgs...), limit+1)
	args = append(append(args, branchArgs...), limit+1)
	args = append(args, limit+1)
	return `SELECT page.id,page.created_at,page.action,page.category,page.actor_kind,page.actor_user_id,page.actor_username,page.detail,page.request_id,COALESCE(page.tenant_id,''),page.source_ip,COALESCE(u.display_name,'') FROM (` +
		branch(`a.tenant_id IS NULL`) + ` UNION ALL ` + branch(auditPlatformCategoriesSQL+` AND a.tenant_id IS NOT NULL`) +
		`) AS page LEFT JOIN users AS u ON u.id=page.actor_user_id ORDER BY page.created_at DESC,page.id DESC LIMIT ?`, args, nil
}

// auditPageLimit returns the page size for the limit a caller asked for.
func auditPageLimit(limit int) int {
	switch {
	case limit <= 0:
		return AuditPageDefaultLimit
	case limit > AuditPageMaxLimit:
		return AuditPageMaxLimit
	}
	return limit
}

// auditFilterSQL returns the conditions of the filter, each starting with
// AND, and their arguments.
func auditFilterSQL(filter AuditFilter) (string, []any, error) {
	var clauses strings.Builder
	var args []any
	if filter.ActionPrefix != "" {
		if len(filter.ActionPrefix) > auditActionPrefixMaxLength || !auditActionPrefixPattern.MatchString(filter.ActionPrefix) {
			return "", nil, NewValidationError(fmt.Errorf("action prefix must be at most %d characters of a-z, 0-9, '.', '_' and '-'", auditActionPrefixMaxLength))
		}
		clauses.WriteString(` AND a.action GLOB ?`)
		args = append(args, filter.ActionPrefix+"*")
	}
	if !filter.Since.IsZero() {
		clauses.WriteString(` AND a.created_at>=?`)
		args = append(args, auditTimeBound(filter.Since))
	}
	if !filter.Until.IsZero() {
		clauses.WriteString(` AND a.created_at<?`)
		args = append(args, auditTimeBound(filter.Until))
	}
	if filter.ActorUserID != "" {
		clauses.WriteString(` AND a.actor_user_id=?`)
		args = append(args, filter.ActorUserID)
	}
	return clauses.String(), args, nil
}

// auditTimeBound formats a time bound for comparison with the stored times,
// which are RFC 3339 with the trailing zeros of the fraction left out. A
// whole second with nine fractional zeros sorts after every stored time of
// the second before it, and before every stored time of its own second that
// has a fraction; a stored time of exactly that second sorts after it, which
// matches it as Since does and leaves it out as Until does. A bound with a
// fraction of its own would not compare correctly with every stored time,
// so the bound is truncated to the second.
func auditTimeBound(value time.Time) string {
	return sqliteTimestamp(value.Truncate(time.Second))
}

// auditCursor returns the condition that starts a page after the record with
// the ID before, and its arguments, or nothing for the first page. lookup
// reads the time of the record with the ID, if the view shows it; a record
// that the view does not show is ErrNotFound, so a cursor never reveals the
// position of another view's record.
func auditCursor(before int64, lookup func(id int64) *sql.Row) (string, []any, error) {
	switch {
	case before < 0:
		return "", nil, NewValidationError(errors.New("before must be the ID of an audit entry"))
	case before == 0:
		return "", nil, nil
	}
	var createdAt string
	if err := lookup(before).Scan(&createdAt); errors.Is(err, sql.ErrNoRows) {
		return "", nil, fmt.Errorf("%w: audit entry %d", ErrNotFound, before)
	} else if err != nil {
		return "", nil, err
	}
	return ` AND (a.created_at,a.id)<(?,?)`, []any{createdAt, before}, nil
}

// readAuditPage runs a page statement, which reads at most limit+1 records,
// and returns the first limit with the cursor of the next page.
func readAuditPage(ctx context.Context, db *sql.DB, query string, args []any, limit int) (AuditLogPage, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return AuditLogPage{}, err
	}
	defer rows.Close()
	var page AuditLogPage
	for rows.Next() {
		var entry AuditLogEntry
		var createdAt string
		if err := rows.Scan(&entry.ID, &createdAt, &entry.Action, &entry.Category, &entry.ActorKind, &entry.ActorUserID, &entry.ActorUsername, &entry.Detail, &entry.RequestID, &entry.TenantID, &entry.SourceIP, &entry.ActorDisplayName); err != nil {
			return AuditLogPage{}, err
		}
		entry.CreatedAt = scanTime(createdAt)
		page.Entries = append(page.Entries, entry)
	}
	if err := rows.Err(); err != nil {
		return AuditLogPage{}, err
	}
	if len(page.Entries) > limit {
		page.Entries = page.Entries[:limit]
		page.NextBefore = page.Entries[limit-1].ID
	}
	return page, nil
}
