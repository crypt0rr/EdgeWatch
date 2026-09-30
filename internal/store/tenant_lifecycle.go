package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// The lifecycle of a tenant, which the console calls a business unit. A
// platform administrator, or the host CLI, creates a tenant, renames it,
// disables it, enables it again, and deletes it. Every change is recorded in
// the platform audit: a security_audit row without a tenant. The AuditEntry
// that each method takes names the actor, a platform administrator's
// account or the host CLI, and the request; the method sets the action and
// the detail itself.
//
//   - Disabling pauses the tenant. Its accounts can no longer sign in, their
//     sessions end and their outstanding invitations are revoked in the same
//     transaction, and the daemon neither schedules its jobs nor delivers its
//     alerts; the undelivered alerts are held until it is enabled again.
//     Retention keeps running.
//   - Only a disabled tenant can be deleted, and never the default tenant.
//     The request archives and pauses the tenant's jobs and discards its scan
//     cycles that were not promoted to a scan. The daemon then erases the
//     tenant's rows (see tenant_purge.go) and leaves the tenant row behind as
//     a tombstone in the deleted state.

// Errors of the tenant lifecycle.
var (
	// ErrTenantNameInUse reports that a tenant that is not deleted already
	// has the name, compared without regard to case.
	ErrTenantNameInUse = errors.New("another business unit already uses this name")
	// ErrTenantSlugInUse reports that a tenant that is not deleted already
	// has the slug.
	ErrTenantSlugInUse = errors.New("another business unit already uses this slug")
	// ErrTenantStateChange reports that the tenant's state does not allow the
	// change: only an active tenant can be disabled, only a disabled one
	// enabled or deleted, and a tenant that is being deleted, or has been,
	// cannot be renamed.
	ErrTenantStateChange = errors.New("the business unit's state does not allow this change")
	// ErrDefaultTenantDeletion reports an attempt to delete the default
	// tenant, which cannot be deleted.
	ErrDefaultTenantDeletion = errors.New("the default business unit cannot be deleted")
	// ErrTenantNameMismatch reports that the name typed to confirm a deletion
	// is not exactly the tenant's name.
	ErrTenantNameMismatch = errors.New("the typed name does not match the business unit's name")
)

// Tenant lifecycle audit actions. They are recorded in the platform audit.
const (
	auditTenantCreated           = "tenant.created"
	auditTenantRenamed           = "tenant.renamed"
	auditTenantDisabled          = "tenant.disabled"
	auditTenantEnabled           = "tenant.enabled"
	auditTenantDeletionRequested = "tenant.deletion_requested"
	auditTenantPurged            = "tenant.purged"
)

// tenantNameMaxLength bounds a tenant name, in characters.
const tenantNameMaxLength = 80

// tenantSlugPattern is the form of a tenant slug, which names the tenant's
// public status page in a URL.
var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9-]{2,40}$`)

// reservedTenantSlugs cannot be a tenant's slug. A slug is a path segment of
// the tenant's public status page, so the words that name the console's own
// paths, now or later, are kept free.
var reservedTenantSlugs = map[string]bool{
	"admin": true, "api": true, "app": true, "assets": true, "auth": true,
	"events": true, "health": true, "healthz": true, "login": true, "logout": true,
	"platform": true, "public": true, "setup": true, "static": true, "status": true,
	"stream": true, "v1": true,
}

// TenantRecord is a tenant as the platform manages it, with counts of its
// accounts, jobs and stored scans. The platform sees counts only, never the
// tenant's accounts, jobs or results themselves.
type TenantRecord struct {
	Tenant
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StateChangedAt time.Time
	// StateChangedBy is the account ID of the platform administrator who
	// last changed the state, or the actor kind, such as host, when no
	// account did.
	StateChangedBy string
	// PurgePhase and PurgeRows report the progress of the purge of a tenant
	// that is being deleted: the table it is erasing, and how many rows it
	// has erased so far.
	PurgePhase string
	PurgeRows  int64
	// Accounts counts every account of the tenant, Administrators its
	// enabled administrators, and Jobs its jobs that are not archived.
	Accounts       int
	Administrators int
	Jobs           int
	// StoredScans counts the scans the tenant's history holds, whatever
	// their status, including the scans of archived jobs. Retention, and
	// the purge of a tenant being deleted, lower it as they erase scans.
	StoredScans int64
}

// ValidateTenantName returns the trimmed name, or a validation error when it
// is empty, longer than tenantNameMaxLength characters, or holds a control
// character.
func ValidateTenantName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", NewValidationError(errors.New("name is required"))
	case !utf8.ValidString(name):
		return "", NewValidationError(errors.New("name must be valid UTF-8"))
	case utf8.RuneCountInString(name) > tenantNameMaxLength:
		return "", NewValidationError(fmt.Errorf("name must be at most %d characters", tenantNameMaxLength))
	case strings.ContainsFunc(name, unicode.IsControl):
		return "", NewValidationError(errors.New("name must not contain control characters"))
	}
	return name, nil
}

// ValidateTenantSlug returns the slug when it is 2 to 40 lowercase letters,
// digits and hyphens and not reserved, or a validation error.
func ValidateTenantSlug(slug string) (string, error) {
	slug = strings.TrimSpace(slug)
	if !tenantSlugPattern.MatchString(slug) {
		return "", NewValidationError(errors.New("slug must be 2 to 40 lowercase letters, digits, or hyphens"))
	}
	if reservedTenantSlugs[slug] {
		return "", NewValidationError(fmt.Errorf("slug %q is reserved", slug))
	}
	return slug, nil
}

// tenantRecordColumns are the columns scanTenantRecord reads, from tenants
// AS t.
const tenantRecordColumns = `t.id,t.name,t.slug,t.state,t.is_default,t.revision,t.created_at,t.updated_at,t.state_changed_at,t.state_changed_by,t.purge_phase,t.purge_rows,` +
	`(SELECT COUNT(*) FROM users AS u WHERE u.tenant_id=t.id),` +
	`(SELECT COUNT(*) FROM users AS u WHERE u.tenant_id=t.id AND u.role='` + RoleAdministrator + `' AND u.enabled=1),` +
	`(SELECT COUNT(*) FROM jobs AS j WHERE j.tenant_id=t.id AND j.archived=0),` +
	`(SELECT COUNT(*) FROM scans AS s WHERE s.tenant_id=t.id)`

func scanTenantRecord(row interface{ Scan(...any) error }) (TenantRecord, error) {
	var record TenantRecord
	var isDefault int
	var created, updated, changed string
	if err := row.Scan(&record.ID, &record.Name, &record.Slug, &record.State, &isDefault, &record.Revision, &created, &updated, &changed, &record.StateChangedBy, &record.PurgePhase, &record.PurgeRows, &record.Accounts, &record.Administrators, &record.Jobs, &record.StoredScans); err != nil {
		return TenantRecord{}, err
	}
	record.IsDefault = isDefault != 0
	record.CreatedAt, record.UpdatedAt, record.StateChangedAt = scanTime(created), scanTime(updated), scanTime(changed)
	return record, nil
}

// ListTenants returns every tenant that has not been deleted, the default
// tenant first and the others by name, with their counts.
func (ps *PlatformStore) ListTenants(ctx context.Context) ([]TenantRecord, error) {
	rows, err := ps.store.reader().QueryContext(ctx, `SELECT `+tenantRecordColumns+` FROM tenants AS t WHERE t.state<>? ORDER BY t.is_default DESC, t.name, t.id`, TenantStateDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []TenantRecord
	for rows.Next() {
		record, err := scanTenantRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// GetTenant returns the tenant with its counts, including the tombstone of a
// deleted tenant. An unknown ID is ErrNotFound.
func (ps *PlatformStore) GetTenant(ctx context.Context, id string) (TenantRecord, error) {
	return getTenantRecord(ctx, ps.store.reader(), id)
}

func getTenantRecord(ctx context.Context, queryer rowQueryer, id string) (TenantRecord, error) {
	record, err := scanTenantRecord(queryer.QueryRowContext(ctx, `SELECT `+tenantRecordColumns+` FROM tenants AS t WHERE t.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return TenantRecord{}, fmt.Errorf("%w: tenant %s", ErrNotFound, id)
	}
	return record, err
}

// CreateTenant creates an active tenant with the name and slug, and with
// InitialTenantCapacity: it inherits the deployment's slots and probe
// budgets, and high-cost work stays off until a platform administrator
// grants a ceiling. Its update routing, stored in the same row, is
// configured and selects nothing, so it gets no update alerts until its
// administrators select destinations. The name and the slug must be unique
// among the tenants that are not deleted.
func (ps *PlatformStore) CreateTenant(ctx context.Context, name, slug string, audit AuditEntry) (TenantRecord, error) {
	name, err := ValidateTenantName(name)
	if err != nil {
		return TenantRecord{}, err
	}
	if slug, err = ValidateTenantSlug(slug); err != nil {
		return TenantRecord{}, err
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return TenantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tenantNameAndSlugFreeTx(ctx, tx, "", "", name, slug); err != nil {
		return TenantRecord{}, err
	}
	now := time.Now().UTC()
	stamp := sqliteTimestamp(now)
	id := uuid.NewString()
	capacity := InitialTenantCapacity()
	ceiling, granted := capacity.highCostColumns()
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants(id,name,slug,state,is_default,update_destinations_json,revision,created_at,updated_at,state_changed_at,state_changed_by,`+tenantCapacityColumns+`) VALUES(?,?,?,?,0,?,1,?,?,?,?,?,?,?,?,?)`, id, name, slug, TenantStateActive, noUpdateDestinations, stamp, stamp, stamp, tenantStateActor(audit),
		nullableInt(capacity.MaxConcurrentScans), nullableInt64(capacity.MaxProbeCount), nullableInt64(capacity.MaxNaabuProbeCount), ceiling, granted); err != nil {
		return TenantRecord{}, tenantUniqueError(err)
	}
	audit.Action, audit.Detail = auditTenantCreated, fmt.Sprintf("business unit %s created: %s", id, tenantLabel(name, slug))
	if err := insertTenantLifecycleAuditTx(ctx, tx, audit, now); err != nil {
		return TenantRecord{}, err
	}
	return commitTenantRecord(ctx, tx, id)
}

// RenameTenant changes the name and the slug of a tenant that is active or
// disabled, when expectedRevision is still its revision. Changing the slug
// changes the address of the tenant's public status page, so links to the
// old address stop working.
func (ps *PlatformStore) RenameTenant(ctx context.Context, id string, expectedRevision int64, name, slug string, audit AuditEntry) (TenantRecord, error) {
	name, err := ValidateTenantName(name)
	if err != nil {
		return TenantRecord{}, err
	}
	if slug, err = ValidateTenantSlug(slug); err != nil {
		return TenantRecord{}, err
	}
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return TenantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantRecord(ctx, tx, id)
	if err != nil {
		return TenantRecord{}, err
	}
	if err := checkTenantChange(current, expectedRevision, TenantStateActive, TenantStateDisabled); err != nil {
		return TenantRecord{}, err
	}
	if current.Name == name && current.Slug == slug {
		return current, nil
	}
	if err := tenantNameAndSlugFreeTx(ctx, tx, id, current.Name, name, slug); err != nil {
		return TenantRecord{}, err
	}
	now := time.Now().UTC()
	if err := updateTenantTx(ctx, tx, current, `name=?,slug=?`, name, slug); err != nil {
		return TenantRecord{}, tenantUniqueError(err)
	}
	audit.Action, audit.Detail = auditTenantRenamed, fmt.Sprintf("business unit %s renamed from %s to %s", id, tenantLabel(current.Name, current.Slug), tenantLabel(name, slug))
	if err := insertTenantLifecycleAuditTx(ctx, tx, audit, now); err != nil {
		return TenantRecord{}, err
	}
	return commitTenantRecord(ctx, tx, id)
}

// DisableTenant pauses an active tenant, when expectedRevision is still its
// revision. In the same transaction it ends the sessions of the tenant's
// accounts and revokes their outstanding invitations, so nobody of the
// tenant stays signed in or can activate an account. Sign-in, scheduling,
// scan leases, alert delivery and the silence watchdog all skip a tenant
// that is not active; the application also cancels the tenant's running
// scans (App.DisableUnit).
func (ps *PlatformStore) DisableTenant(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) (TenantRecord, error) {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return TenantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantRecord(ctx, tx, id)
	if err != nil {
		return TenantRecord{}, err
	}
	if err := checkTenantChange(current, expectedRevision, TenantStateActive); err != nil {
		return TenantRecord{}, err
	}
	now := time.Now().UTC()
	if err := updateTenantTx(ctx, tx, current, `state=?,state_changed_at=?,state_changed_by=?`, TenantStateDisabled, sqliteTimestamp(now), tenantStateActor(audit)); err != nil {
		return TenantRecord{}, err
	}
	sessions, err := execCount(ctx, tx, `DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant_id=?)`, id)
	if err != nil {
		return TenantRecord{}, err
	}
	invites, err := execCount(ctx, tx, `UPDATE user_invites SET used_at=? WHERE used_at IS NULL AND user_id IN (SELECT id FROM users WHERE tenant_id=?)`, now.Format(time.RFC3339Nano), id)
	if err != nil {
		return TenantRecord{}, err
	}
	audit.Action, audit.Detail = auditTenantDisabled, fmt.Sprintf("business unit %s disabled: %s; %d sessions ended, %d invitations revoked", id, tenantLabel(current.Name, current.Slug), sessions, invites)
	if err := insertTenantLifecycleAuditTx(ctx, tx, audit, now); err != nil {
		return TenantRecord{}, err
	}
	return commitTenantRecord(ctx, tx, id)
}

// EnableTenant makes a disabled tenant active again, when expectedRevision is
// still its revision. Its accounts can sign in, its jobs are scheduled, and
// its held alerts are delivered. The silence reference of each of its jobs
// that is not archived restarts now, as when a job is resumed, so the
// watchdog does not count the pause as silence and alert at once.
func (ps *PlatformStore) EnableTenant(ctx context.Context, id string, expectedRevision int64, audit AuditEntry) (TenantRecord, error) {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return TenantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantRecord(ctx, tx, id)
	if err != nil {
		return TenantRecord{}, err
	}
	if err := checkTenantChange(current, expectedRevision, TenantStateDisabled); err != nil {
		return TenantRecord{}, err
	}
	now := time.Now().UTC()
	if err := updateTenantTx(ctx, tx, current, `state=?,state_changed_at=?,state_changed_by=?`, TenantStateActive, sqliteTimestamp(now), tenantStateActor(audit)); err != nil {
		return TenantRecord{}, err
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO job_silence_state(job_id,eligible_at,updated_at) SELECT id,?1,?1 FROM jobs WHERE tenant_id=?2 AND archived=0 ON CONFLICT(job_id) DO UPDATE SET eligible_at=excluded.eligible_at,next_alert_at='',backoff_level=0,updated_at=excluded.updated_at`, stamp, id); err != nil {
		return TenantRecord{}, err
	}
	audit.Action, audit.Detail = auditTenantEnabled, fmt.Sprintf("business unit %s enabled: %s", id, tenantLabel(current.Name, current.Slug))
	if err := insertTenantLifecycleAuditTx(ctx, tx, audit, now); err != nil {
		return TenantRecord{}, err
	}
	return commitTenantRecord(ctx, tx, id)
}

// RequestTenantDeletion starts the deletion of a disabled tenant that is not
// the default tenant. typedName must be exactly the tenant's name, as the
// operator typed it to confirm. In one transaction the tenant moves to the
// deleting state, which lets it accept no new scans or events; its jobs are
// archived and paused; and its scan cycles that were not promoted to a scan
// are discarded. The daemon's purge (SystemStore.PurgeDeletingTenants) then
// erases the tenant's data.
func (ps *PlatformStore) RequestTenantDeletion(ctx context.Context, id, typedName string, audit AuditEntry) (TenantRecord, error) {
	tx, err := ps.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return TenantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := getTenantRecord(ctx, tx, id)
	if err != nil {
		return TenantRecord{}, err
	}
	if current.IsDefault {
		return TenantRecord{}, ErrDefaultTenantDeletion
	}
	if err := checkTenantChange(current, current.Revision, TenantStateDisabled); err != nil {
		return TenantRecord{}, err
	}
	if typedName != current.Name {
		return TenantRecord{}, NewValidationError(ErrTenantNameMismatch)
	}
	now := time.Now().UTC()
	stamp := sqliteTimestamp(now)
	if err := updateTenantTx(ctx, tx, current, `state=?,state_changed_at=?,state_changed_by=?,purge_phase='',purge_rows=0`, TenantStateDeleting, stamp, tenantStateActor(audit)); err != nil {
		return TenantRecord{}, err
	}
	jobs, err := execCount(ctx, tx, `UPDATE jobs SET archived=1,enabled=0,updated_at=? WHERE tenant_id=? AND (archived=0 OR enabled=1)`, now.Format(time.RFC3339Nano), id)
	if err != nil {
		return TenantRecord{}, err
	}
	cycles, err := execCount(ctx, tx, `UPDATE scan_cycles SET status='discarded',updated_at=?1,finished_at=?1,last_error='discarded because the business unit is being deleted' WHERE job_id IN (SELECT id FROM jobs WHERE tenant_id=?2)
		AND (status IN ('running','paused','stalled') OR (status='completed' AND NOT EXISTS (SELECT 1 FROM scans WHERE scans.cycle_id=scan_cycles.id AND scans.tenant_id=?2 AND scans.cycle_status='completed' AND scans.status IN ('success','incomplete'))))`, stamp, id)
	if err != nil {
		return TenantRecord{}, err
	}
	audit.Action, audit.Detail = auditTenantDeletionRequested, fmt.Sprintf("business unit %s deletion requested: %s; %d jobs archived, %d scan cycles discarded", id, tenantLabel(current.Name, current.Slug), jobs, cycles)
	if err := insertTenantLifecycleAuditTx(ctx, tx, audit, now); err != nil {
		return TenantRecord{}, err
	}
	return commitTenantRecord(ctx, tx, id)
}

// checkTenantChange refuses a change of a tenant whose revision is not
// expectedRevision, with ErrConflict, or whose state is not one of states,
// with ErrTenantStateChange. A deleted tenant is not found.
func checkTenantChange(current TenantRecord, expectedRevision int64, states ...string) error {
	if current.State == TenantStateDeleted {
		return fmt.Errorf("%w: tenant %s", ErrNotFound, current.ID)
	}
	if current.Revision != expectedRevision {
		return ErrConflict
	}
	for _, state := range states {
		if current.State == state {
			return nil
		}
	}
	return fmt.Errorf("%w: it is %s", ErrTenantStateChange, current.State)
}

// updateTenantTx sets the columns of assignments on the tenant, together with
// the next revision and the update time, if its revision is still current's.
func updateTenantTx(ctx context.Context, tx *sql.Tx, current TenantRecord, assignments string, args ...any) error {
	args = append(args, sqliteTimestamp(time.Now()), current.ID, current.Revision)
	updated, err := execCount(ctx, tx, `UPDATE tenants SET `+assignments+`,revision=revision+1,updated_at=? WHERE id=? AND revision=?`, args...)
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrConflict
	}
	return nil
}

// tenantNameAndSlugFreeTx refuses a name or a slug that a tenant other than
// id, and not deleted, already uses. The name is compared without regard to
// case by tenantNameUsedTx; currentName is the tenant's own name, which it
// keeps, or "" for a new tenant.
func tenantNameAndSlugFreeTx(ctx context.Context, tx *sql.Tx, id, currentName, name, slug string) error {
	if name != currentName {
		used, err := tenantNameUsedTx(ctx, tx, id, name)
		if err != nil {
			return err
		}
		if used {
			return NewValidationError(ErrTenantNameInUse)
		}
	}
	var slugUsed int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug=? AND state<>'deleted' AND id<>?)`, slug, id).Scan(&slugUsed); err != nil {
		return err
	}
	if slugUsed != 0 {
		return NewValidationError(ErrTenantSlugInUse)
	}
	return nil
}

// tenantNameUsedTx reports whether a tenant other than id, and not deleted,
// has the name without regard to case. The names are compared with
// strings.EqualFold, which folds the case of every letter, such as Ä and ä,
// letter by letter, so ß and ss stay different. The NOCASE collation of the
// name column, and so the unique index on live names, folds only A-Z; the
// index stays the backstop for a write that the check does not see. The
// store's single writer connection runs the check and the write in one
// transaction, so no write of the daemon races it.
func tenantNameUsedTx(ctx context.Context, tx *sql.Tx, id, name string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM tenants WHERE state<>'deleted' AND id<>?`, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return false, err
		}
		if strings.EqualFold(other, name) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// tenantUniqueError maps a violation of the unique indexes on live tenant
// names and slugs, from a write that raced the check, to its error.
func tenantUniqueError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "constraint failed: tenants.name"):
		return NewValidationError(ErrTenantNameInUse)
	case strings.Contains(message, "constraint failed: tenants.slug"):
		return NewValidationError(ErrTenantSlugInUse)
	}
	return err
}

// commitTenantRecord commits tx after reading the tenant's record in it.
func commitTenantRecord(ctx context.Context, tx *sql.Tx, id string) (TenantRecord, error) {
	record, err := getTenantRecord(ctx, tx, id)
	if err != nil {
		return TenantRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantRecord{}, err
	}
	return record, nil
}

// execCount runs a statement and returns the number of rows it changed.
func execCount(ctx context.Context, execer contextExecer, query string, args ...any) (int64, error) {
	result, err := execer.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// tenantLabel names a tenant in an audit record.
func tenantLabel(name, slug string) string {
	return fmt.Sprintf("%q (%s)", name, slug)
}

// tenantStateActor is who changed a tenant's state, for state_changed_by:
// the acting account, or the actor kind when no account acted.
func tenantStateActor(audit AuditEntry) string {
	if audit.ActorUserID != "" {
		return audit.ActorUserID
	}
	if audit.ActorKind != "" {
		return audit.ActorKind
	}
	return AuditActorHost
}

// insertTenantLifecycleAuditTx records a lifecycle change in the platform
// audit with insertPlatformAuditEntry. Only the platform acts on tenants, so
// the actor is an enabled platform administrator (an ActorUserID, with the
// platform kind or none), the host CLI, or the daemon; an entry that names
// neither an account nor a kind is the host CLI's. Any other actor, such as
// an account of a tenant, is refused with ErrAccountNotPermitted, and the
// caller's transaction then commits nothing.
func insertTenantLifecycleAuditTx(ctx context.Context, tx *sql.Tx, entry AuditEntry, now time.Time) error {
	switch {
	case entry.ActorUserID == "" && (entry.ActorKind == "" || entry.ActorKind == AuditActorHost || entry.ActorKind == AuditActorSystem):
		if entry.ActorKind == "" {
			entry.ActorKind = AuditActorHost
		}
	case entry.ActorUserID != "" && (entry.ActorKind == "" || entry.ActorKind == AuditActorPlatform):
		if err := requirePlatformActorTx(ctx, tx, entry.ActorUserID); err != nil {
			return err
		}
		entry.ActorKind = AuditActorPlatform
	default:
		return fmt.Errorf("%w: only the platform acts on business units, not actor kind %q", ErrAccountNotPermitted, entry.ActorKind)
	}
	return insertPlatformAuditEntry(ctx, tx, entry, now)
}
