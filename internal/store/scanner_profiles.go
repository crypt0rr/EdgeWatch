package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/google/uuid"
)

const (
	BuiltinNmapProfileID  = "00000000-0000-0000-0000-000000000013"
	BuiltinNaabuProfileID = "00000000-0000-0000-0000-000000000014"
)

// errBuiltinScannerProfileImmutable rejects edits and lifecycle changes to a
// built-in profile. It is a caller error, not a storage failure.
var errBuiltinScannerProfileImmutable = NewValidationError(errors.New("built-in scanner profiles are immutable"))

// ErrScannerProfileNameInUse rejects a custom profile named like a built-in
// profile. Schema 52 makes custom profile names unique per tenant and gives
// the built-ins a namespace of their own, so the unique index no longer
// rejects that name; the store keeps it reserved, as the global unique name
// did before.
var ErrScannerProfileNameInUse = errors.New("scanner profile name is already in use")

// requireCustomScannerProfileNameTx fails when name, compared without case,
// is the name of a built-in profile. The built-ins belong to no tenant, so
// their names are reserved in every tenant.
func requireCustomScannerProfileNameTx(ctx context.Context, tx *sql.Tx, name string) error {
	var builtins int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scanner_profiles WHERE tenant_id IS NULL AND built_in=1 AND name=?`, name).Scan(&builtins); err != nil {
		return err
	}
	if builtins > 0 {
		return ErrScannerProfileNameInUse
	}
	return nil
}

// ScannerProfileRecord is the durable, revisioned profile exposed to the
// authenticated console. Definition is the complete effective, validated
// profile; arguments are never written to audit records.
type ScannerProfileRecord struct {
	ID          string
	Name        string
	Description string
	Definition  config.ScannerProfile
	BuiltIn     bool
	Archived    bool
	Revision    int64
	CreatedBy   string
	UpdatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ScannerProfileRevision struct {
	ProfileID  string
	Revision   int64
	Definition config.ScannerProfile
	CreatedBy  string
	CreatedAt  time.Time
}

// InvalidScannerProfile describes a stored profile that could not be decoded
// or validated. List operations report these rows separately so one malformed
// definition cannot hide otherwise usable profiles from the console.
type InvalidScannerProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Archived bool   `json:"archived"`
	Error    string `json:"error"`
}

// ScannerProfileList is the result of a profile inventory read. Profiles that
// fail definition decoding are omitted from Profiles and surfaced in Invalid.
// The invalid metadata is deliberately bounded to row identity and a safe
// validation error; raw argument templates are never returned.
type ScannerProfileList struct {
	Profiles []ScannerProfileRecord
	Invalid  []InvalidScannerProfile
}

func ensureBuiltinScannerProfiles(db *sql.DB) error {
	return ensureBuiltinScannerProfilesContext(context.Background(), db)
}

func ensureBuiltinScannerProfilesContext(ctx context.Context, db *sql.DB) error {
	definitions := []struct {
		id, name string
		value    config.ScannerProfile
	}{
		{BuiltinNmapProfileID, "Nmap standard", config.BuiltinNmapProfile()},
		{BuiltinNaabuProfileID, "Naabu full TCP → Nmap", config.BuiltinNaabuProfile()},
	}
	// The seeding reads each built-in profile before it writes it, so it
	// takes the write lock first.
	tx, err := beginWriteTx(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, builtin := range definitions {
		raw, err := marshalProfileDefinition(builtin.value)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		// Every statement names the built-in rows, whose tenant_id is NULL,
		// so the seeding never reads or writes a tenant's profile.
		var currentRaw []byte
		var currentRevision int
		rowErr := tx.QueryRowContext(ctx, `SELECT definition_json,revision FROM scanner_profiles WHERE id=? AND tenant_id IS NULL`, builtin.id).Scan(&currentRaw, &currentRevision)
		if errors.Is(rowErr, sql.ErrNoRows) {
			var taken int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scanner_profiles WHERE id=? AND tenant_id IS NOT NULL`, builtin.id).Scan(&taken); err != nil {
				return err
			}
			if taken != 0 {
				return fmt.Errorf("scanner profile %s conflicts with the built-in profile", builtin.id)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profiles(id,tenant_id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at) VALUES(?,NULL,?,?,?,1,0,1,'system','system',?,?)`, builtin.id, builtin.name, builtin.value.Description, raw, now, now); err != nil {
				return err
			}
			if err := insertBuiltinProfileRevisionTx(ctx, tx, builtin.id, 1, raw, now); err != nil {
				return err
			}
			continue
		}
		if rowErr != nil {
			return rowErr
		}
		if currentRevision < 1 {
			currentRevision = 1
		}

		// Keep the revision table and the current row consistent even if an
		// older startup was interrupted between the two seed writes. A profile
		// change is always represented by a new immutable revision; existing
		// jobs continue to use the revision they already pinned.
		var revisionRaw []byte
		revisionErr := tx.QueryRowContext(ctx, `SELECT r.definition_json FROM scanner_profile_revisions AS r JOIN scanner_profiles AS p ON p.id=r.profile_id AND p.tenant_id IS NULL WHERE r.profile_id=? AND r.revision=?`, builtin.id, currentRevision).Scan(&revisionRaw)
		currentMatches := string(currentRaw) == string(raw)
		revisionMatches := revisionErr == nil && string(revisionRaw) == string(raw)
		if revisionErr != nil && !errors.Is(revisionErr, sql.ErrNoRows) {
			return revisionErr
		}
		if currentMatches && revisionMatches {
			continue
		}
		if currentMatches && errors.Is(revisionErr, sql.ErrNoRows) {
			// Repair a missing current revision without changing the profile's
			// revision number. This is safe because no immutable history exists
			// for that number yet.
			if err := insertBuiltinProfileRevisionTx(ctx, tx, builtin.id, currentRevision, raw, now); err != nil {
				return err
			}
			continue
		}

		nextRevision := currentRevision + 1
		if err := insertBuiltinProfileRevisionTx(ctx, tx, builtin.id, nextRevision, raw, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET name=?,description=?,definition_json=?,revision=?,updated_by='system',updated_at=? WHERE id=? AND tenant_id IS NULL AND revision=?`, builtin.name, builtin.value.Description, raw, nextRevision, now, builtin.id, currentRevision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// insertBuiltinProfileRevisionTx records a revision of a built-in profile.
// The revision is inserted from the built-in row, whose tenant_id is NULL,
// so it can never be attached to a tenant's profile.
func insertBuiltinProfileRevisionTx(ctx context.Context, tx *sql.Tx, id string, revision int, raw []byte, now string) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) SELECT id,?,?,'system',? FROM scanner_profiles WHERE id=? AND tenant_id IS NULL`, revision, raw, now, id)
	if err != nil {
		return err
	}
	if inserted, err := result.RowsAffected(); err != nil || inserted != 1 {
		if err == nil {
			err = fmt.Errorf("%w: built-in scanner profile %s", ErrNotFound, id)
		}
		return err
	}
	return nil
}

// validateScannerProfileRecord returns only ValidationError values, so a
// rejected name or definition stays distinguishable from a storage failure.
func validateScannerProfileRecord(name string, definition config.ScannerProfile) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return NewValidationError(config.NewFieldValidationError("name", errors.New("scanner profile name must be 1..100 characters")))
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return NewValidationError(config.NewFieldValidationError("name", errors.New("scanner profile name contains invalid characters")))
	}
	definition = config.NormalizeScannerProfile(definition)
	return NewValidationError(config.ValidateNewScannerProfile(definition))
}

func marshalProfileDefinition(definition config.ScannerProfile) ([]byte, error) {
	definition = config.NormalizeScannerProfile(definition)
	return json.Marshal(definition)
}

func decodeProfileDefinition(raw []byte) (config.ScannerProfile, error) {
	var definition config.ScannerProfile
	if err := json.Unmarshal(raw, &definition); err != nil {
		return definition, err
	}
	definition = config.NormalizeScannerProfile(definition)
	if err := config.ValidateScannerProfile(definition); err != nil {
		return definition, err
	}
	return definition, nil
}

func scanProfileRow(scanner interface{ Scan(...any) error }) (ScannerProfileRecord, error) {
	var record ScannerProfileRecord
	var raw []byte
	var created, updated string
	var builtIn, archived int
	if err := scanner.Scan(&record.ID, &record.Name, &record.Description, &raw, &builtIn, &archived, &record.Revision, &record.CreatedBy, &record.UpdatedBy, &created, &updated); err != nil {
		return record, err
	}
	definition, err := decodeProfileDefinition(raw)
	if err != nil {
		return record, err
	}
	record.Definition = definition
	record.BuiltIn, record.Archived = builtIn != 0, archived != 0
	record.CreatedAt, record.UpdatedAt = profileTime(created), profileTime(updated)
	return record, nil
}

func profileTime(raw string) time.Time {
	if value, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return value
	}
	return scanTime(raw)
}

// ListScannerProfiles returns the valid profiles the tenant can use: the
// built-in profiles and the tenant's own. Archived profiles are left out
// unless includeArchived is set.
func (ts *TenantStore) ListScannerProfiles(ctx context.Context, includeArchived bool) ([]ScannerProfileRecord, error) {
	result, err := ts.ListScannerProfilesReport(ctx, includeArchived)
	if err != nil {
		return nil, err
	}
	return result.Profiles, nil
}

// ListScannerProfilesReport reads the requested profiles that the tenant can
// use, the built-in profiles and the tenant's own, while isolating a
// malformed definition to that row. Another tenant's profiles are not read,
// so they appear in neither list. SQL/read failures still abort the call;
// only decode or semantic validation errors are represented in Invalid.
func (ts *TenantStore) ListScannerProfilesReport(ctx context.Context, includeArchived bool) (ScannerProfileList, error) {
	var result ScannerProfileList
	if err := ts.ready(); err != nil {
		return result, err
	}
	query := `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles WHERE (tenant_id IS NULL OR tenant_id=?)`
	if !includeArchived {
		query += ` AND archived=0`
	}
	query += ` ORDER BY built_in DESC,name`
	rows, err := ts.store.reader().QueryContext(ctx, query, ts.scope.id)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		profile, err := scanProfileRow(rows)
		if err != nil {
			// scanProfileRow fills the identity fields before decoding the
			// definition. A blank identity means the row itself could not be
			// read and must remain a hard error; otherwise isolate bad JSON or
			// validation data to this profile.
			if profile.ID == "" {
				return result, err
			}
			result.Invalid = append(result.Invalid, InvalidScannerProfile{ID: profile.ID, Name: profile.Name, Archived: profile.Archived, Error: safeProfileError(err)})
			continue
		}
		result.Profiles = append(result.Profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func safeProfileError(err error) string {
	if err == nil {
		return "invalid scanner profile definition"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "invalid scanner profile definition"
	}
	// Keep a corrupt row from turning into an unbounded API response if a
	// future decoder includes user-controlled data in an error string.
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}

// GetScannerProfile returns a built-in profile or one of the tenant's own.
// Another tenant's profile is ErrNotFound, exactly as an unknown ID, so a
// job cannot select it either.
func (ts *TenantStore) GetScannerProfile(ctx context.Context, id string) (ScannerProfileRecord, error) {
	if err := ts.ready(); err != nil {
		return ScannerProfileRecord{}, err
	}
	row := ts.store.reader().QueryRowContext(ctx, `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)`, strings.TrimSpace(id), ts.scope.id)
	profile, err := scanProfileRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRecord{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	}
	return profile, err
}

// CurrentScannerProfileRevisions returns the latest revision number for the
// built-in profiles and the tenant's own without decoding their argument
// templates. Job-list consumers use it to flag pinned profiles that have a
// newer revision with one bounded read.
func (ts *TenantStore) CurrentScannerProfileRevisions(ctx context.Context) (map[string]int64, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT id,revision FROM scanner_profiles WHERE tenant_id IS NULL OR tenant_id=?`, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id string
		var revision int64
		if err := rows.Scan(&id, &revision); err != nil {
			return nil, err
		}
		out[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetScannerProfileRevision returns an immutable historical definition of a
// built-in profile or one of the tenant's own. Jobs pin a profile revision,
// so updating or archiving the current profile must not make an otherwise
// valid job impossible to edit or run. The current profile row is checked
// first so a revision from an unrelated/deleted ID, or another tenant's
// profile, is never exposed as a valid selection.
func (ts *TenantStore) GetScannerProfileRevision(ctx context.Context, id string, revision int64) (ScannerProfileRevision, error) {
	if err := ts.ready(); err != nil {
		return ScannerProfileRevision{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" || revision < 1 {
		return ScannerProfileRevision{}, fmt.Errorf("%w: scanner profile revision", ErrNotFound)
	}
	readDB := ts.store.reader()
	var exists int
	if err := readDB.QueryRowContext(ctx, `SELECT 1 FROM scanner_profiles WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)`, id, ts.scope.id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRevision{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return ScannerProfileRevision{}, err
	}
	var result ScannerProfileRevision
	var raw, created string
	err := readDB.QueryRowContext(ctx, `SELECT r.profile_id,r.revision,r.definition_json,r.created_by,r.created_at FROM scanner_profile_revisions AS r JOIN scanner_profiles AS p ON p.id=r.profile_id AND (p.tenant_id IS NULL OR p.tenant_id=?) WHERE r.profile_id=? AND r.revision=?`, ts.scope.id, id, revision).Scan(&result.ProfileID, &result.Revision, &raw, &result.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRevision{}, fmt.Errorf("%w: scanner profile %s revision %d", ErrNotFound, id, revision)
	}
	if err != nil {
		return ScannerProfileRevision{}, err
	}
	definition, err := decodeProfileDefinition([]byte(raw))
	if err != nil {
		return ScannerProfileRevision{}, err
	}
	result.Definition = definition
	result.CreatedAt = profileTime(created)
	return result, nil
}

// ListScannerProfileRevisions returns the revisions of a built-in profile or
// one of the tenant's own, newest first. Another tenant's profile is
// ErrNotFound.
func (ts *TenantStore) ListScannerProfileRevisions(ctx context.Context, id string) ([]ScannerProfileRevision, error) {
	if _, err := ts.GetScannerProfile(ctx, id); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT r.profile_id,r.revision,r.definition_json,r.created_by,r.created_at FROM scanner_profile_revisions AS r JOIN scanner_profiles AS p ON p.id=r.profile_id AND (p.tenant_id IS NULL OR p.tenant_id=?) WHERE r.profile_id=? ORDER BY r.revision DESC`, ts.scope.id, strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var revisions []ScannerProfileRevision
	for rows.Next() {
		var revision ScannerProfileRevision
		var raw, created string
		if err := rows.Scan(&revision.ProfileID, &revision.Revision, &raw, &revision.CreatedBy, &created); err != nil {
			return nil, err
		}
		definition, err := decodeProfileDefinition([]byte(raw))
		if err != nil {
			// Historical rows are immutable audit data. A malformed revision
			// must not make the whole profile history (or its API page) appear
			// missing; current profile reads still validate the active definition.
			// Omit only this unusable revision and continue returning the rows
			// that can be safely rendered.
			continue
		}
		revision.Definition = definition
		revision.CreatedAt = profileTime(created)
		revisions = append(revisions, revision)
	}
	return revisions, rows.Err()
}

// CreateScannerProfile creates a custom profile in the tenant. Its name must
// be unique in the tenant, compared without case, and must not be the name of
// a built-in profile; another tenant's profile may have the same name.
func (ts *TenantStore) CreateScannerProfile(ctx context.Context, name, description string, definition config.ScannerProfile, actor string, audits ...AuditEntry) (ScannerProfileRecord, error) {
	if err := ts.ready(); err != nil {
		return ScannerProfileRecord{}, err
	}
	name = strings.TrimSpace(name)
	definition = config.NormalizeScannerProfile(definition)
	if err := validateScannerProfileRecord(name, definition); err != nil {
		return ScannerProfileRecord{}, err
	}
	raw, err := marshalProfileDefinition(definition)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	defer tx.Rollback()
	if err := requireCustomScannerProfileNameTx(ctx, tx, name); err != nil {
		return ScannerProfileRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profiles(id,tenant_id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?, ?,0,0,1,?,?,?,?)`, id, ts.scope.id, name, strings.TrimSpace(description), raw, actor, actor, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return ScannerProfileRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) SELECT id,1,?,?,? FROM scanner_profiles WHERE id=? AND tenant_id=?`, raw, actor, now.Format(time.RFC3339Nano), id, ts.scope.id); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ScannerProfileRecord{}, err
	}
	return ScannerProfileRecord{ID: id, Name: name, Description: strings.TrimSpace(description), Definition: definition, Revision: 1, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now}, nil
}

// UpdateScannerProfile writes a new revision of one of the tenant's custom
// profiles. Another tenant's profile is ErrNotFound, exactly as an unknown
// ID, and a built-in profile stays immutable.
func (ts *TenantStore) UpdateScannerProfile(ctx context.Context, id string, expectedRevision int64, name, description string, definition config.ScannerProfile, actor string, audits ...AuditEntry) (ScannerProfileRecord, error) {
	if err := ts.ready(); err != nil {
		return ScannerProfileRecord{}, err
	}
	name = strings.TrimSpace(name)
	definition = config.NormalizeScannerProfile(definition)
	if err := validateScannerProfileRecord(name, definition); err != nil {
		return ScannerProfileRecord{}, err
	}
	raw, err := marshalProfileDefinition(definition)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	defer tx.Rollback()
	var current ScannerProfileRecord
	var currentRaw, created, updated string
	var builtIn, archived int
	if err := tx.QueryRowContext(ctx, `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)`, id, ts.scope.id).Scan(&current.ID, &current.Name, &current.Description, &currentRaw, &builtIn, &archived, &current.Revision, &current.CreatedBy, &current.UpdatedBy, &created, &updated); errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRecord{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return ScannerProfileRecord{}, err
	}
	if current.Revision != expectedRevision {
		return ScannerProfileRecord{}, ErrConflict
	}
	if builtIn != 0 {
		return ScannerProfileRecord{}, errBuiltinScannerProfileImmutable
	}
	if err := requireCustomScannerProfileNameTx(ctx, tx, name); err != nil {
		return ScannerProfileRecord{}, err
	}
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET name=?,description=?,definition_json=?,revision=?,updated_by=?,updated_at=? WHERE id=? AND tenant_id=? AND revision=?`, name, strings.TrimSpace(description), raw, next, actor, now.Format(time.RFC3339Nano), id, ts.scope.id, expectedRevision)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ScannerProfileRecord{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) SELECT id,?,?,?,? FROM scanner_profiles WHERE id=? AND tenant_id=?`, next, raw, actor, now.Format(time.RFC3339Nano), id, ts.scope.id); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ScannerProfileRecord{}, err
	}
	return ScannerProfileRecord{ID: id, Name: name, Description: strings.TrimSpace(description), Definition: definition, Revision: next, CreatedBy: current.CreatedBy, UpdatedBy: actor, CreatedAt: profileTime(created), UpdatedAt: now, Archived: archived != 0}, nil
}

// SetScannerProfileArchived archives or restores one of the tenant's custom
// profiles. Another tenant's profile is ErrNotFound, exactly as an unknown
// ID, and a built-in profile stays immutable.
func (ts *TenantStore) SetScannerProfileArchived(ctx context.Context, id string, archived bool, expectedRevision int64, actor string, audits ...AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	now := time.Now().UTC()
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var builtIn, currentArchived int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT built_in,archived,revision FROM scanner_profiles WHERE id=? AND (tenant_id IS NULL OR tenant_id=?)`, id, ts.scope.id).Scan(&builtIn, &currentArchived, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	if builtIn != 0 {
		return errBuiltinScannerProfileImmutable
	}
	if currentRevision != expectedRevision {
		return ErrConflict
	}
	if currentArchived == boolInt(archived) {
		if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	next := currentRevision + 1
	if _, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET archived=?,revision=?,updated_by=?,updated_at=? WHERE id=? AND tenant_id=? AND revision=?`, boolInt(archived), next, actor, now.Format(time.RFC3339Nano), id, ts.scope.id, expectedRevision); err != nil {
		return err
	}
	// The new revision keeps the current definition; only the lifecycle
	// changed.
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) SELECT id,?,definition_json,?,? FROM scanner_profiles WHERE id=? AND tenant_id=?`, next, actor, now.Format(time.RFC3339Nano), id, ts.scope.id); err != nil {
		return err
	}
	if err := ts.insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
}
