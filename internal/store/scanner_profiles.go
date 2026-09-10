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
	ctx := context.Background()
	definitions := []struct {
		id, name string
		value    config.ScannerProfile
	}{
		{BuiltinNmapProfileID, "Nmap standard", config.BuiltinNmapProfile()},
		{BuiltinNaabuProfileID, "Naabu full TCP → Nmap", config.BuiltinNaabuProfile()},
	}
	tx, err := db.BeginTx(ctx, nil)
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
		var currentRaw []byte
		var builtIn, currentRevision int
		rowErr := tx.QueryRowContext(ctx, `SELECT definition_json,built_in,revision FROM scanner_profiles WHERE id=?`, builtin.id).Scan(&currentRaw, &builtIn, &currentRevision)
		if errors.Is(rowErr, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profiles(id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at) VALUES(?,?,?,?,1,0,1,'system','system',?,?)`, builtin.id, builtin.name, builtin.value.Description, raw, now, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?,'system',?)`, builtin.id, 1, raw, now); err != nil {
				return err
			}
			continue
		}
		if rowErr != nil {
			return rowErr
		}
		if builtIn == 0 {
			return fmt.Errorf("scanner profile %s conflicts with the built-in profile", builtin.id)
		}
		if currentRevision < 1 {
			currentRevision = 1
		}

		// Keep the revision table and the current row consistent even if an
		// older startup was interrupted between the two seed writes. A profile
		// change is always represented by a new immutable revision; existing
		// jobs continue to use the revision they already pinned.
		var revisionRaw []byte
		revisionErr := tx.QueryRowContext(ctx, `SELECT definition_json FROM scanner_profile_revisions WHERE profile_id=? AND revision=?`, builtin.id, currentRevision).Scan(&revisionRaw)
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
			if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?,'system',?)`, builtin.id, currentRevision, raw, now); err != nil {
				return err
			}
			continue
		}

		nextRevision := currentRevision + 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?,'system',?)`, builtin.id, nextRevision, raw, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET name=?,description=?,definition_json=?,revision=?,updated_by='system',updated_at=? WHERE id=? AND revision=?`, builtin.name, builtin.value.Description, raw, nextRevision, now, builtin.id, currentRevision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validateScannerProfileRecord(name string, definition config.ScannerProfile) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return errors.New("scanner profile name must be 1..100 characters")
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return errors.New("scanner profile name contains invalid characters")
	}
	definition = config.NormalizeScannerProfile(definition)
	if err := config.ValidateScannerProfile(definition); err != nil {
		return err
	}
	return nil
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

func (s *Store) ListScannerProfiles(ctx context.Context, includeArchived bool) ([]ScannerProfileRecord, error) {
	result, err := s.ListScannerProfilesReport(ctx, includeArchived)
	if err != nil {
		return nil, err
	}
	return result.Profiles, nil
}

// ListScannerProfilesReport reads all requested profiles while isolating a
// malformed definition to that row. SQL/read failures still abort the call;
// only decode or semantic validation errors are represented in Invalid.
func (s *Store) ListScannerProfilesReport(ctx context.Context, includeArchived bool) (ScannerProfileList, error) {
	var result ScannerProfileList
	query := `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles`
	if !includeArchived {
		query += ` WHERE archived=0`
	}
	query += ` ORDER BY built_in DESC,name`
	rows, err := s.DB.QueryContext(ctx, query)
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

func (s *Store) GetScannerProfile(ctx context.Context, id string) (ScannerProfileRecord, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles WHERE id=?`, strings.TrimSpace(id))
	profile, err := scanProfileRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRecord{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	}
	return profile, err
}

// GetScannerProfileRevision returns an immutable historical definition. Jobs
// pin a profile revision, so updating or archiving the current profile must
// not make an otherwise valid job impossible to edit or run. The current
// profile row is checked first so a revision from an unrelated/deleted ID is
// never exposed as a valid selection.
func (s *Store) GetScannerProfileRevision(ctx context.Context, id string, revision int64) (ScannerProfileRevision, error) {
	id = strings.TrimSpace(id)
	if id == "" || revision < 1 {
		return ScannerProfileRevision{}, fmt.Errorf("%w: scanner profile revision", ErrNotFound)
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM scanner_profiles WHERE id=?`, id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRevision{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return ScannerProfileRevision{}, err
	}
	var result ScannerProfileRevision
	var raw, created string
	err := s.DB.QueryRowContext(ctx, `SELECT profile_id,revision,definition_json,created_by,created_at FROM scanner_profile_revisions WHERE profile_id=? AND revision=?`, id, revision).Scan(&result.ProfileID, &result.Revision, &raw, &result.CreatedBy, &created)
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

func (s *Store) ListScannerProfileRevisions(ctx context.Context, id string) ([]ScannerProfileRevision, error) {
	if _, err := s.GetScannerProfile(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT profile_id,revision,definition_json,created_by,created_at FROM scanner_profile_revisions WHERE profile_id=? ORDER BY revision DESC`, strings.TrimSpace(id))
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
			return nil, err
		}
		revision.Definition = definition
		revision.CreatedAt = profileTime(created)
		revisions = append(revisions, revision)
	}
	return revisions, rows.Err()
}

func (s *Store) CreateScannerProfile(ctx context.Context, name, description string, definition config.ScannerProfile, actor string, audits ...AuditEntry) (ScannerProfileRecord, error) {
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profiles(id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at) VALUES(?,?,?, ?,0,0,1,?,?,?,?)`, id, name, strings.TrimSpace(description), raw, actor, actor, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return ScannerProfileRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?, ?,?)`, id, 1, raw, actor, now.Format(time.RFC3339Nano)); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ScannerProfileRecord{}, err
	}
	return ScannerProfileRecord{ID: id, Name: name, Description: strings.TrimSpace(description), Definition: definition, Revision: 1, CreatedBy: actor, UpdatedBy: actor, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) UpdateScannerProfile(ctx context.Context, id string, expectedRevision int64, name, description string, definition config.ScannerProfile, actor string, audits ...AuditEntry) (ScannerProfileRecord, error) {
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	defer tx.Rollback()
	var current ScannerProfileRecord
	var currentRaw, created, updated string
	var builtIn, archived int
	if err := tx.QueryRowContext(ctx, `SELECT id,name,description,definition_json,built_in,archived,revision,created_by,updated_by,created_at,updated_at FROM scanner_profiles WHERE id=?`, id).Scan(&current.ID, &current.Name, &current.Description, &currentRaw, &builtIn, &archived, &current.Revision, &current.CreatedBy, &current.UpdatedBy, &created, &updated); errors.Is(err, sql.ErrNoRows) {
		return ScannerProfileRecord{}, fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return ScannerProfileRecord{}, err
	}
	if current.Revision != expectedRevision {
		return ScannerProfileRecord{}, ErrConflict
	}
	if builtIn != 0 {
		return ScannerProfileRecord{}, errors.New("built-in scanner profiles are immutable")
	}
	next := current.Revision + 1
	result, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET name=?,description=?,definition_json=?,revision=?,updated_by=?,updated_at=? WHERE id=? AND revision=?`, name, strings.TrimSpace(description), raw, next, actor, now.Format(time.RFC3339Nano), id, expectedRevision)
	if err != nil {
		return ScannerProfileRecord{}, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ScannerProfileRecord{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?,?,?)`, id, next, raw, actor, now.Format(time.RFC3339Nano)); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return ScannerProfileRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return ScannerProfileRecord{}, err
	}
	return ScannerProfileRecord{ID: id, Name: name, Description: strings.TrimSpace(description), Definition: definition, Revision: next, CreatedBy: current.CreatedBy, UpdatedBy: actor, CreatedAt: profileTime(created), UpdatedAt: now, Archived: archived != 0}, nil
}

func (s *Store) SetScannerProfileArchived(ctx context.Context, id string, archived bool, expectedRevision int64, actor string, audits ...AuditEntry) error {
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var builtIn, currentArchived int
	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT built_in,archived,revision FROM scanner_profiles WHERE id=?`, id).Scan(&builtIn, &currentArchived, &currentRevision); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: scanner profile %s", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	if builtIn != 0 {
		return errors.New("built-in scanner profiles are immutable")
	}
	if currentRevision != expectedRevision {
		return ErrConflict
	}
	if currentArchived == boolInt(archived) {
		if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	next := currentRevision + 1
	if _, err := tx.ExecContext(ctx, `UPDATE scanner_profiles SET archived=?,revision=?,updated_by=?,updated_at=? WHERE id=? AND revision=?`, boolInt(archived), next, actor, now.Format(time.RFC3339Nano), id, expectedRevision); err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT definition_json FROM scanner_profiles WHERE id=?`, id).Scan(&raw); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scanner_profile_revisions(profile_id,revision,definition_json,created_by,created_at) VALUES(?,?,?,?,?)`, id, next, raw, actor, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err := insertAuditEntries(ctx, tx, audits, now); err != nil {
		return err
	}
	return tx.Commit()
}
