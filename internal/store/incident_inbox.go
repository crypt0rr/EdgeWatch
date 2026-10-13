package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	incidentReviewNoteMaxBytes = 4096
	incidentReviewHistoryLimit = 20
	incidentFollowUpMaxDays    = 30
	incidentInboxDefaultView   = "all_active"
)

var (
	ErrIncidentReviewInvalid          = errors.New("invalid incident review")
	ErrIncidentOccurrenceChanged      = errors.New("incident occurrence changed since it was loaded")
	ErrIncidentReviewRevisionConflict = errors.New("incident review revision changed since it was loaded")
)

// newestIncidentEvidenceScanIDSQL seeks one same-job, same-tenant scan after
// the incident's last positive observation. The job/time order is backed by
// scansJobHistoryIndex, and the page CTE bounds executions to returned rows.
const newestIncidentEvidenceScanIDSQL = `SELECT candidate.id FROM scans AS candidate
	WHERE candidate.job_id=page.job_id AND candidate.tenant_id=page.tenant_id AND candidate.finished_at>page.last_seen_at_sort
	ORDER BY candidate.finished_at DESC,candidate.id DESC LIMIT 1`

// incidentInboxEvidenceJoinsSQL reads scan identity and comparison metadata
// only from the covering index. Scan results live before these metadata
// columns in the table row, so joining the table directly would visit each
// snapshot's overflow pages.
const incidentInboxEvidenceJoinsSQL = `LEFT JOIN scans AS opening INDEXED BY scans_identity
	ON opening.id=json_extract(page.incident_json,'$.scan_id') AND opening.job_id=page.job_id AND opening.tenant_id=page.tenant_id
LEFT JOIN scans AS newer INDEXED BY scans_identity
	ON newer.id=(` + newestIncidentEvidenceScanIDSQL + `) AND newer.job_id=page.job_id AND newer.tenant_id=page.tenant_id`

// IncidentInboxFilter contains the tenant-scoped filters applied before the
// inbox count, ordering, and pagination are calculated.
type IncidentInboxFilter struct {
	View            string
	JobID           string
	OccurrenceToken string
	Severity        string
	Kind            string
	Limit           int
	Offset          int
	Now             time.Time
}

// IncidentInboxResult contains the filtered page and the unfiltered active
// count for the tenant.
type IncidentInboxResult struct {
	Items       []IncidentInboxItem
	Total       int
	ActiveCount int
	Limit       int
	Offset      int
	HasMore     bool
	NextOffset  *int
}

type incidentInboxSnapshotKey struct {
	tenantID string
	jobID    string
	scanID   string
}

type incidentInboxPendingItem struct {
	item        IncidentInboxItem
	uncertainty IncidentObservationUncertainty
}

type incidentInboxSnapshotReader func(context.Context, incidentInboxSnapshotKey) ([]byte, error)

type incidentInboxSnapshotDecoder func([]byte, *model.Snapshot) error

// IncidentReviewWrite is a proposed optimistic review update. Actor identity
// and timestamp are supplied separately by the authenticated server layer.
type IncidentReviewWrite struct {
	Key              string
	OccurrenceToken  string
	ExpectedRevision int64
	Status           string
	Note             string
	FollowUpAt       *time.Time
}

type occurrenceChangeIdentity struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Address  string `json:"address"`
	Old      string `json:"old"`
	New      string `json:"new"`
}

type incidentOccurrenceIdentity struct {
	Version       int                      `json:"version"`
	TenantID      string                   `json:"tenant_id"`
	JobID         string                   `json:"job_id"`
	Key           string                   `json:"key"`
	OpeningScanID *string                  `json:"opening_scan_id"`
	OpenedAt      *string                  `json:"opened_at"`
	Change        occurrenceChangeIdentity `json:"change"`
}

func incidentOccurrenceToken(tenantID, jobID, key string, incident model.Incident) (string, error) {
	identity := incidentOccurrenceIdentity{
		Version:  1,
		TenantID: tenantID,
		JobID:    jobID,
		Key:      key,
		Change: occurrenceChangeIdentity{
			Key: incident.Change.Key, Kind: incident.Change.Kind, Severity: incident.Change.Severity,
			Target: incident.Change.Target, Protocol: incident.Change.Protocol, Port: incident.Change.Port,
			Address: incident.Change.Address, Old: incident.Change.Old, New: incident.Change.New,
		},
	}
	if incident.ScanID != "" {
		openingScanID := incident.ScanID
		identity.OpeningScanID = &openingScanID
	}
	if !incident.OpenedAt.IsZero() {
		openedAt := incident.OpenedAt.UTC().Format(time.RFC3339Nano)
		identity.OpenedAt = &openedAt
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "v1:" + hex.EncodeToString(digest[:]), nil
}

func validIncidentReviewStatus(status string) bool {
	return status == "needs_review" || status == "investigating"
}

func incidentViewStatus(review IncidentReview, now time.Time) string {
	if review.Revision == 0 || review.Status == "needs_review" {
		return "needs_review"
	}
	if review.FollowUpAt != nil && !review.FollowUpAt.After(now) {
		return "follow_up_due"
	}
	return "investigating"
}

// ListIncidentInbox applies view and field filters before counting and
// paginating. Every query carries the tenant predicate on the owning job.
func (ts *TenantStore) ListIncidentInbox(ctx context.Context, filter IncidentInboxFilter) (IncidentInboxResult, error) {
	return ts.listIncidentInboxWithSnapshotAccess(ctx, filter, nil, nil)
}

// listIncidentInboxWithSnapshotAccess keeps the storage path testable for
// read/decode-count regressions while the exported method uses the production
// SQL query and JSON decoder.
func (ts *TenantStore) listIncidentInboxWithSnapshotAccess(ctx context.Context, filter IncidentInboxFilter, readSnapshot incidentInboxSnapshotReader, decodeSnapshot incidentInboxSnapshotDecoder) (IncidentInboxResult, error) {
	if err := ts.ready(); err != nil {
		return IncidentInboxResult{}, err
	}
	if decodeSnapshot == nil {
		decodeSnapshot = func(raw []byte, snapshot *model.Snapshot) error {
			return json.Unmarshal(raw, snapshot)
		}
	}
	if filter.View == "" {
		filter.View = incidentInboxDefaultView
	}
	switch filter.View {
	case "needs_review", "investigating", "follow_up_due", "all_active":
	default:
		return IncidentInboxResult{}, fmt.Errorf("%w: view", ErrIncidentReviewInvalid)
	}
	filter.Limit, filter.Offset = normalizePage(filter.Limit, filter.Offset)
	now := filter.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	args := []any{ts.scope.id}
	where := []string{`NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`}
	if filter.JobID != "" {
		where = append(where, `j.id=?`)
		args = append(args, filter.JobID)
	}
	if filter.OccurrenceToken != "" {
		if filter.JobID == "" {
			return IncidentInboxResult{}, fmt.Errorf("%w: occurrence_token requires job_id", ErrIncidentReviewInvalid)
		}
		where = append(where, `i.occurrence_token=?`)
		args = append(args, filter.OccurrenceToken)
	}
	if filter.Severity != "" {
		where = append(where, `i.severity=?`)
		args = append(args, filter.Severity)
	}
	if filter.Kind != "" {
		where = append(where, `i.kind=?`)
		args = append(args, filter.Kind)
	}
	switch filter.View {
	case "needs_review":
		where = append(where, `(r.job_id IS NULL OR r.status='needs_review')`)
	case "investigating":
		where = append(where, `r.status='investigating' AND (r.follow_up_at='' OR r.follow_up_at>?)`)
		args = append(args, sqliteTimestamp(now))
	case "follow_up_due":
		where = append(where, `r.status='investigating' AND r.follow_up_at<>'' AND r.follow_up_at<=?`)
		args = append(args, sqliteTimestamp(now))
	}
	from := `FROM runtime_incidents AS i
		JOIN jobs AS j ON j.id=i.job_id AND j.tenant_id=?
		LEFT JOIN incident_reviews AS r ON r.job_id=i.job_id AND r.occurrence_token=i.occurrence_token
		WHERE ` + strings.Join(where, ` AND `)
	var result IncidentInboxResult
	result.Limit, result.Offset = filter.Limit, filter.Offset
	readDB := ts.store.reader()
	tx, err := readDB.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_incidents AS i JOIN jobs AS j ON j.id=i.job_id AND j.tenant_id=? WHERE NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id).Scan(&result.ActiveCount); err != nil {
		return result, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) `+from, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, `WITH page AS MATERIALIZED (
		SELECT i.job_id,j.name AS job_name,j.tenant_id,i.key,i.severity,i.opened_at_sort,i.incident_json,i.occurrence_token,i.last_seen_at_sort,
			r.status,r.reviewer_label,r.reviewed_at,r.note,r.follow_up_at,r.revision
		`+from+`
		ORDER BY CASE lower(i.severity) WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END,
			CASE WHEN i.opened_at_sort='' THEN 1 ELSE 0 END,i.opened_at_sort,j.name COLLATE NOCASE,i.key,j.id,i.occurrence_token
		LIMIT ? OFFSET ?
	)
	SELECT page.job_id,page.job_name,page.incident_json,page.occurrence_token,
		page.status,page.reviewer_label,page.reviewed_at,page.note,page.follow_up_at,page.revision,
		CASE WHEN opening.id IS NULL THEN 0 ELSE 1 END,
		COALESCE(newer.id,''),COALESCE(newer.finished_at,''),COALESCE(newer.status,''),COALESCE(newer.comparison,'')
	FROM page
	`+incidentInboxEvidenceJoinsSQL+`
	ORDER BY CASE lower(page.severity) WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END,
		CASE WHEN page.opened_at_sort='' THEN 1 ELSE 0 END,page.opened_at_sort,page.job_name COLLATE NOCASE,page.key,page.job_id,page.occurrence_token`,
		append(args, filter.Limit, filter.Offset)...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var pending []incidentInboxPendingItem
	neededSnapshotItems := make(map[incidentInboxSnapshotKey][]int)
	for rows.Next() {
		var item IncidentInboxItem
		var raw []byte
		var reviewStatus, reviewerLabel, reviewedAt, note, followUpAt sql.NullString
		var revision sql.NullInt64
		var openingScanAvailable bool
		var newerScanID, newerFinishedAt, newerStatus, newerComparison sql.NullString
		if err := rows.Scan(&item.JobID, &item.Job, &raw, &item.OccurrenceToken,
			&reviewStatus, &reviewerLabel, &reviewedAt, &note, &followUpAt, &revision,
			&openingScanAvailable, &newerScanID, &newerFinishedAt, &newerStatus, &newerComparison); err != nil {
			return result, err
		}
		if err := json.Unmarshal(raw, &item.Incident); err != nil {
			return result, err
		}
		item.OpeningTimeKnown = !item.Incident.OpenedAt.IsZero()
		item.OpeningScanAvailable = openingScanAvailable
		item.Review = IncidentReview{Status: "needs_review", Note: "", Revision: 0}
		if revision.Valid {
			item.Review.Revision = revision.Int64
			item.Review.Status = reviewStatus.String
			item.Review.Note = note.String
			if reviewerLabel.Valid {
				label := reviewerLabel.String
				item.Review.ReviewerLabel = &label
			}
			if reviewedAt.Valid && reviewedAt.String != "" {
				value := scanTime(reviewedAt.String)
				item.Review.ReviewedAt = &value
			}
			if followUpAt.Valid && followUpAt.String != "" {
				value := scanTime(followUpAt.String)
				item.Review.FollowUpAt = &value
			}
		}
		item.ViewStatus = incidentViewStatus(item.Review, now)
		uncertainty, needsSnapshot := incidentObservationMetadataUncertainty(item.Incident, newerScanID.String, newerFinishedAt.String, newerStatus.String, newerComparison.String)
		if needsSnapshot {
			snapshotKey := incidentInboxSnapshotKey{tenantID: ts.scope.id, jobID: item.JobID, scanID: newerScanID.String}
			neededSnapshotItems[snapshotKey] = append(neededSnapshotItems[snapshotKey], len(pending))
		}
		pending = append(pending, incidentInboxPendingItem{item: item, uncertainty: uncertainty})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	if readSnapshot == nil {
		readDB := ts.store.reader()
		readSnapshot = func(ctx context.Context, key incidentInboxSnapshotKey) ([]byte, error) {
			return readIncidentInboxSnapshot(ctx, readDB, key)
		}
	}
	if err := classifyIncidentInboxSnapshots(ctx, neededSnapshotItems, pending, readSnapshot, decodeSnapshot); err != nil {
		return result, err
	}
	result.Items = make([]IncidentInboxItem, 0, len(pending))
	for _, entry := range pending {
		uncertainty := entry.uncertainty
		if !uncertainty.valid() {
			uncertainty.Status = IncidentObservationUnknown
			uncertainty.Reason = IncidentReasonLatestScanUnclassifiable
		}
		entry.item.ObservationUncertainty = uncertainty
		result.Items = append(result.Items, entry.item)
	}
	result.HasMore = result.Offset+len(result.Items) < result.Total
	if result.HasMore {
		next := result.Offset + len(result.Items)
		result.NextOffset = &next
	}
	return result, nil
}

// readIncidentInboxSnapshot scans one fixed identity through the shared
// reader. QueryRow.Scan closes its rows before returning, releasing the pool
// connection before the caller decodes the returned bytes.
func readIncidentInboxSnapshot(ctx context.Context, db *sql.DB, key incidentInboxSnapshotKey) ([]byte, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT snapshot_json FROM scans INDEXED BY scans_identity WHERE id=? AND tenant_id=? AND job_id=?`, key.scanID, key.tenantID, key.jobID).Scan(&raw)
	return raw, err
}

func incidentObservationNeedsSnapshot(incident model.Incident, scanID, finishedAt, scanStatus, comparison string) bool {
	_, needsSnapshot := incidentObservationMetadataUncertainty(incident, scanID, finishedAt, scanStatus, comparison)
	return needsSnapshot
}

func incidentObservationMetadataUncertainty(incident model.Incident, scanID, finishedAt, scanStatus, comparison string) (IncidentObservationUncertainty, bool) {
	uncertainty := IncidentObservationUncertainty{Status: IncidentObservationUnknown}
	if incident.LastSeenAt.IsZero() {
		uncertainty.Reason = IncidentReasonLegacyOriginUnknown
		return uncertainty, false
	}
	if scanID == "" {
		uncertainty.Reason = IncidentReasonNoNewerObservation
		return uncertainty, false
	}
	observedAt := scanTime(finishedAt)
	if observedAt.IsZero() || !observedAt.After(incident.LastSeenAt) {
		uncertainty.Reason = IncidentReasonNoNewerObservation
		return uncertainty, false
	}
	uncertainty.ScanID = scanID
	uncertainty.ObservedAt = &observedAt
	uncertainty.ScanStatus = scanStatus
	uncertainty.Comparison = comparison
	if scanStatus == "failed" {
		uncertainty.Status = IncidentObservationIncomplete
		uncertainty.Reason = IncidentReasonLatestScanFailed
		return uncertainty, false
	}
	if scanStatus == "incomplete" {
		uncertainty.Status = IncidentObservationIncomplete
		uncertainty.Reason = IncidentReasonLatestScanIncomplete
		return uncertainty, false
	}
	if comparison == model.ScanComparisonNotCompared {
		uncertainty.Status = IncidentObservationIncomplete
		uncertainty.Reason = IncidentReasonLatestScanNotCompared
		return uncertainty, false
	}
	if scanStatus != "success" || comparison != model.ScanComparisonCompared {
		uncertainty.Reason = IncidentReasonLatestScanUnclassifiable
		return uncertainty, false
	}
	return uncertainty, true
}

func incidentObservationUncertainty(incident model.Incident, scanID, finishedAt, scanStatus, comparison string, rawSnapshot []byte) IncidentObservationUncertainty {
	uncertainty, needsSnapshot := incidentObservationMetadataUncertainty(incident, scanID, finishedAt, scanStatus, comparison)
	if !needsSnapshot {
		return uncertainty
	}
	var snapshot model.Snapshot
	if err := json.Unmarshal(rawSnapshot, &snapshot); err != nil {
		uncertainty.Reason = IncidentReasonLatestScanUnclassifiable
		return uncertainty
	}
	return incidentObservationUncertaintyFromSnapshot(uncertainty, incident.Change, snapshot)
}

func incidentObservationUncertaintyFromSnapshot(uncertainty IncidentObservationUncertainty, change model.Change, snapshot model.Snapshot) IncidentObservationUncertainty {
	if reason := incidentCoverageUncertainty(change, snapshot); reason != "" {
		if reason != IncidentReasonLatestScanUnclassifiable {
			uncertainty.Status = IncidentObservationIncomplete
		}
		uncertainty.Reason = reason
		return uncertainty
	}
	uncertainty.Reason = IncidentReasonLatestScanDoesNotEstablishRecovery
	return uncertainty
}

// classifyIncidentInboxSnapshots reads and decodes one distinct scan at a
// time, then classifies every matching inbox row before moving to the next
// key. The page metadata transaction is already closed before this helper
// runs, and each reader returns after copying one immutable finalized scan
// blob. This releases the shared read connection before JSON decoding and
// bounds retained snapshot memory to the largest needed snapshot rather than
// the page's aggregate evidence. Retention can delete a scan between metadata
// selection and this read; a missing fixed key remains unclassifiable.
func classifyIncidentInboxSnapshots(ctx context.Context, rowsBySnapshot map[incidentInboxSnapshotKey][]int, pending []incidentInboxPendingItem, read incidentInboxSnapshotReader, decode incidentInboxSnapshotDecoder) error {
	for key, rowIndexes := range rowsBySnapshot {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, readErr := read(ctx, key)
		if readErr != nil && !errors.Is(readErr, sql.ErrNoRows) {
			return readErr
		}
		var snapshot model.Snapshot
		decodeErr := readErr
		if decodeErr == nil {
			decodeErr = decode(raw, &snapshot)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, rowIndex := range rowIndexes {
			if rowIndex < 0 || rowIndex >= len(pending) {
				return fmt.Errorf("incident inbox snapshot row index %d is out of bounds", rowIndex)
			}
			entry := &pending[rowIndex]
			if decodeErr != nil {
				entry.uncertainty.Reason = IncidentReasonLatestScanUnclassifiable
			} else {
				entry.uncertainty = incidentObservationUncertaintyFromSnapshot(entry.uncertainty, entry.item.Incident.Change, snapshot)
			}
		}
		// Do not retain snapshots for the rest of the page. Each iteration
		// keeps at most one raw blob and one decoded model live.
		snapshot = model.Snapshot{}
	}
	return nil
}

func incidentCoverageUncertainty(change model.Change, snapshot model.Snapshot) IncidentObservationReason {
	target := normalizedIncidentTarget(change.Target)
	address := normalizedIncidentTarget(change.Address)
	for _, failure := range snapshot.TargetFailures {
		failedTarget := normalizedIncidentTarget(failure.Target)
		if failedTarget != "" && (failedTarget == target || failedTarget == address) {
			return IncidentReasonTargetResolutionFailed
		}
	}
	for _, host := range snapshot.Hosts {
		if !hostMatchesIncidentChange(host, change) {
			continue
		}
		if reachabilityReasonIsUncertain(host.StatusReason) {
			return IncidentReasonTargetObservationIncomplete
		}
		if change.Kind == "host" {
			if explicitHostDown(host) || snapshotHostStateIsDown(snapshot.HostStates, host.Address) {
				return IncidentReasonTargetHostDown
			}
			continue
		}
		for _, protocol := range host.Protocols {
			if !strings.EqualFold(strings.TrimSpace(protocol.Protocol), strings.TrimSpace(change.Protocol)) {
				continue
			}
			if reachabilityReasonIsUncertain(protocol.StatusReason) {
				return IncidentReasonTargetObservationIncomplete
			}
			if protocol.DiscoveryState == "down" || strings.EqualFold(strings.TrimSpace(protocol.Status), "down") || snapshotHostStateIsDown(snapshot.HostStates, host.Address) || explicitHostDown(host) {
				return IncidentReasonTargetHostDown
			}
		}
	}
	if len(snapshot.Scopes) == 0 {
		return IncidentReasonLatestScanUnclassifiable
	}

	if change.Kind == "host" {
		return ""
	}

	targetSeen, protocolSeen := false, false
	for _, scope := range snapshot.Scopes {
		scopeTarget := normalizedIncidentTarget(scope.Target)
		if scopeTarget != target && (address == "" || scopeTarget != address) {
			continue
		}
		targetSeen = true
		if strings.EqualFold(strings.TrimSpace(scope.Protocol), strings.TrimSpace(change.Protocol)) {
			protocolSeen = true
		}
	}
	if !targetSeen {
		return IncidentReasonTargetUnobserved
	}
	if !protocolSeen {
		return IncidentReasonProtocolUnobserved
	}

	hostMatched, protocolMatched := false, false
	for _, host := range snapshot.Hosts {
		if !hostMatchesIncidentChange(host, change) {
			continue
		}
		hostMatched = true
		for _, protocol := range host.Protocols {
			if !strings.EqualFold(strings.TrimSpace(protocol.Protocol), strings.TrimSpace(change.Protocol)) {
				continue
			}
			protocolMatched = true
			if protocol.DiscoveryState == "down" || snapshotHostStateIsDown(snapshot.HostStates, host.Address) || explicitHostDown(host) {
				return "target_host_down"
			}
			status := strings.ToLower(strings.TrimSpace(protocol.Status))
			reason := strings.ToLower(strings.TrimSpace(protocol.StatusReason))
			if status == "unreachable" || (status == "unknown" && reason != "") {
				if reason == "nmap-omitted" {
					return IncidentReasonProtocolUnobserved
				}
				return IncidentReasonTargetObservationIncomplete
			}
		}
	}
	if !hostMatched {
		return IncidentReasonTargetUnobserved
	}
	if !protocolMatched {
		return IncidentReasonProtocolUnobserved
	}
	return ""
}

func explicitHostDown(host model.HostObservation) bool {
	if strings.EqualFold(strings.TrimSpace(host.Status), "down") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(host.StatusReason)) {
	case "nmap-host-down", "host-down", "down", "no-response":
		return strings.EqualFold(strings.TrimSpace(host.Status), "unreachable")
	default:
		return false
	}
}

func reachabilityReasonIsUncertain(reason string) bool {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "host-unreach", "net-unreach", "admin-prohibited":
		return true
	default:
		return false
	}
}

func snapshotHostStateIsDown(states []model.HostState, address string) bool {
	address = normalizedIncidentTarget(address)
	for _, state := range states {
		if normalizedIncidentTarget(state.Address) == address && strings.EqualFold(strings.TrimSpace(state.State), "down") {
			return true
		}
	}
	return false
}

func hostMatchesIncidentChange(host model.HostObservation, change model.Change) bool {
	target := normalizedIncidentTarget(change.Target)
	address := normalizedIncidentTarget(change.Address)
	if address != "" {
		// Address-specific findings represent one resolved endpoint. Do not
		// attribute evidence from another IP that shares the same source target.
		return normalizedIncidentTarget(host.Address) == address
	}
	if normalizedIncidentTarget(host.Address) == target {
		return true
	}
	for _, source := range host.SourceTargets {
		if normalizedIncidentTarget(source) == target {
			return true
		}
	}
	for _, dnsName := range host.DNSNames {
		if normalizedIncidentTarget(dnsName) == target {
			return true
		}
	}
	return false
}

func normalizedIncidentTarget(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

// SaveIncidentReview stores one occurrence review with optimistic locking.
// It verifies the active occurrence against job_runtime while holding the
// writer lock, and commits the bounded history and audit row atomically.
func (ts *TenantStore) SaveIncidentReview(ctx context.Context, jobID string, write IncidentReviewWrite, reviewerUserID, reviewerLabel string, audit AuditEntry) (IncidentReview, error) {
	if err := ts.ready(); err != nil {
		return IncidentReview{}, err
	}
	if write.Key == "" || write.OccurrenceToken == "" || write.ExpectedRevision < 0 || !validIncidentReviewStatus(write.Status) || !utf8.ValidString(write.Note) || len([]byte(write.Note)) > incidentReviewNoteMaxBytes || strings.TrimSpace(reviewerLabel) == "" {
		return IncidentReview{}, fmt.Errorf("%w: invalid fields", ErrIncidentReviewInvalid)
	}
	now := time.Now().UTC()
	if write.Status == "needs_review" && write.FollowUpAt != nil {
		return IncidentReview{}, fmt.Errorf("%w: follow_up_at must be empty for needs_review", ErrIncidentReviewInvalid)
	}
	var due string
	if write.FollowUpAt != nil {
		followUp := write.FollowUpAt.UTC()
		if followUp.After(now.Add(incidentFollowUpMaxDays * 24 * time.Hour)) {
			return IncidentReview{}, fmt.Errorf("%w: follow_up_at is more than 30 days away", ErrIncidentReviewInvalid)
		}
		due = sqliteTimestamp(followUp)
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return IncidentReview{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var owned int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM jobs AS j WHERE j.id=? AND j.tenant_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.job_id=j.id AND purge.tenant_id=j.tenant_id)`, jobID, ts.scope.id).Scan(&owned); errors.Is(err, sql.ErrNoRows) {
		return IncidentReview{}, fmt.Errorf("%w: job %s", ErrNotFound, jobID)
	} else if err != nil {
		return IncidentReview{}, err
	}
	state, err := loadRuntimeTx(ctx, tx, jobID)
	if err != nil {
		return IncidentReview{}, err
	}
	incident, active := state.Incidents[write.Key]
	if !active {
		return IncidentReview{}, ErrIncidentNotFound
	}
	currentToken, err := incidentOccurrenceToken(ts.scope.id, jobID, write.Key, incident)
	if err != nil {
		return IncidentReview{}, err
	}
	if currentToken != write.OccurrenceToken {
		return IncidentReview{}, ErrIncidentOccurrenceChanged
	}
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT review.revision FROM incident_reviews AS review
		JOIN jobs AS owner ON owner.id=review.job_id AND owner.tenant_id=?
		WHERE review.job_id=? AND review.occurrence_token=?`, ts.scope.id, jobID, currentToken).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		revision = 0
	} else if err != nil {
		return IncidentReview{}, err
	}
	if revision != write.ExpectedRevision {
		return IncidentReview{}, ErrIncidentReviewRevisionConflict
	}
	newRevision := revision + 1
	reviewerLabel = strings.TrimSpace(reviewerLabel)
	stamp := sqliteTimestamp(now)
	openedAt := ""
	if !incident.OpenedAt.IsZero() {
		openedAt = sqliteTimestamp(incident.OpenedAt)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_reviews(job_id,occurrence_token,incident_key,opening_scan_id,opened_at,status,reviewer_user_id,reviewer_label,reviewed_at,note,follow_up_at,revision,closed_at)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,?,'' FROM jobs AS owner WHERE owner.id=? AND owner.tenant_id=?
		ON CONFLICT(job_id,occurrence_token) DO UPDATE SET status=excluded.status,reviewer_user_id=excluded.reviewer_user_id,reviewer_label=excluded.reviewer_label,reviewed_at=excluded.reviewed_at,note=excluded.note,follow_up_at=excluded.follow_up_at,revision=excluded.revision,closed_at=''`,
		jobID, currentToken, write.Key, incident.ScanID, openedAt, write.Status, reviewerUserID, reviewerLabel, stamp, write.Note, due, newRevision, jobID, ts.scope.id); err != nil {
		return IncidentReview{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_review_history(job_id,occurrence_token,revision,status,reviewer_user_id,reviewer_label,reviewed_at,note,follow_up_at)
		SELECT ?,?,?,?,?,?,?,?,? FROM jobs AS owner WHERE owner.id=? AND owner.tenant_id=?`, jobID, currentToken, newRevision, write.Status, reviewerUserID, reviewerLabel, stamp, write.Note, due, jobID, ts.scope.id); err != nil {
		return IncidentReview{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM incident_review_history WHERE rowid IN (
		SELECT history.rowid FROM incident_review_history AS history JOIN jobs AS owner ON owner.id=history.job_id AND owner.tenant_id=?
		WHERE history.job_id=? AND history.occurrence_token=? AND history.revision NOT IN (
			SELECT revision FROM incident_review_history WHERE job_id=? AND occurrence_token=? ORDER BY revision DESC LIMIT ?))`, ts.scope.id, jobID, currentToken, jobID, currentToken, incidentReviewHistoryLimit); err != nil {
		return IncidentReview{}, err
	}
	audit.Action = "incident.review.updated"
	audit.Detail = fmt.Sprintf("%s:%s revision %d", jobID, write.Key, newRevision)
	if err := ts.insertAuditEntries(ctx, tx, []AuditEntry{audit}, now); err != nil {
		return IncidentReview{}, err
	}
	if err := tx.Commit(); err != nil {
		return IncidentReview{}, err
	}
	label := reviewerLabel
	reviewedAt := now
	var followUpAt *time.Time
	if write.FollowUpAt != nil {
		value := write.FollowUpAt.UTC()
		followUpAt = &value
	}
	return IncidentReview{Status: write.Status, ReviewerLabel: &label, ReviewedAt: &reviewedAt, Note: write.Note, FollowUpAt: followUpAt, Revision: newRevision}, nil
}
