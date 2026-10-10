package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type Engine struct{ Store *store.Store }

func (e *Engine) Success(ctx context.Context, job config.Job, scan model.Scan) ([]model.Event, error) {
	return e.Store.System().UpdateState(ctx, job.Name, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

// SuccessForJob is the database-backed equivalent used by web-managed jobs.
// Its state key is the immutable job ID while event payloads keep the name
// users recognize.
func (e *Engine) SuccessForJob(ctx context.Context, jobID string, job config.Job, scan model.Scan) ([]model.Event, error) {
	return e.Store.System().UpdateRuntimeForScan(ctx, jobID, scan.ConfigHash, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

func (e *Engine) SuccessForJobWithDestinations(ctx context.Context, jobID string, job config.Job, scan model.Scan, destinations []string) ([]model.Event, error) {
	return e.Store.System().UpdateRuntimeForScanWithOutbox(ctx, jobID, scan.ConfigHash, destinations, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

// FinalizeManagedScan captures the scan-time comparison and applies the
// resulting runtime transition in the store's single transaction. This keeps
// baseline reset/approval from changing the state between those two steps.
func (e *Engine) FinalizeManagedScan(ctx context.Context, jobID string, job config.Job, scan *model.Scan, destinations []string) ([]model.Event, error) {
	return e.FinalizeManagedScanWithOptions(ctx, jobID, job, scan, destinations, store.ManagedScanFinalizationOptions{})
}

// FinalizeManagedScanWithOptions is FinalizeManagedScan with explicit
// separate writer-wait and transaction-work budgets. The application uses it
// for managed runs so queued SQLite writer contention does not discard a
// completed scan.
func (e *Engine) FinalizeManagedScanWithOptions(ctx context.Context, jobID string, job config.Job, scan *model.Scan, destinations []string, options store.ManagedScanFinalizationOptions) ([]model.Event, error) {
	if scan == nil {
		return nil, fmt.Errorf("scan is required")
	}
	return e.Store.System().FinalizeManagedScanWithOptions(ctx, scan, jobID, scan.ConfigHash, destinations, options, func(state *model.JobState, current *model.Scan, reminderSettings store.IncidentReminderSettings) ([]model.Event, error) {
		// The scan passed its probe budget when it started, so a later
		// budget skip is reported again.
		state.BudgetSkipAlertKey = ""
		if current.Status == "success" {
			MarkIncompleteScan(current)
		}
		if current.Status == "success" || current.Status == "incomplete" {
			hadBaseline := state.Baseline != nil
			if hadBaseline {
				current.BaselineScanID = state.BaselineScanID
				current.BaselineConfigHash = state.BaselineConfigHash
			}
			events, changes, err := processSuccessWithReminderSettings(state, job, *current, reminderSettings)
			if err != nil {
				return nil, err
			}
			// Persist exactly the change set that drove applyChanges. Fingerprint
			// learning can mutate the runtime baseline during processSuccess; a
			// pre-learning diff would otherwise appear in history without an
			// incident or notification.
			current.Changes = changes
			// A scan can be the sample that completes the initial baseline. In
			// that case there was no prior baseline to capture above, but the
			// scan is still the immutable source of the newly established state.
			// Recording its own ID prevents history from falling back to a later
			// mutable runtime baseline after an administrator reset.
			if current.Status == "success" && current.BaselineScanID == "" && state.BaselineScanID == current.ID {
				current.BaselineScanID = state.BaselineScanID
				current.BaselineConfigHash = state.BaselineConfigHash
			}
			current.Comparison = comparisonOutcome(hadBaseline, state, current)
			if current.Resumable && current.CycleAttempt > 1 {
				return append(events, model.Event{Type: "scan-recovered", Job: scan.Job, ScanID: scan.ID, Message: "Resumable scan cycle completed after earlier paused attempts", CreatedAt: scan.FinishedAt}), nil
			}
			return events, nil
		}
		// Failed, timed-out, and canceled scans never enter comparison state,
		// but every terminal non-success outcome is retained as an event so the
		// configured notification destinations can alert the operator.
		current.Comparison = model.ScanComparisonNotCompared
		return processFailure(state, job.Name, *current)
	})
}

// comparisonOutcome names what finalizing a successful or incomplete scan
// did. A scan that finished while the job had a baseline was compared with
// it, even when the comparison found nothing. Without one, the scan was a
// baseline sample, or the sample that completed the baseline. Recording the
// outcome keeps a sample's history from being compared later with a
// baseline that did not exist when it ran.
func comparisonOutcome(hadBaseline bool, state *model.JobState, scan *model.Scan) string {
	switch {
	case hadBaseline:
		return model.ScanComparisonCompared
	case scan.Status == "success" && state.Baseline != nil && state.BaselineScanID == scan.ID:
		return model.ScanComparisonBaselineEstablished
	default:
		return model.ScanComparisonBaselineSample
	}
}

func processSuccess(state *model.JobState, job config.Job, scan model.Scan) ([]model.Event, error) {
	events, _, err := processSuccessWithChanges(state, job, scan)
	return events, err
}

// processSuccessWithChanges applies a successful scan and returns the exact
// change set handed to the incident engine. Keeping the set alongside the
// events prevents immutable scan history from diverging when service
// fingerprints are learned as part of the same transaction.
func processSuccessWithChanges(state *model.JobState, job config.Job, scan model.Scan) ([]model.Event, []model.Change, error) {
	// This legacy entry point also serves config-only scans, which have no
	// business-unit notification menu. Managed scans pass the stored preference.
	return processSuccessWithChangesAndReminders(state, job, scan, false)
}

func processSuccessWithChangesAndReminders(state *model.JobState, job config.Job, scan model.Scan, remindersEnabled bool) ([]model.Event, []model.Change, error) {
	return processSuccessWithReminderSettings(state, job, scan, store.IncidentReminderSettings{Enabled: remindersEnabled, Cadence: store.IncidentReminderCadenceEveryScan})
}

func processSuccessWithReminderSettings(state *model.JobState, job config.Job, scan model.Scan, reminderSettings store.IncidentReminderSettings) ([]model.Event, []model.Change, error) {
	completeHostDiscoveryStates(&scan.Snapshot)
	// A partial or explicitly incomplete result may be retained for diagnosis,
	// but it must never trigger a recurring reminder.
	remindersEnabled := reminderSettings.Enabled && scan.Status == "success"
	// Port-expression normalization changes the representation but not the
	// effective monitored set. When a persisted legacy job still matches its
	// old raw-expression hash, advance only the baseline's scope marker to the
	// canonical hash; do not generate a scope-change diff or relearn the
	// baseline.
	if state.Baseline != nil && state.BaselineConfigHash != "" &&
		job.LegacySecurityHash() != "" && state.BaselineConfigHash == job.LegacySecurityHash() &&
		scan.ConfigHash == job.SecurityHash() {
		state.BaselineConfigHash = scan.ConfigHash
	}
	incomplete := snapshotHasUnreachableHost(scan.Snapshot)
	if incomplete {
		// The scanner has complete evidence for some address/protocol pairs, so
		// compare those now while deferring changes that depend on missing coverage
		// and all baseline learning until a later complete scan.
		return processIncompleteSuccess(state, job, scan)
	}
	state.IncompleteCandidateAttempts = 0
	state.ConsecutiveFailures = 0
	state.LastFailureAlert = 0
	now := scan.FinishedAt
	if state.Baseline == nil {
		clearTotalLossCandidate(state)
		events := advanceCandidateWithDNSMode(state, scan, job.Baseline.Samples, false, job.DNSComparisonMode)
		return events, nil, nil
	}
	scopeChanged := state.BaselineConfigHash != scan.ConfigHash
	// A complete scan that suddenly reports no positive ports across a
	// previously non-empty baseline is usually a degraded discovery result
	// (for example, a transient firewall or scanner-capability problem). Do
	// not turn that one result into an incident for every expected port. Require
	// one consecutive matching result before allowing the normal comparison to
	// proceed. An explicit security-scope change is exempt because it already
	// requires a deliberate rebaseline and may legitimately narrow the scope to
	// zero positive ports.
	if baselineSurfaceIsExplicitlyDownForJob(*state.Baseline, scan.Snapshot, job) {
		// When completed Nmap host discovery accounts for every address that
		// supplied the old positive ports, the absence is a host-state change,
		// not an ambiguous scan-wide port loss. Let Diff report the host
		// transition while suppressing the now-unreachable per-port closures.
		clearTotalLossCandidate(state)
	} else if totalLoss, event := guardTotalLoss(state, scan); totalLoss {
		// An explicit host-discovery transition is useful even while the
		// zero-positive-port guard waits for confirmation of the port loss. It
		// does not confirm individual ports as closed.
		hostChanges := filterDNSAggregateChanges(*state.Baseline, scan.Snapshot, hostStateChanges(*state.Baseline, scan.Snapshot, scopeChanged), job)
		seen := observe(state, job, scanView{snapshot: scan.Snapshot, changes: hostChanges, scopeChanged: scopeChanged, hostsOnly: true})
		if len(hostChanges) > 0 {
			events := append(event, applyObservedChanges(state, job.Name, scan.ID, hostChanges, job.Change.Confirmations, now, seen)...)
			return events, hostChanges, nil
		}
		seen.retireFrom(state)
		return event, nil, nil
	}
	var learningServices map[string]struct{}
	if !scopeChanged {
		// A scope migration uses the candidate-convergence path to decide when
		// replacement service fingerprints are stable. Running the ordinary
		// missing-fingerprint learner here would clear that candidate for every
		// scan because the old baseline already has a fingerprint.
		learningServices = learnMissingFingerprints(state, scan.Snapshot, job.Baseline.Samples)
	}
	changes := diffForJob(*state.Baseline, scan.Snapshot, scopeChanged, job)
	if scopeChanged {
		// Do not run the stateful fingerprint learner while a scope candidate is
		// converging: that would mutate the active baseline before the candidate
		// is accepted. Still defer a first fingerprint on an expected port; the
		// scope candidate merge will adopt it after its normal stability check.
		learningServices = map[string]struct{}{}
		for _, change := range changes {
			if change.Kind == "service" && fingerprintLearnable(state, change.Target, change.Protocol, change.Port) {
				learningServices[change.Key] = struct{}{}
			}
		}
	}
	if len(learningServices) > 0 {
		filtered := changes[:0]
		for _, change := range changes {
			if change.Kind == "service" {
				if _, learning := learningServices[change.Key]; learning {
					continue
				}
			}
			filtered = append(filtered, change)
		}
		changes = filtered
	}
	// Decide what the scan observed before port evidence is learned into the
	// baseline below; the per-address comparison uses the baseline's evidence.
	seen := observe(state, job, scanView{snapshot: scan.Snapshot, changes: changes, scopeChanged: scopeChanged})
	if !scopeChanged && job.DNSComparisonMode != config.DNSComparisonAggregate {
		learnMissingPortEvidence(state.Baseline, scan.Snapshot, completedDownAddressesByProtocolForJob(*state.Baseline, scan.Snapshot, job))
	}
	previous := make(map[string]model.Incident, len(state.Incidents))
	sendRemindersNow := remindersEnabled && incidentReminderDue(state.LastIncidentReminderAt, reminderSettings.Cadence, now)
	if sendRemindersNow {
		for key, incident := range state.Incidents {
			previous[key] = incident
		}
	}
	events := applyObservedChanges(state, job.Name, scan.ID, changes, job.Change.Confirmations, now, seen)
	if sendRemindersNow {
		var reminded []model.Change
		for _, change := range changes {
			old, wasOpen := previous[change.Key]
			current, stillOpen := state.Incidents[change.Key]
			if wasOpen && stillOpen && old.Change.New == change.New && current.Change.New == change.New && current.LastSeenAt.Equal(now) {
				reminded = append(reminded, current.Change)
			}
		}
		if len(reminded) > 0 {
			sort.Slice(reminded, func(i, j int) bool { return reminded[i].Key < reminded[j].Key })
			events = append(events, model.Event{Type: "changes-reminder", Job: job.Name, ScanID: scan.ID, Message: persistentIncidentReminderMessage(len(reminded)), Changes: reminded, CreatedAt: now})
			remindedAt := now
			state.LastIncidentReminderAt = &remindedAt
		}
	}
	if scopeChanged {
		candidateEvents := advanceCandidateWithDNSMode(state, scan, job.Baseline.Samples, true, job.DNSComparisonMode)
		events = append(events, candidateEvents...)
	}
	return events, changes, nil
}

func incidentReminderDue(last *time.Time, cadence string, now time.Time) bool {
	if last == nil || cadence == store.IncidentReminderCadenceEveryScan {
		return true
	}
	var interval time.Duration
	switch cadence {
	case store.IncidentReminderCadenceHourly:
		interval = time.Hour
	case store.IncidentReminderCadenceSixHours:
		interval = 6 * time.Hour
	case store.IncidentReminderCadenceDaily:
		interval = 24 * time.Hour
	default:
		// Persisted values are constrained by the schema. Treat a value from a
		// future or corrupted database like the historical every-scan default.
		return true
	}
	return !now.Before(last.Add(interval))
}

// baselineSurfaceIsExplicitlyDown reports whether every effective address
// contributing a positive baseline port was explicitly discovered down in
// the current complete scan. It intentionally returns false for legacy or
// aggregated evidence whose contributing addresses cannot be determined.
func baselineSurfaceIsExplicitlyDown(baseline, current model.Snapshot) bool {
	return baselineSurfaceIsExplicitlyDownForJob(baseline, current, config.Job{})
}

func baselineSurfaceIsExplicitlyDownForJob(baseline, current model.Snapshot, job config.Job) bool {
	downByProtocol := completedDownAddressesByProtocolForJob(baseline, current, job)
	if len(downByProtocol) == 0 {
		return false
	}
	positivePorts := 0
	for _, unit := range baseline.Units {
		for _, port := range unit.Ports {
			if !isPositivePortState(port.State) {
				continue
			}
			positivePorts++
			addresses := port.Evidence
			if len(addresses) == 0 {
				addresses = unit.Addresses
			}
			if len(addresses) == 0 {
				addresses = baseline.DNS[unit.Target]
			}
			if len(addresses) == 0 && net.ParseIP(strings.TrimSpace(unit.Target)) != nil {
				addresses = []string{unit.Target}
			}
			if len(addresses) == 0 {
				return false
			}
			for _, address := range addresses {
				if !explicitlyDownForProtocol(downByProtocol, unit.Protocol, strings.TrimSpace(address)) {
					return false
				}
			}
		}
	}
	return positivePorts > 0
}

// processIncompleteSuccess compares only evidence that is complete for this
// scan. It deliberately leaves baseline candidates, fingerprint learning, and
// failure counters untouched: an incomplete result is useful for detecting a
// reachable addition, but cannot establish expected state from missing data.
// A service change that a complete scan would learn is therefore neither
// learned nor reported here; the next complete scan learns it.
// While no baseline exists, a separate counter records repeated incomplete
// attempts so the UI can surface a stalled learning state without pretending
// that partial evidence is safe to establish as expected state.
func processIncompleteSuccess(state *model.JobState, job config.Job, scan model.Scan) ([]model.Event, []model.Change, error) {
	if state.Baseline == nil {
		state.IncompleteCandidateAttempts++
	}
	incompleteProtocols := incompleteProtocolCoverage(scan.Snapshot)
	protectedTargetProtocols, protectedTargets := incompleteTargets(state.Baseline, scan.Snapshot, incompleteProtocols)
	var changes []model.Change
	var events []model.Event
	if state.Baseline != nil {
		// An incomplete scan with no positive evidence cannot confirm that every
		// expected port disappeared: the missing coverage may be the reason for
		// the empty result. Do not let it advance the complete-scan total-loss
		// confirmation counter, and discard pending closure anomalies that were
		// waiting on this unreliable observation. A total loss that complete
		// scans already confirmed stays confirmed.
		if positivePortCount(scan.Snapshot) == 0 && len(scan.Snapshot.HostStates) == 0 {
			clearUnconfirmedTotalLoss(state)
			clearPendingTotalLoss(state)
			events = append(events, model.Event{Type: "scan-incomplete", Job: scan.Job, ScanID: scan.ID, Message: incompleteScanError(scan.Snapshot), CreatedAt: scan.FinishedAt})
			return events, nil, nil
		}
		// A partial scan with some positive evidence can still compare reachable
		// targets, but it must never carry a stale total-loss candidate forward.
		clearTotalLossCandidate(state)
		changes = diffForJob(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != scan.ConfigHash, job)
		filtered := changes[:0]
		deferredLearning := make(map[string]struct{})
		for _, change := range changes {
			// A complete scan learns a missing fingerprint of a baseline port
			// without reporting it. This scan cannot learn, so it defers the
			// change to the next complete scan instead of reporting it: an
			// incident opened here would also stop the fingerprint from ever
			// being learned.
			if change.Kind == "service" && fingerprintLearnable(state, change.Target, change.Protocol, change.Port) {
				deferredLearning[change.Key] = struct{}{}
				continue
			}
			if incompleteChange(change, protectedTargetProtocols, protectedTargets) {
				// A positive port addition can still be authoritative when its
				// evidence names only effective addresses that completed. This is
				// important for DNS targets: one timed-out sibling must not hide a
				// newly open port on a healthy address. Removals and service changes
				// remain protected because their aggregate evidence is ambiguous.
				if incompletePositiveAddition(change, scan.Snapshot, incompleteProtocols) {
					filtered = append(filtered, change)
				}
				continue
			}
			filtered = append(filtered, change)
		}
		changes = filtered
		// Unlike a complete scan, an incomplete one retires nothing that it
		// could not compare; such a finding waits for a complete scan.
		seen := observe(state, job, scanView{
			snapshot: scan.Snapshot, changes: changes, scopeChanged: state.BaselineConfigHash != scan.ConfigHash,
			incomplete: &missingCoverage{protocols: protectedTargetProtocols, targets: protectedTargets}, deferred: deferredLearning,
		})
		events = append(events, applyObservedChanges(state, job.Name, scan.ID, changes, job.Change.Confirmations, scan.FinishedAt, seen)...)
	}
	message := incompleteScanError(scan.Snapshot)
	events = append(events, model.Event{Type: "scan-incomplete", Job: scan.Job, ScanID: scan.ID, Message: message, CreatedAt: scan.FinishedAt})
	if state.Baseline == nil && state.IncompleteCandidateAttempts == BaselineStallThreshold {
		events = append(events, model.Event{Type: "baseline-stalled", Job: scan.Job, ScanID: scan.ID, Message: fmt.Sprintf("Baseline learning is stalled after %d incomplete scans", state.IncompleteCandidateAttempts), CreatedAt: scan.FinishedAt})
	}
	return events, changes, nil
}

// incompletePositiveAddition reports whether a positive port addition is
// attributable only to effective addresses whose coverage completed for that
// protocol. Legacy evidence without addresses remains conservatively blocked.
// A port that opened on one address of a DNS target names that address, so
// it is reported when that address completed; a closure on one address is
// deferred like any other removal.
func incompletePositiveAddition(change model.Change, snapshot model.Snapshot, incomplete incompleteCoverage) bool {
	if change.Kind == "port-address" {
		return isPositivePortState(change.New) && !incompleteCoverageHas(incomplete, change.Address, change.Protocol)
	}
	if change.Kind != "port" || !isPositivePortState(change.New) {
		return false
	}
	for _, unit := range snapshot.Units {
		if unit.Target != change.Target || !strings.EqualFold(unit.Protocol, change.Protocol) {
			continue
		}
		for _, port := range unit.Ports {
			if port.Port != change.Port || !strings.EqualFold(port.State, change.New) || len(port.Evidence) == 0 {
				continue
			}
			for _, address := range port.Evidence {
				if incompleteCoverageHas(incomplete, address, change.Protocol) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func isPositivePortState(state string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	return state == "open" || state == "open|filtered"
}

func clearPendingTotalLoss(state *model.JobState) {
	for key, pending := range state.Pending {
		if pending.Change.New == "not-open" {
			delete(state.Pending, key)
		}
	}
}

const totalLossConfirmationScans = 2

// BaselineStallThreshold bounds the number of incomplete attempts before the
// operator is warned that baseline learning cannot converge.
const BaselineStallThreshold = 3

// guardTotalLoss returns a scan-level anomaly event while a zero-positive
// result is awaiting one matching confirmation. Once the confirmation count
// is reached, the confirmed state is kept for the rest of the outage so later
// zero-positive scans go straight to normal comparison. A scan with positive
// ports, a scope change, or a replaced baseline ends it.
func guardTotalLoss(state *model.JobState, scan model.Scan) (bool, []model.Event) {
	baselinePositive := positivePortCount(*state.Baseline)
	currentPositive := positivePortCount(scan.Snapshot)
	// A changed security hash is an administrator-requested scope transition;
	// don't block its fresh baseline collection. Missing hashes are legacy
	// state, so retain the safety check for those installations.
	if baselinePositive == 0 || currentPositive != 0 || (state.BaselineConfigHash != "" && scan.ConfigHash != "" && state.BaselineConfigHash != scan.ConfigHash) {
		clearTotalLossCandidate(state)
		return false, nil
	}
	identity := totalLossIdentity(state, scan)
	if state.TotalLossCandidateHash != identity {
		state.TotalLossCandidateHash = identity
		state.TotalLossCandidateCount = 1
	} else if state.TotalLossCandidateCount < totalLossConfirmationScans {
		state.TotalLossCandidateCount++
	}
	if state.TotalLossCandidateCount < totalLossConfirmationScans {
		return true, []model.Event{{
			Type:      "scan-anomaly",
			Job:       scan.Job,
			ScanID:    scan.ID,
			Message:   fmt.Sprintf("Scan returned zero positive ports while the baseline contains %d; awaiting confirmation", baselinePositive),
			CreatedAt: scan.FinishedAt,
		}}
	}
	return false, nil
}

// totalLossIdentity names the zero-positive evidence that a confirmation
// must match: the same monitored scope observed empty against the same
// baseline. DNS answers, effective addresses, and non-positive port details
// are deliberately excluded, so a DNS target whose resolved addresses rotate
// can still confirm a total loss.
func totalLossIdentity(state *model.JobState, scan model.Scan) string {
	payload, _ := json.Marshal(struct {
		BaselineScanID string `json:"baseline_scan_id"`
		ConfigHash     string `json:"config_hash"`
		Scope          string `json:"scope"`
	}{
		BaselineScanID: state.BaselineScanID,
		ConfigHash:     scan.ConfigHash,
		Scope:          model.Snapshot{Scopes: scan.Snapshot.Scopes}.Hash(),
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func clearTotalLossCandidate(state *model.JobState) {
	state.TotalLossCandidateHash = ""
	state.TotalLossCandidateCount = 0
}

// clearUnconfirmedTotalLoss discards a zero-positive candidate that is still
// awaiting its matching confirmation. A failed or incomplete scan interrupts
// that sequence, but it has no positive evidence that ports returned, so an
// already confirmed total loss is kept.
func clearUnconfirmedTotalLoss(state *model.JobState) {
	if state.TotalLossCandidateCount < totalLossConfirmationScans {
		clearTotalLossCandidate(state)
	}
}

func positivePortCount(snapshot model.Snapshot) int {
	seen := make(map[string]struct{})
	for _, unit := range snapshot.Units {
		for _, port := range unit.Ports {
			state := strings.ToLower(strings.TrimSpace(port.State))
			if state != "open" && state != "open|filtered" {
				continue
			}
			key := fmt.Sprintf("%s\x00%s\x00%d", unit.Target, unit.Protocol, port.Port)
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

func snapshotHasUnreachableHost(snapshot model.Snapshot) bool {
	return len(snapshot.TargetFailures) > 0 || len(incompleteHostAddresses(snapshot)) > 0
}

func incompleteScanError(snapshot model.Snapshot) string {
	addresses := incompleteHostAddresses(snapshot)
	for _, failure := range snapshot.TargetFailures {
		if target := strings.TrimSpace(failure.Target); target != "" {
			addresses = append(addresses, target)
		}
	}
	addresses = sortedUniqueStrings(addresses)
	if len(addresses) == 0 {
		return "Scan incomplete: scan coverage did not complete"
	}
	const previewLimit = 8
	if len(addresses) > previewLimit {
		return fmt.Sprintf("Scan incomplete: scan coverage did not complete for %s (+%d more)", strings.Join(addresses[:previewLimit], ", "), len(addresses)-previewLimit)
	}
	return "Scan incomplete: scan coverage did not complete for " + strings.Join(addresses, ", ")
}

type incompleteCoverage map[string]map[string]struct{}

// scanCompleteCoverageReason is emitted by the Naabu full-range discovery
// phase when every port was examined but no positive JSONL records were
// produced. The host remains unknown for display, but this reason means the
// scan covered its configured scope and must not be treated as a partial
// result. Other unknown observations (for example unknown/no-response from a
// failed or legacy scan) remain conservatively incomplete.
const scanCompleteCoverageReason = "scan-complete"

type protocolCoverageStatus struct {
	status          string
	reason          string
	discoveryState  string
	discoveryEngine string
}

func incompleteProtocolCoverage(snapshot model.Snapshot) incompleteCoverage {
	coverage := incompleteCoverage{}
	mark := func(address, protocol string) {
		address = strings.TrimSpace(address)
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if address == "" {
			return
		}
		if protocol == "" {
			protocol = "*"
		}
		if coverage[address] == nil {
			coverage[address] = make(map[string]struct{})
		}
		coverage[address][protocol] = struct{}{}
	}
	expected := make(map[string]map[string]struct{})
	addExpected := func(address, protocol string) {
		address = strings.TrimSpace(address)
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if address == "" || protocol == "" {
			return
		}
		if expected[address] == nil {
			expected[address] = make(map[string]struct{})
		}
		expected[address][protocol] = struct{}{}
	}
	addressesFor := func(target string, addresses []string) []string {
		if len(addresses) > 0 {
			return addresses
		}
		if resolved := snapshot.DNS[target]; len(resolved) > 0 {
			return resolved
		}
		return []string{target}
	}
	for _, scope := range snapshot.Scopes {
		for _, address := range addressesFor(scope.Target, nil) {
			addExpected(address, scope.Protocol)
		}
	}
	for _, unit := range snapshot.Units {
		for _, address := range addressesFor(unit.Target, unit.Addresses) {
			addExpected(address, unit.Protocol)
		}
	}
	for _, host := range snapshot.Hosts {
		statuses := make(map[string]protocolCoverageStatus, len(host.Protocols))
		for _, protocol := range host.Protocols {
			name := strings.ToLower(strings.TrimSpace(protocol.Protocol))
			status := strings.ToLower(strings.TrimSpace(protocol.Status))
			reason := strings.TrimSpace(protocol.StatusReason)
			if name == "" {
				continue
			}
			discoveryState := strings.ToLower(strings.TrimSpace(protocol.DiscoveryState))
			discoveryEngine := strings.ToLower(strings.TrimSpace(protocol.DiscoveryEngine))
			observed := protocolCoverageStatus{status: status, reason: reason, discoveryState: discoveryState, discoveryEngine: discoveryEngine}
			incomplete := isIncompleteCoverageObservation(status, reason) && !isCompletedProtocolHostDiscoveryDown(protocol)
			// Protocol failures are sticky even if a duplicate fragment reports
			// the address as healthy later. A blank status is retained only until
			// explicit evidence for the same protocol is available.
			existing := statuses[name]
			if incomplete || existing.status == "" || (existing.status == "unknown" && strings.EqualFold(existing.reason, scanCompleteCoverageReason) && status == "up") {
				statuses[name] = observed
			}
			if incomplete {
				mark(host.Address, name)
			}
		}
		if !isIncompleteCoverageObservation(host.Status, host.StatusReason) {
			continue
		}
		protocols := make(map[string]struct{}, len(expected[host.Address])+len(statuses))
		for protocol := range expected[host.Address] {
			protocols[protocol] = struct{}{}
		}
		for protocol := range statuses {
			protocols[protocol] = struct{}{}
		}
		if len(protocols) == 0 {
			mark(host.Address, "*")
			continue
		}
		for protocol := range protocols {
			status, observed := statuses[protocol]
			completeDown := observed && status.discoveryEngine != "naabu" && isCompletedHostDiscoveryDown(status.status, status.reason, status.discoveryState)
			if !observed || (status.status != "up" && !completeDown) {
				mark(host.Address, protocol)
			}
		}
	}
	return coverage
}

func isIncompleteCoverageStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "unreachable", "down", "timedout", "timed-out", "timeout", "unknown":
		return true
	default:
		return false
	}
}

func isIncompleteCoverageObservation(status, reason string) bool {
	if strings.EqualFold(strings.TrimSpace(status), "unknown") && strings.EqualFold(strings.TrimSpace(reason), scanCompleteCoverageReason) {
		return false
	}
	return isIncompleteCoverageStatus(status)
}

func isCompletedHostDiscoveryDown(status, reason, discoveryState string) bool {
	if strings.ToLower(strings.TrimSpace(discoveryState)) != "down" {
		return false
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "down" && status != "unreachable" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "nmap-host-down", "host-down", "down", "no-response", "host-unreach", "net-unreach", "admin-prohibited":
		return true
	default:
		return false
	}
}

func isCompletedProtocolHostDiscoveryDown(protocol model.ProtocolObservation) bool {
	// A Naabu TCP discovery result cannot be overridden by contradictory Nmap
	// enrichment evidence. Keep the protocol incomplete so its ports cannot be
	// treated as closed or used to seed a baseline.
	if strings.EqualFold(strings.TrimSpace(protocol.DiscoveryEngine), "naabu") {
		return false
	}
	return isCompletedHostDiscoveryDown(protocol.Status, protocol.StatusReason, protocol.DiscoveryState)
}

func incompleteCoverageHas(coverage incompleteCoverage, address, protocol string) bool {
	protocols := coverage[strings.TrimSpace(address)]
	if _, ok := protocols["*"]; ok {
		return true
	}
	_, ok := protocols[strings.ToLower(strings.TrimSpace(protocol))]
	return ok
}

func incompleteHostAddresses(snapshot model.Snapshot) []string {
	coverage := incompleteProtocolCoverage(snapshot)
	addresses := make([]string, 0, len(coverage))
	for address := range coverage {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses
}

// MarkIncompleteScan turns an otherwise successful result into an explicit
// partial outcome. The status is stored in history and deliberately excluded
// from successful-host projections, while the engine still compares its
// reachable evidence.
func MarkIncompleteScan(scan *model.Scan) bool {
	if scan == nil || scan.Status != "success" {
		return false
	}
	completeHostDiscoveryStates(&scan.Snapshot)
	if !snapshotHasUnreachableHost(scan.Snapshot) {
		return false
	}
	scan.Status = "incomplete"
	scan.Error = incompleteScanError(scan.Snapshot)
	return true
}

// completeHostDiscoveryStates derives the small monitored host-state set from
// explicit Nmap discovery results. Unknown, omitted, timed-out, and Naabu-only
// observations never become a baseline state. Existing explicit states are
// preserved so accepting an incident in a runtime baseline remains stable.
func completeHostDiscoveryStates(snapshot *model.Snapshot) {
	if snapshot == nil {
		return
	}
	expected := map[string]map[string]struct{}{}
	addExpected := func(address, protocol string) {
		address = strings.TrimSpace(address)
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if address == "" || protocol == "" {
			return
		}
		if expected[address] == nil {
			expected[address] = map[string]struct{}{}
		}
		expected[address][protocol] = struct{}{}
	}
	for _, scope := range snapshot.Scopes {
		addresses := snapshot.DNS[scope.Target]
		if len(addresses) == 0 {
			addresses = []string{scope.Target}
		}
		for _, address := range addresses {
			addExpected(address, scope.Protocol)
		}
	}
	discovery := map[string]map[string]string{}
	for _, host := range snapshot.Hosts {
		for _, protocol := range host.Protocols {
			name := strings.ToLower(strings.TrimSpace(protocol.Protocol))
			state := strings.ToLower(strings.TrimSpace(protocol.DiscoveryState))
			if name == "" || (state != "up" && state != "down") || protocol.DiscoveryEngine == "naabu" {
				continue
			}
			if state == "down" && !isCompletedProtocolHostDiscoveryDown(protocol) {
				continue
			}
			if state == "up" && strings.ToLower(strings.TrimSpace(protocol.Status)) != "up" {
				continue
			}
			address := strings.TrimSpace(host.Address)
			if discovery[address] == nil {
				discovery[address] = map[string]string{}
			}
			previous := discovery[address][name]
			if previous == "conflict" {
				continue
			}
			if previous != "" && previous != state {
				// Different Nmap work fragments disagreed. Do not turn a
				// contradictory result into an expected up/down state.
				discovery[address][name] = "conflict"
				continue
			}
			if _, exists := discovery[address][name]; !exists {
				discovery[address][name] = state
			}
			addExpected(address, name)
		}
	}
	states := make(map[string]string, len(snapshot.HostStates))
	for _, host := range snapshot.HostStates {
		address := strings.TrimSpace(host.Address)
		state := strings.ToLower(strings.TrimSpace(host.State))
		if address != "" && (state == "up" || state == "down") {
			states[address] = state
		}
	}
	for address, protocols := range expected {
		observed := discovery[address]
		if len(protocols) == 0 || len(observed) == 0 {
			continue
		}
		allDown := true
		anyUp := false
		for protocol := range protocols {
			state := observed[protocol]
			if state == "up" {
				anyUp = true
			}
			if state != "down" {
				allDown = false
			}
		}
		if anyUp {
			states[address] = "up"
		} else if allDown {
			states[address] = "down"
		}
	}
	snapshot.HostStates = snapshot.HostStates[:0]
	for address, state := range states {
		snapshot.HostStates = append(snapshot.HostStates, model.HostState{Address: address, State: state})
	}
	snapshot.Normalize()
}

func hostStateChanges(old, current model.Snapshot, intersectionOnly bool) []model.Change {
	oldStates, newStates := effectiveHostStates(old), effectiveHostStates(current)
	addresses := make(map[string]struct{}, len(oldStates)+len(newStates))
	for address := range oldStates {
		addresses[address] = struct{}{}
	}
	for address := range newStates {
		addresses[address] = struct{}{}
	}
	var changes []model.Change
	for address := range addresses {
		oldState, hadOld := oldStates[address]
		newState, hasNew := newStates[address]
		if !hadOld || !hasNew || oldState == newState {
			continue
		}
		change := model.Change{Key: "host|" + address, Kind: "host", Target: address, Old: oldState, New: newState, Severity: "warning"}
		if newState == "up" {
			change.Severity = "info"
		}
		if intersectionOnly && (!hostInScope(old, address) || !hostInScope(current, address)) {
			continue
		}
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes
}

func effectiveHostStates(snapshot model.Snapshot) map[string]string {
	states := make(map[string]string, len(snapshot.HostStates))
	for _, host := range snapshot.HostStates {
		address := strings.TrimSpace(host.Address)
		state := strings.ToLower(strings.TrimSpace(host.State))
		if address != "" && (state == "up" || state == "down") {
			states[address] = state
		}
	}
	for _, unit := range snapshot.Units {
		for _, port := range unit.Ports {
			if !isPositivePortState(port.State) {
				continue
			}
			addresses := port.Evidence
			if len(addresses) == 0 {
				addresses = unit.Addresses
			}
			if len(addresses) == 0 && net.ParseIP(strings.TrimSpace(unit.Target)) != nil {
				addresses = []string{unit.Target}
			}
			if len(addresses) == 1 {
				if _, exists := states[addresses[0]]; !exists {
					states[addresses[0]] = "up"
				}
			}
		}
	}
	return states
}

func hostInScope(snapshot model.Snapshot, address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	for _, scope := range snapshot.Scopes {
		target := strings.TrimSpace(scope.Target)
		if target == address {
			return true
		}
		if _, network, err := net.ParseCIDR(target); err == nil && ip != nil && network.Contains(ip) {
			return true
		}
		for _, resolved := range snapshot.DNS[target] {
			if strings.TrimSpace(resolved) == strings.TrimSpace(address) {
				return true
			}
		}
	}
	return false
}

func incompleteTargets(baseline *model.Snapshot, current model.Snapshot, coverage incompleteCoverage) (map[string]struct{}, map[string]struct{}) {
	protectedProtocols := make(map[string]struct{})
	protectedTargets := make(map[string]struct{})
	addTarget := func(target, protocol string) {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		protectedProtocols[target+"\x00"+protocol] = struct{}{}
		protectedTargets[target] = struct{}{}
	}
	for _, snapshot := range []*model.Snapshot{baseline, &current} {
		if snapshot == nil {
			continue
		}
		for _, scope := range snapshot.Scopes {
			addresses := snapshot.DNS[scope.Target]
			if len(addresses) == 0 {
				addresses = []string{scope.Target}
			}
			for _, address := range addresses {
				if incompleteCoverageHas(coverage, address, scope.Protocol) {
					addTarget(scope.Target, scope.Protocol)
					break
				}
			}
		}
		for _, unit := range snapshot.Units {
			addresses := unit.Addresses
			if len(addresses) == 0 {
				addresses = []string{unit.Target}
			}
			for _, address := range addresses {
				if incompleteCoverageHas(coverage, address, unit.Protocol) {
					addTarget(unit.Target, unit.Protocol)
					break
				}
			}
		}
		for _, failure := range snapshot.TargetFailures {
			if strings.TrimSpace(failure.Target) == "" {
				continue
			}
			protectedTargets[failure.Target] = struct{}{}
			for _, scope := range snapshot.Scopes {
				if scope.Target == failure.Target {
					addTarget(scope.Target, scope.Protocol)
				}
			}
			for _, unit := range snapshot.Units {
				if unit.Target == failure.Target {
					addTarget(unit.Target, unit.Protocol)
				}
			}
		}
	}
	for address := range coverage {
		// Host-state changes use the effective address as their target, whereas
		// aggregate DNS port changes use the configured hostname.
		protectedTargets[address] = struct{}{}
	}
	return protectedProtocols, protectedTargets
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	unique := values[:1]
	for _, value := range values[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

func incompleteChange(change model.Change, protocols, targets map[string]struct{}) bool {
	if strings.TrimSpace(change.Protocol) == "" {
		_, ok := targets[change.Target]
		return ok
	}
	_, ok := protocols[change.Target+"\x00"+strings.ToLower(strings.TrimSpace(change.Protocol))]
	return ok
}

func advanceCandidate(state *model.JobState, scan model.Scan, required int, merge bool) []model.Event {
	return advanceCandidateWithDNSMode(state, scan, required, merge, config.DNSComparisonAddressSensitive)
}

func advanceCandidateWithDNSMode(state *model.JobState, scan model.Scan, required int, merge bool, dnsMode string) []model.Event {
	updateFingerprintCandidates(state, scan.Snapshot)
	hash := snapshotHashForDNSMode(scan.Snapshot, dnsMode)
	state.CandidateAttempts++
	candidate := cloneSnapshot(scan.Snapshot)
	if state.CandidateHash == hash {
		state.CandidateCount++
		// The convergence identity may intentionally omit descriptive or
		// volatile address evidence. Keep the candidate snapshot current even
		// when that normalized identity is unchanged, so the accepted baseline
		// reflects the latest successful sample rather than the first one.
		state.Candidate = &candidate
	} else {
		state.Candidate = &candidate
		state.CandidateHash = hash
		state.CandidateCount = 1
	}
	if state.CandidateCount >= required {
		stableCandidate := withStableFingerprints(*state.Candidate, state.FingerprintCandidates, required)
		if merge && state.Baseline != nil {
			merged := mergeForScopeChange(*state.Baseline, stableCandidate)
			state.Baseline = &merged
		} else {
			baseline := stableCandidate
			state.Baseline = &baseline
		}
		state.BaselineScanID = scan.ID
		state.BaselineConfigHash = scan.ConfigHash
		state.BaselineModified = false
		// The new baseline records what the scans observed, so a port without
		// a stable fingerprint in it may learn one again.
		state.ServiceDecisionRequired = nil
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		state.IncompleteCandidateAttempts = 0
		typeName := "baseline-complete"
		message := "Baseline established"
		if merge {
			typeName = "baseline-updated"
			message = "Baseline updated for changed scan scope"
		}
		return []model.Event{{Type: typeName, Job: scan.Job, ScanID: scan.ID, Message: message, CreatedAt: scan.FinishedAt}}
	}
	stallAt := required * 3
	if stallAt < BaselineStallThreshold {
		stallAt = BaselineStallThreshold
	}
	if state.CandidateAttempts == stallAt {
		return []model.Event{{Type: "baseline-stalled", Job: scan.Job, ScanID: scan.ID, Message: fmt.Sprintf("Baseline has not converged after %d scans", state.CandidateAttempts), CreatedAt: scan.FinishedAt}}
	}
	return nil
}

func snapshotHashForDNSMode(snapshot model.Snapshot, dnsMode string) string {
	if dnsMode != config.DNSComparisonAggregate {
		return addressSensitiveSnapshotHash(snapshot)
	}
	stable := cloneSnapshot(snapshot)
	dnsTargets := dnsTargetsInSnapshot(stable)
	dnsAddresses := dnsAddressesInSnapshot(stable)
	if len(dnsTargets) > 0 {
		stable.DNS = make(map[string][]string, len(dnsTargets))
		for target := range dnsTargets {
			stable.DNS[target] = []string{}
		}
		for index := range stable.Units {
			unit := &stable.Units[index]
			if _, isDNS := dnsTargets[unit.Target]; !isDNS {
				continue
			}
			unit.Addresses = nil
			for portIndex := range unit.Ports {
				unit.Ports[portIndex].Evidence = nil
			}
		}
		states := stable.HostStates[:0]
		for _, host := range stable.HostStates {
			if _, dnsAddress := dnsAddresses[host.Address]; dnsAddress && !snapshotHasNonDNSAddressScope(stable, host.Address) {
				continue
			}
			states = append(states, host)
		}
		stable.HostStates = states
	}
	stable.Normalize()
	return stable.Hash()
}

// addressSensitiveSnapshotHash extends the snapshot hash, which leaves out
// port evidence, with the addresses that expose each positive port of a DNS
// target. Address-sensitive mode compares those addresses, so samples whose
// ports differ between a name's addresses must not converge into one
// baseline. A snapshot without such evidence keeps the snapshot hash.
func addressSensitiveSnapshotHash(snapshot model.Snapshot) string {
	hash := snapshot.Hash()
	var exposures []string
	for _, unit := range snapshot.Units {
		if !isDNSComparisonTarget(unit.Target) {
			continue
		}
		for _, port := range unit.Ports {
			if !isPositivePortState(port.State) || len(port.Evidence) == 0 {
				continue
			}
			addresses := make([]string, 0, len(port.Evidence))
			for address := range canonicalAddressSet(port.Evidence) {
				addresses = append(addresses, address)
			}
			sort.Strings(addresses)
			exposures = append(exposures, fmt.Sprintf("%s\x00%s\x00%d\x00%s", unit.Target, unit.Protocol, port.Port, strings.Join(addresses, ",")))
		}
	}
	if len(exposures) == 0 {
		return hash
	}
	sort.Strings(exposures)
	payload, _ := json.Marshal(struct {
		Snapshot      string   `json:"snapshot"`
		PortAddresses []string `json:"port_addresses"`
	}{Snapshot: hash, PortAddresses: exposures})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func fingerprintKey(target, protocol string, port int) string {
	return fmt.Sprintf("service|%s|%s|%d", target, protocol, port)
}

func updateFingerprintCandidates(state *model.JobState, snapshot model.Snapshot) {
	seen := map[string]bool{}
	for _, unit := range snapshot.Units {
		for _, port := range unit.Ports {
			if port.Service == "" {
				continue
			}
			key := fingerprintKey(unit.Target, unit.Protocol, port.Port)
			seen[key] = true
			candidate := state.FingerprintCandidates[key]
			if candidate.Value == port.Service {
				candidate.Count++
			} else {
				candidate = model.ValueCount{Value: port.Service, Count: 1}
			}
			state.FingerprintCandidates[key] = candidate
		}
	}
	for key := range state.FingerprintCandidates {
		if !seen[key] {
			delete(state.FingerprintCandidates, key)
		}
	}
}

func withStableFingerprints(snapshot model.Snapshot, candidates map[string]model.ValueCount, required int) model.Snapshot {
	for i := range snapshot.Units {
		for j := range snapshot.Units[i].Ports {
			port := &snapshot.Units[i].Ports[j]
			candidate := candidates[fingerprintKey(snapshot.Units[i].Target, snapshot.Units[i].Protocol, port.Port)]
			if candidate.Count < required || candidate.Value != port.Service {
				port.Service = ""
			}
		}
	}
	return snapshot
}

// learnMissingFingerprints fills in the service of a baseline port that was
// established without a stable fingerprint. It returns the service keys that
// are still collecting samples so their changes are not reported yet.
func learnMissingFingerprints(state *model.JobState, current model.Snapshot, required int) map[string]struct{} {
	learning := map[string]struct{}{}
	if state.Baseline == nil {
		return learning
	}
	seen := map[string]bool{}
	for _, unit := range current.Units {
		for _, port := range unit.Ports {
			if port.Service == "" || !fingerprintLearnable(state, unit.Target, unit.Protocol, port.Port) {
				continue
			}
			key := fingerprintKey(unit.Target, unit.Protocol, port.Port)
			seen[key] = true
			candidate := state.FingerprintCandidates[key]
			if candidate.Value == port.Service {
				candidate.Count++
			} else {
				candidate = model.ValueCount{Value: port.Service, Count: 1}
			}
			state.FingerprintCandidates[key] = candidate
			if candidate.Count >= required {
				if setBaselineService(state.Baseline, unit.Target, unit.Protocol, port.Port, candidate.Value) {
					// The learned service is an expected-state mutation that does not
					// replace the immutable source scan. Host explorer reads must use the
					// runtime baseline until a later scan establishes a new source.
					state.BaselineModified = true
				}
				delete(state.FingerprintCandidates, key)
			} else {
				learning[key] = struct{}{}
			}
		}
	}
	for key := range state.FingerprintCandidates {
		if strings.HasPrefix(key, "service|") && !seen[key] {
			delete(state.FingerprintCandidates, key)
		}
	}
	return learning
}

// fingerprintLearnable reports whether a complete scan learns an observed
// service of this port instead of comparing it. It does not change state, so
// an incomplete scan can use it to defer the same services.
func fingerprintLearnable(state *model.JobState, target, protocol string, port int) bool {
	if state.Baseline == nil || !scopeAllows(*state.Baseline, target, protocol, port, true) {
		return false
	}
	// Only a port that is already expected can learn its missing
	// fingerprint. The service of a port that is not in the baseline is
	// part of that port's new observation and goes through the normal
	// comparison; learning it here could never complete and would make
	// the service incident open and recover on alternate scans.
	expected, ok := baselinePort(*state.Baseline, target, protocol, port)
	if !ok || expected.Service != "" {
		return false
	}
	key := fingerprintKey(target, protocol, port)
	// A service incident reported before its port entered the baseline
	// (for example, when an operator accepted the port first) stays
	// under normal comparison until the operator acts on it. Learning it
	// now would recover an unchanged fingerprint. The same holds after
	// the incident is suppressed or recovers: the port was accepted
	// without its service, so only an accepted service ends the
	// comparison. The suppression check also covers a port accepted
	// before accepted ports were recorded.
	_, reported := state.Incidents[key]
	_, suppressed := state.Suppressed[key]
	return !reported && !suppressed && !state.ServiceDecisionRequired[key]
}

func baselineService(snapshot model.Snapshot, target, protocol string, port int) string {
	value, _ := baselinePort(snapshot, target, protocol, port)
	return value.Service
}

// baselinePort distinguishes a baseline port without a fingerprint from a
// port that is absent from the baseline.
func baselinePort(snapshot model.Snapshot, target, protocol string, port int) (model.PortState, bool) {
	for _, unit := range snapshot.Units {
		if unit.Target != target || unit.Protocol != protocol {
			continue
		}
		for _, value := range unit.Ports {
			if value.Port == port {
				return value, true
			}
		}
	}
	return model.PortState{}, false
}

func setBaselineService(snapshot *model.Snapshot, target, protocol string, port int, service string) bool {
	for i := range snapshot.Units {
		if snapshot.Units[i].Target != target || snapshot.Units[i].Protocol != protocol {
			continue
		}
		for j := range snapshot.Units[i].Ports {
			if snapshot.Units[i].Ports[j].Port == port {
				if snapshot.Units[i].Ports[j].Service == service {
					return false
				}
				snapshot.Units[i].Ports[j].Service = service
				return true
			}
		}
	}
	return false
}

func (e *Engine) Failure(ctx context.Context, job string, scan model.Scan) ([]model.Event, error) {
	return e.Store.System().UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func (e *Engine) FailureForJob(ctx context.Context, jobID, job string, scan model.Scan) ([]model.Event, error) {
	return e.Store.System().UpdateRuntimeForScan(ctx, jobID, scan.ConfigHash, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func (e *Engine) FailureForJobWithDestinations(ctx context.Context, jobID, job string, scan model.Scan, destinations []string) ([]model.Event, error) {
	return e.Store.System().UpdateRuntimeForScanWithOutbox(ctx, jobID, scan.ConfigHash, destinations, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func processFailure(state *model.JobState, job string, scan model.Scan) ([]model.Event, error) {
	clearUnconfirmedTotalLoss(state)
	if scan.Interrupted {
		// A restart is not an operator's cancellation. Keep it in the
		// activity history without notifying anyone; the job-silence alert
		// still reports a daemon that keeps stopping.
		message := "Scan interrupted"
		if reason := strings.TrimSpace(scan.Error); reason != "" {
			message = sanitizeNotificationText(strings.ToUpper(reason[:1]) + reason[1:])
		}
		return []model.Event{{Type: model.EventScanInterrupted, Job: job, ScanID: scan.ID, Message: message, CreatedAt: scan.FinishedAt}}, nil
	}
	if scan.Resumable && scan.CycleStatus == "paused" {
		if scan.Status == "canceled" {
			return []model.Event{{Type: "scan-canceled", Job: job, ScanID: scan.ID, Message: scanOutcomeMessage(scan), CreatedAt: scan.FinishedAt}}, nil
		}
		return []model.Event{{Type: "scan-paused", Job: job, ScanID: scan.ID, Message: scanOutcomeMessage(scan), CreatedAt: scan.FinishedAt}}, nil
	}
	if scan.Status == "canceled" {
		return []model.Event{{Type: "scan-canceled", Job: job, ScanID: scan.ID, Message: scanOutcomeMessage(scan), CreatedAt: scan.FinishedAt}}, nil
	}
	state.ConsecutiveFailures++
	// A terminal failure is actionable even when it is the first failure. Keep
	// the counters for dashboard health and future alert policies, but do not
	// suppress the notification that explains the failed run.
	state.LastFailureAlert = state.ConsecutiveFailures
	return []model.Event{{Type: "scan-failure", Job: job, ScanID: scan.ID, Message: scanOutcomeMessage(scan), CreatedAt: scan.FinishedAt}}, nil
}

func scanOutcomeMessage(scan model.Scan) string {
	label := strings.TrimSpace(scan.Status)
	switch label {
	case "":
		label = "failed"
	case "canceled":
		label = "canceled"
	case "timed_out", "timeout", "timed-out":
		label = "timed out"
	default:
		label = strings.ReplaceAll(label, "_", " ")
	}
	message := "Scan " + label
	if reason := strings.TrimSpace(scan.Error); reason != "" {
		message += ": " + sanitizeNotificationText(reason)
	}
	return message
}

type item struct {
	Kind, Target, Protocol string
	Port                   int
	Value, Severity        string
}

func items(s model.Snapshot) map[string]item {
	out := map[string]item{}
	for _, u := range s.Units {
		for _, p := range u.Ports {
			key := fmt.Sprintf("port|%s|%s|%d", u.Target, u.Protocol, p.Port)
			sev := "critical"
			if p.State == "open|filtered" {
				sev = "warning"
			}
			out[key] = item{"port", u.Target, u.Protocol, p.Port, p.State, sev}
			if p.Service != "" {
				key = fmt.Sprintf("service|%s|%s|%d", u.Target, u.Protocol, p.Port)
				out[key] = item{"service", u.Target, u.Protocol, p.Port, p.Service, "warning"}
			}
		}
	}
	for target, addresses := range s.DNS {
		for _, address := range addresses {
			key := "dns|" + target + "|" + address
			out[key] = item{"dns", target, "", 0, address, "warning"}
		}
	}
	return out
}

func Diff(old, new model.Snapshot, intersectionOnly bool) []model.Change {
	return diffWithDownAddresses(old, new, intersectionOnly, completedDownAddressesByProtocol(new))
}

func diffWithDownAddresses(old, new model.Snapshot, intersectionOnly bool, downByProtocol map[string]map[string]struct{}) []model.Change {
	a, b := items(old), items(new)
	newPositivePorts := make(map[string]struct{})
	for _, unit := range new.Units {
		for _, port := range unit.Ports {
			if isPositivePortState(port.State) {
				newPositivePorts[fmt.Sprintf("port|%s|%s|%d", unit.Target, unit.Protocol, port.Port)] = struct{}{}
			}
		}
	}
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []model.Change
	for key := range keys {
		x, xok := a[key]
		y, yok := b[key]
		probe := x
		if yok {
			probe = y
		}
		if intersectionOnly && !inBothScopes(old, new, probe) {
			continue
		}
		// A service fingerprint is evidence about a positively observed port,
		// not an independent service removal when that port has closed. The
		// port change below represents the single operator-facing transition.
		if probe.Kind == "service" {
			portKey := fmt.Sprintf("port|%s|%s|%d", probe.Target, probe.Protocol, probe.Port)
			if _, positive := newPositivePorts[portKey]; !positive {
				continue
			}
		}
		if xok && yok && x.Value == y.Value {
			continue
		}
		c := model.Change{Key: key, Kind: probe.Kind, Severity: probe.Severity, Target: probe.Target, Protocol: probe.Protocol, Port: probe.Port}
		if probe.Kind == "dns" {
			if !xok {
				c.Kind = "dns-added"
				c.New = y.Value
			} else {
				c.Kind = "dns-removed"
				c.Old = x.Value
			}
		} else {
			if xok {
				c.Old = x.Value
			} else {
				c.Old = "not-open"
			}
			if yok {
				c.New = y.Value
			} else {
				c.New = "not-open"
			}
			if c.New == "not-open" {
				c.Severity = "info"
			}
		}
		if !yok && xok && (probe.Kind == "port" || probe.Kind == "service") && missingPositivePortExplainedByDown(old, probe, downByProtocol) {
			continue
		}
		out = append(out, c)
	}
	_, portAddresses := comparePortAddresses(old, new, intersectionOnly, downByProtocol)
	out = append(out, portAddresses...)
	out = append(out, hostStateChanges(old, new, intersectionOnly)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func portAddressKey(target, protocol string, port int, address string) string {
	return fmt.Sprintf("port-address|%s|%s|%d|%s", target, protocol, port, address)
}

// comparePortAddresses compares which resolved addresses of a DNS target
// expose each of its ports. The target is one logical unit whose ports are
// merged across its DNS answer, so the port comparison cannot see a port that
// opens on one address while another address already exposes it, or that
// closes on one address while another keeps it open. Each such difference is
// one port-address change.
//
// Only a port that is positive in both snapshots, with address evidence in
// both, is compared, and only on addresses in both DNS answers: a port that
// appears or disappears altogether is a port change, an answer that changed
// is a dns-added or dns-removed change, and a port without evidence, as in
// an older baseline, has unknown addresses. A port missing from an address
// whose host discovery completed down is that host's state change.
//
// It returns the key of every comparison it made, whether or not the address
// changed, together with the changes.
func comparePortAddresses(old, current model.Snapshot, intersectionOnly bool, downByProtocol map[string]map[string]struct{}) (map[string]struct{}, []model.Change) {
	compared := map[string]struct{}{}
	var changes []model.Change
	oldUnits := unitMap(old)
	for _, unit := range current.Units {
		if !isDNSComparisonTarget(unit.Target) {
			continue
		}
		oldUnit, ok := oldUnits[unit.Target+"\x00"+unit.Protocol]
		if !ok {
			continue
		}
		oldAnswer := canonicalAddressSet(old.DNS[unit.Target])
		var addresses []string
		for address := range canonicalAddressSet(current.DNS[unit.Target]) {
			if _, inBoth := oldAnswer[address]; inBoth && net.ParseIP(address) != nil {
				addresses = append(addresses, address)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		sort.Strings(addresses)
		oldPorts := make(map[int]model.PortState, len(oldUnit.Ports))
		for _, port := range oldUnit.Ports {
			oldPorts[port.Port] = port
		}
		for _, port := range unit.Ports {
			oldPort, ok := oldPorts[port.Port]
			if !ok || !isPositivePortState(oldPort.State) || !isPositivePortState(port.State) || len(oldPort.Evidence) == 0 || len(port.Evidence) == 0 {
				continue
			}
			if intersectionOnly && !inBothScopes(old, current, item{Kind: "port", Target: unit.Target, Protocol: unit.Protocol, Port: port.Port}) {
				continue
			}
			before, after := canonicalAddressSet(oldPort.Evidence), canonicalAddressSet(port.Evidence)
			for _, address := range addresses {
				_, wasExposed := before[address]
				_, isExposed := after[address]
				if !isExposed && explicitlyDownForProtocol(downByProtocol, unit.Protocol, address) {
					// A host that is down shows no ports, so this scan cannot
					// compare the address. Its host state change reports it.
					continue
				}
				key := portAddressKey(unit.Target, unit.Protocol, port.Port, address)
				compared[key] = struct{}{}
				if wasExposed == isExposed {
					continue
				}
				change := model.Change{Key: key, Kind: "port-address", Target: unit.Target, Protocol: unit.Protocol, Port: port.Port, Address: address}
				if isExposed {
					change.Old, change.New, change.Severity = "not-open", port.State, "critical"
					if port.State == "open|filtered" {
						change.Severity = "warning"
					}
				} else {
					change.Old, change.New, change.Severity = oldPort.State, "not-open", "info"
				}
				changes = append(changes, change)
			}
		}
	}
	return compared, changes
}

// learnMissingPortEvidence records which addresses expose a positive baseline
// port of a DNS target when the baseline does not say. An incident names only
// the logical target, so a port accepted from one has no address evidence,
// and neither has a port of a baseline recorded before ports carried it.
// Such a port's addresses are unknown rather than changed: this complete scan
// supplies them, limited to addresses in both DNS answers, so that later
// scans can compare them. A unit with an address whose host discovery
// completed down is left for a later scan.
func learnMissingPortEvidence(baseline *model.Snapshot, current model.Snapshot, downByProtocol map[string]map[string]struct{}) {
	if baseline == nil {
		return
	}
	currentUnits := unitMap(current)
	for unitIndex := range baseline.Units {
		unit := &baseline.Units[unitIndex]
		if !isDNSComparisonTarget(unit.Target) {
			continue
		}
		currentUnit, ok := currentUnits[unit.Target+"\x00"+unit.Protocol]
		if !ok {
			continue
		}
		baselineAnswer := canonicalAddressSet(baseline.DNS[unit.Target])
		currentAnswer := canonicalAddressSet(current.DNS[unit.Target])
		down := false
		for address := range currentAnswer {
			if explicitlyDownForProtocol(downByProtocol, unit.Protocol, address) {
				down = true
				break
			}
		}
		if down {
			continue
		}
		currentPorts := make(map[int]model.PortState, len(currentUnit.Ports))
		for _, port := range currentUnit.Ports {
			currentPorts[port.Port] = port
		}
		for portIndex := range unit.Ports {
			port := &unit.Ports[portIndex]
			observed, ok := currentPorts[port.Port]
			if len(port.Evidence) != 0 || !isPositivePortState(port.State) || !ok || !isPositivePortState(observed.State) {
				continue
			}
			var evidence []string
			for address := range canonicalAddressSet(observed.Evidence) {
				_, inBaseline := baselineAnswer[address]
				_, inCurrent := currentAnswer[address]
				if inBaseline && inCurrent {
					evidence = append(evidence, address)
				}
			}
			if len(evidence) == 0 {
				continue
			}
			sort.Strings(evidence)
			port.Evidence = evidence
		}
	}
}

func canonicalAddress(address string) string {
	address = strings.TrimSpace(address)
	if ip := net.ParseIP(address); ip != nil {
		return ip.String()
	}
	return address
}

func canonicalAddressSet(addresses []string) map[string]struct{} {
	set := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if address = canonicalAddress(address); address != "" {
			set[address] = struct{}{}
		}
	}
	return set
}

func inBothScopes(a, b model.Snapshot, v item) bool {
	if v.Kind == "dns" {
		return hasTarget(a, v.Target) && hasTarget(b, v.Target)
	}
	if v.Kind == "host" {
		return hostInScope(a, v.Target) && hostInScope(b, v.Target)
	}
	return scopeAllows(a, v.Target, v.Protocol, v.Port, v.Kind == "service") && scopeAllows(b, v.Target, v.Protocol, v.Port, v.Kind == "service")
}

func missingPositivePortExplainedByDown(old model.Snapshot, value item, downByProtocol map[string]map[string]struct{}) bool {
	if len(downByProtocol) == 0 {
		return false
	}
	addresses, found := positivePortAddresses(old, value.Target, value.Protocol, value.Port)
	if !found || len(addresses) == 0 {
		return false
	}
	// An aggregate DNS port may have been observed on several addresses.
	// Suppress its closure only when every contributing address is explicitly
	// down; a live sibling can still establish a real removal for the target.
	for address := range addresses {
		if !explicitlyDownForProtocol(downByProtocol, value.Protocol, address) {
			return false
		}
	}
	return true
}

// positivePortAddresses returns the effective addresses that exposed a
// positive port of snapshot: the port's evidence, or else its unit's
// addresses, the target's DNS answer, or the IP literal target. found
// reports whether the snapshot has the port as positive at all. The address
// set is nil when a matching port has no address that can be determined.
func positivePortAddresses(snapshot model.Snapshot, target, protocol string, port int) (map[string]struct{}, bool) {
	addresses := map[string]struct{}{}
	found := false
	for _, unit := range snapshot.Units {
		if unit.Target != target || !strings.EqualFold(unit.Protocol, protocol) {
			continue
		}
		for _, value := range unit.Ports {
			if value.Port != port || !isPositivePortState(value.State) {
				continue
			}
			found = true
			portAddresses := value.Evidence
			if len(portAddresses) == 0 {
				portAddresses = unit.Addresses
			}
			if len(portAddresses) == 0 {
				portAddresses = snapshot.DNS[unit.Target]
			}
			if len(portAddresses) == 0 && net.ParseIP(strings.TrimSpace(unit.Target)) != nil {
				portAddresses = []string{unit.Target}
			}
			if len(portAddresses) == 0 {
				return nil, true
			}
			for _, address := range portAddresses {
				addresses[strings.TrimSpace(address)] = struct{}{}
			}
		}
	}
	return addresses, found
}

// targetAddresses returns the effective addresses that a scan examined for
// a target and protocol: its unit's addresses, or else the target's DNS
// answer or the IP literal target.
func targetAddresses(snapshot model.Snapshot, target, protocol string) []string {
	for _, unit := range snapshot.Units {
		if unit.Target == target && strings.EqualFold(unit.Protocol, protocol) && len(unit.Addresses) > 0 {
			return unit.Addresses
		}
	}
	if addresses := snapshot.DNS[target]; len(addresses) > 0 {
		return addresses
	}
	if net.ParseIP(strings.TrimSpace(target)) != nil {
		return []string{target}
	}
	return nil
}

// completedDownAddressesByProtocol includes protocol-specific Nmap discovery
// results and address-level down states (which require every configured
// protocol to be down). Protocol-specific evidence prevents one transport's
// host-discovery result from hiding a meaningful port change in another.
func completedDownAddressesByProtocol(snapshot model.Snapshot) map[string]map[string]struct{} {
	return completedDownAddressesByProtocolForJob(model.Snapshot{}, snapshot, config.Job{})
}

func completedDownAddressesByProtocolForJob(old, snapshot model.Snapshot, job config.Job) map[string]map[string]struct{} {
	down := map[string]map[string]struct{}{}
	add := func(protocol, address string) {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		address = strings.TrimSpace(address)
		if protocol == "" || address == "" {
			return
		}
		if down[protocol] == nil {
			down[protocol] = map[string]struct{}{}
		}
		down[protocol][address] = struct{}{}
	}
	for _, host := range snapshot.HostStates {
		if strings.EqualFold(strings.TrimSpace(host.State), "down") {
			add("*", host.Address)
		}
	}
	for _, host := range snapshot.Hosts {
		for _, observation := range host.Protocols {
			if isCompletedProtocolHostDiscoveryDown(observation) {
				add(observation.Protocol, host.Address)
			}
		}
	}
	if job.DNSComparisonMode == config.DNSComparisonAggregate {
		dnsAddresses := dnsAddressesInSnapshot(old)
		for address := range dnsAddressesInSnapshot(snapshot) {
			dnsAddresses[address] = struct{}{}
		}
		for protocol, addresses := range down {
			for address := range addresses {
				if dnsOnlyAddressInSnapshot(address, dnsAddresses, old) && dnsOnlyAddressInSnapshot(address, dnsAddresses, snapshot) {
					delete(addresses, address)
				}
			}
			if len(addresses) == 0 {
				delete(down, protocol)
			}
		}
	}
	return down
}

func explicitlyDownForProtocol(downByProtocol map[string]map[string]struct{}, protocol, address string) bool {
	address = strings.TrimSpace(address)
	for _, name := range []string{"*", strings.ToLower(strings.TrimSpace(protocol))} {
		if _, ok := downByProtocol[name][address]; ok {
			return true
		}
	}
	return false
}

func hasTarget(s model.Snapshot, target string) bool {
	for _, scope := range s.Scopes {
		if scope.Target == target {
			return true
		}
	}
	return false
}
func scopeAllows(s model.Snapshot, target, protocol string, port int, service bool) bool {
	for _, scope := range s.Scopes {
		if scope.Target == target && scope.Protocol == protocol && config.PortContains(scope.Ports, port) && (!service || scope.ServiceDetection) {
			return true
		}
	}
	return false
}

func baselineChangeCount(count int) string {
	noun := "changes"
	if count == 1 {
		noun = "change"
	}
	return fmt.Sprintf("%d baseline %s", count, noun)
}

func baselineChangeMessage(count int, action string) string {
	return baselineChangeCount(count) + " " + action
}

func persistentIncidentReminderMessage(count int) string {
	verb := "remain"
	if count == 1 {
		verb = "remains"
	}
	return fmt.Sprintf("Reminder: %s %s open", baselineChangeCount(count), verb)
}

func mergeForScopeChange(old, candidate model.Snapshot) model.Snapshot {
	result := cloneSnapshot(candidate)
	oldUnits := unitMap(old)
	candidateUnits := unitMap(candidate)
	// Keep only ports that the new security scope actually covers. A malformed
	// or stale candidate must not smuggle an out-of-scope positive port into the
	// new baseline during a hash migration.
	for key, cu := range candidateUnits {
		parts := strings.Split(key, "\x00")
		target, protocol := parts[0], parts[1]
		ou, oldExists := oldUnits[key]
		ports := map[int]model.PortState{}
		for _, p := range cu.Ports {
			if scopeAllows(candidate, target, protocol, p.Port, false) {
				if !scopeAllows(candidate, target, protocol, p.Port, true) {
					p.Service = ""
				}
				ports[p.Port] = p
			}
		}
		if oldExists {
			for _, p := range ou.Ports {
				if scopeAllows(candidate, target, protocol, p.Port, false) {
					if !scopeAllows(candidate, target, protocol, p.Port, true) {
						p.Service = ""
					}
					if current, exists := ports[p.Port]; exists {
						// A scope candidate can omit a service because the scanner
						// did not return one or because a replacement fingerprint has
						// not reached its sample threshold. Keep the last expected
						// fingerprint until a stable replacement is available.
						if current.Service == "" && p.Service != "" && scopeAllows(candidate, target, protocol, p.Port, true) {
							current.Service = p.Service
							ports[p.Port] = current
						}
					} else {
						ports[p.Port] = p
					}
				}
			}
		}
		cu.Ports = nil
		for _, p := range ports {
			cu.Ports = append(cu.Ports, p)
		}
		candidateUnits[key] = cu
	}
	// If a target remains in the new scope but a degraded candidate omitted its
	// unit entirely, retain the old expected unit filtered to the new scope. A
	// target removed from the scope is intentionally not copied forward.
	for key, ou := range oldUnits {
		if _, exists := candidateUnits[key]; exists {
			continue
		}
		parts := strings.Split(key, "\x00")
		target, protocol := parts[0], parts[1]
		if !hasTarget(candidate, target) || !scopeAllowsProtocol(candidate, target, protocol) {
			continue
		}
		clone := ou
		clone.Ports = nil
		for _, p := range ou.Ports {
			if !scopeAllows(candidate, target, protocol, p.Port, false) {
				continue
			}
			if !scopeAllows(candidate, target, protocol, p.Port, true) {
				p.Service = ""
			}
			clone.Ports = append(clone.Ports, p)
		}
		if addresses := result.DNS[target]; len(addresses) > 0 {
			clone.Addresses = append([]string(nil), addresses...)
		}
		candidateUnits[key] = clone
	}
	result.Units = nil
	for _, u := range candidateUnits {
		result.Units = append(result.Units, u)
	}
	result.Normalize()
	return result
}

func dnsTargetsInSnapshot(snapshot model.Snapshot) map[string]struct{} {
	// Use one input for the capacity hint rather than summing both lengths,
	// which could overflow before map allocation for an extremely large
	// untrusted snapshot.
	targets := make(map[string]struct{}, len(snapshot.Scopes))
	for _, scope := range snapshot.Scopes {
		if isDNSComparisonTarget(scope.Target) {
			targets[strings.TrimSpace(scope.Target)] = struct{}{}
		}
	}
	for target := range snapshot.DNS {
		targets[strings.TrimSpace(target)] = struct{}{}
	}
	return targets
}

func dnsAddressesInSnapshot(snapshot model.Snapshot) map[string]struct{} {
	addresses := map[string]struct{}{}
	for _, resolved := range snapshot.DNS {
		for _, address := range resolved {
			address = strings.TrimSpace(address)
			if ip := net.ParseIP(address); ip != nil {
				address = ip.String()
			}
			if address != "" {
				addresses[address] = struct{}{}
			}
		}
	}
	return addresses
}

func isDNSComparisonTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || net.ParseIP(target) != nil {
		return false
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return false
	}
	return true
}

func snapshotHasNonDNSAddressScope(snapshot model.Snapshot, address string) bool {
	ip := net.ParseIP(strings.TrimSpace(address))
	if ip == nil {
		return false
	}
	for _, scope := range snapshot.Scopes {
		target := strings.TrimSpace(scope.Target)
		if isDNSComparisonTarget(target) {
			continue
		}
		if targetIP := net.ParseIP(target); targetIP != nil && targetIP.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(target); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func dnsOnlyAddressInSnapshot(address string, dnsAddresses map[string]struct{}, snapshot model.Snapshot) bool {
	address = strings.TrimSpace(address)
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	if _, seenAsDNS := dnsAddresses[address]; !seenAsDNS {
		return false
	}
	return !snapshotHasNonDNSAddressScope(snapshot, address)
}

func filterDNSAggregateChanges(old, current model.Snapshot, changes []model.Change, job config.Job) []model.Change {
	if job.DNSComparisonMode != config.DNSComparisonAggregate || len(changes) == 0 {
		return changes
	}
	dnsTargets := dnsTargetsInSnapshot(old)
	for target := range dnsTargetsInSnapshot(current) {
		dnsTargets[target] = struct{}{}
	}
	dnsAddresses := dnsAddressesInSnapshot(old)
	for address := range dnsAddressesInSnapshot(current) {
		dnsAddresses[address] = struct{}{}
	}
	filtered := changes[:0]
	for _, change := range changes {
		switch change.Kind {
		case "dns-added", "dns-removed":
			if _, dnsTarget := dnsTargets[change.Target]; dnsTarget {
				continue
			}
		case "port-address":
			// Aggregate mode compares only the logical port surface, not which
			// of a name's addresses exposes each port.
			continue
		case "host":
			if dnsOnlyAddressInSnapshot(change.Target, dnsAddresses, old) && !snapshotHasNonDNSAddressScope(current, change.Target) {
				continue
			}
		}
		filtered = append(filtered, change)
	}
	return filtered
}

func diffForJob(old, current model.Snapshot, intersectionOnly bool, job config.Job) []model.Change {
	downByProtocol := completedDownAddressesByProtocolForJob(old, current, job)
	return filterDNSAggregateChanges(old, current, diffWithDownAddresses(old, current, intersectionOnly, downByProtocol), job)
}

func scopeAllowsProtocol(snapshot model.Snapshot, target, protocol string) bool {
	for _, scope := range snapshot.Scopes {
		if scope.Target == target && strings.EqualFold(scope.Protocol, protocol) {
			return true
		}
	}
	return false
}

// cloneSnapshot makes scope migration work on an independent value. Scan
// snapshots are immutable history; in particular DNS relationships and unit
// slices must not be changed while constructing the mutable runtime baseline.
func cloneSnapshot(snapshot model.Snapshot) model.Snapshot {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return snapshot
	}
	var clone model.Snapshot
	if err := json.Unmarshal(payload, &clone); err != nil {
		return snapshot
	}
	return clone
}
func unitMap(s model.Snapshot) map[string]model.Unit {
	m := map[string]model.Unit{}
	for _, u := range s.Units {
		m[u.Target+"\x00"+u.Protocol] = u
	}
	return m
}

func FormatEvent(e model.Event) string {
	switch e.Type {
	case model.EventSecurityAlert:
		return formatSecurityAlert(e)
	case model.EventHealthAlert:
		return formatHealthAlert(e)
	}
	var b strings.Builder
	if e.Type == "application-update-available" {
		b.WriteString("⬆️ EdgeWatch update available")
		if e.CurrentVersion != "" {
			b.WriteString("\nCurrent version: ")
			b.WriteString(e.CurrentVersion)
		}
		if e.LatestVersion != "" {
			b.WriteString("\nNew version: ")
			b.WriteString(e.LatestVersion)
		}
		if e.ReleaseURL != "" {
			b.WriteString("\nRelease: ")
			b.WriteString(e.ReleaseURL)
		}
		return b.String()
	}
	if e.Type == "application-updated" {
		b.WriteString("🟢 EdgeWatch updated")
		if e.PreviousVersion != "" {
			b.WriteString("\nPrevious version: ")
			b.WriteString(e.PreviousVersion)
		}
		if e.CurrentVersion != "" {
			b.WriteString("\nCurrent version: ")
			b.WriteString(e.CurrentVersion)
		}
		if e.ReleaseURL != "" {
			b.WriteString("\nRelease: ")
			b.WriteString(e.ReleaseURL)
		}
		return b.String()
	}
	switch {
	case e.Type == "changes-recovered" || e.Type == "scan-recovered":
		b.WriteString("🟢 ")
	case e.Type == "scan-anomaly" || e.Type == "scan-incomplete":
		b.WriteString("⚠️ ")
	case (e.Type == "changes-detected" || e.Type == "changes-reminder") && (e.HasCriticalChanges || hasCriticalChange(e.Changes)):
		b.WriteString("🔴 ")
	}
	b.WriteString("EdgeWatch: ")
	b.WriteString(notificationField(notificationEventMessage(e)))
	if e.Job != "" {
		b.WriteString("\nJob: ")
		b.WriteString(notificationField(e.Job))
	}
	if e.ScanID != "" {
		b.WriteString("\nScan: ")
		b.WriteString(notificationField(e.ScanID))
	}
	for _, c := range e.Changes {
		b.WriteString("\n- [")
		b.WriteString(notificationField(c.Severity))
		b.WriteString("] ")
		b.WriteString(safeChangeSummary(c))
	}
	return b.String()
}

// notificationEventMessage regenerates the fixed change summaries from their
// structured event data. Besides keeping new notifications grammatical, this
// also fixes queued legacy events whose persisted Message used "change(s)".
func notificationEventMessage(event model.Event) string {
	count := event.ChangesCount
	if count <= 0 {
		count = len(event.Changes)
	}
	message := event.Message
	if count > 0 {
		switch event.Type {
		case "changes-detected":
			message = baselineChangeMessage(count, "confirmed")
		case "changes-recovered":
			message = baselineChangeMessage(count, "recovered")
		case "changes-reminder":
			message = persistentIncidentReminderMessage(count)
		}
	}
	if event.ChangesTruncated && !strings.HasSuffix(message, " (details truncated)") {
		message += " (details truncated)"
	}
	return message
}

const maxNotificationFieldRunes = 512

// notificationField preserves trusted notification wording while flattening
// control and Unicode formatting characters and bounding the rendered field.
func notificationField(value string) string {
	value = strings.Map(func(r rune) rune {
		if notificationControl(r) {
			return ' '
		}
		return r
	}, value)
	return limitNotificationField(value)
}

func notificationControl(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func limitNotificationField(value string) string {
	runes := []rune(value)
	if len(runes) <= maxNotificationFieldRunes {
		return value
	}
	return string(runes[:maxNotificationFieldRunes-1]) + "…"
}

// sanitizeNotificationText neutralizes untrusted scan-derived text before it
// is sent through chat providers that may interpret HTML or Markdown. Keep it
// scoped to Nmap service values and scanner error details; generated wording,
// job names, and fixed state vocabulary retain their ordinary characters.
func sanitizeNotificationText(value string) string {
	value = strings.Map(func(r rune) rune {
		if notificationControl(r) {
			return ' '
		}
		switch r {
		case '&':
			return '＆'
		case '<':
			return '‹'
		case '>':
			return '›'
		case '[':
			return '［'
		case ']':
			return '］'
		case '(':
			return '（'
		case ')':
			return '）'
		case '`':
			return '｀'
		case '*':
			return '＊'
		case '_':
			return '＿'
		case '~':
			return '～'
		case '@':
			return '＠'
		case '|':
			return '｜'
		default:
			return r
		}
	}, value)
	return limitNotificationField(value)
}

func safeChangeSummary(change model.Change) string {
	// Service fingerprints can include arbitrary scanner-reported product and
	// banner text, so neutralize those values. Port and host states, targets,
	// protocols, kinds, and the summary separators are fixed or validated
	// application values; in particular, preserve the literal open|filtered
	// state used by both operators and downstream text searches.
	if change.Kind == "service" {
		change.Old = sanitizeNotificationText(change.Old)
		change.New = sanitizeNotificationText(change.New)
	}
	return model.ChangeSummary(change)
}

func hasCriticalChange(changes []model.Change) bool {
	for _, change := range changes {
		if strings.EqualFold(strings.TrimSpace(change.Severity), "critical") {
			return true
		}
	}
	return false
}

func ScopeDescription(s model.Scope) string {
	return s.Target + " " + s.Protocol + "/" + s.Ports + " service=" + strconv.FormatBool(s.ServiceDetection)
}
