package engine

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

type Engine struct{ Store *store.Store }

func (e *Engine) Success(ctx context.Context, job config.Job, scan model.Scan) ([]model.Event, error) {
	return e.Store.UpdateState(ctx, job.Name, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

// SuccessForJob is the database-backed equivalent used by web-managed jobs.
// Its state key is the immutable job ID while event payloads keep the name
// users recognize.
func (e *Engine) SuccessForJob(ctx context.Context, jobID string, job config.Job, scan model.Scan) ([]model.Event, error) {
	return e.Store.UpdateRuntimeForScan(ctx, jobID, scan.ConfigHash, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

func (e *Engine) SuccessForJobWithDestinations(ctx context.Context, jobID string, job config.Job, scan model.Scan, destinations []string) ([]model.Event, error) {
	return e.Store.UpdateRuntimeForScanWithOutbox(ctx, jobID, scan.ConfigHash, destinations, func(state *model.JobState) ([]model.Event, error) {
		return processSuccess(state, job, scan)
	})
}

// FinalizeManagedScan captures the scan-time comparison and applies the
// resulting runtime transition in the store's single transaction. This keeps
// baseline reset/approval from changing the state between those two steps.
func (e *Engine) FinalizeManagedScan(ctx context.Context, jobID string, job config.Job, scan *model.Scan, destinations []string) ([]model.Event, error) {
	if scan == nil {
		return nil, fmt.Errorf("scan is required")
	}
	return e.Store.FinalizeManagedScan(ctx, scan, jobID, scan.ConfigHash, destinations, func(state *model.JobState, current *model.Scan) ([]model.Event, error) {
		if current.Status == "success" {
			if state.Baseline != nil {
				current.BaselineScanID = state.BaselineScanID
				current.BaselineConfigHash = state.BaselineConfigHash
				current.Changes = Diff(*state.Baseline, current.Snapshot, state.BaselineConfigHash != current.ConfigHash)
			}
			events, err := processSuccess(state, job, *current)
			if err != nil {
				return nil, err
			}
			// A scan can be the sample that completes the initial baseline. In
			// that case there was no prior baseline to capture above, but the
			// scan is still the immutable source of the newly established state.
			// Recording its own ID prevents history from falling back to a later
			// mutable runtime baseline after an administrator reset.
			if current.BaselineScanID == "" && state.BaselineScanID == current.ID {
				current.BaselineScanID = state.BaselineScanID
				current.BaselineConfigHash = state.BaselineConfigHash
			}
			return events, nil
		}
		// Failed, timed-out, and canceled scans never enter comparison state,
		// but every terminal non-success outcome is retained as an event so the
		// configured notification destinations can alert the operator.
		return processFailure(state, job.Name, *current)
	})
}

func processSuccess(state *model.JobState, job config.Job, scan model.Scan) ([]model.Event, error) {
	state.ConsecutiveFailures = 0
	state.LastFailureAlert = 0
	now := scan.FinishedAt
	if state.Baseline == nil {
		events := advanceCandidate(state, scan, job.Baseline.Samples, false)
		return events, nil
	}
	learnMissingFingerprints(state, scan.Snapshot, job.Baseline.Samples)
	changes := Diff(*state.Baseline, scan.Snapshot, state.BaselineConfigHash != scan.ConfigHash)
	events := applyChanges(state, job.Name, scan.ID, changes, job.Change.Confirmations, now)
	if state.BaselineConfigHash != scan.ConfigHash {
		candidateEvents := advanceCandidate(state, scan, job.Baseline.Samples, true)
		events = append(events, candidateEvents...)
	}
	return events, nil
}

func advanceCandidate(state *model.JobState, scan model.Scan, required int, merge bool) []model.Event {
	updateFingerprintCandidates(state, scan.Snapshot)
	hash := scan.Snapshot.Hash()
	state.CandidateAttempts++
	if state.CandidateHash == hash {
		state.CandidateCount++
	} else {
		candidate := scan.Snapshot
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
		state.Candidate = nil
		state.CandidateHash = ""
		state.CandidateCount = 0
		state.CandidateAttempts = 0
		typeName := "baseline-complete"
		message := "Baseline established"
		if merge {
			typeName = "baseline-updated"
			message = "Baseline updated for changed scan scope"
		}
		return []model.Event{{Type: typeName, Job: scan.Job, ScanID: scan.ID, Message: message, CreatedAt: scan.FinishedAt}}
	}
	stallAt := required * 3
	if stallAt < 3 {
		stallAt = 3
	}
	if state.CandidateAttempts == stallAt {
		return []model.Event{{Type: "baseline-stalled", Job: scan.Job, ScanID: scan.ID, Message: fmt.Sprintf("Baseline has not converged after %d scans", state.CandidateAttempts), CreatedAt: scan.FinishedAt}}
	}
	return nil
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

func learnMissingFingerprints(state *model.JobState, current model.Snapshot, required int) {
	if state.Baseline == nil {
		return
	}
	seen := map[string]bool{}
	for _, unit := range current.Units {
		for _, port := range unit.Ports {
			if port.Service == "" || baselineService(*state.Baseline, unit.Target, unit.Protocol, port.Port) != "" || !scopeAllows(*state.Baseline, unit.Target, unit.Protocol, port.Port, true) {
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
				setBaselineService(state.Baseline, unit.Target, unit.Protocol, port.Port, candidate.Value)
				delete(state.FingerprintCandidates, key)
			}
		}
	}
	for key := range state.FingerprintCandidates {
		if strings.HasPrefix(key, "service|") && !seen[key] {
			delete(state.FingerprintCandidates, key)
		}
	}
}

func baselineService(snapshot model.Snapshot, target, protocol string, port int) string {
	for _, unit := range snapshot.Units {
		if unit.Target != target || unit.Protocol != protocol {
			continue
		}
		for _, value := range unit.Ports {
			if value.Port == port {
				return value.Service
			}
		}
	}
	return ""
}

func setBaselineService(snapshot *model.Snapshot, target, protocol string, port int, service string) {
	for i := range snapshot.Units {
		if snapshot.Units[i].Target != target || snapshot.Units[i].Protocol != protocol {
			continue
		}
		for j := range snapshot.Units[i].Ports {
			if snapshot.Units[i].Ports[j].Port == port {
				snapshot.Units[i].Ports[j].Service = service
				return
			}
		}
	}
}

func (e *Engine) Failure(ctx context.Context, job string, scan model.Scan) ([]model.Event, error) {
	return e.Store.UpdateState(ctx, job, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func (e *Engine) FailureForJob(ctx context.Context, jobID, job string, scan model.Scan) ([]model.Event, error) {
	return e.Store.UpdateRuntimeForScan(ctx, jobID, scan.ConfigHash, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func (e *Engine) FailureForJobWithDestinations(ctx context.Context, jobID, job string, scan model.Scan, destinations []string) ([]model.Event, error) {
	return e.Store.UpdateRuntimeForScanWithOutbox(ctx, jobID, scan.ConfigHash, destinations, func(state *model.JobState) ([]model.Event, error) {
		return processFailure(state, job, scan)
	})
}

func processFailure(state *model.JobState, job string, scan model.Scan) ([]model.Event, error) {
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
		message += ": " + reason
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
	a, b := items(old), items(new)
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
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func inBothScopes(a, b model.Snapshot, v item) bool {
	if v.Kind == "dns" {
		return hasTarget(a, v.Target) && hasTarget(b, v.Target)
	}
	return scopeAllows(a, v.Target, v.Protocol, v.Port, v.Kind == "service") && scopeAllows(b, v.Target, v.Protocol, v.Port, v.Kind == "service")
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

func applyChanges(state *model.JobState, job, scanID string, current []model.Change, required int, now time.Time) []model.Event {
	currentMap := map[string]model.Change{}
	for _, c := range current {
		currentMap[c.Key] = c
	}
	// Suppression is counted in successful scans, rather than wall-clock time.
	// Keep the confirmed change one extra state transition so an unchanged
	// incident can be re-opened immediately when its one-scan suppression ends.
	suppressedThisScan := map[string]bool{}
	expiredSuppression := map[string]model.Change{}
	for key, remaining := range state.Suppressed {
		if remaining <= 0 {
			if change, ok := state.SuppressedChanges[key]; ok {
				expiredSuppression[key] = change
			}
			delete(state.Suppressed, key)
			delete(state.SuppressedChanges, key)
			continue
		}
		suppressedThisScan[key] = true
		state.Suppressed[key] = remaining - 1
	}
	allCurrent := make(map[string]model.Change, len(currentMap))
	for key, change := range currentMap {
		allCurrent[key] = change
	}
	for key := range suppressedThisScan {
		// The action removes the active incident immediately. Repeat that
		// cleanup here so a state written by an older server cannot leak a
		// suppressed row or pending confirmation into the next scan.
		delete(currentMap, key)
		delete(state.Pending, key)
		delete(state.Incidents, key)
	}
	for key, change := range expiredSuppression {
		if current, ok := allCurrent[key]; ok && current.New == change.New {
			// Re-open below without making the administrator confirm the same
			// already-confirmed change again. A changed value is processed by the
			// normal confirmation path instead.
			delete(currentMap, key)
			delete(state.Pending, key)
			delete(state.Incidents, key)
		}
	}
	var opened, recovered []model.Change
	for key, c := range currentMap {
		if incident, ok := state.Incidents[key]; ok && incident.Change.New == c.New {
			incident.LastSeenAt = now
			incident.RecoveryCount = 0
			state.Incidents[key] = incident
			delete(state.Pending, key)
			continue
		}
		p := state.Pending[key]
		if p.Change.New == c.New && p.Change.Old == c.Old {
			p.Count++
		} else {
			p = model.Pending{Change: c, Count: 1}
		}
		if p.Count >= required {
			state.Incidents[key] = model.Incident{Change: c, ScanID: scanID, OpenedAt: now, LastSeenAt: now}
			delete(state.Pending, key)
			opened = append(opened, c)
		} else {
			state.Pending[key] = p
		}
	}
	for key, change := range expiredSuppression {
		currentChange, ok := allCurrent[key]
		if !ok || currentChange.New != change.New {
			continue
		}
		state.Incidents[key] = model.Incident{Change: currentChange, ScanID: scanID, OpenedAt: now, LastSeenAt: now}
		opened = append(opened, currentChange)
	}
	for key := range state.Pending {
		if _, ok := currentMap[key]; !ok {
			delete(state.Pending, key)
		}
	}
	for key, incident := range state.Incidents {
		if _, ok := allCurrent[key]; ok {
			continue
		}
		incident.RecoveryCount++
		if incident.RecoveryCount >= required {
			recovery := incident.Change
			recovery.Old, recovery.New = recovery.New, recovery.Old
			recovered = append(recovered, recovery)
			delete(state.Incidents, key)
		} else {
			state.Incidents[key] = incident
		}
	}
	sort.Slice(opened, func(i, j int) bool { return opened[i].Key < opened[j].Key })
	sort.Slice(recovered, func(i, j int) bool { return recovered[i].Key < recovered[j].Key })
	var events []model.Event
	if len(opened) > 0 {
		events = append(events, model.Event{Type: "changes-detected", Job: job, ScanID: scanID, Message: fmt.Sprintf("%d baseline change(s) confirmed", len(opened)), Changes: opened, CreatedAt: now})
	}
	if len(recovered) > 0 {
		events = append(events, model.Event{Type: "changes-recovered", Job: job, ScanID: scanID, Message: fmt.Sprintf("%d baseline change(s) recovered", len(recovered)), Changes: recovered, CreatedAt: now})
	}
	return events
}

func mergeForScopeChange(old, candidate model.Snapshot) model.Snapshot {
	result := candidate
	oldUnits := unitMap(old)
	candidateUnits := unitMap(candidate)
	for key, cu := range candidateUnits {
		parts := strings.Split(key, "\x00")
		target, protocol := parts[0], parts[1]
		ou, oldExists := oldUnits[key]
		if !oldExists {
			continue
		}
		ports := map[int]model.PortState{}
		for _, p := range cu.Ports {
			if !scopeAllows(old, target, protocol, p.Port, false) {
				ports[p.Port] = p
			}
		}
		for _, p := range ou.Ports {
			if scopeAllows(candidate, target, protocol, p.Port, false) {
				if !scopeAllows(candidate, target, protocol, p.Port, true) {
					p.Service = ""
				}
				ports[p.Port] = p
			}
		}
		cu.Ports = nil
		for _, p := range ports {
			cu.Ports = append(cu.Ports, p)
		}
		candidateUnits[key] = cu
	}
	result.Units = nil
	for _, u := range candidateUnits {
		result.Units = append(result.Units, u)
	}
	for target, addresses := range old.DNS {
		if hasTarget(candidate, target) {
			result.DNS[target] = append([]string(nil), addresses...)
		}
	}
	result.Normalize()
	return result
}
func unitMap(s model.Snapshot) map[string]model.Unit {
	m := map[string]model.Unit{}
	for _, u := range s.Units {
		m[u.Target+"\x00"+u.Protocol] = u
	}
	return m
}

func FormatEvent(e model.Event) string {
	var b strings.Builder
	switch {
	case e.Type == "changes-recovered":
		b.WriteString("🟢 ")
	case e.Type == "changes-detected" && hasCriticalChange(e.Changes):
		b.WriteString("🔴 ")
	}
	b.WriteString("EdgeWatch: ")
	b.WriteString(e.Message)
	b.WriteString("\nJob: ")
	b.WriteString(e.Job)
	if e.ScanID != "" {
		b.WriteString("\nScan: ")
		b.WriteString(e.ScanID)
	}
	for _, c := range e.Changes {
		b.WriteString("\n- [")
		b.WriteString(c.Severity)
		b.WriteString("] ")
		b.WriteString(model.ChangeSummary(c))
	}
	return b.String()
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
