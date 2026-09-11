package store

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// AcceptIncidentWithOutboxAndAudit folds one active incident into the current
// baseline and queues the resulting event for the supplied job destinations in
// the same transaction as the state and audit mutation.
func (s *Store) AcceptIncidentWithOutboxAndAudit(ctx context.Context, jobID, jobName, key string, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.updateIncidentAction(ctx, jobID, destinations, []AuditEntry{audit}, true, func(state *model.JobState) ([]model.Event, error) {
		if state.Baseline == nil {
			return nil, ErrBaselineNotReady
		}
		incident, ok := state.Incidents[key]
		if !ok {
			return nil, ErrIncidentNotFound
		}
		change := incident.Change
		if change.Key == "" {
			change.Key = key
		}

		// A single scan can remove both a positive port and its service
		// fingerprint. Treat the pair as one operator decision so accepting the
		// first row cannot leave the other row (or the old positive port) behind.
		// Keep service-only changes independent: a port that is still open may
		// legitimately lose only its fingerprint.
		accepted := []model.Change{change}
		acceptedKeys := []string{key}
		relatedKey, related, hasRelated := relatedIncident(state, key, change)
		if hasRelated {
			// Apply the port first so a paired service removal cannot leave a
			// positive port behind. The order is deterministic regardless of
			// which incident row the administrator selected.
			if change.Kind == "port" {
				accepted = []model.Change{change, related.Change}
				acceptedKeys = []string{key, relatedKey}
			} else {
				accepted = []model.Change{related.Change, change}
				acceptedKeys = []string{relatedKey, key}
			}
		}
		for index := range accepted {
			if accepted[index].Key == "" {
				accepted[index].Key = acceptedKeys[index]
			}
		}
		for _, acceptedChange := range accepted {
			if err := applyAcceptedChange(state.Baseline, acceptedChange); err != nil {
				return nil, err
			}
		}
		// The accepted comparison state is now a deliberate runtime overlay on
		// the immutable source scan. Host explorer endpoints use this marker to
		// avoid serving the source scan's stale expected ports or services.
		state.BaselineModified = true
		for index, acceptedChange := range accepted {
			acceptedKey := acceptedChange.Key
			if acceptedKey == "" {
				acceptedKey = acceptedKeys[index]
			}
			delete(state.Incidents, acceptedKey)
			delete(state.Pending, acceptedKey)
			delete(state.Suppressed, acceptedKey)
			delete(state.SuppressedChanges, acceptedKey)
			if acceptedChange.Kind == "service" || acceptedChange.Kind == "port" {
				delete(state.FingerprintCandidates, fingerprintCandidateKey(acceptedChange))
			}
		}
		return []model.Event{{Type: "incident-accepted", Job: jobName, ScanID: incident.ScanID, Message: acceptedIncidentMessage(len(accepted)), Changes: accepted, CreatedAt: time.Now().UTC()}}, nil
	})
}

// AcceptIncidentWithAudit is retained for callers that only need the durable
// state/audit mutation. Passing no destinations deliberately preserves the
// historical silent behavior for those callers.
func (s *Store) AcceptIncidentWithAudit(ctx context.Context, jobID, jobName, key string, audit AuditEntry) ([]model.Event, error) {
	return s.AcceptIncidentWithOutboxAndAudit(ctx, jobID, jobName, key, nil, audit)
}

// relatedIncident finds the sibling port/service change for the same scan and
// effective logical target. An empty scan ID is retained for legacy runtime
// state, but non-empty IDs must match so unrelated incidents are never folded
// into one administrator decision.
func relatedIncident(state *model.JobState, key string, change model.Change) (string, model.Incident, bool) {
	if change.Kind != "port" && change.Kind != "service" {
		return "", model.Incident{}, false
	}
	primary := state.Incidents[key]
	primaryScanID := strings.TrimSpace(primary.ScanID)
	for candidateKey, candidate := range state.Incidents {
		if candidateKey == key {
			continue
		}
		if change.Kind == candidate.Change.Kind || (candidate.Change.Kind != "port" && candidate.Change.Kind != "service") {
			continue
		}
		if strings.TrimSpace(candidate.Change.Target) != strings.TrimSpace(change.Target) ||
			!strings.EqualFold(strings.TrimSpace(candidate.Change.Protocol), strings.TrimSpace(change.Protocol)) ||
			candidate.Change.Port != change.Port {
			continue
		}
		// Pair only the disappearance of a port and its fingerprint. A newly
		// opened port can legitimately have a separate service change, and an
		// administrator accepting the port alone must not silently approve that
		// fingerprint too.
		if change.New != "not-open" || candidate.Change.New != "not-open" {
			continue
		}
		candidateScanID := strings.TrimSpace(candidate.ScanID)
		if primaryScanID != "" || candidateScanID != "" {
			// Incident scan identity prevents two observations of the same
			// target/port from being folded together when one is stale.
			if primaryScanID == "" || candidateScanID == "" || primaryScanID != candidateScanID {
				continue
			}
		}
		return candidateKey, candidate, true
	}
	return "", model.Incident{}, false
}

func acceptedIncidentMessage(count int) string {
	if count > 1 {
		return fmt.Sprintf("%d related incidents accepted into baseline", count)
	}
	return "Incident accepted into baseline"
}

// SuppressIncidentWithOutboxAndAudit hides an active incident for exactly one
// future successful scan and queues the action event for the supplied job
// destinations transactionally.
func (s *Store) SuppressIncidentWithOutboxAndAudit(ctx context.Context, jobID, jobName, key string, destinations []string, audit AuditEntry) ([]model.Event, error) {
	return s.updateIncidentAction(ctx, jobID, destinations, []AuditEntry{audit}, false, func(state *model.JobState) ([]model.Event, error) {
		incident, ok := state.Incidents[key]
		if !ok {
			return nil, ErrIncidentNotFound
		}
		if state.Suppressed == nil {
			state.Suppressed = map[string]int{}
		}
		if state.SuppressedChanges == nil {
			state.SuppressedChanges = map[string]model.Change{}
		}
		state.Suppressed[key] = 1
		change := incident.Change
		if change.Key == "" {
			change.Key = key
		}
		state.SuppressedChanges[key] = change
		delete(state.Incidents, key)
		delete(state.Pending, key)
		return []model.Event{{Type: "incident-suppressed", Job: jobName, ScanID: incident.ScanID, Message: "Incident suppressed for the next scan", Changes: []model.Change{change}, CreatedAt: time.Now().UTC()}}, nil
	})
}

// SuppressIncidentWithAudit is retained for source compatibility with callers
// that do not provide notification destinations.
func (s *Store) SuppressIncidentWithAudit(ctx context.Context, jobID, jobName, key string, audit AuditEntry) ([]model.Event, error) {
	return s.SuppressIncidentWithOutboxAndAudit(ctx, jobID, jobName, key, nil, audit)
}

// updateIncidentAction applies a baseline/incident mutation only when the job
// is not actively scanning. Keeping the active-scan check, state transition,
// event write, and audit insert in one transaction prevents a scan from
// finishing against a half-applied operator decision.
func (s *Store) updateIncidentAction(ctx context.Context, jobID string, destinations []string, audits []AuditEntry, syncBaseline bool, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := getJobTx(ctx, tx, jobID); err != nil {
		return nil, err
	}
	active, err := jobActiveTx(ctx, tx, jobID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrJobScanActive
	}
	var resultingState *model.JobState
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, destinations, func(state *model.JobState) ([]model.Event, error) {
		events, err := fn(state)
		if err == nil && syncBaseline && state.Baseline != nil {
			resultingState = state
		}
		return events, err
	})
	if err != nil {
		return nil, err
	}
	if resultingState != nil {
		if err := replaceBaselineHostProjectionTx(ctx, tx, jobID, *resultingState.Baseline); err != nil {
			return nil, err
		}
	}
	if err := insertAuditEntries(ctx, tx, audits, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func fingerprintCandidateKey(change model.Change) string {
	return fmt.Sprintf("service|%s|%s|%d", change.Target, change.Protocol, change.Port)
}

// applyAcceptedChange updates the comparison fields represented by an
// incident. The immutable scan history remains untouched; the runtime
// baseline's host evidence is updated only enough for the expected host view
// to agree with its accepted port/service state.
func applyAcceptedChange(snapshot *model.Snapshot, change model.Change) error {
	if snapshot == nil {
		return ErrBaselineNotReady
	}
	switch change.Kind {
	case "port":
		return acceptPortChange(snapshot, change)
	case "service":
		return acceptServiceChange(snapshot, change)
	case "dns-added", "dns-removed":
		return acceptDNSChange(snapshot, change)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedIncidentChange, change.Kind)
	}
}

func acceptPortChange(snapshot *model.Snapshot, change model.Change) error {
	if strings.TrimSpace(change.Target) == "" || strings.TrimSpace(change.Protocol) == "" || change.Port < 1 || change.Port > 65535 {
		return fmt.Errorf("%w: invalid port change", ErrUnsupportedIncidentChange)
	}
	unitIndex := findUnit(snapshot, change.Target, change.Protocol)
	if change.New == "not-open" {
		if unitIndex < 0 {
			return nil
		}
		ports := snapshot.Units[unitIndex].Ports[:0]
		for _, port := range snapshot.Units[unitIndex].Ports {
			if port.Port != change.Port {
				ports = append(ports, port)
			}
		}
		snapshot.Units[unitIndex].Ports = ports
		syncAcceptedPortHosts(snapshot, change)
		snapshot.Normalize()
		return nil
	}
	if strings.TrimSpace(change.New) == "" {
		return fmt.Errorf("%w: port state is empty", ErrUnsupportedIncidentChange)
	}
	if unitIndex < 0 {
		snapshot.Units = append(snapshot.Units, model.Unit{Target: change.Target, Protocol: change.Protocol})
		unitIndex = len(snapshot.Units) - 1
	}
	for i := range snapshot.Units[unitIndex].Ports {
		if snapshot.Units[unitIndex].Ports[i].Port == change.Port {
			snapshot.Units[unitIndex].Ports[i].State = change.New
			syncAcceptedPortHosts(snapshot, change)
			snapshot.Normalize()
			return nil
		}
	}
	snapshot.Units[unitIndex].Ports = append(snapshot.Units[unitIndex].Ports, model.PortState{Port: change.Port, State: change.New})
	syncAcceptedPortHosts(snapshot, change)
	snapshot.Normalize()
	return nil
}

func acceptServiceChange(snapshot *model.Snapshot, change model.Change) error {
	if strings.TrimSpace(change.Target) == "" || strings.TrimSpace(change.Protocol) == "" || change.Port < 1 || change.Port > 65535 {
		return fmt.Errorf("%w: invalid service change", ErrUnsupportedIncidentChange)
	}
	unitIndex := findUnit(snapshot, change.Target, change.Protocol)
	if unitIndex < 0 {
		// A port-removal incident and its service-removal incident are emitted
		// together. If the administrator accepts the port first, the related
		// service change is already reflected by the missing unit and is safe to
		// acknowledge as an idempotent no-op.
		if change.New == "not-open" {
			return nil
		}
		return fmt.Errorf("%w: baseline port is missing", ErrUnsupportedIncidentChange)
	}
	for i := range snapshot.Units[unitIndex].Ports {
		if snapshot.Units[unitIndex].Ports[i].Port == change.Port {
			snapshot.Units[unitIndex].Ports[i].Service = ""
			if change.New != "not-open" {
				if strings.TrimSpace(change.New) == "" {
					return fmt.Errorf("%w: service value is empty", ErrUnsupportedIncidentChange)
				}
				snapshot.Units[unitIndex].Ports[i].Service = change.New
			}
			syncAcceptedServiceHosts(snapshot, change)
			snapshot.Normalize()
			return nil
		}
	}
	if change.New == "not-open" {
		// The port may have been accepted first and removed from this unit. The
		// service is absent as a consequence, so there is nothing left to write.
		return nil
	}
	return fmt.Errorf("%w: baseline port is missing", ErrUnsupportedIncidentChange)
}

func normalizedAcceptedTarget(target string) string {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
	}
	return target
}

func acceptedHostMatches(snapshot *model.Snapshot, host model.HostObservation, target string) bool {
	target = normalizedAcceptedTarget(target)
	if normalizedAcceptedTarget(host.Address) == target {
		return true
	}
	for _, value := range append(append([]string(nil), host.SourceTargets...), host.DNSNames...) {
		if normalizedAcceptedTarget(value) == target {
			return true
		}
	}
	for _, unit := range snapshot.Units {
		if normalizedAcceptedTarget(unit.Target) != target {
			continue
		}
		for _, address := range unit.Addresses {
			if normalizedAcceptedTarget(address) == normalizedAcceptedTarget(host.Address) {
				return true
			}
		}
	}
	return false
}

func syncAcceptedPortHosts(snapshot *model.Snapshot, change model.Change) {
	for hostIndex := range snapshot.Hosts {
		host := &snapshot.Hosts[hostIndex]
		if !acceptedHostMatches(snapshot, *host, change.Target) {
			continue
		}
		for protocolIndex := range host.Protocols {
			protocol := &host.Protocols[protocolIndex]
			if protocol.Protocol != change.Protocol {
				continue
			}
			if change.New == "not-open" {
				ports := protocol.Ports[:0]
				for _, port := range protocol.Ports {
					if port.Port != change.Port {
						ports = append(ports, port)
					}
				}
				protocol.Ports = ports
				continue
			}
			found := false
			for portIndex := range protocol.Ports {
				if protocol.Ports[portIndex].Port != change.Port {
					continue
				}
				protocol.Ports[portIndex].State = change.New
				found = true
				break
			}
			if !found {
				protocol.Ports = append(protocol.Ports, model.PortObservation{Port: change.Port, State: change.New})
			}
		}
	}
}

func syncAcceptedServiceHosts(snapshot *model.Snapshot, change model.Change) {
	for hostIndex := range snapshot.Hosts {
		host := &snapshot.Hosts[hostIndex]
		if !acceptedHostMatches(snapshot, *host, change.Target) {
			continue
		}
		for protocolIndex := range host.Protocols {
			protocol := &host.Protocols[protocolIndex]
			if protocol.Protocol != change.Protocol {
				continue
			}
			for portIndex := range protocol.Ports {
				port := &protocol.Ports[portIndex]
				if port.Port != change.Port {
					continue
				}
				if change.New == "not-open" {
					port.Service = nil
				} else {
					port.Service = &model.ServiceObservation{Product: change.New, Method: "accepted"}
				}
			}
		}
	}
}

func acceptDNSChange(snapshot *model.Snapshot, change model.Change) error {
	target := strings.TrimSpace(change.Target)
	address := strings.TrimSpace(change.New)
	if change.Kind == "dns-removed" {
		address = strings.TrimSpace(change.Old)
	}
	if target == "" || address == "" {
		return fmt.Errorf("%w: DNS target or address is empty", ErrUnsupportedIncidentChange)
	}
	if snapshot.DNS == nil {
		snapshot.DNS = map[string][]string{}
	}
	addresses := snapshot.DNS[target]
	if change.Kind == "dns-added" {
		found := false
		for _, value := range addresses {
			if value == address {
				found = true
				break
			}
		}
		if !found {
			snapshot.DNS[target] = append(addresses, address)
		}
	} else {
		filtered := addresses[:0]
		for _, value := range addresses {
			if value != address {
				filtered = append(filtered, value)
			}
		}
		if len(filtered) == 0 {
			delete(snapshot.DNS, target)
		} else {
			snapshot.DNS[target] = filtered
		}
	}
	snapshot.Normalize()
	return nil
}

func findUnit(snapshot *model.Snapshot, target, protocol string) int {
	for i := range snapshot.Units {
		if snapshot.Units[i].Target == target && snapshot.Units[i].Protocol == protocol {
			return i
		}
	}
	return -1
}
