package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// AcceptIncidentWithAudit folds one active incident into the current baseline.
// The mutation and its audit row share the same transaction, so a successful
// response always means both durable records were committed.
func (s *Store) AcceptIncidentWithAudit(ctx context.Context, jobID, jobName, key string, audit AuditEntry) ([]model.Event, error) {
	return s.updateIncidentAction(ctx, jobID, []AuditEntry{audit}, func(state *model.JobState) ([]model.Event, error) {
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
		if err := applyAcceptedChange(state.Baseline, change); err != nil {
			return nil, err
		}
		delete(state.Incidents, key)
		delete(state.Pending, key)
		delete(state.Suppressed, key)
		delete(state.SuppressedChanges, key)
		if change.Kind == "service" || change.Kind == "port" {
			delete(state.FingerprintCandidates, fingerprintCandidateKey(change))
		}
		return []model.Event{{Type: "incident-accepted", Job: jobName, ScanID: incident.ScanID, Message: "Incident accepted into baseline", Changes: []model.Change{change}, CreatedAt: time.Now().UTC()}}, nil
	})
}

// SuppressIncidentWithAudit hides an active incident for exactly one future
// successful scan. The confirmed change is retained privately so the engine
// can re-open it immediately if the next scan still observes the change.
func (s *Store) SuppressIncidentWithAudit(ctx context.Context, jobID, jobName, key string, audit AuditEntry) ([]model.Event, error) {
	return s.updateIncidentAction(ctx, jobID, []AuditEntry{audit}, func(state *model.JobState) ([]model.Event, error) {
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

// updateIncidentAction applies a baseline/incident mutation only when the job
// is not actively scanning. Keeping the active-scan check, state transition,
// event write, and audit insert in one transaction prevents a scan from
// finishing against a half-applied operator decision.
func (s *Store) updateIncidentAction(ctx context.Context, jobID string, audits []AuditEntry, fn func(*model.JobState) ([]model.Event, error)) ([]model.Event, error) {
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
	events, err := updateRuntimeTxWithOutbox(ctx, tx, jobID, nil, fn)
	if err != nil {
		return nil, err
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

// applyAcceptedChange updates only the comparison fields represented by an
// incident. Host observation metadata and scan history remain untouched.
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
			snapshot.Normalize()
			return nil
		}
	}
	snapshot.Units[unitIndex].Ports = append(snapshot.Units[unitIndex].Ports, model.PortState{Port: change.Port, State: change.New})
	snapshot.Normalize()
	return nil
}

func acceptServiceChange(snapshot *model.Snapshot, change model.Change) error {
	if strings.TrimSpace(change.Target) == "" || strings.TrimSpace(change.Protocol) == "" || change.Port < 1 || change.Port > 65535 {
		return fmt.Errorf("%w: invalid service change", ErrUnsupportedIncidentChange)
	}
	unitIndex := findUnit(snapshot, change.Target, change.Protocol)
	if unitIndex < 0 {
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
			snapshot.Normalize()
			return nil
		}
	}
	return fmt.Errorf("%w: baseline port is missing", ErrUnsupportedIncidentChange)
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
