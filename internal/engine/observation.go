package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// A job tracks findings: pending changes, open incidents and one-scan
// suppressions. When a scan reports no change for a tracked finding, it saw
// the finding back in its baseline state, which recovers an incident,
// resets a pending change and uses up a suppression. That holds only for a
// finding the scan observed: absence that a scan could not observe is
// neither a closure nor a recovery. observe decides, once for each scan,
// which tracked findings it did not observe, and applyObservedChanges is
// the only place that turns a missing change into a recovery.

// observation is what one scan observed of the findings that a job tracks.
// Every tracked finding that is in neither set was observed.
type observation struct {
	// retired are findings that the scan shows cannot be compared any more
	// as they are, because their scope, port or address is gone. They leave
	// the state without a recovery.
	retired map[string]bool
	// unobserved are findings that the scan did not observe. They keep their
	// pending count, suppression and recovery count for a later scan.
	unobserved map[string]bool
}

// scanView describes how a scan was compared with the baseline.
type scanView struct {
	snapshot model.Snapshot
	// changes are the changes that the scan reports.
	changes []model.Change
	// scopeChanged is set when the scan ran with a security scope other
	// than the baseline's, so it compared the intersection of both.
	scopeChanged bool
	// hostsOnly is set while the total-loss guard compares host state
	// transitions only.
	hostsOnly bool
	// incomplete is the coverage that an incomplete scan lacks, or nil for
	// a complete scan.
	incomplete *missingCoverage
	// deferred are the changes that an incomplete scan leaves to the next
	// complete scan, such as a fingerprint that scan learns.
	deferred map[string]struct{}
}

// missingCoverage names the targets, and the targets and protocols, whose
// scan coverage did not complete.
type missingCoverage struct {
	protocols, targets map[string]struct{}
}

// observe returns what the scan in view observed of the findings that state
// tracks. A finding is not observed when:
//
//   - the scan's new scope no longer covers it (retired);
//   - its port is on a host that host discovery reports down, or its host
//     state is missing from the scan (unobserved), or its address left the
//     scan's scope (retired by a complete scan);
//   - it is a service of a port that a complete scan no longer shows as
//     positive (retired), or a per-address finding that the scan could not
//     compare (retired by a complete scan);
//   - its coverage is incomplete, or an incomplete scan deferred it
//     (unobserved);
//   - it is not a host state while the total-loss guard compares host
//     states only (unobserved).
//
// A change that the scan reports was always observed. An incomplete scan
// and the total-loss guard never retire a finding beyond the scope change.
func observe(state *model.JobState, job config.Job, view scanView) observation {
	seen := observation{retired: map[string]bool{}, unobserved: map[string]bool{}}
	if state.Baseline == nil {
		return seen
	}
	if view.scopeChanged && view.incomplete == nil {
		seen.retire(outOfScopeChangeKeys(state, view.snapshot, job))
	}
	hostsKept, hostsGone := unobservedHostChangeKeys(state, view.snapshot)
	seen.keep(hostsKept)
	switch {
	case view.hostsOnly:
		seen.keep(protectedNonHostChangeKeys(state))
		seen.keep(hostsGone)
	case view.incomplete != nil:
		seen.keep(protectedChangeKeys(state, *state.Baseline, view.snapshot, view.incomplete.protocols, view.incomplete.targets))
		for key := range view.deferred {
			seen.unobserved[key] = true
		}
		seen.keep(uncomparedPortAddressKeys(state, view.snapshot, view.scopeChanged, job))
		seen.keep(downHostChangeKeys(state, view.snapshot, job))
		seen.keep(hostsGone)
	default:
		down := downHostChangeKeys(state, view.snapshot, job)
		seen.keep(down)
		for key := range closedPortServiceKeys(state, view.snapshot) {
			if !down[key] {
				seen.retired[key] = true
			}
		}
		seen.retire(uncomparedPortAddressKeys(state, view.snapshot, view.scopeChanged, job))
		seen.retire(hostsGone)
	}
	for _, change := range view.changes {
		delete(seen.unobserved, change.Key)
	}
	return seen
}

func (o observation) retire(keys map[string]bool) {
	for key := range keys {
		o.retired[key] = true
	}
}

func (o observation) keep(keys map[string]bool) {
	for key := range keys {
		o.unobserved[key] = true
	}
}

// retireFrom removes the retired findings from state.
func (o observation) retireFrom(state *model.JobState) {
	for key := range o.retired {
		delete(state.Pending, key)
		delete(state.Incidents, key)
		delete(state.Suppressed, key)
		delete(state.SuppressedChanges, key)
	}
}

// eachTrackedChange calls fn with each tracked finding that carries its
// change: the pending changes, open incidents and suppressed changes.
func eachTrackedChange(state *model.JobState, fn func(key string, change model.Change)) {
	for key, pending := range state.Pending {
		fn(key, pending.Change)
	}
	for key, incident := range state.Incidents {
		fn(key, incident.Change)
	}
	for key, change := range state.SuppressedChanges {
		fn(key, change)
	}
}

// eachKeyOnlySuppression calls fn with each suppression that state holds
// without its change, as older releases stored them. Its key still names
// the finding.
func eachKeyOnlySuppression(state *model.JobState, fn func(key string)) {
	for key := range state.Suppressed {
		if _, ok := state.SuppressedChanges[key]; !ok {
			fn(key)
		}
	}
}

// outOfScopeChangeKeys returns the findings that a complete scan with a new
// security scope can no longer observe. They are not recoveries: no scan
// established that the old state changed back to baseline.
func outOfScopeChangeKeys(state *model.JobState, snapshot model.Snapshot, job config.Job) map[string]bool {
	out := map[string]bool{}
	dnsAddresses := dnsAddressesInSnapshot(snapshot)
	eachTrackedChange(state, func(key string, change model.Change) {
		if !changeWithinScopeWithDNSAddresses(snapshot, change, job, dnsAddresses) {
			out[key] = true
		}
	})
	return out
}

func changeWithinScopeWithDNSAddresses(snapshot model.Snapshot, change model.Change, job config.Job, dnsAddresses map[string]struct{}) bool {
	switch change.Kind {
	case "port":
		return scopeAllows(snapshot, change.Target, change.Protocol, change.Port, false)
	case "port-address":
		if job.DNSComparisonMode == config.DNSComparisonAggregate {
			return false
		}
		return scopeAllows(snapshot, change.Target, change.Protocol, change.Port, false)
	case "service":
		return scopeAllows(snapshot, change.Target, change.Protocol, change.Port, true)
	case "host":
		if job.DNSComparisonMode == config.DNSComparisonAggregate && dnsOnlyAddressInSnapshot(change.Target, dnsAddresses, snapshot) {
			return false
		}
		return hostInScope(snapshot, change.Target)
	case "dns", "dns-added", "dns-removed":
		if job.DNSComparisonMode == config.DNSComparisonAggregate {
			return false
		}
		return hasTarget(snapshot, change.Target)
	default:
		return false
	}
}

// protectedNonHostChangeKeys prevents a total-loss anomaly from advancing
// recovery, pending confirmation, or one-scan suppression for port and
// service changes while the guard evaluates only an explicit host transition.
func protectedNonHostChangeKeys(state *model.JobState) map[string]bool {
	protected := map[string]bool{}
	protect := func(key string) {
		if !strings.HasPrefix(key, "host|") {
			protected[key] = true
		}
	}
	for key := range state.Pending {
		protect(key)
	}
	for key := range state.Incidents {
		protect(key)
	}
	for key := range state.Suppressed {
		protect(key)
	}
	for key := range state.SuppressedChanges {
		protect(key)
	}
	return protected
}

// protectedChangeKeys returns the keys whose target, or target and protocol,
// an incomplete scan did not cover completely, in the baseline, the scan, or
// the tracked findings.
func protectedChangeKeys(state *model.JobState, baseline, current model.Snapshot, protocols, targets map[string]struct{}) map[string]bool {
	protected := make(map[string]bool)
	for key, value := range items(baseline) {
		if incompleteChange(model.Change{Target: value.Target, Protocol: value.Protocol}, protocols, targets) {
			protected[key] = true
		}
	}
	for key, value := range items(current) {
		if incompleteChange(model.Change{Target: value.Target, Protocol: value.Protocol}, protocols, targets) {
			protected[key] = true
		}
	}
	eachTrackedChange(state, func(key string, change model.Change) {
		if incompleteChange(change, protocols, targets) {
			protected[key] = true
		}
	})
	return protected
}

// uncomparedPortAddressKeys returns the tracked port-address findings that
// this scan could not compare, for example because the address left the DNS
// answer, its host is down, or the port is no longer positive. The scan did
// not observe such an address returning to its expected state, so the
// finding must not count towards a recovery.
func uncomparedPortAddressKeys(state *model.JobState, current model.Snapshot, intersectionOnly bool, job config.Job) map[string]bool {
	uncompared := map[string]bool{}
	compared := map[string]struct{}{}
	if job.DNSComparisonMode != config.DNSComparisonAggregate {
		compared, _ = comparePortAddresses(*state.Baseline, current, intersectionOnly, completedDownAddressesByProtocolForJob(*state.Baseline, current, job))
	}
	eachTrackedChange(state, func(key string, change model.Change) {
		if change.Kind != "port-address" {
			return
		}
		if _, ok := compared[key]; !ok {
			uncompared[key] = true
		}
	})
	return uncompared
}

// closedPortServiceKeys returns the service findings whose port is not
// positive in snapshot. A service fingerprint is meaningful only while its
// port is positively observed: Diff reports a port closure without also
// reporting a service removal, so such a service was not observed returning
// to its baseline fingerprint.
func closedPortServiceKeys(state *model.JobState, snapshot model.Snapshot) map[string]bool {
	closed := map[string]bool{}
	positive := positivePortKeys(snapshot)
	eachTrackedChange(state, func(key string, change model.Change) {
		if change.Kind != "service" {
			return
		}
		if _, ok := positive[portChangeKey(change.Target, change.Protocol, change.Port)]; !ok {
			closed[key] = true
		}
	})
	eachKeyOnlySuppression(state, func(key string) {
		if !strings.HasPrefix(key, "service|") {
			return
		}
		if _, ok := positive["port|"+strings.TrimPrefix(key, "service|")]; !ok {
			closed[key] = true
		}
	})
	return closed
}

// retireClosedPortServiceChanges removes service findings whose port is no
// longer positive in this complete snapshot. Such a service has not been
// observed returning to its baseline fingerprint, so it is not a recovery.
func retireClosedPortServiceChanges(state *model.JobState, snapshot model.Snapshot) {
	observation{retired: closedPortServiceKeys(state, snapshot)}.retireFrom(state)
}

// downHostChangeKeys returns the tracked port and service findings that this
// complete or incomplete scan could not observe because the host that would
// show their port was discovered down. A host that is down shows no ports,
// so a missing change for such a finding is not evidence that the port
// returned to its baseline state. A finding whose port the scan observed as
// positive was observed.
//
// A port of the baseline names the addresses that exposed it, and is not
// observed when all of them are down, as Diff decides when it leaves out its
// closure. Any other port, such as one that opened unexpectedly, may have
// been on any address of its target, so one address that is down is enough.
func downHostChangeKeys(state *model.JobState, current model.Snapshot, job config.Job) map[string]bool {
	hidden := map[string]bool{}
	downByProtocol := completedDownAddressesByProtocolForJob(*state.Baseline, current, job)
	if len(downByProtocol) == 0 {
		return hidden
	}
	positive := positivePortKeys(current)
	mark := func(key string, change model.Change) {
		if change.Kind != "port" && change.Kind != "service" {
			return
		}
		if _, ok := positive[portChangeKey(change.Target, change.Protocol, change.Port)]; ok {
			return
		}
		if portHiddenByDownHost(*state.Baseline, current, change.Target, change.Protocol, change.Port, downByProtocol) {
			hidden[key] = true
		}
	}
	eachTrackedChange(state, mark)
	eachKeyOnlySuppression(state, func(key string) {
		if change, ok := portChangeFromKey(key); ok {
			mark(key, change)
		}
	})
	return hidden
}

// portHiddenByDownHost reports whether a port that the current scan does not
// show as positive was on a host that the scan discovered down.
func portHiddenByDownHost(baseline, current model.Snapshot, target, protocol string, port int, downByProtocol map[string]map[string]struct{}) bool {
	if addresses, expected := positivePortAddresses(baseline, target, protocol, port); expected {
		if len(addresses) == 0 {
			return false
		}
		for address := range addresses {
			if !explicitlyDownForProtocol(downByProtocol, protocol, address) {
				return false
			}
		}
		return true
	}
	for _, address := range targetAddresses(current, target, protocol) {
		if explicitlyDownForProtocol(downByProtocol, protocol, address) {
			return true
		}
	}
	return false
}

// unobservedHostChangeKeys returns the tracked host-state findings that this
// scan did not observe because it has no state for their address. A host
// state recovers only when the scan observes the host in its baseline
// state. An address that is no longer in the scan's scope, for example one
// that left a DNS name's answer, cannot be compared any more (gone); the DNS
// change reports the transition. Any other finding is kept.
func unobservedHostChangeKeys(state *model.JobState, current model.Snapshot) (kept, gone map[string]bool) {
	kept, gone = map[string]bool{}, map[string]bool{}
	states := effectiveHostStates(current)
	mark := func(key string, change model.Change) {
		if change.Kind != "host" {
			return
		}
		if _, ok := states[strings.TrimSpace(change.Target)]; ok {
			return
		}
		if hostInScope(current, change.Target) {
			kept[key] = true
		} else {
			gone[key] = true
		}
	}
	eachTrackedChange(state, mark)
	eachKeyOnlySuppression(state, func(key string) {
		if strings.HasPrefix(key, "host|") {
			mark(key, model.Change{Key: key, Kind: "host", Target: strings.TrimPrefix(key, "host|")})
		}
	})
	return kept, gone
}

func portChangeKey(target, protocol string, port int) string {
	return fmt.Sprintf("port|%s|%s|%d", target, protocol, port)
}

func positivePortKeys(snapshot model.Snapshot) map[string]struct{} {
	positive := make(map[string]struct{})
	for _, unit := range snapshot.Units {
		for _, port := range unit.Ports {
			if isPositivePortState(port.State) {
				positive[portChangeKey(unit.Target, unit.Protocol, port.Port)] = struct{}{}
			}
		}
	}
	return positive
}

// portChangeFromKey reads the kind, target, protocol and port from the key
// of a port or service change.
func portChangeFromKey(key string) (model.Change, bool) {
	parts := strings.Split(key, "|")
	if len(parts) < 4 || (parts[0] != "port" && parts[0] != "service") {
		return model.Change{}, false
	}
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return model.Change{}, false
	}
	return model.Change{Key: key, Kind: parts[0], Target: strings.Join(parts[1:len(parts)-2], "|"), Protocol: parts[len(parts)-2], Port: port}, true
}

func applyChanges(state *model.JobState, job, scanID string, current []model.Change, required int, now time.Time) []model.Event {
	return applyObservedChanges(state, job, scanID, current, required, now, observation{})
}

// applyObservedChanges applies the changes that a scan reports to the
// tracked findings, given what the scan observed. It first retires the
// findings that cannot be compared any more. A reported change confirms or
// continues its finding; a tracked finding without a reported change
// recovers, or loses its pending confirmation, only when the scan observed
// it.
func applyObservedChanges(state *model.JobState, job, scanID string, current []model.Change, required int, now time.Time, seen observation) []model.Event {
	seen.retireFrom(state)
	protected := seen.unobserved
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
		if protected[key] {
			continue
		}
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
		if protected[key] {
			continue
		}
		if _, ok := currentMap[key]; !ok {
			delete(state.Pending, key)
		}
	}
	for key, incident := range state.Incidents {
		if protected[key] {
			continue
		}
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
		events = append(events, model.Event{Type: "changes-detected", Job: job, ScanID: scanID, Message: baselineChangeMessage(len(opened), "confirmed"), Changes: opened, CreatedAt: now})
	}
	if len(recovered) > 0 {
		events = append(events, model.Event{Type: "changes-recovered", Job: job, ScanID: scanID, Message: baselineChangeMessage(len(recovered), "recovered"), Changes: recovered, CreatedAt: now})
	}
	return events
}
