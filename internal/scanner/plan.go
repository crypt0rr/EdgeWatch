package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

// WorkUnit is one independently checkpointable Nmap invocation. Targets are
// repeated in the plan deliberately: a plan is persisted as a self-contained
// immutable snapshot so it can resume after a process restart or DNS change.
type WorkUnit struct {
	Sequence  int              `json:"sequence"`
	Protocol  string           `json:"protocol"`
	Family    int              `json:"family"`
	Targets   []ResolvedTarget `json:"targets"`
	Addresses []string         `json:"addresses"`
	Ports     string           `json:"ports"`
	PortCount int              `json:"port_count"`
	Probes    int64            `json:"probes"`
}

// ResolvedTarget is the pinned result of expanding one configured target.
// Aggregate and Hostname preserve the logical DNS comparison behavior while
// Addresses identifies the effective hosts scanned by each work unit.
type ResolvedTarget struct {
	Name             string   `json:"name"`
	ConfiguredTarget string   `json:"configured_target"`
	Addresses        []string `json:"addresses"`
	Aggregate        bool     `json:"aggregate,omitempty"`
	Hostname         bool     `json:"hostname,omitempty"`
}

// WorkPlan is an immutable execution plan for one complete scan cycle.
type WorkPlan struct {
	CreatedAt   time.Time           `json:"created_at"`
	Job         config.Job          `json:"job"`
	Targets     []ResolvedTarget    `json:"targets"`
	DNS         map[string][]string `json:"dns,omitempty"`
	Scopes      []model.Scope       `json:"scopes"`
	Units       []WorkUnit          `json:"units"`
	TotalProbes int64               `json:"total_probes"`
	TotalUnits  int                 `json:"total_units"`
}

const (
	// maxWorkUnitProbes keeps one invocation small enough to checkpoint. It is
	// an execution guard, not a deployment budget; the latter remains enforced
	// by App.CheckScanWorkBudget.
	maxWorkUnitProbes int64 = 65_536
	maxWorkUnitPorts        = 4_096
	minRetryPortChunk       = 256
)

// ResumableScanner is implemented by scanners that can create and execute
// deterministic checkpointable work units. The ordinary Scanner interface is
// intentionally left unchanged for deterministic test and plugin scanners.
type ResumableScanner interface {
	Plan(context.Context, config.Job) (WorkPlan, error)
	ScanWorkUnit(context.Context, config.Job, WorkUnit, ProgressReporter) (model.Snapshot, error)
}

// Plan resolves targets once and creates deterministic address/port work
// units. It does not start a scan process beyond the DNS resolution needed to
// pin the cycle's effective targets.
func (n *Nmap) Plan(ctx context.Context, job config.Job) (WorkPlan, error) {
	job = config.NormalizeJob(job)
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return WorkPlan{}, err
	}
	plan := WorkPlan{CreatedAt: time.Now().UTC(), Job: job, Targets: exportResolvedTargets(targets), DNS: map[string][]string{}}
	for _, target := range targets {
		if target.Hostname {
			plan.DNS[target.Name] = append([]string(nil), target.Addresses...)
		}
	}
	for _, item := range []struct {
		protocol string
		config.Protocol
	}{
		{protocol: "tcp", Protocol: valueProtocol(job.TCP)},
		{protocol: "udp", Protocol: valueProtocol(job.UDP)},
	} {
		if item.Ports == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return WorkPlan{}, err
		}
		ports, err := config.ParsePorts(item.Ports)
		if err != nil {
			return WorkPlan{}, fmt.Errorf("%s: %w", item.protocol, err)
		}
		for _, target := range targets {
			plan.Scopes = append(plan.Scopes, model.Scope{Target: target.Name, Protocol: item.protocol, Ports: item.Ports, ServiceDetection: item.ServiceDetection})
		}
		addressesByFamily := map[int][]string{4: {}, 6: {}}
		seen := map[string]bool{}
		for _, target := range targets {
			for _, address := range target.Addresses {
				if seen[address] {
					continue
				}
				seen[address] = true
				family := 4
				if net.ParseIP(address).To4() == nil {
					family = 6
				}
				addressesByFamily[family] = append(addressesByFamily[family], address)
			}
		}
		for _, family := range []int{4, 6} {
			if err := ctx.Err(); err != nil {
				return WorkPlan{}, err
			}
			addresses := addressesByFamily[family]
			sort.Strings(addresses)
			for addressStart := 0; addressStart < len(addresses); addressStart += nmapBatchSize {
				addressEnd := min(addressStart+nmapBatchSize, len(addresses))
				addressBatch := append([]string(nil), addresses[addressStart:addressEnd]...)
				unitTargets := subsetResolvedTargets(targets, addressBatch)
				factor := int64(1)
				if item.ServiceDetection {
					factor = 2
				}
				perChunk := maxWorkUnitPorts
				if capacity := maxWorkUnitProbes / (int64(len(addressBatch)) * factor); capacity > 0 && int64(perChunk) > capacity {
					perChunk = int(capacity)
				}
				if perChunk < 1 {
					perChunk = 1
				}
				for portStart := 0; portStart < len(ports); portStart += perChunk {
					portEnd := min(portStart+perChunk, len(ports))
					chunk := ports[portStart:portEnd]
					unit := WorkUnit{
						Sequence:  len(plan.Units),
						Protocol:  item.protocol,
						Family:    family,
						Targets:   exportResolvedTargets(unitTargets),
						Addresses: append([]string(nil), addressBatch...),
						Ports:     formatPorts(chunk),
						PortCount: len(chunk),
						Probes:    int64(len(addressBatch)) * int64(len(chunk)) * factor,
					}
					plan.Units = append(plan.Units, unit)
					plan.TotalProbes += unit.Probes
				}
			}
		}
	}
	plan.TotalUnits = len(plan.Units)
	return plan, nil
}

// ScanWorkUnit executes exactly one planned Nmap invocation and returns a
// fragment that can be committed independently by the application.
func (n *Nmap) ScanWorkUnit(ctx context.Context, job config.Job, unit WorkUnit, report ProgressReporter) (model.Snapshot, error) {
	pc, ok := protocolForJob(job, unit.Protocol)
	if !ok {
		return model.Snapshot{}, fmt.Errorf("%s scan is not enabled", unit.Protocol)
	}
	pc.Ports = unit.Ports
	started := time.Now().UTC()
	emit := func(progress Progress) {
		if progress.ElapsedSeconds <= 0 {
			progress.ElapsedSeconds = int64(time.Since(started).Seconds())
		}
		if progress.ElapsedSeconds < 0 {
			progress.ElapsedSeconds = 0
		}
		if report != nil {
			report(progress)
		}
	}
	emit(Progress{StartedAt: started, TotalProbes: unit.Probes, TotalInvocations: 1, Phase: unit.Protocol + " scanning", Protocol: unit.Protocol, TotalBatches: 1, CurrentUnit: unit.Sequence + 1, TotalUnits: 1, UnitPorts: unit.Ports, UnitAddresses: len(unit.Addresses), ProcessAlive: true})
	lastOutput := ""
	lastFraction := 0.0
	result, err := n.scanProtocolBatchDetailedProgress(ctx, importResolvedTargets(unit.Targets), unit.Protocol, pc, job.Timing, job.AssumesAlive(), nil, func(update invocationProgress) {
		lastOutput = update.Output
		if update.Fraction > lastFraction {
			lastFraction = update.Fraction
		}
		emit(Progress{StartedAt: started, CompletedProbes: int64(float64(unit.Probes) * lastFraction), TotalProbes: unit.Probes, CompletedInvocations: 0, TotalInvocations: 1, Phase: unit.Protocol + " scanning", Protocol: unit.Protocol, CurrentInvocation: 1, TotalBatches: 1, ProcessProgressPercent: int(lastFraction * 100), LastOutput: lastOutput, ProcessAlive: update.Alive, CurrentUnit: unit.Sequence + 1, TotalUnits: 1, UnitPorts: unit.Ports, UnitAddresses: len(unit.Addresses)})
	})
	if err != nil {
		emit(Progress{StartedAt: started, CompletedProbes: int64(float64(unit.Probes) * lastFraction), TotalProbes: unit.Probes, TotalInvocations: 1, Phase: unit.Protocol + " scanning", Protocol: unit.Protocol, CurrentInvocation: 1, TotalBatches: 1, ProcessProgressPercent: int(lastFraction * 100), LastOutput: lastOutput, ProcessAlive: false, CurrentUnit: unit.Sequence + 1, TotalUnits: 1, UnitPorts: unit.Ports, UnitAddresses: len(unit.Addresses)})
		return model.Snapshot{}, err
	}
	snapshot := model.Snapshot{Units: result.Units, Hosts: mapHosts(result.Hosts)}
	snapshot.Normalize()
	emit(Progress{StartedAt: started, CompletedProbes: unit.Probes, TotalProbes: unit.Probes, CompletedInvocations: 1, TotalInvocations: 1, Phase: "unit complete", Protocol: unit.Protocol, CurrentInvocation: 1, TotalBatches: 1, ProcessProgressPercent: 100, LastOutput: lastOutput, ProcessAlive: false, CurrentUnit: unit.Sequence + 1, TotalUnits: 1, UnitPorts: unit.Ports, UnitAddresses: len(unit.Addresses)})
	return snapshot, nil
}

func protocolForJob(job config.Job, protocol string) (config.Protocol, bool) {
	if protocol == "tcp" && job.TCP != nil {
		return *job.TCP, true
	}
	if protocol == "udp" && job.UDP != nil {
		return *job.UDP, true
	}
	return config.Protocol{}, false
}

func mapHosts(hosts map[string]model.HostObservation) []model.HostObservation {
	out := make([]model.HostObservation, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, host)
	}
	return out
}

// MergeWorkSnapshots combines independently completed fragments into the
// immutable snapshot used by the comparison engine. The configured scopes are
// restored after merging because each fragment intentionally carries only its
// own port chunk in detailed host evidence.
func MergeWorkSnapshots(plan WorkPlan, fragments []model.Snapshot) model.Snapshot {
	units := map[string]model.Unit{}
	hosts := map[string]model.HostObservation{}
	result := model.Snapshot{Scopes: append([]model.Scope(nil), plan.Scopes...), DNS: map[string][]string{}}
	for name, addresses := range plan.DNS {
		result.DNS[name] = append([]string(nil), addresses...)
	}
	for _, fragment := range fragments {
		for _, unit := range fragment.Units {
			key := unit.Target + "\x00" + unit.Protocol
			current, exists := units[key]
			if !exists {
				current = model.Unit{Target: unit.Target, Protocol: unit.Protocol}
			}
			current.Addresses = append(current.Addresses, unit.Addresses...)
			for _, port := range unit.Ports {
				found := -1
				for index := range current.Ports {
					if current.Ports[index].Port == port.Port {
						found = index
						break
					}
				}
				if found < 0 {
					current.Ports = append(current.Ports, port)
					continue
				}
				existing := &current.Ports[found]
				if existing.State != "open" && port.State == "open" {
					existing.State = port.State
				}
				existing.Evidence = append(existing.Evidence, port.Evidence...)
				if existing.Service == "" {
					existing.Service = port.Service
				}
			}
			units[key] = current
		}
		for _, host := range fragment.Hosts {
			mergeHostObservationMap(hosts, host.Address, host)
		}
	}
	for _, unit := range units {
		unit.Addresses = uniqueSorted(unit.Addresses)
		for portIndex := range unit.Ports {
			unit.Ports[portIndex].Evidence = uniqueSorted(unit.Ports[portIndex].Evidence)
		}
		result.Units = append(result.Units, unit)
	}
	for _, host := range hosts {
		result.Hosts = append(result.Hosts, host)
	}
	result.Normalize()
	// Restore the exact configured scope on every detailed host protocol. This
	// keeps the host explorer useful while ensuring chunk expressions never leak
	// into the public result.
	scopeByProtocol := map[string]model.Scope{}
	for _, scope := range plan.Scopes {
		if _, exists := scopeByProtocol[scope.Protocol]; !exists {
			scopeByProtocol[scope.Protocol] = scope
		}
	}
	for hostIndex := range result.Hosts {
		for protocolIndex := range result.Hosts[hostIndex].Protocols {
			protocol := &result.Hosts[hostIndex].Protocols[protocolIndex]
			if scope, ok := scopeByProtocol[protocol.Protocol]; ok {
				protocol.ScannedPorts = scope.Ports
				protocol.ServiceDetection = scope.ServiceDetection
				if ports, err := config.ParsePorts(scope.Ports); err == nil {
					protocol.ScannedPortCount = len(ports)
				}
			}
		}
	}
	result.Normalize()
	return result
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// SplitWorkUnit deterministically halves a timed-out invocation. Addresses
// are split before ports so a single difficult host is not repeatedly retried
// alongside otherwise fast hosts. Once one address remains, a port range is
// split until each retry is at most minRetryPortChunk ports wide. Halving is
// intentional: it avoids creating a one-port tail for ranges just above the
// checkpoint bound while still guaranteeing that a 257-port unit can make
// progress toward the 256-port retry size.
func SplitWorkUnit(unit WorkUnit) (WorkUnit, WorkUnit, bool) {
	if len(unit.Addresses) > 1 {
		mid := len(unit.Addresses) / 2
		firstAddresses := append([]string(nil), unit.Addresses[:mid]...)
		secondAddresses := append([]string(nil), unit.Addresses[mid:]...)
		first := unit
		first.Addresses = firstAddresses
		first.Targets = exportResolvedTargets(subsetResolvedTargets(importResolvedTargets(unit.Targets), firstAddresses))
		second := unit
		second.Sequence = 0
		second.Addresses = secondAddresses
		second.Targets = exportResolvedTargets(subsetResolvedTargets(importResolvedTargets(unit.Targets), secondAddresses))
		first.Probes = scaleWorkUnitProbes(unit, len(firstAddresses), unit.PortCount)
		second.Probes = scaleWorkUnitProbes(unit, len(secondAddresses), unit.PortCount)
		return first, second, true
	}
	ports, err := config.ParsePorts(unit.Ports)
	if err != nil || len(ports) <= minRetryPortChunk {
		return WorkUnit{}, WorkUnit{}, false
	}
	mid := len(ports) / 2
	if mid <= 0 || mid >= len(ports) {
		return WorkUnit{}, WorkUnit{}, false
	}
	first := unit
	first.Ports = formatPorts(ports[:mid])
	first.PortCount = mid
	second := unit
	second.Sequence = 0
	second.Ports = formatPorts(ports[mid:])
	second.PortCount = len(ports) - mid
	first.Probes = scaleWorkUnitProbes(unit, len(unit.Addresses), first.PortCount)
	second.Probes = scaleWorkUnitProbes(unit, len(unit.Addresses), second.PortCount)
	return first, second, true
}

func scaleWorkUnitProbes(unit WorkUnit, addresses, ports int) int64 {
	if addresses <= 0 || ports <= 0 {
		return 0
	}
	// Alternate scanners may omit PortCount while still providing a valid
	// expression. Derive it from the expression before scaling so splitting a
	// checkpoint never loses (or invents) probe progress metadata.
	portCount := unit.PortCount
	if portCount <= 0 {
		if parsed, err := config.ParsePorts(unit.Ports); err == nil {
			portCount = len(parsed)
		}
	}
	denominator := int64(len(unit.Addresses)) * int64(portCount)
	factor := int64(1)
	if denominator > 0 && unit.Probes > 0 {
		factor = unit.Probes / denominator
		if factor < 1 {
			factor = 1
		}
	}
	return int64(addresses) * int64(ports) * factor
}

func exportResolvedTargets(targets []resolvedTarget) []ResolvedTarget {
	out := make([]ResolvedTarget, 0, len(targets))
	for _, target := range targets {
		out = append(out, ResolvedTarget{Name: target.Name, ConfiguredTarget: target.ConfiguredTarget, Addresses: append([]string(nil), target.Addresses...), Aggregate: target.Aggregate, Hostname: target.Hostname})
	}
	return out
}

func importResolvedTargets(targets []ResolvedTarget) []resolvedTarget {
	out := make([]resolvedTarget, 0, len(targets))
	for _, target := range targets {
		out = append(out, resolvedTarget{Name: target.Name, ConfiguredTarget: target.ConfiguredTarget, Addresses: append([]string(nil), target.Addresses...), Aggregate: target.Aggregate, Hostname: target.Hostname})
	}
	return out
}

func subsetResolvedTargets(targets []resolvedTarget, addresses []string) []resolvedTarget {
	set := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		set[address] = true
	}
	var out []resolvedTarget
	for _, target := range targets {
		var selected []string
		for _, address := range target.Addresses {
			if set[address] {
				selected = append(selected, address)
			}
		}
		if len(selected) == 0 {
			continue
		}
		out = append(out, resolvedTarget{Name: target.Name, ConfiguredTarget: target.ConfiguredTarget, Addresses: selected, Aggregate: target.Aggregate, Hostname: target.Hostname})
	}
	return out
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	start, previous := ports[0], ports[0]
	flush := func() {
		if start == previous {
			parts = append(parts, fmt.Sprintf("%d", start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, previous))
		}
	}
	for _, port := range ports[1:] {
		if port == previous+1 {
			previous = port
			continue
		}
		flush()
		start, previous = port, port
	}
	flush()
	return strings.Join(parts, ",")
}
