package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	naabuFullPortExpression = config.NaabuFullPortExpression
	// Naabu emits one JSON object per discovered port. A pathological target
	// set can still produce a large response, so cap one invocation before it
	// can exhaust the daemon's memory. The scan fails safely when the cap is
	// reached and can be resumed from the previous completed unit.
	maxNaabuOutput = 64 << 20
)

type naabuResult struct {
	Host       string    `json:"host"`
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	MacAddress string    `json:"mac_address"`
	Timestamp  time.Time `json:"timestamp"`
}

// scanNaabuPipeline performs TCP discovery first and then asks Nmap to
// confirm/enrich only the ports Naabu found. UDP remains on the existing Nmap
// path. The compact Units returned by this method contain Nmap-confirmed
// states only; richer discovery evidence is kept on HostObservation.
func (n *Nmap) scanNaabuPipeline(ctx context.Context, job config.Job, report ProgressReporter) (model.Snapshot, error) {
	job = config.NormalizeJob(job)
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
	return n.scanNaabuPipelineResolved(ctx, job, targets, report)
}

// scanNaabuDiscoveryResolved executes only the first, full-range phase of a
// Naabu pipeline. It intentionally does not invoke Nmap: the returned host
// observations are the durable discovery checkpoint from which the store can
// deterministically create the later enrichment units. A target that produced
// no JSONL records still receives an observation and a complete 1-65535
// non-discovery summary, so an empty result is distinguishable from missing
// checkpoint data.
func (n *Nmap) scanNaabuDiscoveryResolved(ctx context.Context, job config.Job, targets []resolvedTarget, report ProgressReporter) (model.Snapshot, error) {
	started := time.Now().UTC()
	job = config.NormalizeJob(job)
	snapshot := model.Snapshot{DNS: map[string][]string{}}
	for _, target := range targets {
		if target.Hostname {
			snapshot.DNS[target.Name] = append([]string(nil), target.Addresses...)
		}
	}
	if job.TCP == nil {
		return model.Snapshot{}, errors.New("naabu discovery requires tcp")
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "tcp", Ports: naabuFullPortExpression, ServiceDetection: job.TCP.ServiceDetection})
	}
	addresses := uniqueAddresses(targets)
	options := *job.TCP.Naabu
	config.ApplyNaabuDefaultsForScanner(&options)
	if err := config.ValidateNaabuOptions(options); err != nil {
		return model.Snapshot{}, fmt.Errorf("tcp naabu: %w", err)
	}
	if options.ScanType == "syn" && !hasRawScannerPrivileges() {
		return model.Snapshot{}, errors.New("naabu SYN scanning requires NET_RAW and NET_ADMIN capabilities; choose connect mode or grant the capabilities explicitly")
	}
	if len(addresses) == 0 {
		return model.Snapshot{}, errors.New("no effective targets")
	}
	batchSize := options.AddressBatchSize
	if batchSize < 1 {
		batchSize = 16
	}
	discoveryTotal := int64(len(addresses)) * 65535
	totalInvocations := int64((len(addresses) + batchSize - 1) / batchSize)
	reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", TotalProbes: discoveryTotal, TotalInvocations: totalInvocations})
	discovered := map[string]map[int]bool{}
	discoveryHosts := map[string]model.HostObservation{}
	portsFound, addressesFound := 0, 0
	discoveryStarted := time.Now()
	// Keep a diagnostic snapshot available even when a child exits halfway
	// through discovery. The application persists failed scans for operators,
	// but an empty return here would discard the useful JSONL records collected
	// before the failure.
	partialSnapshot := func() model.Snapshot {
		copyHosts := materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job)
		snapshot.Hosts = mapHosts(copyHosts)
		snapshot.Normalize()
		return snapshot
	}
	for start := 0; start < len(addresses); start += batchSize {
		end := min(start+batchSize, len(addresses))
		batch := addresses[start:end]
		localInvocation := int64(start/batchSize) + 1
		reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: totalInvocations, TotalInvocations: totalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(start) * 65535, ProcessAlive: true, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound})
		batchProbes := int64(len(batch)) * 65535
		results, stderr, err := n.runNaabu(ctx, options, job.TCP.NaabuArgs, batch, job.AssumesAlive(), func(update invocationProgress) {
			completed := int64(start) * 65535
			if update.Fraction > 0 {
				completed += int64(float64(batchProbes) * update.Fraction)
			}
			reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: totalInvocations, TotalInvocations: totalInvocations, TotalProbes: discoveryTotal, CompletedProbes: completed, ProcessAlive: update.Alive, LastOutput: update.Output, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
		})
		if err != nil {
			if ctx.Err() != nil {
				return partialSnapshot(), fmt.Errorf("naabu discovery canceled or timed out: %w", ctx.Err())
			}
			return partialSnapshot(), fmt.Errorf("naabu discovery failed: %v: %s", err, sanitizeStderr(stderr))
		}
		for _, result := range results {
			address := normalizeAddress(result.IP)
			if address == "" {
				address = normalizeAddress(result.Host)
			}
			if net.ParseIP(address) == nil {
				return partialSnapshot(), fmt.Errorf("naabu returned invalid address %q", address)
			}
			if !containsString(batch, address) {
				return partialSnapshot(), fmt.Errorf("naabu returned unexpected address %s", address)
			}
			if result.Port < 1 || result.Port > 65535 {
				return partialSnapshot(), fmt.Errorf("naabu returned invalid port %d", result.Port)
			}
			if result.Protocol != "" && !strings.EqualFold(result.Protocol, "tcp") {
				return partialSnapshot(), fmt.Errorf("naabu returned non-TCP protocol %q", result.Protocol)
			}
			if discovered[address] == nil {
				discovered[address] = map[int]bool{}
				addressesFound++
			}
			if !discovered[address][result.Port] {
				discovered[address][result.Port] = true
				portsFound++
			}
			host := discoveryHosts[address]
			host.Address = address
			host.AddressFamily = addressFamily(address)
			host.Status = "up"
			if result.MacAddress != "" {
				host.LinkAddresses = append(host.LinkAddresses, model.LinkAddress{Address: result.MacAddress, Type: "mac"})
			}
			discoveryHosts[address] = host
		}
		reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: totalInvocations, TotalInvocations: totalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(end) * 65535, CompletedInvocations: localInvocation, ProcessAlive: false, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
	}
	discoveryDuration := time.Since(discoveryStarted).Milliseconds()
	discoveryHosts = materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job)
	// Discovery units carry no authoritative ports. They preserve logical DNS
	// aggregation and give MergeWorkSnapshots a stable address inventory while
	// the follow-up enrichment units are generated from DiscoveredPorts.
	emptyUnits := make(map[string]model.Unit, len(addresses))
	for _, address := range addresses {
		emptyUnits[address] = model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}}
	}
	for _, target := range targets {
		if target.Aggregate {
			snapshot.Units = append(snapshot.Units, aggregate(target, unitsForAddresses(emptyUnits, target.Addresses), "tcp"))
			continue
		}
		for _, address := range target.Addresses {
			snapshot.Units = append(snapshot.Units, emptyUnits[address])
		}
	}
	snapshot.Hosts = mapHosts(discoveryHosts)
	snapshot.Normalize()
	reportProgress(report, Progress{StartedAt: started, Phase: "discovery complete", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, TotalInvocations: totalInvocations, CompletedInvocations: totalInvocations, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, ProcessAlive: false})
	return snapshot, nil
}

// scanNaabuPipelineResolved executes a pipeline against an already pinned
// target set. The public scan path resolves once here; resumable work units
// pass the immutable subset stored in their cycle plan so a restart cannot
// observe a different DNS answer.
func (n *Nmap) scanNaabuPipelineResolved(ctx context.Context, job config.Job, targets []resolvedTarget, report ProgressReporter) (model.Snapshot, error) {
	started := time.Now().UTC()
	job = config.NormalizeJob(job)
	snapshot := model.Snapshot{DNS: map[string][]string{}}
	for _, target := range targets {
		if target.Hostname {
			snapshot.DNS[target.Name] = append([]string(nil), target.Addresses...)
		}
	}
	if job.TCP == nil {
		return n.scanUDPAfterNaabu(ctx, job, targets, snapshot, started, report)
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "tcp", Ports: naabuFullPortExpression, ServiceDetection: job.TCP.ServiceDetection})
	}
	addresses := uniqueAddresses(targets)
	options := *job.TCP.Naabu
	config.ApplyNaabuDefaultsForScanner(&options)
	if err := config.ValidateNaabuOptions(options); err != nil {
		return model.Snapshot{}, fmt.Errorf("tcp naabu: %w", err)
	}
	if options.ScanType == "syn" && !hasRawScannerPrivileges() {
		return model.Snapshot{}, errors.New("naabu SYN scanning requires NET_RAW and NET_ADMIN capabilities; choose connect mode or grant the capabilities explicitly")
	}
	if len(addresses) == 0 {
		return model.Snapshot{}, errors.New("no effective targets")
	}
	batchSize := options.AddressBatchSize
	if batchSize < 1 {
		batchSize = 16
	}
	// Discovery is the expensive full-range phase. Its progress is reported in
	// exact probe units, while Naabu's stderr remains sanitized and advisory.
	discoveryTotal := int64(len(addresses)) * 65535
	progress := Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", TotalProbes: discoveryTotal, TotalInvocations: int64((len(addresses) + batchSize - 1) / batchSize)}
	reportProgress(report, progress)
	discovered := map[string]map[int]bool{}
	discoveryHosts := map[string]model.HostObservation{}
	portsFound := 0
	addressesFound := 0
	discoveryStarted := time.Now()
	partialSnapshot := func() model.Snapshot {
		copyHosts := materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job)
		snapshot.Hosts = mapHosts(copyHosts)
		snapshot.Normalize()
		return snapshot
	}
	for start := 0; start < len(addresses); start += batchSize {
		end := min(start+batchSize, len(addresses))
		batch := addresses[start:end]
		localInvocation := int64(start/batchSize) + 1
		if report != nil {
			reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: progress.TotalInvocations, TotalInvocations: progress.TotalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(start) * 65535, ProcessAlive: true, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound})
		}
		batchProbes := int64(len(batch)) * 65535
		results, stderr, err := n.runNaabu(ctx, options, job.TCP.NaabuArgs, batch, job.AssumesAlive(), func(update invocationProgress) {
			completed := int64(start) * 65535
			if update.Fraction > 0 {
				completed += int64(float64(batchProbes) * update.Fraction)
			}
			reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: progress.TotalInvocations, TotalInvocations: progress.TotalInvocations, TotalProbes: discoveryTotal, CompletedProbes: completed, ProcessAlive: update.Alive, LastOutput: update.Output, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
		})
		if err != nil {
			if ctx.Err() != nil {
				return partialSnapshot(), fmt.Errorf("naabu discovery canceled or timed out: %w", ctx.Err())
			}
			return partialSnapshot(), fmt.Errorf("naabu discovery failed: %v: %s", err, sanitizeStderr(stderr))
		}
		for _, result := range results {
			address := normalizeAddress(result.IP)
			if address == "" {
				address = normalizeAddress(result.Host)
			}
			if net.ParseIP(address) == nil {
				return partialSnapshot(), fmt.Errorf("naabu returned invalid address %q", address)
			}
			if !containsString(batch, address) {
				return partialSnapshot(), fmt.Errorf("naabu returned unexpected address %s", address)
			}
			if result.Port < 1 || result.Port > 65535 {
				return partialSnapshot(), fmt.Errorf("naabu returned invalid port %d", result.Port)
			}
			if result.Protocol != "" && !strings.EqualFold(result.Protocol, "tcp") {
				return partialSnapshot(), fmt.Errorf("naabu returned non-TCP protocol %q", result.Protocol)
			}
			if discovered[address] == nil {
				discovered[address] = map[int]bool{}
				addressesFound++
			}
			if !discovered[address][result.Port] {
				discovered[address][result.Port] = true
				portsFound++
			}
			host := discoveryHosts[address]
			host.Address = address
			host.AddressFamily = addressFamily(address)
			host.Status = "up"
			if result.MacAddress != "" {
				host.LinkAddresses = append(host.LinkAddresses, model.LinkAddress{Address: result.MacAddress, Type: "mac"})
			}
			discoveryHosts[address] = host
		}
		if report != nil {
			reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: progress.TotalInvocations, TotalInvocations: progress.TotalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(end) * 65535, CompletedInvocations: localInvocation, ProcessAlive: false, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
		}
	}
	discoveryDuration := time.Since(discoveryStarted).Milliseconds()
	// Every effective address receives a discovery observation, including hosts
	// for which no port replied. This distinguishes complete zero-open coverage
	// from the absence of an address in a legacy snapshot.
	enrichmentStarted := time.Now()
	for _, address := range addresses {
		host := discoveryHosts[address]
		host.Address = address
		if host.AddressFamily == "" {
			host.AddressFamily = addressFamily(address)
		}
		if host.Status == "" {
			// Naabu JSONL reports positive ports only. A target that produced
			// no records was still covered by the full-range pass, but its
			// reachability is unknown (especially with assume_alive=true).
			host.Status = "unknown"
			host.StatusReason = "no-response"
		}
		fingerprintArgs := naabuArgsWithTemplate(options, "<targets-file>", job.AssumesAlive(), job.TCP.NaabuArgs)
		protocol := model.ProtocolObservation{Protocol: "tcp", ScanType: "naabu", ScannedPorts: naabuFullPortExpression, ScannedPortCount: 65535, ServiceDetection: job.TCP.ServiceDetection, DiscoveryEngine: "naabu", NSEProfile: job.TCP.NSEProfile, NSEArgs: cloneStringMap(job.TCP.NSEArgs), CommandFingerprint: commandFingerprint(fingerprintArgs)}
		for port := range discovered[address] {
			protocol.DiscoveredPorts = append(protocol.DiscoveredPorts, model.PortObservation{Port: port, State: "open", Reason: "naabu", Verification: "discovered"})
		}
		missing := protocol.ScannedPortCount - len(discovered[address])
		if missing > 0 {
			addStateSummary(&protocol, "not-discovered", "no-response", missing)
		}
		host.Protocols = append(host.Protocols, protocol)
		discoveryHosts[address] = host
	}

	// Group hosts by their deterministic discovered-port set. Nmap can confirm
	// the same scope for several addresses in one invocation, while the parsed
	// result remains keyed per effective address for disagreement evidence and
	// host-detail presentation.
	confirmedUnits := make(map[string]model.Unit, len(addresses))
	for _, address := range addresses {
		// A host with no Naabu discoveries still has a complete, successful
		// full-range result. Keep an empty unit so DNS aggregates retain the
		// effective address even when every port is closed or filtered.
		confirmedUnits[address] = model.Unit{Target: address, Protocol: "tcp", Addresses: []string{address}}
	}
	groups := map[string][]string{}
	portsByGroup := map[string][]int{}
	for _, address := range addresses {
		ports := sortedPortSet(discovered[address])
		if len(ports) == 0 {
			continue
		}
		scope := formatPorts(ports)
		groups[scope] = append(groups[scope], address)
		portsByGroup[scope] = ports
	}
	groupScopes := make([]string, 0, len(groups))
	for scope := range groups {
		groupScopes = append(groupScopes, scope)
	}
	sort.Strings(groupScopes)
	for _, scope := range groupScopes {
		group := append([]string(nil), groups[scope]...)
		ports := portsByGroup[scope]
		pc := *job.TCP
		pc.Engine = config.EngineNmap
		pc.Ports = scope
		pc.NSEProfile = job.TCP.NSEProfile
		// NormalizeJob resolves an omitted Naabu confirmation mode to connect;
		// an explicit job mode (including SYN) is preserved here. Keeping this
		// assignment unconditional makes the confirmation command deterministic
		// and avoids an unreachable fallback that could silently couple the two
		// phases.
		pc.Mode = job.TCP.Mode
		if report != nil {
			reportProgress(report, Progress{StartedAt: started, Phase: "nmap enrichment", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, ProcessAlive: true, UnitAddresses: len(group), UnitPorts: pc.Ports, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, EnrichmentDurationMS: time.Since(enrichmentStarted).Milliseconds()})
		}
		// Keep the pinned logical target relationships (especially DNS names)
		// when narrowing enrichment to a discovered port-set. Replacing these
		// with synthetic address-only targets would make the host detail lose
		// its configured-target attribution.
		groupTargets := subsetResolvedTargets(targets, group)
		// Enrichment needs one authoritative unit per effective address so the
		// confirmation map below can retain distinct DNS answers. Keep the
		// configured target and Hostname fields for host attribution, but disable
		// logical aggregation for this intermediate Nmap result; the final pass
		// restores DNS aggregation from the per-address units.
		for index := range groupTargets {
			groupTargets[index].Aggregate = false
		}
		result, err := n.scanProtocolBatchDetailedProgressWithTemplate(ctx, groupTargets, "tcp", pc, job.Timing, job.AssumesAlive(), pc.EnrichmentArgs, nil, func(update invocationProgress) {
			if report == nil {
				return
			}
			reportProgress(report, Progress{StartedAt: started, Phase: "nmap enrichment", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, ProcessAlive: update.Alive, ProcessProgressPercent: int(update.Fraction * 100), LastOutput: update.Output, UnitAddresses: len(group), UnitPorts: pc.Ports, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, EnrichmentDurationMS: time.Since(enrichmentStarted).Milliseconds()})
		})
		if err != nil {
			// Preserve all discovery and any partial Nmap host evidence. The
			// enclosing scan is marked failed, so these Units cannot affect a
			// baseline, while the persisted snapshot remains useful for diagnosis.
			for address, unit := range confirmedUnits {
				if unit.Target == "" {
					unit.Target = address
					confirmedUnits[address] = unit
				}
			}
			if len(confirmedUnits) > 0 {
				for _, target := range targets {
					if target.Aggregate {
						snapshot.Units = append(snapshot.Units, aggregate(target, unitsForAddresses(confirmedUnits, target.Addresses), "tcp"))
						continue
					}
					for _, address := range target.Addresses {
						if unit, ok := confirmedUnits[address]; ok {
							unit.Target = address
							snapshot.Units = append(snapshot.Units, unit)
						}
					}
				}
			}
			snapshot.Hosts = mapHosts(materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job))
			snapshot.Normalize()
			return snapshot, fmt.Errorf("nmap enrichment for %s: %w", strings.Join(group, ","), err)
		}
		for _, unit := range result.Units {
			address := normalizeAddress(unit.Target)
			if address == "" {
				continue
			}
			unit.Target = address
			confirmedUnits[address] = unit
		}
		for _, address := range group {
			if host, ok := result.Hosts[address]; ok {
				mergeHostObservationMap(discoveryHosts, address, host)
			}
			// Mark Naabu discoveries that Nmap did not confirm. These are shown in
			// host detail but are intentionally absent from Units and the change
			// engine.
			host := discoveryHosts[address]
			markNaabuDisagreements(&host, ports)
			discoveryHosts[address] = host
		}
	}
	// Preserve the existing comparison model: DNS targets are represented by a
	// logical aggregate Unit, while direct IP/CIDR targets retain one Unit per
	// effective address. Host observations above remain address-specific.
	for _, target := range targets {
		if target.Aggregate {
			snapshot.Units = append(snapshot.Units, aggregate(target, unitsForAddresses(confirmedUnits, target.Addresses), "tcp"))
			continue
		}
		for _, address := range target.Addresses {
			unit := confirmedUnits[address]
			unit.Target = address
			snapshot.Units = append(snapshot.Units, unit)
		}
	}
	for address, host := range discoveryHosts {
		attachConfiguredTargets(&host, targets, address)
		dedupeHostObservation(&host)
		discoveryHosts[address] = host
	}
	snapshot.Hosts = mapHosts(discoveryHosts)
	if job.UDP != nil {
		return n.scanUDPAfterNaabu(ctx, job, targets, snapshot, started, report)
	}
	snapshot.Normalize()
	if report != nil {
		reportProgress(report, Progress{StartedAt: started, Phase: "complete", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, TotalInvocations: progress.TotalInvocations, CompletedInvocations: progress.TotalInvocations, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, EnrichmentDurationMS: time.Since(enrichmentStarted).Milliseconds()})
	}
	return snapshot, nil
}

func unitsForAddresses(units map[string]model.Unit, addresses []string) map[string]model.Unit {
	scoped := make(map[string]model.Unit, len(addresses))
	for _, address := range addresses {
		if unit, ok := units[address]; ok {
			scoped[address] = unit
		}
	}
	return scoped
}

// materializeNaabuDiscoveryHosts turns the positive JSONL records collected
// so far into deterministic host observations. It is intentionally safe to
// call repeatedly: an existing Naabu protocol is replaced rather than
// appended, which keeps cancellation/error snapshots free of duplicate
// protocol sections.
func materializeNaabuDiscoveryHosts(targets []resolvedTarget, addresses []string, discovered map[string]map[int]bool, existing map[string]model.HostObservation, options config.NaabuOptions, job config.Job) map[string]model.HostObservation {
	hosts := make(map[string]model.HostObservation, len(addresses))
	for address, host := range existing {
		hosts[address] = host
	}
	fingerprintArgs := naabuArgsWithTemplate(options, "<targets-file>", job.AssumesAlive(), job.TCP.NaabuArgs)
	for _, address := range addresses {
		host := hosts[address]
		host.Address = address
		if host.AddressFamily == "" {
			host.AddressFamily = addressFamily(address)
		}
		if host.Status == "" {
			host.Status = "unknown"
			host.StatusReason = "no-response"
		}
		protocol := model.ProtocolObservation{Protocol: "tcp", ScanType: "naabu", ScannedPorts: naabuFullPortExpression, ScannedPortCount: 65535, ServiceDetection: job.TCP.ServiceDetection, DiscoveryEngine: "naabu", NSEProfile: job.TCP.NSEProfile, NSEArgs: cloneStringMap(job.TCP.NSEArgs), CommandFingerprint: commandFingerprint(fingerprintArgs)}
		for port := range discovered[address] {
			protocol.DiscoveredPorts = append(protocol.DiscoveredPorts, model.PortObservation{Port: port, State: "open", Reason: "naabu", Verification: "discovered"})
		}
		missing := protocol.ScannedPortCount - len(discovered[address])
		if missing > 0 {
			addStateSummary(&protocol, "not-discovered", "no-response", missing)
		}
		updated := make([]model.ProtocolObservation, 0, len(host.Protocols)+1)
		for _, current := range host.Protocols {
			if strings.EqualFold(current.Protocol, "tcp") && strings.EqualFold(current.ScanType, "naabu") {
				continue
			}
			updated = append(updated, current)
		}
		host.Protocols = append(updated, protocol)
		attachConfiguredTargets(&host, targets, address)
		dedupeHostObservation(&host)
		hosts[address] = host
	}
	return hosts
}

func (n *Nmap) scanUDPAfterNaabu(ctx context.Context, job config.Job, targets []resolvedTarget, snapshot model.Snapshot, started time.Time, report ProgressReporter) (model.Snapshot, error) {
	if job.UDP == nil {
		snapshot.Normalize()
		return snapshot, nil
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
	}
	result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "udp", *job.UDP, job.Timing, job.AssumesAlive(), nil, func(update invocationProgress) {
		if report == nil {
			return
		}
		reportProgress(report, Progress{StartedAt: started, Phase: "udp scanning", Protocol: "udp", LastOutput: update.Output, ProcessAlive: update.Alive, ProcessProgressPercent: int(update.Fraction * 100), UnitPorts: job.UDP.Ports})
	})
	if err != nil {
		// Keep a successful TCP phase (and any partial UDP host evidence) in the
		// failed scan record for troubleshooting; the engine will reject the
		// incomplete result before baseline comparison.
		mergeHostObservations(&snapshot.Hosts, result.Hosts)
		snapshot.Normalize()
		return snapshot, fmt.Errorf("udp scan: %w", err)
	}
	snapshot.Units = append(snapshot.Units, result.Units...)
	mergeHostObservations(&snapshot.Hosts, result.Hosts)
	snapshot.Normalize()
	if report != nil {
		reportProgress(report, Progress{StartedAt: started, Phase: "complete", CompletedProbes: 1, TotalProbes: 1})
	}
	return snapshot, nil
}

func (n *Nmap) runNaabu(ctx context.Context, options config.NaabuOptions, profileArgs, addresses []string, assumeAlive bool, statusReports ...func(invocationProgress)) ([]naabuResult, string, error) {
	file, err := os.CreateTemp("", "edgewatch-naabu-targets-*")
	if err != nil {
		return nil, "", err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, "", err
	}
	for _, address := range addresses {
		if _, err := io.WriteString(file, address+"\n"); err != nil {
			file.Close()
			return nil, "", err
		}
	}
	if err := file.Close(); err != nil {
		return nil, "", err
	}

	if err := config.ValidateScannerProfile(config.ScannerProfile{Engine: config.EngineNaabuNmap, Naabu: options, NaabuArgs: profileArgs}); err != nil {
		return nil, "", fmt.Errorf("scanner profile arguments: %w", err)
	}
	args := naabuArgsWithTemplate(options, path, assumeAlive, profileArgs)
	naabuPath := strings.TrimSpace(n.NaabuPath)
	if naabuPath == "" {
		// Keep standalone scanner values safe and useful outside the production
		// constructor. The image installs Naabu at this fixed path; an empty
		// injected value must never fall back to PATH lookup or an operator-owned
		// binary.
		naabuPath = "/usr/local/bin/naabu"
	}
	cmd := exec.CommandContext(ctx, naabuPath, args...)
	// Naabu should not read an operator's home configuration or inherit
	// credentials. A non-existent home/config directory makes profile
	// execution deterministic and prevents an image or host-local config from
	// enabling cloud, proxy, resolver, or output behavior behind the UI's back.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent"}
	var stdout cappedBuffer
	stdout.limit = maxNaabuOutput
	var status func(invocationProgress)
	if len(statusReports) > 0 {
		status = statusReports[0]
	}
	var statusMu sync.Mutex
	lastOutput := ""
	emitStatus := func(update invocationProgress) {
		if status == nil {
			return
		}
		if update.Output != "" {
			update.Output = trimProgressOutput(update.Output)
		}
		statusMu.Lock()
		if update.Output != "" {
			lastOutput = update.Output
		}
		update.Output = lastOutput
		statusMu.Unlock()
		status(update)
	}
	stderr := &progressOutputWriter{limit: maxProgressOutput, emit: func(line string) {
		emitStatus(invocationProgress{Output: line, Alive: true})
	}}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, stderr.String(), err
	}
	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	if status != nil {
		go func() {
			defer close(heartbeatDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					emitStatus(invocationProgress{Alive: true})
				case <-heartbeatStop:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	} else {
		close(heartbeatDone)
	}
	waitErr := cmd.Wait()
	close(heartbeatStop)
	if status != nil {
		// Flush a final partial diagnostic line before publishing the terminal
		// heartbeat. The callback is serialized by emitStatus, so consumers see
		// the last useful output followed by ProcessAlive=false.
		stderr.Flush()
		<-heartbeatDone
		emitStatus(invocationProgress{Alive: false})
	}
	if stderr.exceeded {
		return nil, stderr.String(), fmt.Errorf("naabu diagnostic output exceeded %d bytes", maxProgressOutput)
	}
	if stdout.exceeded {
		return nil, stderr.String(), errors.New("naabu output exceeded 64 MiB")
	}
	if waitErr != nil {
		return nil, stderr.String(), waitErrWithContext(ctx, waitErr)
	}
	results, err := parseNaabuJSON(stdout.Bytes())
	return results, stderr.String(), err
}

func naabuArgs(options config.NaabuOptions, targetsFile string, assumeAlive bool) []string {
	return naabuArgsWithTemplate(options, targetsFile, assumeAlive, nil)
}

// naabuArgsWithTemplate renders the fixed Naabu safety contract and an
// administrator-validated argument template. Managed placeholders expand to
// complete argv fragments; all other switches remain fixed or are appended
// as safe profile tuning. This keeps the executable, target source, JSONL
// output, and full-range scope under EdgeWatch's control.
func naabuArgsWithTemplate(options config.NaabuOptions, targetsFile string, assumeAlive bool, template []string) []string {
	scanType := "c"
	if options.ScanType == "syn" {
		scanType = "s"
	}
	if len(template) == 0 {
		args := []string{"-list", targetsFile, "-p", "-", "-json", "-silent", "-no-stdin", "-disable-update-check", "-auth=false", "-pd=false", "-scan-type", scanType, "-rate", strconv.Itoa(options.Rate), "-c", strconv.Itoa(options.Workers), "-retries", strconv.Itoa(options.Retries), "-timeout", strconv.Itoa(options.TimeoutMS) + "ms", "-warm-up-time", strconv.Itoa(options.WarmUpSeconds)}
		if options.Verify {
			args = append(args, "-verify")
		}
		if assumeAlive {
			args = append(args, "-skip-host-discovery")
		} else {
			args = append(args, "-with-host-discovery")
		}
		return args
	}

	// These flags cannot be overridden by a profile and are intentionally
	// emitted even when the corresponding placeholder is omitted. Validation
	// requires the target/port/output placeholders, while the remaining
	// placeholders are optional declarations for the typed fields below.
	args := []string{"-silent", "-no-stdin", "-disable-update-check", "-auth=false", "-pd=false"}
	if !templateContains(template, config.PlaceholderScanType) {
		args = append(args, "-scan-type", scanType)
	}
	args = append(args, "-rate", strconv.Itoa(options.Rate), "-c", strconv.Itoa(options.Workers), "-retries", strconv.Itoa(options.Retries), "-timeout", strconv.Itoa(options.TimeoutMS)+"ms", "-warm-up-time", strconv.Itoa(options.WarmUpSeconds))
	if options.Verify {
		// Naabu's verification is a typed option, not service detection. Keep
		// it fixed unless a future placeholder is added; profiles currently use
		// the typed default rather than a free-form -verify flag.
		args = append(args, "-verify")
	}
	if !templateContains(template, config.PlaceholderHostDiscovery) {
		if assumeAlive {
			args = append(args, "-skip-host-discovery")
		} else {
			args = append(args, "-with-host-discovery")
		}
	}
	args = append(args, renderNaabuTemplate(template, targetsFile, options, assumeAlive)...)
	return args
}

func renderNaabuTemplate(template []string, targetsFile string, options config.NaabuOptions, assumeAlive bool) []string {
	var out []string
	for _, value := range template {
		switch value {
		case config.PlaceholderTargetsFile:
			out = append(out, "-list", targetsFile)
		case config.PlaceholderPorts:
			out = append(out, "-p", "-")
		case config.PlaceholderStructuredOutput:
			out = append(out, "-json")
		case config.PlaceholderAddressFamily:
			// Naabu receives a mixed target file and selects families itself.
			// The placeholder is accepted for template portability but has no
			// extra argument when the fixed target resolver already supplies both
			// families.
		case config.PlaceholderHostDiscovery:
			if assumeAlive {
				out = append(out, "-skip-host-discovery")
			} else {
				out = append(out, "-with-host-discovery")
			}
		case config.PlaceholderScanType:
			scanType := "c"
			if options.ScanType == "syn" {
				scanType = "s"
			}
			out = append(out, "-scan-type", scanType)
		case config.PlaceholderAddress, config.PlaceholderAddresses, config.PlaceholderServiceDetection, config.PlaceholderNSE:
			// These placeholders are meaningful to Nmap but not to Naabu. A
			// shared profile can declare them without causing a literal token to
			// reach the fixed Naabu executable.
		default:
			out = append(out, value)
		}
	}
	return out
}

func parseNaabuJSON(data []byte) ([]naabuResult, error) {
	var results []naabuResult
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// A JSON result is small, but keep the bound explicit so a malformed line
	// cannot allocate unbounded memory inside bufio.Scanner.
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result naabuResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, fmt.Errorf("parse naabu JSON: %w", err)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read naabu JSON: %w", err)
	}
	return results, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	if b.limit > 0 && b.Len()+len(data) > b.limit {
		remaining := b.limit - b.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(data[:remaining])
		}
		b.exceeded = true
		return len(data), errors.New("output limit exceeded")
	}
	return b.Buffer.Write(data)
}

func uniqueAddresses(targets []resolvedTarget) []string {
	seen := map[string]bool{}
	var addresses []string
	for _, target := range targets {
		for _, address := range target.Addresses {
			address = normalizeAddress(address)
			if address == "" || seen[address] {
				continue
			}
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	sort.Strings(addresses)
	return addresses
}

func sortedPortSet(values map[int]bool) []int {
	ports := make([]int, 0, len(values))
	for port := range values {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func addressFamily(address string) string {
	if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func attachConfiguredTargets(host *model.HostObservation, targets []resolvedTarget, address string) {
	for _, target := range targets {
		for _, candidate := range target.Addresses {
			if normalizeAddress(candidate) != address {
				continue
			}
			configured := target.ConfiguredTarget
			if configured == "" {
				configured = target.Name
			}
			host.SourceTargets = append(host.SourceTargets, configured)
			if target.Hostname {
				host.DNSNames = append(host.DNSNames, target.Name)
			}
		}
	}
}

func markNaabuDisagreements(host *model.HostObservation, discovered []int) {
	if host == nil {
		return
	}
	confirmed := map[int]bool{}
	for _, protocol := range host.Protocols {
		if protocol.Protocol != "tcp" {
			continue
		}
		for _, port := range protocol.Ports {
			if port.State == "open" || port.State == "open|filtered" {
				confirmed[port.Port] = true
			}
		}
	}
	for index := range host.Protocols {
		if host.Protocols[index].DiscoveryEngine != "naabu" {
			continue
		}
		for _, port := range discovered {
			if !confirmed[port] {
				host.Protocols[index].UnconfirmedPorts = append(host.Protocols[index].UnconfirmedPorts, model.PortObservation{Port: port, State: "unconfirmed", Reason: "nmap-disagreement", Verification: "unconfirmed"})
			}
		}
	}
}

// hasRawScannerPrivileges is intentionally conservative. Connect mode is
// usable without either capability. Linux deployments that grant both raw
// packet capabilities can opt into Naabu SYN mode; non-Linux/test hosts are
// treated as unavailable instead of guessing.
func hasRawScannerPrivileges() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Root is not sufficient inside a container: cap_drop: ALL leaves the
	// process without the packet capabilities even when its UID is zero. Read
	// the effective capability mask and require both NET_ADMIN (bit 12) and
	// NET_RAW (bit 13), matching Naabu's SYN/raw-packet requirements.
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return false
		}
		const netAdmin = uint64(1) << 12
		const netRaw = uint64(1) << 13
		return mask&netAdmin != 0 && mask&netRaw != 0
	}
	return false
}

// NaabuSYNSupported reports whether the current process has both capabilities
// required for raw SYN discovery. It is intentionally a runtime check rather
// than a UID check because Compose drops all capabilities by default.
func (n *Nmap) NaabuSYNSupported() bool { return hasRawScannerPrivileges() }
