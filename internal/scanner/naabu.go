package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

const (
	naabuFullPortExpression = config.NaabuFullPortExpression
	// A completed full-range Naabu pass can legitimately produce no JSONL
	// records. Keep the host status unknown (Naabu only reports positive
	// ports), but use a distinct reason so the change engine can distinguish
	// complete zero-positive coverage from a failed or partial discovery.
	naabuFullRangeCompleteReason = "scan-complete"
	// naabuResultLimitReason marks an address whose discoveries were dropped
	// because one invocation reported more distinct open ports than
	// maxNaabuUniqueResults. The address stays incomplete instead of failing
	// the whole work unit on every retry.
	naabuResultLimitReason = "naabu-too-many-open-ports"
	// maxNaabuLineBytes bounds one JSONL record. A result is a few hundred
	// bytes; a longer line is malformed output.
	maxNaabuLineBytes = 1 << 20
)

// Naabu emits one JSON object per discovered port, and v2.6.1 prints every
// result twice: once when found and again when the scan ends. EdgeWatch
// parses the stream as it arrives and keeps one bit per distinct
// address:port, so the retained data is bounded by distinct results rather
// than raw bytes. These are variables only so tests can exercise the limits
// without generating millions of records.
var (
	// maxNaabuUniqueResults bounds the distinct results one invocation may
	// contribute to a checkpoint: two addresses with every TCP port open.
	// When a batch exceeds it, the addresses with the most results are
	// recorded as incomplete, largest first, until the rest fit.
	maxNaabuUniqueResults = 2 * 65535
	// maxNaabuRecordsPerAddress bounds raw records, including repeats, so a
	// child that keeps printing the same result is stopped.
	maxNaabuRecordsPerAddress = 8 * 65535
)

type naabuResult struct {
	Host       string `json:"host"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	MacAddress string `json:"mac_address"`
}

// naabuDiscovery is the deduplicated result of one Naabu invocation.
type naabuDiscovery struct {
	// ports holds the sorted distinct open ports of every address that
	// reported at least one result and fits the result limit.
	ports map[string][]int
	macs  map[string][]string
	// truncated lists, sorted, the addresses whose results exceeded
	// maxNaabuUniqueResults and were therefore not retained.
	truncated []string
}

// naabuSkipsHostDiscovery reports whether the invocation probes every port of
// every address. Only then does an address without JSONL records prove that
// no port was open. With host discovery, Naabu silently skips addresses that
// did not answer, which is indistinguishable from an address with no open
// port.
func naabuSkipsHostDiscovery(options config.NaabuOptions, assumeAlive bool) bool {
	return naabuHostDiscoveryFlag(options, assumeAlive) == "-skip-host-discovery"
}

// recordNaabuDiscovery merges one invocation's deduplicated results into the
// discovery state and returns the number of newly seen addresses and ports.
func recordNaabuDiscovery(result naabuDiscovery, discovered map[string]map[int]bool, hosts map[string]model.HostObservation) (addresses, ports int) {
	for address, found := range result.ports {
		if discovered[address] == nil {
			discovered[address] = map[int]bool{}
			addresses++
		}
		for _, port := range found {
			if !discovered[address][port] {
				discovered[address][port] = true
				ports++
			}
		}
		host := hosts[address]
		host.Address = address
		host.AddressFamily = addressFamily(address)
		host.Status = "up"
		for _, mac := range result.macs[address] {
			host.LinkAddresses = append(host.LinkAddresses, model.LinkAddress{Address: mac, Type: "mac"})
		}
		hosts[address] = host
	}
	for _, address := range result.truncated {
		host := hosts[address]
		host.Address = address
		host.AddressFamily = addressFamily(address)
		host.Status = "unknown"
		host.StatusReason = naabuResultLimitReason
		hosts[address] = host
	}
	return addresses, ports
}

// scanNaabuPipeline performs TCP discovery first and then asks Nmap to
// confirm/enrich only the ports Naabu found. UDP remains on the existing Nmap
// path. The compact Units returned by this method contain Nmap-confirmed
// states only; richer discovery evidence is kept on HostObservation.
func (n *Nmap) scanNaabuPipeline(ctx context.Context, job config.Job, report ProgressReporter) (model.Snapshot, error) {
	return n.scanNaabuPipelineWithBudget(ctx, job, report, nil)
}

func (n *Nmap) scanNaabuPipelineWithBudget(ctx context.Context, job config.Job, report ProgressReporter, budgetCheck func(discoveryProbes, nmapProbes int64) error) (model.Snapshot, error) {
	job = config.NormalizeJob(job)
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
	return n.scanNaabuPipelineResolvedWithBudget(ctx, job, targets, report, budgetCheck)
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
		return model.Snapshot{}, ConfigurationError(errors.New("naabu discovery requires tcp"))
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "tcp", Ports: naabuFullPortExpression, ServiceDetection: job.TCP.ServiceDetection})
	}
	addresses := uniqueAddresses(targets)
	options := *job.TCP.Naabu
	config.ApplyNaabuDefaultsForScanner(&options)
	if err := config.ValidateNaabuOptions(options); err != nil {
		return model.Snapshot{}, ConfigurationError(fmt.Errorf("tcp naabu: %w", err))
	}
	if err := validateNaabuInvocation(options, job.AssumesAlive(), naabuRawPrivileges()); err != nil {
		return model.Snapshot{}, err
	}
	if len(addresses) == 0 {
		return model.Snapshot{}, ConfigurationError(errors.New("no effective targets"))
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
			return partialSnapshot(), fmt.Errorf("naabu discovery failed: %w: %s", err, sanitizeStderr(stderr))
		}
		newAddresses, newPorts := recordNaabuDiscovery(results, discovered, discoveryHosts)
		addressesFound += newAddresses
		portsFound += newPorts
		reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: totalInvocations, TotalInvocations: totalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(end) * 65535, CompletedInvocations: localInvocation, ProcessAlive: false, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
	}
	discoveryDuration := time.Since(discoveryStarted).Milliseconds()
	discoveryHosts = materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job)
	if naabuSkipsHostDiscovery(options, job.AssumesAlive()) {
		// Every port of every address was probed, so an address without
		// records is complete zero-positive coverage (#718). With host
		// discovery a silent address may simply be down; it keeps the
		// incomplete unknown/no-response marker, as a down host does with Nmap.
		markCompletedNaabuDiscoveryHosts(discoveryHosts)
	}
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
	return n.scanNaabuPipelineResolvedWithBudget(ctx, job, targets, report, nil)
}

func (n *Nmap) scanNaabuPipelineResolvedWithBudget(ctx context.Context, job config.Job, targets []resolvedTarget, report ProgressReporter, budgetCheck func(discoveryProbes, nmapProbes int64) error) (model.Snapshot, error) {
	started := time.Now().UTC()
	job = config.NormalizeJob(job)
	snapshot := model.Snapshot{DNS: map[string][]string{}}
	for _, target := range targets {
		if target.Hostname {
			snapshot.DNS[target.Name] = append([]string(nil), target.Addresses...)
		}
	}
	if job.TCP == nil {
		return n.scanUDPAfterNaabu(ctx, job, targets, snapshot, started, 0, 0, report)
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "tcp", Ports: naabuFullPortExpression, ServiceDetection: job.TCP.ServiceDetection})
	}
	addresses := uniqueAddresses(targets)
	options := *job.TCP.Naabu
	config.ApplyNaabuDefaultsForScanner(&options)
	if err := config.ValidateNaabuOptions(options); err != nil {
		return model.Snapshot{}, ConfigurationError(fmt.Errorf("tcp naabu: %w", err))
	}
	if err := validateNaabuInvocation(options, job.AssumesAlive(), naabuRawPrivileges()); err != nil {
		return model.Snapshot{}, err
	}
	if len(addresses) == 0 {
		return model.Snapshot{}, ConfigurationError(errors.New("no effective targets"))
	}
	batchSize := options.AddressBatchSize
	if batchSize < 1 {
		batchSize = 16
	}
	// Discovery is the expensive full-range phase. Its progress is reported in
	// exact probe units, while Naabu's stderr remains sanitized and advisory.
	discoveryTotal := int64(len(addresses)) * 65535
	discoveryInvocations := int64((len(addresses) + batchSize - 1) / batchSize)
	udpProbes := int64(0)
	if job.UDP != nil {
		udpProbes, _ = protocolProgressTotals(targets, *job.UDP, nil)
	}
	if budgetCheck != nil {
		// The caller's budget check used an earlier resolution, and a DNS
		// answer can grow in between. Check the discovery and UDP work of
		// this resolution before Naabu starts; enrichment is checked again
		// once the discovered ports are known.
		if err := budgetCheck(discoveryTotal, udpProbes); err != nil {
			return model.Snapshot{}, err
		}
	}
	progress := Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", TotalProbes: discoveryTotal, TotalInvocations: discoveryInvocations}
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
			return partialSnapshot(), fmt.Errorf("naabu discovery failed: %w: %s", err, sanitizeStderr(stderr))
		}
		newAddresses, newPorts := recordNaabuDiscovery(results, discovered, discoveryHosts)
		addressesFound += newAddresses
		portsFound += newPorts
		if report != nil {
			reportProgress(report, Progress{StartedAt: started, Phase: "tcp discovery", Protocol: "tcp", CurrentInvocation: localInvocation, TotalBatches: progress.TotalInvocations, TotalInvocations: progress.TotalInvocations, TotalProbes: discoveryTotal, CompletedProbes: int64(end) * 65535, CompletedInvocations: localInvocation, ProcessAlive: false, UnitAddresses: len(batch), UnitPorts: naabuFullPortExpression, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: time.Since(discoveryStarted).Milliseconds()})
		}
	}
	discoveryDuration := time.Since(discoveryStarted).Milliseconds()
	// Every effective address receives a discovery observation, including hosts
	// for which no port replied. This distinguishes complete zero-open coverage
	// from the absence of an address in a legacy snapshot.
	enrichmentStarted := time.Now()
	silentAddressesComplete := naabuSkipsHostDiscovery(options, job.AssumesAlive())
	for _, address := range addresses {
		host := discoveryHosts[address]
		host.Address = address
		if host.AddressFamily == "" {
			host.AddressFamily = addressFamily(address)
		}
		if host.Status == "" {
			// Naabu JSONL reports positive ports only. Without host discovery
			// a target that produced no records was still covered by the
			// full-range pass, but its reachability is unknown. With host
			// discovery Naabu skips addresses that did not answer, so a silent
			// address stays incomplete.
			host.Status = "unknown"
			host.StatusReason = "no-response"
			if silentAddressesComplete {
				host.StatusReason = naabuFullRangeCompleteReason
			}
		}
		fingerprintArgs := naabuArgsWithTemplate(options, "<targets-file>", job.AssumesAlive(), job.TCP.NaabuArgs)
		protocol := model.ProtocolObservation{Protocol: "tcp", Status: strings.ToLower(host.Status), StatusReason: host.StatusReason, ScanType: "naabu", ScannedPorts: naabuFullPortExpression, ScannedPortCount: 65535, ServiceDetection: job.TCP.ServiceDetection, DiscoveryEngine: "naabu", NSEProfile: job.TCP.NSEProfile, NSEArgs: cloneStringMap(job.TCP.NSEArgs), CommandFingerprint: commandFingerprint(fingerprintArgs)}
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
	enrichmentProbes := int64(0)
	for _, scope := range groupScopes {
		group := append([]string(nil), groups[scope]...)
		ports := portsByGroup[scope]
		// A discovered port is not a closed result until Nmap confirms it. Drop
		// the optimistic empty units before enrichment so an omitted/failed Nmap
		// response cannot be persisted as a false all-closed observation.
		for _, address := range group {
			delete(confirmedUnits, address)
		}
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
		enrichmentArgs := pc.EnrichmentArgs
		if len(enrichmentArgs) == 0 {
			enrichmentArgs = pc.NmapArgs
		}
		groupProbes, _ := protocolProgressTotals(groupTargets, pc, enrichmentArgs)
		if budgetCheck != nil {
			if err := budgetCheck(discoveryTotal, enrichmentProbes+groupProbes+udpProbes); err != nil {
				return partialSnapshot(), err
			}
		}
		enrichmentProbes += groupProbes
		result, err := n.scanProtocolBatchDetailedProgressWithTemplate(ctx, groupTargets, "tcp", pc, job.Timing, job.AssumesAlive(), enrichmentArgs, nil, func(update invocationProgress) {
			if report == nil {
				return
			}
			reportProgress(report, Progress{StartedAt: started, Phase: "nmap enrichment", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, ProcessAlive: update.Alive, ProcessProgressPercent: int(update.Fraction * 100), LastOutput: update.Output, UnitAddresses: len(group), UnitPorts: pc.Ports, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, EnrichmentDurationMS: time.Since(enrichmentStarted).Milliseconds()})
		})
		// A successful Nmap process can still omit an address when host
		// discovery reports it down. That is incomplete enrichment, not an
		// authoritative all-closed result. Convert the omission into the same
		// failure path as a process error so the caller cannot promote it into
		// a baseline or incident comparison.
		missingAddresses := missingNmapAddresses(result, group)
		if err == nil && len(missingAddresses) > 0 {
			err = fmt.Errorf("nmap enrichment omitted expected address(s): %s", strings.Join(missingAddresses, ", "))
		}
		if err != nil {
			// Preserve all discovery and any partial Nmap host evidence. The
			// enclosing scan is marked failed, so these Units cannot affect a
			// baseline, while the persisted snapshot remains useful for diagnosis.
			for _, unit := range result.Units {
				address := normalizeAddress(unit.Target)
				if address == "" {
					continue
				}
				unit.Target = address
				confirmedUnits[address] = unit
			}
			for address, host := range result.Hosts {
				mergeHostObservationMap(discoveryHosts, address, host)
			}
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
			hosts := materializeNaabuDiscoveryHosts(targets, addresses, discovered, discoveryHosts, options, job)
			for _, address := range failedNmapAddresses(missingAddresses, group) {
				failedHost := hosts[address]
				markNaabuEnrichmentFailure(&failedHost, ports)
				hosts[address] = failedHost
			}
			snapshot.Hosts = mapHosts(hosts)
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
			// Addresses whose enrichment was omitted are intentionally absent.
			// Appending a zero Unit here would make a failed Nmap confirmation look
			// like an authoritative all-closed result.
			if unit, ok := confirmedUnits[address]; ok {
				unit.Target = address
				snapshot.Units = append(snapshot.Units, unit)
			}
		}
	}
	for address, host := range discoveryHosts {
		attachConfiguredTargets(&host, targets, address)
		dedupeHostObservation(&host)
		discoveryHosts[address] = host
	}
	snapshot.Hosts = mapHosts(discoveryHosts)
	if job.UDP != nil {
		if budgetCheck != nil && len(groupScopes) == 0 {
			if err := budgetCheck(discoveryTotal, enrichmentProbes+udpProbes); err != nil {
				return partialSnapshot(), err
			}
		}
		return n.scanUDPAfterNaabu(ctx, job, targets, snapshot, started, discoveryTotal, discoveryInvocations, report)
	}
	snapshot.Normalize()
	if report != nil {
		reportProgress(report, Progress{StartedAt: started, Phase: "complete", Protocol: "tcp", TotalProbes: discoveryTotal, CompletedProbes: discoveryTotal, TotalInvocations: progress.TotalInvocations, CompletedInvocations: progress.TotalInvocations, DiscoveryPortsFound: portsFound, DiscoveryAddresses: addressesFound, DiscoveryDurationMS: discoveryDuration, EnrichmentDurationMS: time.Since(enrichmentStarted).Milliseconds()})
	}
	return snapshot, nil
}

// markCompletedNaabuDiscoveryHosts changes only the successful discovery
// checkpoint's empty-result marker, and only callers whose invocation skipped
// host discovery may use it. Error and cancellation snapshots, and silent
// addresses under host discovery, keep unknown/no-response and therefore
// remain protected from baseline and change detection.
func markCompletedNaabuDiscoveryHosts(hosts map[string]model.HostObservation) {
	for address, host := range hosts {
		if strings.EqualFold(host.Status, "unknown") && strings.EqualFold(host.StatusReason, "no-response") {
			host.StatusReason = naabuFullRangeCompleteReason
		}
		for index := range host.Protocols {
			protocol := &host.Protocols[index]
			if strings.EqualFold(protocol.DiscoveryEngine, "naabu") && strings.EqualFold(protocol.Status, "unknown") && strings.EqualFold(protocol.StatusReason, "no-response") {
				protocol.StatusReason = naabuFullRangeCompleteReason
			}
		}
		hosts[address] = host
	}
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

// missingNmapAddresses identifies effective addresses that did not produce an
// authoritative Nmap Unit. A host observation alone is not sufficient: down,
// timed-out, and omitted hosts are deliberately represented without a Unit so
// they cannot be mistaken for closed ports.
func missingNmapAddresses(result protocolScanResult, expected []string) []string {
	present := make(map[string]struct{}, len(result.Units))
	for _, unit := range result.Units {
		if address := normalizeAddress(unit.Target); address != "" {
			present[address] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, address := range expected {
		if _, ok := present[address]; !ok {
			missing = append(missing, address)
		}
	}
	sort.Strings(missing)
	return missing
}

func failedNmapAddresses(missing, expected []string) []string {
	if len(missing) > 0 {
		return missing
	}
	// A process, parse, or output failure without any address-level result
	// leaves the whole invocation untrusted. Mark every address incomplete so
	// diagnostics are explicit even when the child emitted no usable XML.
	return expected
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
		protocol := model.ProtocolObservation{Protocol: "tcp", Status: strings.ToLower(host.Status), StatusReason: host.StatusReason, ScanType: "naabu", ScannedPorts: naabuFullPortExpression, ScannedPortCount: 65535, ServiceDetection: job.TCP.ServiceDetection, DiscoveryEngine: "naabu", NSEProfile: job.TCP.NSEProfile, NSEArgs: cloneStringMap(job.TCP.NSEArgs), CommandFingerprint: commandFingerprint(fingerprintArgs)}
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

func (n *Nmap) scanUDPAfterNaabu(ctx context.Context, job config.Job, targets []resolvedTarget, snapshot model.Snapshot, started time.Time, priorProbes, priorInvocations int64, report ProgressReporter) (model.Snapshot, error) {
	if job.UDP == nil {
		snapshot.Normalize()
		return snapshot, nil
	}
	for _, target := range targets {
		snapshot.Scopes = append(snapshot.Scopes, model.Scope{Target: target.Name, Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
	}
	udpProbes, udpInvocations := progressTotals(targets, config.Job{UDP: job.UDP})
	totalProbes := priorProbes + udpProbes
	totalInvocations := priorInvocations + udpInvocations
	completedUDP := int64(0)
	result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "udp", *job.UDP, job.Timing, job.AssumesAlive(), nil, func(update invocationProgress) {
		if report == nil {
			return
		}
		if update.BatchProbes > 0 {
			candidate := (update.Invocation-1)*update.BatchProbes + int64(float64(update.BatchProbes)*update.Fraction)
			if candidate > completedUDP {
				completedUDP = candidate
			}
		}
		if completedUDP > udpProbes {
			completedUDP = udpProbes
		}
		reportProgress(report, Progress{StartedAt: started, Phase: "udp scanning", Protocol: "udp", TotalProbes: totalProbes, CompletedProbes: priorProbes + completedUDP, TotalInvocations: totalInvocations, CompletedInvocations: priorInvocations, CurrentInvocation: priorInvocations + update.Invocation, LastOutput: update.Output, ProcessAlive: update.Alive, ProcessProgressPercent: int(update.Fraction * 100), UnitPorts: job.UDP.Ports})
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
		reportProgress(report, Progress{StartedAt: started, Phase: "complete", Protocol: "udp", TotalProbes: totalProbes, CompletedProbes: totalProbes, TotalInvocations: totalInvocations, CompletedInvocations: totalInvocations, UnitPorts: job.UDP.Ports})
	}
	return snapshot, nil
}

func (n *Nmap) runNaabu(ctx context.Context, options config.NaabuOptions, profileArgs, addresses []string, assumeAlive bool, statusReports ...func(invocationProgress)) (naabuDiscovery, string, error) {
	file, err := os.CreateTemp("", "edgewatch-naabu-targets-*")
	if err != nil {
		return naabuDiscovery{}, "", err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return naabuDiscovery{}, "", err
	}
	for _, address := range addresses {
		if _, err := io.WriteString(file, address+"\n"); err != nil {
			file.Close()
			return naabuDiscovery{}, "", err
		}
	}
	if err := file.Close(); err != nil {
		return naabuDiscovery{}, "", err
	}

	if err := config.ValidateScannerProfile(config.ScannerProfile{Engine: config.EngineNaabuNmap, Naabu: options, NaabuArgs: profileArgs}); err != nil {
		return naabuDiscovery{}, "", ConfigurationError(fmt.Errorf("scanner profile arguments: %w", err))
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
	var outputExceeded atomic.Bool
	killOnOutputLimit := func() {
		if outputExceeded.CompareAndSwap(false, true) && cmd.Process != nil {
			// Stop the child as soon as either output channel reaches its cap
			// or emits an invalid record. Returning an error only after Wait
			// would leave a malformed scanner free to consume CPU.
			_ = cmd.Process.Kill()
		}
	}
	stdout := newNaabuResultCollector(addresses, killOnOutputLimit)
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
	stderr := &progressOutputWriter{limit: maxProgressOutput, onExceeded: killOnOutputLimit, emit: func(line string) {
		emitStatus(invocationProgress{Output: line, Alive: true})
	}}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return naabuDiscovery{}, stderr.String(), ExecutableStartError(cmd.Path, err)
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
		return naabuDiscovery{}, stderr.String(), fmt.Errorf("naabu diagnostic output exceeded %d bytes", maxProgressOutput)
	}
	if stdout.err != nil {
		// The collector killed the child; its error explains why, while the
		// wait error would only report the signal.
		return naabuDiscovery{}, stderr.String(), stdout.err
	}
	if waitErr != nil {
		return naabuDiscovery{}, stderr.String(), scannerStorageError(waitErrWithContext(ctx, waitErr), stderr.String())
	}
	results, err := stdout.finish()
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
		args = append(args, naabuHostDiscoveryFlag(options, assumeAlive))
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
		args = append(args, naabuHostDiscoveryFlag(options, assumeAlive))
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
			out = append(out, naabuHostDiscoveryFlag(options, assumeAlive))
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

// Naabu v2.6.1 validates -with-host-discovery by changing any non-SYN
// scan-type to a raw SYN scan. That behavior is unsafe for EdgeWatch because
// the job's scan type, capability check, and evidence would no longer match
// the process that actually ran. Connect mode therefore cannot be combined
// with assume_alive=false; operators must either keep the default assumed-live
// policy or explicitly select SYN with both raw-packet capabilities.
func validateNaabuInvocation(options config.NaabuOptions, assumeAlive, rawPrivileges bool) error {
	if options.ScanType == "connect" && !assumeAlive {
		return ConfigurationError(errors.New("naabu connect mode cannot use host discovery; keep assume_alive enabled or select SYN mode with NET_RAW and NET_ADMIN"))
	}
	if options.ScanType == "syn" && !rawPrivileges {
		return ConfigurationError(errors.New("naabu SYN scanning requires NET_RAW and NET_ADMIN capabilities; choose connect mode or grant the capabilities explicitly"))
	}
	return nil
}

// naabuHostDiscoveryFlag is defensive for previews and any future caller that
// renders arguments before runtime validation. Never emit the upstream switch
// that converts connect scans into SYN scans.
func naabuHostDiscoveryFlag(options config.NaabuOptions, assumeAlive bool) string {
	if assumeAlive || options.ScanType == "connect" {
		return "-skip-host-discovery"
	}
	return "-with-host-discovery"
}

// naabuResultCollector parses Naabu's JSONL stdout as the child writes it.
// Each record is validated against the invocation's address batch and
// deduplicated into one bit per address:port, so memory is bounded by the
// batch size however often Naabu repeats a result. An invalid or oversized
// record, or an implausible number of repeats, stops the child.
type naabuResultCollector struct {
	allowed    map[string]struct{}
	maxRecords int
	onFailure  func()
	pending    []byte
	records    int
	addresses  map[string]*naabuAddressPorts
	err        error
}

type naabuAddressPorts struct {
	bits  [65536 / 64]uint64
	count int
	macs  []string
}

func newNaabuResultCollector(addresses []string, onFailure func()) *naabuResultCollector {
	allowed := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if normalized := normalizeAddress(address); normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	return &naabuResultCollector{allowed: allowed, maxRecords: max(len(allowed), 1) * maxNaabuRecordsPerAddress, onFailure: onFailure, addresses: map[string]*naabuAddressPorts{}}
}

func (c *naabuResultCollector) Write(data []byte) (int, error) {
	if c.err != nil {
		return len(data), c.err
	}
	written := len(data)
	for len(data) > 0 {
		newline := bytes.IndexByte(data, '\n')
		chunk := data
		if newline >= 0 {
			chunk = data[:newline]
		}
		if len(c.pending)+len(chunk) >= maxNaabuLineBytes {
			return written, c.fail(fmt.Errorf("naabu JSON line exceeded %d bytes", maxNaabuLineBytes))
		}
		if newline < 0 {
			c.pending = append(c.pending, chunk...)
			break
		}
		line := chunk
		if len(c.pending) > 0 {
			c.pending = append(c.pending, chunk...)
			line = c.pending
		}
		if err := c.record(line); err != nil {
			return written, c.fail(err)
		}
		c.pending = c.pending[:0]
		data = data[newline+1:]
	}
	return written, nil
}

func (c *naabuResultCollector) fail(err error) error {
	c.err = err
	if c.onFailure != nil {
		c.onFailure()
	}
	return err
}

func (c *naabuResultCollector) record(line []byte) error {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	c.records++
	if c.records > c.maxRecords {
		return fmt.Errorf("naabu emitted more than %d JSON records for %d address(es)", c.maxRecords, len(c.allowed))
	}
	var result naabuResult
	if err := json.Unmarshal(line, &result); err != nil {
		return fmt.Errorf("parse naabu JSON: %w", err)
	}
	address := normalizeAddress(result.IP)
	if address == "" {
		address = normalizeAddress(result.Host)
	}
	if net.ParseIP(address) == nil {
		return fmt.Errorf("naabu returned invalid address %q", address)
	}
	if _, ok := c.allowed[address]; !ok {
		return fmt.Errorf("naabu returned unexpected address %s", address)
	}
	if result.Port < 1 || result.Port > 65535 {
		return fmt.Errorf("naabu returned invalid port %d", result.Port)
	}
	if result.Protocol != "" && !strings.EqualFold(result.Protocol, "tcp") {
		return fmt.Errorf("naabu returned non-TCP protocol %q", result.Protocol)
	}
	ports := c.addresses[address]
	if ports == nil {
		ports = &naabuAddressPorts{}
		c.addresses[address] = ports
	}
	word, bit := result.Port/64, uint64(1)<<(result.Port%64)
	if ports.bits[word]&bit == 0 {
		ports.bits[word] |= bit
		ports.count++
	}
	if mac := boundScannerMetadata(result.MacAddress); mac != "" && len(ports.macs) < maxScannerLinkAddresses && !slices.Contains(ports.macs, mac) {
		ports.macs = append(ports.macs, mac)
	}
	return nil
}

// finish parses a final record without a trailing newline and returns the
// deduplicated results. When the batch reported more distinct results than
// maxNaabuUniqueResults, the addresses with the most results are dropped,
// largest first, and listed as truncated so their coverage stays incomplete.
func (c *naabuResultCollector) finish() (naabuDiscovery, error) {
	if c.err == nil && len(c.pending) > 0 {
		if err := c.record(c.pending); err != nil {
			c.err = err
		}
		c.pending = nil
	}
	if c.err != nil {
		return naabuDiscovery{}, c.err
	}
	addresses := make([]string, 0, len(c.addresses))
	total := 0
	for address, ports := range c.addresses {
		addresses = append(addresses, address)
		total += ports.count
	}
	sort.Slice(addresses, func(i, j int) bool {
		left, right := c.addresses[addresses[i]].count, c.addresses[addresses[j]].count
		if left != right {
			return left > right
		}
		return addresses[i] < addresses[j]
	})
	result := naabuDiscovery{ports: make(map[string][]int, len(addresses)), macs: make(map[string][]string, len(addresses))}
	for _, address := range addresses {
		ports := c.addresses[address]
		if total > maxNaabuUniqueResults {
			total -= ports.count
			result.truncated = append(result.truncated, address)
			continue
		}
		found := make([]int, 0, ports.count)
		for word, set := range ports.bits {
			for ; set != 0; set &= set - 1 {
				found = append(found, word*64+bits.TrailingZeros64(set))
			}
		}
		result.ports[address] = found
		if len(ports.macs) > 0 {
			result.macs[address] = ports.macs
		}
	}
	sort.Strings(result.truncated)
	return result, nil
}

type cappedBuffer struct {
	buffer     bytes.Buffer
	limit      int
	exceeded   bool
	onExceeded func()
	exceedOnce sync.Once
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	trigger := false
	if b.limit > 0 && b.Len()+len(data) > b.limit {
		remaining := b.limit - b.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(data[:remaining])
		}
		if !b.exceeded {
			trigger = true
		}
		b.exceeded = true
		if trigger && b.onExceeded != nil {
			b.exceedOnce.Do(b.onExceeded)
		}
		return len(data), errors.New("output limit exceeded")
	}
	return b.buffer.Write(data)
}

func (b *cappedBuffer) Len() int {
	return b.buffer.Len()
}

func (b *cappedBuffer) String() string {
	return b.buffer.String()
}

func (b *cappedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
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

// markNaabuEnrichmentFailure keeps a discovery-only host visibly incomplete
// when the confirming Nmap invocation fails. Naabu discoveries remain useful
// diagnostics, but every discovered port is explicitly unconfirmed so a
// failed enrichment can never look like authoritative closed-state evidence.
func markNaabuEnrichmentFailure(host *model.HostObservation, discovered []int) {
	if host == nil {
		return
	}
	host.Status, host.StatusReason = mergeHostStatus(host.Status, host.StatusReason, "unreachable", "nmap-enrichment-failed")
	for index := range host.Protocols {
		protocol := &host.Protocols[index]
		if !strings.EqualFold(protocol.Protocol, "tcp") || !strings.EqualFold(protocol.DiscoveryEngine, "naabu") {
			continue
		}
		protocol.Status, protocol.StatusReason = mergeHostStatus(protocol.Status, protocol.StatusReason, "unreachable", "nmap-enrichment-failed")
		seen := make(map[int]struct{}, len(protocol.UnconfirmedPorts))
		for _, port := range protocol.UnconfirmedPorts {
			seen[port.Port] = struct{}{}
		}
		for _, port := range discovered {
			if _, exists := seen[port]; exists {
				continue
			}
			protocol.UnconfirmedPorts = append(protocol.UnconfirmedPorts, model.PortObservation{Port: port, State: "unconfirmed", Reason: "nmap-enrichment-failed", Verification: "unconfirmed"})
			addStateSummary(protocol, "unconfirmed", "nmap-enrichment-failed", 1)
		}
	}
}

// naabuRawPrivileges is the capability check applied before a Naabu
// invocation. It is a variable only so tests can exercise SYN discovery
// without granting the test process raw-packet capabilities.
var naabuRawPrivileges = hasRawScannerPrivileges

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
