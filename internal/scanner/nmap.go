package scanner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}
type Nmap struct {
	Path      string
	NaabuPath string
	Resolver  Resolver
}

// maxProgressOutput bounds diagnostic stderr retained from either scanner.
// XML remains on stdout and has its own command-specific handling; stderr is
// only a live status hint and must never be allowed to grow with a verbose or
// compromised child process.
const maxProgressOutput = 4 << 20

// maxNmapOutput bounds one XML result before it can exhaust daemon memory.
// Nmap output is normally compact even for a 65,535-port scope because only
// positive ports are emitted individually; extraports state summaries cover
// the remainder. A pathological or compromised child is failed safely.
const maxNmapOutput = 64 << 20

// Progress describes the bounded, operator-facing work completed by a scan.
// Counts are based on resolved addresses and ports, and are deliberately
// estimates of Nmap probes rather than an SLA for network response time.
type Progress struct {
	StartedAt            time.Time
	CompletedProbes      int64
	TotalProbes          int64
	CompletedInvocations int64
	TotalInvocations     int64
	Phase                string
	// The remaining fields describe liveness inside one Nmap process. They are
	// intentionally advisory: Nmap may not emit a percentage for every scan,
	// but the heartbeat and last output still prove that the process is alive.
	Protocol               string
	CurrentInvocation      int64
	TotalBatches           int64
	ProcessProgressPercent int
	ElapsedSeconds         int64
	LastOutput             string
	ProcessAlive           bool
	// Work-unit fields are populated by resumable scans. They let the
	// dashboard distinguish persisted cycle progress from the current Nmap
	// process without exposing engine-specific command arguments.
	CurrentUnit   int
	TotalUnits    int
	UnitPorts     string
	UnitAddresses int
	// Discovery fields are populated by the optional Naabu phase. They are
	// cumulative for the current scan and intentionally contain counts only;
	// individual discovery evidence is persisted with the completed snapshot.
	DiscoveryPortsFound  int
	DiscoveryAddresses   int
	DiscoveryDurationMS  int64
	EnrichmentDurationMS int64
}

// ProgressReporter receives scan progress after resolution, while an Nmap
// process is alive, and after each completed invocation. Implementations must
// not retain or call it after Scan returns.
type ProgressReporter func(Progress)

func New(path string) *Nmap {
	if path == "" {
		path = "nmap"
	}
	return &Nmap{Path: path, NaabuPath: "/usr/local/bin/naabu", Resolver: net.DefaultResolver}
}

// NewWithNaabu is the production constructor used by the daemon and the
// deterministic scanner tests. Keeping the binary paths injectable avoids a
// package-level dependency on the container image while preserving the
// existing New(path) API for Nmap-only callers.
func NewWithNaabu(nmapPath, naabuPath string) *Nmap {
	scanner := New(nmapPath)
	if strings.TrimSpace(naabuPath) != "" {
		scanner.NaabuPath = naabuPath
	}
	return scanner
}

type resolvedTarget struct {
	Name             string
	ConfiguredTarget string
	Addresses        []string
	Aggregate        bool
	Hostname         bool
}

// nmapBatchSize bounds one command's target list while avoiding one process
// launch per expanded CIDR address. It is deliberately internal so the
// deployment-level job schema remains focused on scan intent rather than
// engine-specific tuning.
const nmapBatchSize = 128

func (n *Nmap) Version(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, n.Path, "--version").Output()
	if err != nil {
		return "unknown"
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	return strings.TrimSpace(line)
}

// NaabuVersion reports the fixed Naabu binary version without exposing the
// command or environment to callers. An unavailable optional binary is
// represented as "unknown" and is surfaced as scan metadata only when the
// Naabu engine is selected.
func (n *Nmap) NaabuVersion(ctx context.Context) string {
	path := n.NaabuPath
	if strings.TrimSpace(path) == "" {
		path = "/usr/local/bin/naabu"
	}
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	if err != nil {
		out, err = exec.CommandContext(ctx, path, "--version").CombinedOutput()
	}
	if err != nil {
		return "unknown"
	}
	// Naabu prints an ASCII banner before the actual version line (currently
	// `[INF] Current Version: 2.6.1`). Do not report the banner as the version;
	// scan metadata and the capabilities endpoint need a stable, compact value.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		for _, marker := range []string{"current version:", "version:"} {
			if index := strings.Index(lower, marker); index >= 0 {
				value := strings.TrimSpace(line[index+len(marker):])
				value = strings.TrimPrefix(value, "v")
				if value != "" {
					return value
				}
			}
		}
		// Older/newer builds may put the version directly after the product
		// name (for example, `naabu v2.6.1`). Keep this fallback conservative
		// so an ASCII-art line is never mistaken for a version.
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(strings.Trim(fields[0], "[]"), "naabu") {
			value := strings.TrimPrefix(fields[1], "v")
			if value != "" {
				return value
			}
		}
	}
	return "unknown"
}

func (n *Nmap) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return n.ScanWithProgress(ctx, job, nil)
}

// ScanWithProgress is the cancellable scanner entry point used by the web
// console. The legacy Scan method delegates here so test and plugin scanners
// do not need to implement progress reporting.
func (n *Nmap) ScanWithProgress(ctx context.Context, job config.Job, report ProgressReporter) (model.Snapshot, error) {
	job = config.NormalizeJob(job)
	if job.TCP != nil && job.TCP.Engine == config.EngineNaabuNmap {
		return n.scanNaabuPipeline(ctx, job, report)
	}
	started := time.Now().UTC()
	emit := func(progress Progress) {
		if progress.ElapsedSeconds <= 0 {
			progress.ElapsedSeconds = int64(time.Since(started).Seconds())
		}
		if progress.ElapsedSeconds < 0 {
			progress.ElapsedSeconds = 0
		}
		reportProgress(report, progress)
	}
	emit(Progress{Phase: "resolving", StartedAt: started})
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
	totalProbes, totalInvocations := progressTotals(targets, job)
	progress := Progress{TotalProbes: totalProbes, TotalInvocations: totalInvocations, Phase: "scanning", StartedAt: started}
	emit(progress)
	snap := model.Snapshot{DNS: map[string][]string{}}
	for _, rt := range targets {
		if rt.Hostname {
			snap.DNS[rt.Name] = append([]string(nil), rt.Addresses...)
		}
	}
	if job.TCP != nil {
		for _, rt := range targets {
			snap.Scopes = append(snap.Scopes, model.Scope{Target: rt.Name, Protocol: "tcp", Ports: job.TCP.Ports, ServiceDetection: job.TCP.ServiceDetection})
		}
		baseInvocations, baseProbes := progress.CompletedInvocations, progress.CompletedProbes
		result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "tcp", *job.TCP, job.Timing, job.AssumesAlive(), func(invocations, probes int64) {
			progress.CompletedInvocations += invocations
			progress.CompletedProbes += probes
			emit(progress)
		}, func(update invocationProgress) {
			live := progress
			live.Protocol = update.Protocol
			live.CurrentInvocation = baseInvocations + update.Invocation
			live.TotalBatches = totalInvocations
			live.ProcessProgressPercent = int(update.Fraction * 100)
			live.ProcessAlive = update.Alive
			live.LastOutput = update.Output
			live.CompletedProbes = baseProbes + int64(float64(update.BatchProbes)*update.Fraction)
			if update.Alive {
				live.Phase = update.Protocol + " scanning"
			}
			emit(live)
		})
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("tcp scan: %w", err)
		}
		snap.Units = append(snap.Units, result.Units...)
		mergeHostObservations(&snap.Hosts, result.Hosts)
	}
	if job.UDP != nil {
		for _, rt := range targets {
			snap.Scopes = append(snap.Scopes, model.Scope{Target: rt.Name, Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
		}
		baseInvocations, baseProbes := progress.CompletedInvocations, progress.CompletedProbes
		result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "udp", *job.UDP, job.Timing, job.AssumesAlive(), func(invocations, probes int64) {
			progress.CompletedInvocations += invocations
			progress.CompletedProbes += probes
			emit(progress)
		}, func(update invocationProgress) {
			live := progress
			live.Protocol = update.Protocol
			live.CurrentInvocation = baseInvocations + update.Invocation
			live.TotalBatches = totalInvocations
			live.ProcessProgressPercent = int(update.Fraction * 100)
			live.ProcessAlive = update.Alive
			live.LastOutput = update.Output
			live.CompletedProbes = baseProbes + int64(float64(update.BatchProbes)*update.Fraction)
			if update.Alive {
				live.Phase = update.Protocol + " scanning"
			}
			emit(live)
		})
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("udp scan: %w", err)
		}
		snap.Units = append(snap.Units, result.Units...)
		mergeHostObservations(&snap.Hosts, result.Hosts)
	}
	snap.Normalize()
	progress.CompletedInvocations = progress.TotalInvocations
	progress.CompletedProbes = progress.TotalProbes
	progress.Phase = "complete"
	progress.ProcessAlive = false
	progress.CurrentInvocation = progress.TotalInvocations
	progress.ElapsedSeconds = int64(time.Since(started).Seconds())
	emit(progress)
	return snap, nil
}

func reportProgress(report ProgressReporter, progress Progress) {
	if report != nil {
		report(progress)
	}
}

func progressTotals(targets []resolvedTarget, job config.Job) (probes, invocations int64) {
	for _, item := range []struct {
		protocol string
		config.Protocol
	}{
		{protocol: "tcp", Protocol: valueProtocol(job.TCP)},
		{protocol: "udp", Protocol: valueProtocol(job.UDP)},
	} {
		if item.Protocol.Ports == "" {
			continue
		}
		ports, err := config.ParsePorts(item.Protocol.Ports)
		if err != nil {
			continue
		}
		factor := int64(1)
		if item.ServiceDetection {
			factor = 2
		}
		byFamily := map[int]map[string]struct{}{4: {}, 6: {}}
		for _, target := range targets {
			for _, address := range target.Addresses {
				family := 4
				if strings.Contains(address, ":") {
					family = 6
				}
				byFamily[family][address] = struct{}{}
			}
		}
		for _, addresses := range byFamily {
			count := int64(len(addresses))
			invocations += int64((len(addresses) + nmapBatchSize - 1) / nmapBatchSize)
			probes += count * int64(len(ports)) * factor
		}
	}
	return probes, invocations
}

func valueProtocol(protocol *config.Protocol) config.Protocol {
	if protocol == nil {
		return config.Protocol{}
	}
	return *protocol
}

func (n *Nmap) resolve(ctx context.Context, job config.Job) ([]resolvedTarget, error) {
	var out []resolvedTarget
	count := 0
	for _, input := range job.Targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw := config.CanonicalTarget(input)
		if ip := net.ParseIP(raw); ip != nil {
			count++
			if count > job.MaxExpandedHosts {
				return nil, fmt.Errorf("expanded targets exceed max_expanded_hosts=%d", job.MaxExpandedHosts)
			}
			out = append(out, resolvedTarget{Name: ip.String(), ConfiguredTarget: raw, Addresses: []string{ip.String()}})
			continue
		}
		if ip, network, err := net.ParseCIDR(raw); err == nil {
			for current := ip.Mask(network.Mask); network.Contains(current); incrementIP(current) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				count++
				if count > job.MaxExpandedHosts {
					return nil, fmt.Errorf("expanded targets exceed max_expanded_hosts=%d", job.MaxExpandedHosts)
				}
				value := current.String()
				out = append(out, resolvedTarget{Name: value, ConfiguredTarget: raw, Addresses: []string{value}})
			}
			continue
		}
		ips, err := n.Resolver.LookupIP(ctx, "ip", raw)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", raw, err)
		}
		set := map[string]bool{}
		var addresses []string
		for _, ip := range ips {
			value := ip.String()
			if !set[value] {
				set[value] = true
				addresses = append(addresses, value)
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve %s: no A or AAAA records", raw)
		}
		count += len(addresses)
		if count > job.MaxExpandedHosts {
			return nil, fmt.Errorf("resolved targets exceed max_expanded_hosts=%d", job.MaxExpandedHosts)
		}
		sort.Strings(addresses)
		out = append(out, resolvedTarget{Name: strings.ToLower(raw), ConfiguredTarget: strings.ToLower(raw), Addresses: addresses, Aggregate: true, Hostname: true})
	}
	return out, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func (n *Nmap) scanProtocol(ctx context.Context, target resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool) ([]model.Unit, error) {
	return n.scanProtocolBatch(ctx, []resolvedTarget{target}, protocol, pc, timing, assumeAlive)
}

func (n *Nmap) scanProtocolBatch(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool) ([]model.Unit, error) {
	return n.scanProtocolBatchProgress(ctx, targets, protocol, pc, timing, assumeAlive, nil)
}

func (n *Nmap) scanProtocolBatchProgress(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool, report func(int64, int64)) ([]model.Unit, error) {
	result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, protocol, pc, timing, assumeAlive, report, nil)
	return result.Units, err
}

type protocolScanResult struct {
	Units []model.Unit
	Hosts map[string]model.HostObservation
}

type invocationProgress struct {
	Protocol    string
	Invocation  int64
	BatchProbes int64
	Fraction    float64
	Output      string
	Alive       bool
}

// scanProtocolBatchDetailedProgress retains the compact units used by the
// comparison engine and, alongside them, detailed per-effective-address
// observations for the host explorer. The two representations intentionally
// have separate lifecycles: descriptive host evidence never affects hashes.
func (n *Nmap) scanProtocolBatchDetailedProgress(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool, report func(int64, int64), statusReports ...func(invocationProgress)) (protocolScanResult, error) {
	return n.scanProtocolBatchDetailedProgressWithTemplate(ctx, targets, protocol, pc, timing, assumeAlive, pc.NmapArgs, report, statusReports...)
}

func (n *Nmap) scanProtocolBatchDetailedProgressWithTemplate(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool, template []string, report func(int64, int64), statusReports ...func(invocationProgress)) (protocolScanResult, error) {
	if err := config.ValidateScannerProfile(config.ScannerProfile{Engine: config.EngineNmap, NmapArgs: pc.NmapArgs, EnrichmentArgs: pc.EnrichmentArgs, NSEProfile: pc.NSEProfile, NSEArgs: pc.NSEArgs}); err != nil {
		return protocolScanResult{}, fmt.Errorf("scanner profile arguments: %w", err)
	}
	var status func(invocationProgress)
	if len(statusReports) > 0 {
		status = statusReports[0]
	}
	byFamily := map[int][]string{4: {}, 6: {}}
	seen := map[string]bool{}
	for _, target := range targets {
		for _, address := range target.Addresses {
			if seen[address] {
				continue
			}
			seen[address] = true
			if strings.Contains(address, ":") {
				byFamily[6] = append(byFamily[6], address)
			} else {
				byFamily[4] = append(byFamily[4], address)
			}
		}
	}
	all := map[string]model.Unit{}
	allHosts := map[string]model.HostObservation{}
	batchLimit := nmapBatchSize
	// {address} is deliberately singular. A custom profile that uses it is
	// still safe for a multi-address target set, but each invocation must carry
	// exactly one address; {addresses} is the opt-in list form for batching.
	if templateContains(template, config.PlaceholderAddress) {
		batchLimit = 1
	}
	for _, family := range []int{4, 6} {
		addresses := byFamily[family]
		for start := 0; start < len(addresses); start += batchLimit {
			end := min(start+batchLimit, len(addresses))
			batch := addresses[start:end]
			args := nmapArgsWithTemplate(family, protocol, pc, timing, assumeAlive, batch, template)
			cmd := exec.CommandContext(ctx, n.Path, args...)
			// Keep profile execution deterministic and prevent host-local Nmap
			// configuration, script directories, or credential-bearing environment
			// variables from changing the fixed scanner contract. Browser/API input
			// never controls this environment; only the validated argv template does.
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "NMAPDIR=/usr/share/nmap", "XDG_CONFIG_HOME=/nonexistent", "LANG=C"}
			batchProbes := int64(len(batch))
			ports, _ := config.ParsePorts(pc.Ports)
			factor := int64(1)
			if pc.ServiceDetection {
				factor = 2
			}
			batchProbes *= int64(len(ports)) * factor
			localInvocation := int64(start/batchLimit) + 1
			if family == 6 && len(byFamily[4]) > 0 {
				localInvocation += int64((len(byFamily[4]) + batchLimit - 1) / batchLimit)
			}
			if status != nil {
				status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Alive: true})
			}
			var lastOutput string
			lastFraction := 0.0
			stdout, stderr, err := runNmapInvocation(ctx, cmd, func(line string, fraction float64) {
				lastOutput = line
				if fraction > lastFraction {
					lastFraction = fraction
				}
				if status != nil {
					status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Fraction: lastFraction, Output: line, Alive: true})
				}
			}, func() {
				if status != nil {
					status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Fraction: lastFraction, Output: lastOutput, Alive: true})
				}
			})
			if ctx.Err() != nil {
				if status != nil {
					status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Output: lastOutput, Fraction: lastFraction, Alive: false})
				}
				return protocolScanResult{}, fmt.Errorf("scan timed out or cancelled: %w", ctx.Err())
			}
			if err != nil {
				if status != nil {
					status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Output: lastOutput, Fraction: lastFraction, Alive: false})
				}
				return protocolScanResult{}, fmt.Errorf("nmap failed: %v: %s", err, sanitizeStderr(stderr))
			}
			if status != nil {
				status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Fraction: 1, Output: lastOutput, Alive: false})
			}
			parsed, err := parseXMLWithConfig(stdout, protocol, pc)
			if err != nil {
				return protocolScanResult{}, err
			}
			if parsed.Exit != "success" {
				return protocolScanResult{}, fmt.Errorf("nmap run incomplete: %s", parsed.Exit)
			}
			for _, address := range batch {
				unit, ok := parsed.Units[address]
				if !ok {
					return protocolScanResult{}, fmt.Errorf("nmap output omitted expected address %s", address)
				}
				all[address] = unit
				if host, ok := parsed.Hosts[address]; ok {
					// Fingerprint the fixed executable and argv shape without
					// retaining target addresses or any profile values in logs.
					for index := range host.Protocols {
						host.Protocols[index].CommandFingerprint = commandFingerprint(args)
					}
					mergeHostObservationMap(allHosts, address, host)
				}
			}
			if report != nil {
				report(1, int64(len(batch))*int64(len(ports))*factor)
			}
		}
	}
	var units []model.Unit
	for _, target := range targets {
		if target.Aggregate {
			aggregated := make(map[string]model.Unit, len(target.Addresses))
			for _, address := range target.Addresses {
				aggregated[address] = all[address]
			}
			units = append(units, aggregate(target, aggregated, protocol))
			continue
		}
		for _, address := range target.Addresses {
			unit := all[address]
			unit.Target = address
			units = append(units, unit)
		}
	}
	for address, host := range allHosts {
		for _, target := range targets {
			for _, candidate := range target.Addresses {
				if candidate != address {
					continue
				}
				sourceTarget := target.ConfiguredTarget
				if sourceTarget == "" {
					sourceTarget = target.Name
				}
				host.SourceTargets = append(host.SourceTargets, sourceTarget)
				if target.Hostname {
					host.DNSNames = append(host.DNSNames, target.Name)
				}
			}
		}
		host.Address = normalizeAddress(address)
		dedupeHostObservation(&host)
		allHosts[address] = host
	}
	return protocolScanResult{Units: units, Hosts: allHosts}, nil
}

func nmapArgs(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses []string) []string {
	return nmapArgsWithTemplate(family, protocol, pc, timing, assumeAlive, addresses, pc.NmapArgs)
}

// nmapEnrichmentArgs renders the Naabu→Nmap confirmation invocation. The
// profile has separate Nmap-only and enrichment templates; applying the former
// here would make a job silently inherit switches intended for a different
// engine. NSE settings remain common to both paths and are rendered by the
// shared helper.
func nmapEnrichmentArgs(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses []string) []string {
	return nmapArgsWithTemplate(family, protocol, pc, timing, assumeAlive, addresses, pc.EnrichmentArgs)
}

func nmapArgsWithTemplate(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses, template []string) []string {
	// Nmap keeps XML on stdout and emits periodic timing lines on its status
	// channel. These flags are internal observability/safety settings and are
	// never replaceable by a profile. When a profile supplies placeholders, the
	// corresponding managed argument is rendered in the profile's position;
	// otherwise the built-in argument is emitted here.
	custom := len(template) > 0
	args := []string{"-n"}
	if !custom {
		args = append(args, "-oX", "-", "-p", pc.Ports, timingArg(timing), "--reason", "--stats-every", "1s")
		if assumeAlive {
			args = append(args, "-Pn")
		}
		if family == 6 {
			args = append(args, "-6")
		}
		if protocol == "udp" {
			args = append(args, "-sU")
		} else if pc.Mode == "connect" {
			args = append(args, "-sT")
		} else {
			args = append(args, "-sS")
		}
		if pc.ServiceDetection {
			args = append(args, "-sV", "--version-light")
		}
		args = appendNSEArgs(args, pc)
		return append(args, addresses...)
	}

	// Keep timing and Nmap's reason/progress diagnostics mandatory even for a
	// custom profile. Optional managed fields default to the same values as the
	// built-in command when a profile omits their placeholder. This is important
	// for profile authors who only want to add a safe tuning switch: leaving out
	// {host_discovery}, {scan_type}, or {service_detection} must not silently
	// change the job's scan semantics.
	args = append(args, timingArg(timing), "--reason", "--stats-every", "1s")
	if !templateContains(template, config.PlaceholderHostDiscovery) && assumeAlive {
		args = append(args, "-Pn")
	}
	if !templateContains(template, config.PlaceholderAddressFamily) && family == 6 {
		args = append(args, "-6")
	}
	if !templateContains(template, config.PlaceholderScanType) {
		args = append(args, nmapScanTypeArgs(protocol, pc)...)
	}
	if !templateContains(template, config.PlaceholderServiceDetection) && pc.ServiceDetection {
		args = append(args, "-sV", "--version-light")
	}
	args = append(args, renderNmapTemplate(template, family, protocol, pc, assumeAlive, addresses)...)
	if !templateContains(template, config.PlaceholderNSE) {
		args = appendNSEArgs(args, pc)
	}
	return args
}

func nmapScanTypeArgs(protocol string, pc config.Protocol) []string {
	if protocol == "udp" {
		return []string{"-sU"}
	}
	if pc.Mode == "connect" {
		return []string{"-sT"}
	}
	return []string{"-sS"}
}

func appendNSEArgs(args []string, pc config.Protocol) []string {
	if strings.TrimSpace(pc.NSEProfile) == "" {
		return args
	}
	// NSE names are validated against the bundled, non-invasive catalog before
	// a job is persisted. The generated flags are internal and never come from
	// a browser-supplied command string.
	args = append(args, "--script", pc.NSEProfile)
	if len(pc.NSEArgs) == 0 {
		return args
	}
	keys := make([]string, 0, len(pc.NSEArgs))
	for key := range pc.NSEArgs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+pc.NSEArgs[key])
	}
	return append(args, "--script-args", strings.Join(values, ","))
}

func templateContains(values []string, placeholder string) bool {
	for _, value := range values {
		if value == placeholder {
			return true
		}
	}
	return false
}

// renderNmapTemplate expands a validated profile template. Placeholders are
// whole argv items, so values that naturally consist of multiple arguments
// (XML output, service detection, NSE, or an address list) can never be
// concatenated with a user-controlled token.
func renderNmapTemplate(template []string, family int, protocol string, pc config.Protocol, assumeAlive bool, addresses []string) []string {
	var out []string
	addressRendered := false
	for _, value := range template {
		switch value {
		case config.PlaceholderAddress:
			addressRendered = true
			if len(addresses) > 0 {
				// A singular address placeholder is intended for one-address
				// batches. The caller limits such templates to one address; use the
				// first value as a defensive fallback for direct unit callers.
				out = append(out, addresses[0])
			}
		case config.PlaceholderAddresses:
			addressRendered = true
			out = append(out, addresses...)
		case config.PlaceholderAddressFamily:
			if family == 6 {
				out = append(out, "-6")
			} else {
				out = append(out, "-4")
			}
		case config.PlaceholderHostDiscovery:
			if assumeAlive {
				out = append(out, "-Pn")
			}
		case config.PlaceholderScanType:
			if protocol == "udp" {
				out = append(out, "-sU")
			} else if pc.Mode == "connect" {
				out = append(out, "-sT")
			} else {
				out = append(out, "-sS")
			}
		case config.PlaceholderPorts:
			out = append(out, "-p", pc.Ports)
		case config.PlaceholderStructuredOutput:
			out = append(out, "-oX", "-")
		case config.PlaceholderServiceDetection:
			if pc.ServiceDetection {
				out = append(out, "-sV", "--version-light")
			}
		case config.PlaceholderNSE:
			out = appendNSEArgs(out, pc)
		case config.PlaceholderTargetsFile:
			// Target files belong to Naabu. Keep the placeholder accepted for
			// shared profile tooling but never leak it as a literal Nmap token.
		default:
			out = append(out, value)
		}
	}
	if !addressRendered {
		out = append(out, addresses...)
	}
	return out
}

func commandFingerprint(args []string) string {
	// The complete argv is already validated and contains no credentials. Do
	// not retain effective addresses in the fingerprint, though: a template
	// may place its managed address placeholder before other flags, so stripping
	// only trailing targets would leak inventory into audit metadata. Replacing
	// every bare IP keeps the command-shape identifier stable across hosts.
	sanitized := make([]string, len(args))
	for index, value := range args {
		if net.ParseIP(strings.Trim(value, "[]")) != nil {
			sanitized[index] = "<address>"
		} else {
			sanitized[index] = value
		}
	}
	b := []byte(strings.Join(sanitized, "\x00"))
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func appendTemplateArgs(args, values []string) []string {
	for _, value := range values {
		switch value {
		case config.PlaceholderTargetsFile, config.PlaceholderAddress, config.PlaceholderAddresses, config.PlaceholderAddressFamily, config.PlaceholderHostDiscovery, config.PlaceholderScanType, config.PlaceholderPorts, config.PlaceholderStructuredOutput, config.PlaceholderServiceDetection, config.PlaceholderNSE:
			// Runtime-owned arguments are already rendered above. A placeholder
			// in a profile is a declaration, not a second copy of a target or
			// output argument.
			continue
		default:
			args = append(args, value)
		}
	}
	return args
}

func timingArg(profile string) string {
	if profile == "conservative" {
		return "-T2"
	}
	if profile == "fast" {
		return "-T4"
	}
	return "-T3"
}
func sanitizeStderr(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 500 {
		v = v[:500] + "…"
	}
	return v
}

// runNmapInvocation keeps XML on stdout while consuming Nmap's human status
// channel concurrently. A ticker is intentionally part of this helper: some
// Nmap versions only print --stats-every output for interactive terminals, but
// the process heartbeat still gives the console truthful liveness information.
func runNmapInvocation(ctx context.Context, cmd *exec.Cmd, onOutput func(string, float64), onHeartbeat func()) ([]byte, string, error) {
	stdout := &cappedBuffer{limit: maxNmapOutput}
	var callbackMu sync.Mutex
	emitOutput := func(line string, fraction float64) {
		if onOutput == nil {
			return
		}
		line = trimProgressOutput(line)
		if line == "" {
			return
		}
		callbackMu.Lock()
		defer callbackMu.Unlock()
		onOutput(line, fraction)
	}
	emitHeartbeat := func() {
		if onHeartbeat == nil {
			return
		}
		callbackMu.Lock()
		defer callbackMu.Unlock()
		onHeartbeat()
	}
	stderr := &progressOutputWriter{limit: maxProgressOutput, emit: func(line string) {
		fraction, _ := parseNmapProgress(line)
		emitOutput(line, fraction)
	}}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}

	heartbeatStop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				emitHeartbeat()
			case <-ctx.Done():
				return
			case <-heartbeatStop:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	close(heartbeatStop)
	stderr.Flush()
	// The heartbeat goroutine may have observed the stop signal just before the
	// command exited. Waiting for its completion prevents callbacks after the
	// invocation's terminal update.
	<-heartbeatDone
	if stderr.exceeded {
		if waitErr != nil {
			return stdout.Bytes(), stderr.String(), fmt.Errorf("%w; nmap diagnostic output exceeded %d bytes", waitErr, maxProgressOutput)
		}
		return stdout.Bytes(), stderr.String(), fmt.Errorf("nmap diagnostic output exceeded %d bytes", maxProgressOutput)
	}
	if stdout.exceeded {
		if waitErr != nil {
			return stdout.Bytes(), stderr.String(), fmt.Errorf("%w; nmap XML output exceeded %d bytes", waitErr, maxNmapOutput)
		}
		return stdout.Bytes(), stderr.String(), fmt.Errorf("nmap XML output exceeded %d bytes", maxNmapOutput)
	}
	return stdout.Bytes(), stderr.String(), waitErrWithContext(ctx, waitErr)
}

// progressOutputWriter lets os/exec own the pipe-copy lifecycle while still
// exposing complete stderr lines to the progress callback. Using Stdout and
// Stderr writers instead of StdoutPipe/StderrPipe avoids a race where Wait
// closes a pipe at the same moment a reader goroutine observes its EOF.
type progressOutputWriter struct {
	mu       sync.Mutex
	all      strings.Builder
	pending  strings.Builder
	limit    int
	exceeded bool
	emit     func(string)
}

func (w *progressOutputWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	accepted := data
	if w.limit > 0 {
		remaining := w.limit - w.all.Len()
		if remaining <= 0 {
			accepted = nil
			w.exceeded = true
		} else if len(accepted) > remaining {
			accepted = accepted[:remaining]
			w.exceeded = true
		}
	}
	if len(accepted) > 0 {
		_, _ = w.all.Write(accepted)
		_, _ = w.pending.Write(accepted)
	}
	value := w.pending.String()
	lines := strings.Split(value, "\n")
	w.pending.Reset()
	if len(lines) > 0 && lines[len(lines)-1] != "" {
		w.pending.WriteString(lines[len(lines)-1])
		lines = lines[:len(lines)-1]
	} else if len(lines) > 0 {
		lines = lines[:len(lines)-1]
	}
	w.mu.Unlock()
	for _, line := range lines {
		if w.emit != nil {
			w.emit(line)
		}
	}
	return len(data), nil
}

func (w *progressOutputWriter) Flush() {
	w.mu.Lock()
	line := w.pending.String()
	w.pending.Reset()
	w.mu.Unlock()
	if strings.TrimSpace(line) != "" && w.emit != nil {
		w.emit(line)
	}
}

func (w *progressOutputWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.all.String()
}

func waitErrWithContext(ctx context.Context, waitErr error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return waitErr
}

func trimProgressOutput(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 240 {
		line = line[:240] + "…"
	}
	return line
}

func parseNmapProgress(line string) (float64, bool) {
	lower := strings.ToLower(line)
	start := strings.Index(lower, "about ")
	if start < 0 {
		return 0, false
	}
	start += len("about ")
	end := strings.IndexByte(line[start:], '%')
	if end < 0 {
		return 0, false
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(line[start:start+end]), 64)
	if err != nil {
		return 0, false
	}
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	return value / 100, true
}

type nmapRun struct {
	Hosts []struct {
		Status struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
			TTL    int    `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr   string `xml:"addr,attr"`
			Type   string `xml:"addrtype,attr"`
			Vendor string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostnames>hostname"`
		HostScripts []struct {
			ID     string `xml:"id,attr"`
			Output string `xml:"output,attr"`
		} `xml:"hostscript>script"`
		Times struct {
			SRTT string `xml:"srtt,attr"`
		} `xml:"times"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State  string `xml:"state,attr"`
				Reason string `xml:"reason,attr"`
				TTL    int    `xml:"reason_ttl,attr"`
			} `xml:"state"`
			Service struct {
				Name       string   `xml:"name,attr"`
				Product    string   `xml:"product,attr"`
				Version    string   `xml:"version,attr"`
				Extra      string   `xml:"extrainfo,attr"`
				Method     string   `xml:"method,attr"`
				Confidence int      `xml:"conf,attr"`
				Tunnel     string   `xml:"tunnel,attr"`
				OSType     string   `xml:"ostype,attr"`
				DeviceType string   `xml:"devicetype,attr"`
				CPES       []string `xml:"cpe"`
			} `xml:"service"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
		ExtraPorts []struct {
			State   string `xml:"state,attr"`
			Count   int    `xml:"count,attr"`
			Reasons []struct {
				Reason string `xml:"reason,attr"`
				Count  int    `xml:"count,attr"`
			} `xml:"extrareasons"`
		} `xml:"ports>extraports"`
	} `xml:"host"`
	RunStats struct {
		Exit string `xml:"exit,attr"`
	} `xml:"runstats>finished"`
}
type parsedRun struct {
	Exit  string
	Units map[string]model.Unit
	Hosts map[string]model.HostObservation
}

func parseXML(data []byte, protocol string, detectService bool) (parsedRun, error) {
	return parseXMLWithConfig(data, protocol, config.Protocol{Ports: "1-65535", Mode: "syn", ServiceDetection: detectService})
}

func parseXMLWithConfig(data []byte, protocol string, pc config.Protocol) (parsedRun, error) {
	var raw nmapRun
	if err := xml.Unmarshal(data, &raw); err != nil {
		return parsedRun{}, fmt.Errorf("parse nmap XML: %w", err)
	}
	result := parsedRun{Exit: raw.RunStats.Exit, Units: map[string]model.Unit{}, Hosts: map[string]model.HostObservation{}}
	for _, host := range raw.Hosts {
		if host.Status.State != "up" {
			continue
		}
		var address string
		var family string
		var links []model.LinkAddress
		for _, a := range host.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				if address == "" {
					address = normalizeAddress(a.Addr)
					family = map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[a.Type]
				}
			} else if strings.TrimSpace(a.Addr) != "" {
				links = append(links, model.LinkAddress{Address: strings.TrimSpace(a.Addr), Type: strings.TrimSpace(a.Type), Vendor: strings.TrimSpace(a.Vendor)})
			}
		}
		if address == "" {
			continue
		}
		unit := model.Unit{Target: address, Protocol: protocol, Addresses: []string{address}}
		hostObservation := model.HostObservation{Address: address, AddressFamily: family, Status: host.Status.State, StatusReason: host.Status.Reason, ReasonTTL: host.Status.TTL, LinkAddresses: links}
		for _, hostname := range host.Hostnames {
			hostObservation.Hostnames = append(hostObservation.Hostnames, model.Hostname{Name: strings.TrimSpace(hostname.Name), Type: strings.TrimSpace(hostname.Type)})
		}
		if host.Times.SRTT != "" {
			if srtt, err := strconv.ParseFloat(host.Times.SRTT, 64); err == nil {
				// Nmap reports srtt in microseconds.
				hostObservation.LatencyMS = srtt / 1000
			}
		}
		for _, a := range host.Addresses {
			if a.Type == "mac" {
				hostObservation.LinkAddresses = append(hostObservation.LinkAddresses, model.LinkAddress{Address: strings.TrimSpace(a.Addr), Type: a.Type, Vendor: strings.TrimSpace(a.Vendor)})
			}
		}
		observation := model.ProtocolObservation{Protocol: protocol, ScanType: scanType(protocol, pc), ScannedPorts: pc.Ports, ServiceDetection: pc.ServiceDetection, NSEProfile: strings.TrimSpace(pc.NSEProfile), NSEArgs: cloneStringMap(pc.NSEArgs)}
		for _, script := range host.HostScripts {
			if summary := summarizeNSEOutput(script.ID, script.Output); summary != "" {
				observation.NSEOutput = append(observation.NSEOutput, summary)
			}
		}
		if ports, err := config.ParsePorts(pc.Ports); err == nil {
			observation.ScannedPortCount = len(ports)
		}
		for _, p := range host.Ports {
			if p.Protocol != protocol {
				continue
			}
			addStateSummary(&observation, p.State.State, p.State.Reason, 1)
			if p.State.State != "open" && p.State.State != "open|filtered" {
				continue
			}
			for _, script := range p.Scripts {
				if summary := summarizeNSEOutput(script.ID, script.Output); summary != "" {
					observation.NSEOutput = append(observation.NSEOutput, summary)
				}
			}
			state := model.PortState{Port: p.PortID, State: p.State.State, Evidence: []string{address}}
			if pc.ServiceDetection && p.Service.Method == "probed" {
				state.Service = model.Fingerprint(p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Extra, p.Service.CPES)
			}
			unit.Ports = append(unit.Ports, state)
			port := model.PortObservation{Port: p.PortID, State: p.State.State, Reason: p.State.Reason, ReasonTTL: p.State.TTL, Verification: "confirmed"}
			if pc.ServiceDetection && hasServiceEvidence(p.Service) {
				port.Service = &model.ServiceObservation{Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, ExtraInfo: p.Service.Extra, Method: p.Service.Method, Confidence: p.Service.Confidence, Tunnel: p.Service.Tunnel, OSType: p.Service.OSType, DeviceType: p.Service.DeviceType, CPEs: append([]string(nil), p.Service.CPES...)}
			}
			observation.Ports = append(observation.Ports, port)
		}
		for _, extra := range host.ExtraPorts {
			addStateSummary(&observation, extra.State, "", extra.Count)
			for _, reason := range extra.Reasons {
				addStateReason(&observation, extra.State, reason.Reason, reason.Count)
			}
		}
		hostObservation.Protocols = append(hostObservation.Protocols, observation)
		hostObservation.Address = address
		dedupeHostObservation(&hostObservation)
		result.Units[address] = unit
		result.Hosts[address] = hostObservation
	}
	return result, nil
}

func normalizeAddress(raw string) string {
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(raw)
}

func scanType(protocol string, pc config.Protocol) string {
	if protocol == "udp" {
		return "udp"
	}
	if pc.Mode == "connect" {
		return "tcp connect"
	}
	return "tcp syn"
}

func hasServiceEvidence(service struct {
	Name       string   `xml:"name,attr"`
	Product    string   `xml:"product,attr"`
	Version    string   `xml:"version,attr"`
	Extra      string   `xml:"extrainfo,attr"`
	Method     string   `xml:"method,attr"`
	Confidence int      `xml:"conf,attr"`
	Tunnel     string   `xml:"tunnel,attr"`
	OSType     string   `xml:"ostype,attr"`
	DeviceType string   `xml:"devicetype,attr"`
	CPES       []string `xml:"cpe"`
}) bool {
	return service.Name != "" || service.Product != "" || service.Version != "" || service.Extra != "" || service.Method != "" || len(service.CPES) > 0
}

func summarizeNSEOutput(id, output string) string {
	id = strings.TrimSpace(id)
	output = strings.Join(strings.Fields(strings.TrimSpace(output)), " ")
	if id == "" && output == "" {
		return ""
	}
	if len(output) > 512 {
		output = output[:512] + "…"
	}
	if id == "" {
		return output
	}
	if output == "" {
		return id
	}
	return id + ": " + output
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func addStateSummary(observation *model.ProtocolObservation, state, reason string, count int) {
	if count <= 0 {
		return
	}
	for i := range observation.StateSummaries {
		if observation.StateSummaries[i].State == state {
			observation.StateSummaries[i].Count += count
			if reason != "" {
				addStateReason(observation, state, reason, count)
			}
			return
		}
	}
	observation.StateSummaries = append(observation.StateSummaries, model.StateSummary{State: state, Count: count})
	if reason != "" {
		addStateReason(observation, state, reason, count)
	}
}

func addStateReason(observation *model.ProtocolObservation, state, reason string, count int) {
	if reason == "" || count <= 0 {
		return
	}
	for i := range observation.StateSummaries {
		if observation.StateSummaries[i].State != state {
			continue
		}
		for j := range observation.StateSummaries[i].Reasons {
			if observation.StateSummaries[i].Reasons[j].Reason == reason {
				observation.StateSummaries[i].Reasons[j].Count += count
				return
			}
		}
		observation.StateSummaries[i].Reasons = append(observation.StateSummaries[i].Reasons, model.StateReason{Reason: reason, Count: count})
		return
	}
}

func mergeHostObservations(hosts *[]model.HostObservation, additions map[string]model.HostObservation) {
	byAddress := make(map[string]model.HostObservation, len(*hosts)+len(additions))
	for _, host := range *hosts {
		byAddress[host.Address] = host
	}
	for address, host := range additions {
		mergeHostObservationMap(byAddress, address, host)
	}
	*hosts = (*hosts)[:0]
	for _, host := range byAddress {
		dedupeHostObservation(&host)
		*hosts = append(*hosts, host)
	}
	sort.Slice(*hosts, func(i, j int) bool { return (*hosts)[i].Address < (*hosts)[j].Address })
}

func mergeHostObservationMap(hosts map[string]model.HostObservation, address string, addition model.HostObservation) {
	current, ok := hosts[address]
	if !ok {
		hosts[address] = addition
		return
	}
	current.SourceTargets = append(current.SourceTargets, addition.SourceTargets...)
	current.DNSNames = append(current.DNSNames, addition.DNSNames...)
	current.LinkAddresses = append(current.LinkAddresses, addition.LinkAddresses...)
	current.Hostnames = append(current.Hostnames, addition.Hostnames...)
	current.Protocols = append(current.Protocols, addition.Protocols...)
	if current.Address == "" {
		current.Address = addition.Address
	}
	if current.AddressFamily == "" {
		current.AddressFamily = addition.AddressFamily
	}
	if current.Status == "" || (current.Status == "unknown" && addition.Status != "") {
		current.Status = addition.Status
	}
	// Naabu discovery creates an address inventory before Nmap enrichment. It
	// can mark the host up without carrying Nmap's reason/latency fields, so
	// merge each descriptive field independently rather than treating a
	// non-empty status as a complete observation.
	if current.StatusReason == "" && addition.StatusReason != "" {
		current.StatusReason = addition.StatusReason
	}
	if current.ReasonTTL == 0 && addition.ReasonTTL != 0 {
		current.ReasonTTL = addition.ReasonTTL
	}
	if current.LatencyMS == 0 && addition.LatencyMS != 0 {
		current.LatencyMS = addition.LatencyMS
	}
	hosts[address] = current
}

func dedupeHostObservation(host *model.HostObservation) {
	uniqueStrings := func(values []string) []string {
		seen := map[string]struct{}{}
		out := values[:0]
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		sort.Strings(out)
		return out
	}
	host.SourceTargets = uniqueStrings(host.SourceTargets)
	host.DNSNames = uniqueStrings(host.DNSNames)
	seenLinks := map[string]model.LinkAddress{}
	for _, link := range host.LinkAddresses {
		seenLinks[link.Type+"\x00"+link.Address] = link
	}
	host.LinkAddresses = host.LinkAddresses[:0]
	for _, link := range seenLinks {
		host.LinkAddresses = append(host.LinkAddresses, link)
	}
	seenNames := map[string]model.Hostname{}
	for _, name := range host.Hostnames {
		seenNames[name.Type+"\x00"+name.Name] = name
	}
	host.Hostnames = host.Hostnames[:0]
	for _, name := range seenNames {
		host.Hostnames = append(host.Hostnames, name)
	}
	// A host can be encountered more than once when callers merge batches or
	// combine protocol results. Collapse those observations into one TCP and
	// one UDP record before normalizing the nested evidence.
	protocolIndex := map[string]int{}
	mergedProtocols := make([]model.ProtocolObservation, 0, len(host.Protocols))
	for _, incoming := range host.Protocols {
		index, exists := protocolIndex[incoming.Protocol]
		if !exists {
			protocolIndex[incoming.Protocol] = len(mergedProtocols)
			mergedProtocols = append(mergedProtocols, incoming)
			continue
		}
		protocol := &mergedProtocols[index]
		protocol.Ports = append(protocol.Ports, incoming.Ports...)
		protocol.DiscoveredPorts = append(protocol.DiscoveredPorts, incoming.DiscoveredPorts...)
		protocol.UnconfirmedPorts = append(protocol.UnconfirmedPorts, incoming.UnconfirmedPorts...)
		if protocol.DiscoveryEngine == "" {
			protocol.DiscoveryEngine = incoming.DiscoveryEngine
		}
		if protocol.ScanType == "" {
			protocol.ScanType = incoming.ScanType
		}
		if protocol.CommandFingerprint == "" {
			protocol.CommandFingerprint = incoming.CommandFingerprint
		}
		if protocol.ScannedPorts == "" {
			protocol.ScannedPorts = incoming.ScannedPorts
		}
		if incoming.ScannedPortCount > protocol.ScannedPortCount {
			protocol.ScannedPortCount = incoming.ScannedPortCount
		}
		protocol.ServiceDetection = protocol.ServiceDetection || incoming.ServiceDetection
		if protocol.NSEProfile == "" {
			protocol.NSEProfile = incoming.NSEProfile
		}
		if protocol.NSEArgs == nil {
			protocol.NSEArgs = cloneStringMap(incoming.NSEArgs)
		}
		protocol.NSEOutput = append(protocol.NSEOutput, incoming.NSEOutput...)
		for _, summary := range incoming.StateSummaries {
			found := false
			for i := range protocol.StateSummaries {
				if protocol.StateSummaries[i].State != summary.State {
					continue
				}
				protocol.StateSummaries[i].Count += summary.Count
				for _, reason := range summary.Reasons {
					mergedReason := false
					for j := range protocol.StateSummaries[i].Reasons {
						if protocol.StateSummaries[i].Reasons[j].Reason == reason.Reason {
							protocol.StateSummaries[i].Reasons[j].Count += reason.Count
							mergedReason = true
							break
						}
					}
					if !mergedReason {
						protocol.StateSummaries[i].Reasons = append(protocol.StateSummaries[i].Reasons, reason)
					}
				}
				found = true
				break
			}
			if !found {
				protocol.StateSummaries = append(protocol.StateSummaries, summary)
			}
		}
	}
	host.Protocols = mergedProtocols
	for i := range host.Protocols {
		protocol := &host.Protocols[i]
		portIndex := map[int]int{}
		mergedPorts := make([]model.PortObservation, 0, len(protocol.Ports))
		for _, incoming := range protocol.Ports {
			index, exists := portIndex[incoming.Port]
			if !exists {
				portIndex[incoming.Port] = len(mergedPorts)
				mergedPorts = append(mergedPorts, incoming)
				continue
			}
			port := &mergedPorts[index]
			if port.State != "open" && incoming.State == "open" {
				port.State = incoming.State
			}
			if port.Reason == "" {
				port.Reason, port.ReasonTTL = incoming.Reason, incoming.ReasonTTL
			}
			if port.Service == nil {
				port.Service = incoming.Service
			} else if incoming.Service != nil {
				if port.Service.Name == "" {
					port.Service.Name = incoming.Service.Name
				}
				if port.Service.Product == "" {
					port.Service.Product = incoming.Service.Product
				}
				if port.Service.Version == "" {
					port.Service.Version = incoming.Service.Version
				}
				if port.Service.ExtraInfo == "" {
					port.Service.ExtraInfo = incoming.Service.ExtraInfo
				}
				if port.Service.Method == "" {
					port.Service.Method = incoming.Service.Method
				}
				if port.Service.Confidence == 0 {
					port.Service.Confidence = incoming.Service.Confidence
				}
				if port.Service.Tunnel == "" {
					port.Service.Tunnel = incoming.Service.Tunnel
				}
				if port.Service.OSType == "" {
					port.Service.OSType = incoming.Service.OSType
				}
				if port.Service.DeviceType == "" {
					port.Service.DeviceType = incoming.Service.DeviceType
				}
				port.Service.CPEs = append(port.Service.CPEs, incoming.Service.CPEs...)
			}
		}
		protocol.Ports = mergedPorts
		for _, field := range []*[]model.PortObservation{&protocol.DiscoveredPorts, &protocol.UnconfirmedPorts} {
			seen := map[int]int{}
			merged := make([]model.PortObservation, 0, len(*field))
			for _, port := range *field {
				if index, exists := seen[port.Port]; exists {
					if verificationRank(port.Verification) > verificationRank(merged[index].Verification) {
						merged[index].Verification = port.Verification
					}
					if merged[index].Reason == "" {
						merged[index].Reason, merged[index].ReasonTTL = port.Reason, port.ReasonTTL
					}
					continue
				}
				seen[port.Port] = len(merged)
				merged = append(merged, port)
			}
			*field = merged
		}
		for j := range protocol.Ports {
			if protocol.Ports[j].Service != nil {
				protocol.Ports[j].Service.CPEs = uniqueStrings(protocol.Ports[j].Service.CPEs)
			}
		}
	}
	// Reuse the model's deterministic ordering rules without exposing scanner
	// internals on the observation type itself.
	snapshot := model.Snapshot{Hosts: []model.HostObservation{*host}}
	snapshot.Normalize()
	*host = snapshot.Hosts[0]
}

func verificationRank(value string) int {
	switch value {
	case "confirmed":
		return 3
	case "discovered":
		return 2
	case "unconfirmed":
		return 1
	default:
		return 0
	}
}

func aggregate(target resolvedTarget, units map[string]model.Unit, protocol string) model.Unit {
	out := model.Unit{Target: target.Name, Protocol: protocol, Addresses: append([]string(nil), target.Addresses...)}
	type combined struct {
		state    string
		evidence map[string]bool
		services map[string]bool
	}
	ports := map[int]*combined{}
	for address, unit := range units {
		for _, p := range unit.Ports {
			c := ports[p.Port]
			if c == nil {
				c = &combined{state: p.State, evidence: map[string]bool{}, services: map[string]bool{}}
				ports[p.Port] = c
			}
			if p.State == "open" {
				c.state = "open"
			}
			c.evidence[address] = true
			if p.Service != "" {
				c.services[p.Service] = true
			}
		}
	}
	for port, c := range ports {
		p := model.PortState{Port: port, State: c.state}
		for v := range c.evidence {
			p.Evidence = append(p.Evidence, v)
		}
		sort.Strings(p.Evidence)
		var services []string
		for v := range c.services {
			services = append(services, v)
		}
		sort.Strings(services)
		p.Service = strings.Join(services, " || ")
		out.Ports = append(out.Ports, p)
	}
	sort.Slice(out.Ports, func(i, j int) bool { return out.Ports[i].Port < out.Ports[j].Port })
	return out
}

func NewID(now time.Time) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%x", now.UnixNano())
}

var ErrBusy = errors.New("job is already running")
