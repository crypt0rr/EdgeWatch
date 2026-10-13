package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/creack/pty"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/sandbox"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type targetResolutionFailure struct {
	target string
	reason string
	err    error
}

type Nmap struct {
	Path             string
	NaabuPath        string
	Resolver         Resolver
	targetExclusions []*net.IPNet
	// sandbox confines scan processes. Nil starts them unconfined.
	sandbox *sandbox.Policy
	// workDir holds the private files of scans, and workDirLock keeps it
	// from being removed as stale. Empty uses the system's temporary
	// directory.
	workDir     string
	workDirLock *os.File
	// maxJobHosts is scanner.max_job_hosts; see SetMaxJobHosts.
	maxJobHosts int
}

// SetMaxJobHosts installs scanner.max_job_hosts, the most addresses the
// targets of one job may expand to whatever the job allows. Zero, the
// default, is config.DefaultMaxJobHosts.
func (n *Nmap) SetMaxJobHosts(limit int) {
	n.maxJobHosts = limit
}

func (n *Nmap) jobHostCeiling() int {
	if n.maxJobHosts > 0 {
		return n.maxJobHosts
	}
	return config.DefaultMaxJobHosts
}

// SetSandbox installs the policy that confines Nmap and Naabu scan
// processes. Nil, the default, starts them unconfined.
func (n *Nmap) SetSandbox(policy *sandbox.Policy) {
	n.sandbox = policy
}

// confineNmap makes cmd start its Nmap process in the sandbox. Nmap assumes
// that a process other than UID 0 cannot send raw packets and falls back to
// connect scans, so a confined Nmap, which holds NET_RAW as an ambient
// capability, is told so with --privileged. The flag goes only into the
// executed argument list; the recorded command fingerprint is computed from
// the scan's arguments without it. Call it once the XML output file is
// shared: Landlock lets Nmap reopen only the files it inherits by then.
func confineNmap(cmd *exec.Cmd, policy *sandbox.Policy) {
	if policy.Enforced() {
		cmd.Args = append([]string{cmd.Args[0], "--privileged"}, cmd.Args[1:]...)
	}
	policy.Confine(cmd)
}

// maxProgressOutput bounds diagnostic stderr retained from either scanner.
// XML remains on stdout and has its own command-specific handling; stderr is
// only a live status hint and must never be allowed to grow with a verbose or
// compromised child process.
const maxProgressOutput = 8 << 20

// maxNmapOutput bounds one XML result before it can exhaust daemon memory.
// Nmap output is normally compact even for a 65,535-port scope because only
// positive ports are emitted individually; extraports state summaries cover
// the remainder. A pathological or compromised child is failed safely.
// Compose gives the container a 128 MiB /tmp tmpfs while scanner XML is
// redirected to the data-volume temporary directory. Keep the XML cap below
// that limit and terminate a child while it is writing, rather than waiting
// for a full filesystem or allocating an oversized result in memory.
const maxNmapOutput = 16 << 20

var errNmapProgressOutputExceeded = fmt.Errorf("nmap XML output exceeded %d bytes", maxNmapOutput)

// nmapUnlistedOpenFilteredReason marks a protocol observation whose
// open|filtered ports Nmap folded into <extraports> without a usable port
// list. Nmap folds a state once it exceeds a display threshold that depends
// on the count and the verbosity level, so the unlisted ports are neither
// recorded nor treated as closed: the protocol is incomplete coverage.
const nmapUnlistedOpenFilteredReason = "open-filtered-ports-unlisted"

// Scanner metadata is descriptive evidence, not scan scope. Keep each
// target-controlled value small enough that a single hostile response cannot
// inflate a snapshot or its compact service fingerprint. The item limits also
// bound repeated XML elements while retaining enough evidence for normal
// Nmap output.
const (
	maxScannerMetadataBytes = 512
	maxScannerCPEs          = 32
	maxScannerHostnames     = 32
	maxScannerLinkAddresses = 32
	maxScannerNSEOutputs    = 32
	maxScannerStateReasons  = 32
)

// Nmap's XML DTD leaves most repeated records unbounded. The parser therefore
// applies limits derived from EdgeWatch's own scan scope and evidence limits.
// The scanner output byte cap remains the first bound; these limits also keep
// a compact XML document from expanding into a much larger object graph.
const (
	maxNmapXMLTokens = 1_000_000
	maxNmapXMLDepth  = 128
	maxNmapXMLHosts  = maxNmapXMLTokens / 2 // each host requires at least a start and end token
	// One invocation may materialize at most one scanner work unit's
	// address-by-port scope, matching the planner's hard probe-work ceiling.
	maxNmapXMLMaterializedPortSlots int64 = MaxWorkUnitProbes
	// Nmap elements use small fixed attribute groups; leave generous room for extensions.
	maxNmapXMLAttributes         = 64
	maxNmapXMLMaterializedHosts  = nmapBatchSize
	maxNmapMetadataRecordSlack   = 8 // retain the established fixture allowance beyond stored evidence caps
	maxNmapPortDuplicateSlack    = maxNmapMetadataRecordSlack
	maxNmapAddressesPerHost      = maxScannerLinkAddresses + 2 + maxNmapMetadataRecordSlack // retained links, IPv4/IPv6, and existing allowance
	maxNmapHostnamesPerHost      = maxScannerHostnames + maxNmapMetadataRecordSlack
	maxNmapCPEsPerService        = maxScannerCPEs + maxNmapMetadataRecordSlack
	maxNmapExtraPortsPerHost     = 16 // Nmap's finite port-state set has fewer states; leave room for extensions
	maxNmapExtraReasonsPerRecord = maxScannerStateReasons + maxNmapMetadataRecordSlack
	maxNmapFoldedListBytes       = 1 << 20 // above the text needed to name every port in the 1..65535 domain
	maxNmapStateSummaries        = 16      // bounds state indexes while allowing the finite Nmap state set
)

// scannerProbeEnv keeps version probes deterministic and prevents a scanner
// binary from reading user configuration or credentials from the daemon's
// environment. Scan invocations have the same contract in their own runner;
// version checks use it as well so startup cannot be influenced by host-local
// settings.
var scannerProbeEnv = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent"}

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
	// The remaining fields describe liveness inside one Nmap process. Nmap's
	// taskprogress records are parsed from its XML output when available; the
	// heartbeat and last output still prove that the process is alive when a
	// scanner version does not emit progress records.
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

// SetTargetExclusions installs the deployment-wide target policy. A nil list
// keeps embedded callers backwards-compatible; a non-nil empty list is an
// explicit allow-all override. The parsed networks are copied before use.
func (n *Nmap) SetTargetExclusions(exclusions []string) error {
	if exclusions == nil {
		n.targetExclusions = nil
		return nil
	}
	parsed, err := config.ParseTargetExclusions(exclusions)
	if err != nil {
		return err
	}
	n.targetExclusions = make([]*net.IPNet, 0, len(parsed))
	for _, network := range parsed {
		if network == nil {
			continue
		}
		copyNetwork := &net.IPNet{IP: append(net.IP(nil), network.IP...), Mask: append(net.IPMask(nil), network.Mask...)}
		n.targetExclusions = append(n.targetExclusions, copyNetwork)
	}
	if len(exclusions) == 0 {
		n.targetExclusions = []*net.IPNet{}
	}
	return nil
}

func (n *Nmap) excludedNetwork(ip net.IP) string {
	// Unspecified addresses are never valid scan destinations. This invariant
	// applies even when an administrator explicitly overrides the configurable
	// exclusion list with an empty set: DNS answers such as 0.0.0.0 and :: must
	// not make a host-networked scanner probe itself or populate a false
	// baseline.
	if ip == nil {
		return "invalid-address"
	}
	if ip.IsUnspecified() {
		return "unspecified"
	}
	for _, network := range n.targetExclusions {
		if network != nil && network.Contains(ip) {
			return network.String()
		}
	}
	return ""
}

type resolvedTarget struct {
	Name             string
	ConfiguredTarget string
	Addresses        []string
	Aggregate        bool
	Hostname         bool
	// network marks a target that stands for one literal target per
	// address, named by the address: every address of the CIDR that
	// ConfiguredTarget and Name hold. A scan of the network target's
	// addresses observes them exactly as it observes those literal targets.
	network bool
}

// nmapBatchSize bounds one command's target list while avoiding one process
// launch per expanded CIDR address. It is deliberately internal so the
// deployment-level job schema remains focused on scan intent rather than
// engine-specific tuning.
const nmapBatchSize = 128

func (n *Nmap) Version(ctx context.Context) string {
	out, err := runScannerVersionProbe(ctx, n.Path, "--version")
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
	out, err := runScannerVersionProbe(ctx, path, "-version")
	if err != nil {
		out, err = runScannerVersionProbe(ctx, path, "--version")
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

const maxVersionProbeOutput = 64 << 10

// runScannerVersionProbe bounds both stdout and stderr independently. A
// scanner banner is diagnostic startup metadata, not a scan result, and must
// never be allowed to consume the daemon's output budget or inherit a user's
// scanner configuration. The fixed command is killed as soon as either stream
// exceeds the cap so a malicious replacement cannot keep running after the
// bound is reached.
func runScannerVersionProbe(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string(nil), scannerProbeEnv...)
	startInProcessGroup(cmd, false)
	var stdout, stderr cappedBuffer
	var exceeded atomic.Bool
	kill := func() {
		if exceeded.CompareAndSwap(false, true) {
			_ = stopProcessGroup(cmd)
		}
	}
	stdout = cappedBuffer{limit: maxVersionProbeOutput, onExceeded: kill}
	stderr = cappedBuffer{limit: maxVersionProbeOutput, onExceeded: kill}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Start()
	if err == nil {
		err = waitProcessGroup(cmd)
	}
	if exceeded.Load() || stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("scanner version output exceeded %d bytes", maxVersionProbeOutput)
	}
	if err != nil {
		return nil, err
	}
	// A few Naabu builds print their version banner on stderr. Keep stdout and
	// stderr independently bounded above, then expose their bounded combined
	// text to the conservative parser used by NaabuVersion.
	return append(stdout.Bytes(), stderr.Bytes()...), nil
}

func (n *Nmap) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return n.ScanWithProgress(ctx, job, nil)
}

// weightedProcessPercent keeps live progress monotonic across a scan made up
// of several Nmap invocations. A process reaching 100% for batch one must not
// make the overall scan appear complete before later batches have started.
func weightedProcessPercent(completedInvocations, totalInvocations int64, fraction float64) int {
	if totalInvocations <= 0 {
		return 0
	}
	if completedInvocations < 0 {
		completedInvocations = 0
	}
	if completedInvocations >= totalInvocations {
		return 100
	}
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	value := int(((float64(completedInvocations) + fraction) / float64(totalInvocations)) * 100)
	if value < 0 {
		return 0
	}
	return value
}

// ScanWithProgress is the cancellable scanner entry point used by the web
// console. The legacy Scan method delegates here so test and plugin scanners
// do not need to implement progress reporting.
func (n *Nmap) ScanWithProgress(ctx context.Context, job config.Job, report ProgressReporter) (model.Snapshot, error) {
	return n.scanWithProgress(ctx, job, report, nil)
}

// ScanWithProgressBudget is the application entry point for scans whose work
// is data-dependent. The scan resolves its targets again, so the caller
// supplies a check that sees the resolved work before any process starts.
// Naabu discovers the TCP ports before Nmap enrichment, so the check also
// rejects the exact discovered Nmap work before enrichment starts. Keeping
// this as an optional interface preserves the small Scanner contract used by
// deterministic test scanners and integrations.
func (n *Nmap) ScanWithProgressBudget(ctx context.Context, job config.Job, report ProgressReporter, check func(discoveryProbes, nmapProbes int64) error) (model.Snapshot, error) {
	return n.scanWithProgress(ctx, job, report, check)
}

func (n *Nmap) scanWithProgress(ctx context.Context, job config.Job, report ProgressReporter, budgetCheck func(discoveryProbes, nmapProbes int64) error) (model.Snapshot, error) {
	job = config.NormalizeJob(job)
	if job.TCP != nil && job.TCP.Engine == config.EngineNaabuNmap {
		return n.scanNaabuPipelineWithBudget(ctx, job, report, budgetCheck)
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
	targets, failures, err := n.resolvePartial(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
	totalProbes, totalInvocations := progressTotals(targets, job)
	if budgetCheck != nil {
		// The caller's budget check used an earlier resolution, and a DNS
		// answer can grow in between. Check the work this scan will run.
		if err := budgetCheck(0, totalProbes); err != nil {
			return model.Snapshot{}, err
		}
	}
	progress := Progress{TotalProbes: totalProbes, TotalInvocations: totalInvocations, Phase: "scanning", StartedAt: started}
	emit(progress)
	snap := model.Snapshot{DNS: map[string][]string{}, TargetFailures: coverageFailures(failures)}
	for _, rt := range targets {
		if rt.Hostname {
			snap.DNS[rt.Name] = append([]string(nil), rt.Addresses...)
		}
	}
	if job.TCP != nil {
		for _, rt := range targets {
			snap.Scopes = append(snap.Scopes, model.Scope{Target: rt.Name, Protocol: "tcp", Ports: job.TCP.Ports, ServiceDetection: job.TCP.ServiceDetection})
		}
	}
	if job.UDP != nil {
		for _, rt := range targets {
			snap.Scopes = append(snap.Scopes, model.Scope{Target: rt.Name, Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
		}
	}
	snap.Scopes = appendTargetFailureScopes(snap.Scopes, snap.TargetFailures, job)
	if job.TCP != nil {
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
			live.ProcessProgressPercent = weightedProcessPercent(baseInvocations+update.Invocation-1, totalInvocations, update.Fraction)
			live.ProcessAlive = update.Alive
			live.LastOutput = update.Output
			live.CompletedProbes = baseProbes + int64(float64(update.BatchProbes)*update.Fraction)
			if update.Alive {
				live.Phase = update.Protocol + " scanning"
			}
			emit(live)
		})
		if err != nil {
			snap.Units = append(snap.Units, result.Units...)
			mergeHostObservations(&snap.Hosts, result.Hosts)
			snap.Normalize()
			return snap, fmt.Errorf("tcp scan: %w", err)
		}
		snap.Units = append(snap.Units, result.Units...)
		mergeHostObservations(&snap.Hosts, result.Hosts)
	}
	if job.UDP != nil {
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
			live.ProcessProgressPercent = weightedProcessPercent(baseInvocations+update.Invocation-1, totalInvocations, update.Fraction)
			live.ProcessAlive = update.Alive
			live.LastOutput = update.Output
			live.CompletedProbes = baseProbes + int64(float64(update.BatchProbes)*update.Fraction)
			if update.Alive {
				live.Phase = update.Protocol + " scanning"
			}
			emit(live)
		})
		if err != nil {
			snap.Units = append(snap.Units, result.Units...)
			mergeHostObservations(&snap.Hosts, result.Hosts)
			snap.Normalize()
			return snap, fmt.Errorf("udp scan: %w", err)
		}
		snap.Units = append(snap.Units, result.Units...)
		mergeHostObservations(&snap.Hosts, result.Hosts)
	}
	snap.Normalize()
	// A successful Nmap invocation can still omit individual addresses when
	// host discovery receives no response. Keep the complete observations and
	// let the application mark the snapshot as incomplete so the engine can
	// compare reachable targets while protecting missing-host removals.
	progress.CompletedInvocations = progress.TotalInvocations
	progress.CompletedProbes = progress.TotalProbes
	progress.Phase = "complete"
	progress.ProcessAlive = false
	progress.CurrentInvocation = progress.TotalInvocations
	progress.ElapsedSeconds = int64(time.Since(started).Seconds())
	emit(progress)
	return snap, nil
}

func incompleteHostAddresses(snapshot model.Snapshot) []string {
	addresses := make([]string, 0)
	for _, host := range snapshot.Hosts {
		switch strings.ToLower(strings.TrimSpace(host.Status)) {
		case "unreachable", "down", "timedout", "timed-out", "timeout":
			if address := normalizeAddress(host.Address); address != "" {
				addresses = append(addresses, address)
			}
		}
	}
	sort.Strings(addresses)
	return dedupeStrings(addresses)
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
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
		var template []string
		if item.protocol == "tcp" {
			template = item.NmapArgs
		}
		protocolProbes, protocolInvocations := protocolProgressTotals(targets, item.Protocol, template)
		probes += protocolProbes
		invocations += protocolInvocations
	}
	return probes, invocations
}

func protocolProgressTotals(targets []resolvedTarget, protocol config.Protocol, template []string) (probes, invocations int64) {
	ports, err := config.ParsePorts(protocol.Ports)
	if err != nil {
		return 0, 0
	}
	factor := int64(1)
	if protocol.ServiceDetection {
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
	batchLimit := nmapInvocationAddressLimit(template, len(ports))
	for _, addresses := range byFamily {
		count := int64(len(addresses))
		invocations += int64((len(addresses) + batchLimit - 1) / batchLimit)
		probes += count * int64(len(ports)) * factor
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
	targets, failures, err := n.resolvePartial(ctx, job)
	if err != nil {
		return nil, err
	}
	if len(failures) > 0 {
		failure := failures[0]
		if failure.err != nil {
			return nil, fmt.Errorf("resolve %s: %w", failure.target, failure.err)
		}
		return nil, ConfigurationError(fmt.Errorf("resolve %s: no A or AAAA records", failure.target))
	}
	return targets, nil
}

// resolvePartial pins every target that can be resolved and separately records
// DNS targets whose coverage is unknown. A lookup failure is non-fatal only
// when at least one configured target still resolves; exclusions, expansion
// limits, and cancellation remain fatal.
func (n *Nmap) resolvePartial(ctx context.Context, job config.Job) ([]resolvedTarget, []targetResolutionFailure, error) {
	return n.resolveTargets(ctx, job, false)
}

// resolveTargets is resolvePartial. With groupNetworks, it pins a CIDR as one
// network target that holds every address of the CIDR, rather than as one
// target per address, which takes a third of the memory.
func (n *Nmap) resolveTargets(ctx context.Context, job config.Job, groupNetworks bool) ([]resolvedTarget, []targetResolutionFailure, error) {
	var out []resolvedTarget
	var failures []targetResolutionFailure
	count := 0
	// The deployment's scanner.max_job_hosts caps every job, whatever its
	// own max_expanded_hosts allows.
	limit, setting := job.MaxExpandedHosts, fmt.Sprintf("max_expanded_hosts=%d", job.MaxExpandedHosts)
	if ceiling := n.jobHostCeiling(); limit > ceiling {
		limit, setting = ceiling, fmt.Sprintf("scanner.max_job_hosts=%d", ceiling)
	}
	for _, input := range job.Targets {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		raw := config.CanonicalTarget(input)
		if ip := net.ParseIP(raw); ip != nil {
			if exclusion := n.excludedNetwork(ip); exclusion != "" {
				return nil, nil, ConfigurationError(fmt.Errorf("target %s is excluded by scanner.target_exclusions (%s)", raw, exclusion))
			}
			count++
			if count > limit {
				return nil, nil, ConfigurationError(fmt.Errorf("expanded targets exceed %s", setting))
			}
			out = append(out, resolvedTarget{Name: ip.String(), ConfiguredTarget: raw, Addresses: []string{ip.String()}})
			continue
		}
		if ip, network, err := net.ParseCIDR(raw); err == nil {
			group := len(out)
			if groupNetworks {
				out = append(out, resolvedTarget{Name: raw, ConfiguredTarget: raw, network: true})
			}
			for current := ip.Mask(network.Mask); network.Contains(current); incrementIP(current) {
				if err := ctx.Err(); err != nil {
					return nil, nil, err
				}
				if exclusion := n.excludedNetwork(current); exclusion != "" {
					return nil, nil, ConfigurationError(fmt.Errorf("target %s includes excluded address %s (%s)", raw, current.String(), exclusion))
				}
				count++
				if count > limit {
					return nil, nil, ConfigurationError(fmt.Errorf("expanded targets exceed %s", setting))
				}
				value := current.String()
				if groupNetworks {
					out[group].Addresses = append(out[group].Addresses, value)
					continue
				}
				out = append(out, resolvedTarget{Name: value, ConfiguredTarget: raw, Addresses: []string{value}})
			}
			continue
		}
		ips, err := n.Resolver.LookupIP(ctx, "ip", raw)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			failures = append(failures, targetResolutionFailure{target: strings.ToLower(raw), reason: "lookup-failed", err: err})
			if len(ips) == 0 {
				continue
			}
		}
		set := map[string]bool{}
		var addresses []string
		for _, ip := range ips {
			if ip == nil || (ip.To4() == nil && ip.To16() == nil) {
				continue
			}
			if exclusion := n.excludedNetwork(ip); exclusion != "" {
				return nil, nil, ConfigurationError(fmt.Errorf("target %s resolved to excluded address %s (%s)", raw, ip.String(), exclusion))
			}
			value := ip.String()
			if !set[value] {
				set[value] = true
				addresses = append(addresses, value)
			}
		}
		if len(addresses) == 0 {
			if err == nil {
				failures = append(failures, targetResolutionFailure{target: strings.ToLower(raw), reason: "no-addresses"})
			}
			continue
		}
		count += len(addresses)
		if count > limit {
			return nil, nil, ConfigurationError(fmt.Errorf("resolved targets exceed %s", setting))
		}
		sort.Strings(addresses)
		out = append(out, resolvedTarget{Name: strings.ToLower(raw), ConfiguredTarget: strings.ToLower(raw), Addresses: addresses, Aggregate: true, Hostname: true})
	}
	if len(out) == 0 {
		if len(failures) > 0 {
			failure := failures[0]
			if failure.err != nil {
				return nil, failures, fmt.Errorf("no effective targets could be resolved: %s: %w", failure.target, failure.err)
			}
			return nil, failures, ConfigurationError(fmt.Errorf("resolve %s: no A or AAAA records", failure.target))
		}
		return nil, nil, ConfigurationError(errors.New("no effective targets"))
	}
	return out, failures, nil
}

func coverageFailures(failures []targetResolutionFailure) []model.TargetCoverageFailure {
	if len(failures) == 0 {
		return nil
	}
	snapshot := model.Snapshot{}
	for _, failure := range failures {
		snapshot.TargetFailures = append(snapshot.TargetFailures, model.TargetCoverageFailure{Target: failure.target, Reason: failure.reason})
	}
	snapshot.Normalize()
	return snapshot.TargetFailures
}

func appendTargetFailureScopes(scopes []model.Scope, failures []model.TargetCoverageFailure, job config.Job) []model.Scope {
	appendScope := func(target string, protocol *config.Protocol, name string) {
		if protocol == nil {
			return
		}
		for _, scope := range scopes {
			if scope.Target == target && scope.Protocol == name {
				return
			}
		}
		scopes = append(scopes, model.Scope{Target: target, Protocol: name, Ports: protocol.Ports, ServiceDetection: protocol.ServiceDetection})
	}
	for _, failure := range failures {
		appendScope(failure.Target, job.TCP, "tcp")
		appendScope(failure.Target, job.UDP, "udp")
	}
	return scopes
}

func applyTargetResolutionFailures(snapshot *model.Snapshot, job config.Job, failures []targetResolutionFailure) {
	if snapshot == nil || len(failures) == 0 {
		return
	}
	evidence := coverageFailures(failures)
	snapshot.TargetFailures = append(snapshot.TargetFailures, evidence...)
	snapshot.Scopes = appendTargetFailureScopes(snapshot.Scopes, evidence, job)
	snapshot.Normalize()
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
	result, err := n.scanProtocolBatchDetailedProgress(ctx, []resolvedTarget{target}, protocol, pc, timing, assumeAlive, nil)
	if err == nil && len(result.Units) == 0 && len(result.Hosts) > 0 {
		// Keep the narrow legacy helper's contract for callers that request a
		// single protocol directly. The production Scan/ScanWorkUnit paths use
		// the detailed result and treat an all-down host as a successful,
		// explicitly incomplete observation so resumable cycles can advance.
		return result.Units, fmt.Errorf("nmap output omitted expected address(s): %s", strings.Join(unreachableAddresses(result.Hosts), ", "))
	}
	return result.Units, err
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
	return n.scanProtocolBatchDetailedProgressWithTemplate(ctx, targets, protocol, pc, timing, assumeAlive, !assumeAlive, pc.NmapArgs, report, statusReports...)
}

func (n *Nmap) scanProtocolBatchDetailedProgressWithTemplate(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive, includeDownHosts bool, template []string, report func(int64, int64), statusReports ...func(invocationProgress)) (protocolScanResult, error) {
	if err := config.ValidateScannerProfile(config.ScannerProfile{Engine: config.EngineNmap, NmapArgs: pc.NmapArgs, EnrichmentArgs: pc.EnrichmentArgs, NSEProfile: pc.NSEProfile, NSEArgs: pc.NSEArgs}); err != nil {
		return protocolScanResult{}, ConfigurationError(fmt.Errorf("scanner profile arguments: %w", err))
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
	ports, err := config.ParsePorts(pc.Ports)
	if err != nil {
		return protocolScanResult{}, ConfigurationError(fmt.Errorf("invalid %s ports: %w", protocol, err))
	}
	batchLimit := nmapInvocationAddressLimit(template, len(ports))
	probesPerHost := int64(len(ports))
	if pc.ServiceDetection {
		probesPerHost *= 2
	}
	for _, family := range []int{4, 6} {
		addresses := byFamily[family]
		for start := 0; start < len(addresses); start += batchLimit {
			end := min(start+batchLimit, len(addresses))
			batch := addresses[start:end]
			args := nmapArgsWithTemplateAndDiscovery(family, protocol, pc, timing, assumeAlive, batch, template, includeDownHosts)
			cmd := exec.CommandContext(ctx, n.Path, args...)
			// Keep profile execution deterministic and prevent host-local Nmap
			// configuration, script directories, or credential-bearing environment
			// variables from changing the fixed scanner contract. Browser/API input
			// never controls this environment; only the validated argv template does.
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "NMAPDIR=/usr/share/nmap", "XDG_CONFIG_HOME=/nonexistent", "LANG=C"}
			batchProbes := int64(len(batch)) * probesPerHost
			localInvocation := int64(start/batchLimit) + 1
			if family == 6 && len(byFamily[4]) > 0 {
				localInvocation += int64((len(byFamily[4]) + batchLimit - 1) / batchLimit)
			}
			if status != nil {
				status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Alive: true})
			}
			var lastOutput string
			lastFraction := 0.0
			stdout, stderr, err := runNmapInvocation(ctx, cmd, n.sandbox, n.workDir, func(line string, fraction float64) {
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
				return protocolScanResult{Units: unitsFromMap(all), Hosts: allHosts}, fmt.Errorf("scan timed out or cancelled: %w", ctx.Err())
			}
			if err != nil {
				if status != nil {
					status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Output: lastOutput, Fraction: lastFraction, Alive: false})
				}
				return protocolScanResult{Units: unitsFromMap(all), Hosts: allHosts}, fmt.Errorf("nmap failed: %w: %s", err, sanitizeStderr(stderr))
			}
			if status != nil {
				status(invocationProgress{Protocol: protocol, Invocation: localInvocation, BatchProbes: batchProbes, Fraction: 1, Output: lastOutput, Alive: false})
			}
			parsed, err := parseXMLWithPortCount(ctx, stdout, protocol, pc, batch, len(ports), nil)
			if err != nil {
				return protocolScanResult{Units: unitsFromMap(all), Hosts: allHosts}, err
			}
			if parsed.Exit != "success" {
				return protocolScanResult{Units: unitsFromMap(all), Hosts: allHosts}, fmt.Errorf("nmap run incomplete: %s", parsed.Exit)
			}
			// A completely omitted invocation is represented below, once per
			// effective address. Do not merge an additional copy here: merging
			// observations is additive for state summaries and would otherwise
			// double unreachable-host evidence.
			for _, address := range batch {
				unit, ok := parsed.Units[address]
				if ok {
					all[address] = unit
				}
				host, hostOK := parsed.Hosts[address]
				if !hostOK {
					// Nmap can omit a host entirely when discovery receives no
					// response. Preserve an explicit state for the host explorer,
					// but do not synthesize a Unit: an absent Unit must never be
					// interpreted as a closed port by the comparison engine.
					host = unreachableHostObservationWithPortCount(address, protocol, pc, "nmap-omitted", len(ports))
				} else if !ok {
					// Down hosts are represented as observations by the XML parser
					// without a compact Unit. Normalize any non-up status to the
					// explicit state used for incomplete scan coverage.
					if !strings.EqualFold(strings.TrimSpace(host.Status), "up") {
						host.Status = "unreachable"
						if strings.TrimSpace(host.StatusReason) == "" {
							host.StatusReason = "nmap-host-down"
						}
					}
				}
				if hostOK {
					recordNmapDiscoveryState(&host, assumeAlive)
				}
				// Fingerprint the fixed executable and argv shape without
				// retaining target addresses or any profile values in logs.
				for index := range host.Protocols {
					host.Protocols[index].CommandFingerprint = commandFingerprint(args)
				}
				mergeHostObservationMap(allHosts, address, host)
			}
			if report != nil {
				report(1, int64(len(batch))*probesPerHost)
			}
		}
	}
	var units []model.Unit
	emittedUnitAddresses := make(map[string]struct{}, len(all))
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
			if _, emitted := emittedUnitAddresses[address]; emitted {
				continue
			}
			unit, ok := all[address]
			if !ok {
				continue
			}
			emittedUnitAddresses[address] = struct{}{}
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

func unreachableAddresses(hosts map[string]model.HostObservation) []string {
	addresses := make([]string, 0, len(hosts))
	for address, host := range hosts {
		if strings.EqualFold(strings.TrimSpace(host.Status), "unreachable") || strings.EqualFold(strings.TrimSpace(host.Status), "down") {
			addresses = append(addresses, address)
		}
	}
	sort.Strings(addresses)
	return addresses
}

func mapsToHosts(values map[string]model.HostObservation) []model.HostObservation {
	hosts := make([]model.HostObservation, 0, len(values))
	for _, host := range values {
		hosts = append(hosts, host)
	}
	return hosts
}

func unitsFromMap(units map[string]model.Unit) []model.Unit {
	out := make([]model.Unit, 0, len(units))
	for _, unit := range units {
		out = append(out, unit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func nmapArgs(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses []string) []string {
	return nmapArgsWithTemplate(family, protocol, pc, timing, assumeAlive, addresses, pc.NmapArgs)
}

func nmapArgsWithTemplate(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses, template []string) []string {
	return nmapArgsWithTemplateAndDiscovery(family, protocol, pc, timing, assumeAlive, addresses, template, !assumeAlive)
}

func nmapArgsWithTemplateAndDiscovery(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses, template []string, includeDownHosts bool) []string {
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
		} else if includeDownHosts {
			// Nmap only includes explicitly down hosts in XML at verbosity 1+.
			// Without this, the parser cannot distinguish discovery-down from an
			// omitted (incomplete) address.
			args = append(args, "-v")
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
	if includeDownHosts && !templateHasNmapVerbosity(template) {
		args = append(args, "-v")
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

func templateHasNmapVerbosity(template []string) bool {
	for _, argument := range template {
		switch argument {
		case "-v", "-vv", "-vvv", "--verbose":
			return true
		}
	}
	return false
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
	return boundScannerText(v, 500)
}

// runNmapInvocation keeps XML available to the parser while consuming Nmap's
// human status channel and XML taskprogress records concurrently. Nmap only
// emits its periodic status stream when stdout is a terminal, even when
// --stats-every is supplied. Run the fixed child under a private pseudo-terminal
// so the daemon receives the same supported progress stream as an interactive
// operator, while XML remains file-backed and bounded. The XML file is created
// in dir, or in the system's temporary directory when dir is empty.
//
// The child leads a process group of its own. Cancellation, an exceeded
// output bound, and the child's own exit stop every process in that group,
// and the invocation then waits at most scannerWaitDelay for the child's
// stderr and terminal to close, and fails when either is still held.
func runNmapInvocation(ctx context.Context, cmd *exec.Cmd, policy *sandbox.Policy, dir string, onOutput func(string, float64), onHeartbeat func()) ([]byte, string, error) {
	xmlPath, releaseXML, err := prepareNmapXMLOutput(cmd, policy, dir)
	if err != nil {
		return nil, "", err
	}
	if xmlPath != "" {
		defer func() {
			releaseXML()
			_ = os.Remove(xmlPath)
		}()
	}
	confineNmap(cmd, policy)
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
	// xmlExceeded records that the XML, in its file or on stdout, exceeded
	// maxNmapOutput, and stops the child.
	var xmlExceeded atomic.Bool
	stopForXML := func() {
		if xmlExceeded.CompareAndSwap(false, true) {
			_ = stopProcessGroup(cmd)
		}
	}
	// While Nmap writes its XML to the file, the terminal stream is only a
	// progress hint, and it grows with the scan's duration: it has no
	// cumulative bound. The writer keeps the start of the stream, for
	// compatibility binaries that print their XML instead of writing the file,
	// drops it once it exceeds maxProgressOutput, and keeps passing complete
	// lines on. Without the file the stream is the XML, bounded like the file.
	// Only human-readable lines reach the progress callback; XML fragments
	// printed by a compatibility binary must never replace the last useful
	// progress detail.
	stdout := &progressOutputWriter{limit: maxProgressOutput, streaming: true, emit: func(line string) {
		if looksLikeNmapXML(line) {
			return
		}
		fraction, _ := parseNmapProgress(line)
		emitOutput(line, fraction)
	}}
	if xmlPath == "" {
		stdout.limit, stdout.streaming, stdout.onExceeded = maxNmapOutput, false, stopForXML
	}
	// Diagnostic output is not expected to grow with a scan's duration, so it
	// keeps its cumulative bound and stops the child once it exceeds it.
	stderr := &progressOutputWriter{limit: maxProgressOutput, onExceeded: func() { _ = stopProcessGroup(cmd) }, emit: func(line string) {
		fraction, _ := parseNmapProgress(line)
		emitOutput(line, fraction)
	}}
	cmd.Stderr = stderr
	// The pseudo-terminal becomes the child's stdin, stdout, and controlling
	// terminal. Stderr intentionally remains our bounded writer so error
	// diagnostics stay separate. When no pseudo-terminal can be opened, such as
	// without /dev/pts or once the system's terminals are used up, the child
	// writes to the stdout writer through a pipe instead; the heartbeat still
	// reports truthful liveness there. Keep status records on one line so the
	// parser receives a useful update even when a terminal implementation would
	// otherwise report a zero-sized window (common in containers).
	master, terminal, terminalErr := openTerminal(&pty.Winsize{Rows: 24, Cols: 256})
	if terminalErr == nil {
		cmd.Stdin, cmd.Stdout = terminal, terminal
	} else {
		cmd.Stdout = stdout
	}
	startInProcessGroup(cmd, terminalErr == nil)
	startErr := cmd.Start()
	if terminal != nil {
		// The child has its own descriptor; the daemon reads the master only.
		_ = terminal.Close()
	}
	if startErr != nil {
		if master != nil {
			_ = master.Close()
		}
		return nil, "", ExecutableStartError(cmd.Path, startErr)
	}

	terminalDone := make(chan struct{})
	if master != nil {
		go func() {
			_, _ = io.Copy(stdout, master)
			close(terminalDone)
		}()
	} else {
		close(terminalDone)
	}

	progressStop := make(chan struct{})
	progressDone := make(chan struct{})
	progressParser := &nmapXMLProgressParser{}
	go func() {
		defer close(progressDone)
		heartbeatTicker := time.NewTicker(time.Second)
		defer heartbeatTicker.Stop()
		progressTicker := time.NewTicker(200 * time.Millisecond)
		defer progressTicker.Stop()
		poll := func() {
			if xmlPath == "" {
				return
			}
			if exceeded, err := nmapXMLOutputExceeded(xmlPath, maxNmapOutput); err == nil && exceeded {
				// Stop the child before it can fill the scanner's temporary
				// storage. The result below reports a stable size-limit error
				// rather than exposing a platform-specific ENOSPC message.
				stopForXML()
				return
			}
			if err := pollNmapXMLProgress(xmlPath, progressParser, emitOutput); errors.Is(err, errNmapProgressOutputExceeded) {
				stopForXML()
			}
		}
		poll()
		for {
			select {
			case <-progressTicker.C:
				poll()
			case <-heartbeatTicker.C:
				emitHeartbeat()
			case <-ctx.Done():
				return
			case <-progressStop:
				return
			}
		}
	}()

	outputDeadline, waitErr := waitProcessGroupUntil(cmd)
	terminalHeld := false
	if master != nil {
		// Once every process holding the terminal has exited, Linux completes the
		// master read with EIO. Drain that final terminal buffer before closing
		// the master so XML fallback output from compatibility binaries cannot be
		// lost. A process that left the child's process group can keep the
		// terminal open, so stop reading at the deadline the child's stderr had.
		drained := time.NewTimer(time.Until(outputDeadline))
		select {
		case <-terminalDone:
		case <-drained.C:
			select {
			case <-terminalDone:
			default:
				terminalHeld = true
			}
		}
		drained.Stop()
		_ = master.Close()
		<-terminalDone
	}
	close(progressStop)
	stderr.Flush()
	// The progress goroutine may have observed the stop signal just before the
	// command exited. Waiting for its completion prevents callbacks after the
	// invocation's terminal update, then one final poll captures records flushed
	// as the child exited.
	<-progressDone
	structured := stdout.Bytes()
	terminalDropped := false
	if xmlPath != "" {
		if exceeded, err := nmapXMLOutputExceeded(xmlPath, maxNmapOutput); err == nil && exceeded {
			xmlExceeded.Store(true)
		}
		if err := pollNmapXMLProgress(xmlPath, progressParser, emitOutput); errors.Is(err, errNmapProgressOutputExceeded) {
			xmlExceeded.Store(true)
		}
		if data, exceeded, readErr := readCappedFile(xmlPath, maxNmapOutput); readErr == nil && len(data) > 0 {
			structured = data
			if exceeded {
				xmlExceeded.Store(true)
			}
		} else {
			// Without an XML file only a compatibility binary's terminal output
			// can carry the result, and none is left once it was dropped.
			terminalDropped = stdout.overflowed()
		}
	}
	diagnostic := stderr.String()
	waitErr = scannerWaitError("nmap", waitErr)
	if stderr.overflowed() {
		return structured, diagnostic, withWaitError(waitErr, fmt.Errorf("nmap diagnostic output exceeded %d bytes", maxProgressOutput))
	}
	if xmlExceeded.Load() {
		return structured, diagnostic, withWaitError(waitErr, fmt.Errorf("nmap XML output exceeded %d bytes", maxNmapOutput))
	}
	if terminalDropped {
		return nil, diagnostic, withWaitError(waitErr, fmt.Errorf("nmap wrote no XML file, and its terminal output exceeded %d bytes", maxProgressOutput))
	}
	if terminalHeld && ctx.Err() == nil && waitErr == nil {
		return structured, diagnostic, errors.New("nmap left a process holding its terminal open after it exited")
	}
	return structured, diagnostic, scannerStorageError(waitErrWithContext(ctx, waitErr), diagnostic)
}

// withWaitError reports err, which explains why the scanner was stopped,
// after the wait error, which then only reports the signal.
func withWaitError(waitErr, err error) error {
	if waitErr != nil {
		return fmt.Errorf("%w; %w", waitErr, err)
	}
	return err
}

// scannerWaitError explains exec.ErrWaitDelay, which a scanner that exited
// normally reports when a process that left its process group still held its
// output scannerWaitDelay later.
func scannerWaitError(scanner string, err error) error {
	if errors.Is(err, exec.ErrWaitDelay) {
		return fmt.Errorf("%s left a process holding its output open after it exited: %w", scanner, err)
	}
	return err
}

// scannerStorageError turns the platform-specific ENOSPC/diagnostic outcome
// into a stable operator-facing error. This is important for a read-only
// container: a full tmpfs should fail one scan clearly rather than look like a
// parser, timeout, or unexplained child-process failure.
func scannerStorageError(err error, diagnostic string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOSPC) || strings.Contains(strings.ToLower(diagnostic), "no space left on device") {
		return fmt.Errorf("scanner temporary storage exhausted: %w", err)
	}
	return err
}

func nmapXMLOutputExceeded(path string, limit int) (bool, error) {
	if limit <= 0 {
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Size() > int64(limit), nil
}

// prepareNmapXMLOutput redirects the internal "-oX -" destination emitted by
// EdgeWatch's validated templates to a private file in dir, or in the
// system's temporary directory when dir is empty. User-defined argument
// arrays cannot provide alternate output destinations, so rewriting this
// exact pair cannot broaden the scanner's command surface. It returns the
// file's path, which the daemon reads, and a release function to call once
// the process has exited. A confined Nmap cannot reach the temporary
// directory, so it writes the file through an inherited write-only
// descriptor.
func prepareNmapXMLOutput(cmd *exec.Cmd, policy *sandbox.Policy, dir string) (string, func(), error) {
	for index := 0; index+1 < len(cmd.Args); index++ {
		if cmd.Args[index] != "-oX" || cmd.Args[index+1] != "-" {
			continue
		}
		file, err := os.CreateTemp(dir, "edgewatch-nmap-*.xml")
		if err != nil {
			return "", nil, fmt.Errorf("create nmap progress file: %w", err)
		}
		path := file.Name()
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return "", nil, fmt.Errorf("prepare nmap progress file: %w", err)
		}
		if !policy.InheritsFiles() {
			cmd.Args[index+1] = path
			return path, func() {}, nil
		}
		output, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			_ = os.Remove(path)
			return "", nil, fmt.Errorf("prepare nmap progress file: %w", err)
		}
		childPath, err := policy.InheritFile(cmd, output, sandbox.Write)
		if err != nil {
			_ = output.Close()
			_ = os.Remove(path)
			return "", nil, fmt.Errorf("prepare nmap progress file: %w", err)
		}
		cmd.Args[index+1] = childPath
		return path, func() { _ = output.Close() }, nil
	}
	return "", func() {}, nil
}

// readCappedFile reads a scanner result without allowing a malformed child to
// bypass the same XML memory bound used for stdout results.
func readCappedFile(path string, limit int) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	buffer := &cappedBuffer{limit: limit}
	chunk := make([]byte, 32*1024)
	for {
		count, readErr := file.Read(chunk)
		if count > 0 {
			_, _ = buffer.Write(chunk[:count])
			if buffer.exceeded {
				return buffer.Bytes(), true, nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, false, readErr
		}
	}
	return buffer.Bytes(), false, nil
}

type nmapTaskProgress struct {
	Task    string  `xml:"task,attr"`
	Percent float64 `xml:"percent,attr"`
}

// nmapXMLProgressParser extracts self-closing taskprogress elements from an
// XML document that is still being written. It deliberately does not attempt
// to unmarshal the incomplete document; the complete document is parsed only
// after the child exits.
type nmapXMLProgressParser struct {
	pending string
	offset  int64
}

func (p *nmapXMLProgressParser) feed(data []byte, emit func(string, float64)) {
	if len(data) == 0 {
		return
	}
	p.pending += string(data)
	for {
		start := strings.Index(p.pending, "<taskprogress")
		if start < 0 {
			// Keep a short suffix in case the next read completes a split tag.
			if len(p.pending) > 64 {
				p.pending = p.pending[len(p.pending)-64:]
			}
			return
		}
		if start > 0 {
			p.pending = p.pending[start:]
		}
		end := strings.Index(p.pending, "/>")
		endLength := 2
		if end < 0 {
			end = strings.IndexByte(p.pending, '>')
			endLength = 1
		}
		if end < 0 {
			if len(p.pending) > 4096 {
				p.pending = p.pending[len(p.pending)-4096:]
			}
			return
		}
		fragment := p.pending[:end+endLength]
		p.pending = p.pending[end+endLength:]
		var progress nmapTaskProgress
		if err := xml.Unmarshal([]byte(fragment), &progress); err != nil {
			continue
		}
		if progress.Percent < 0 {
			progress.Percent = 0
		}
		if progress.Percent > 100 {
			progress.Percent = 100
		}
		if emit != nil {
			task := strings.TrimSpace(progress.Task)
			line := fmt.Sprintf("Nmap %s: %.2f%% complete", task, progress.Percent)
			if task == "" {
				line = fmt.Sprintf("Nmap progress: %.2f%% complete", progress.Percent)
			}
			emit(line, progress.Percent/100)
		}
	}
}

func pollNmapXMLProgress(path string, parser *nmapXMLProgressParser, emit func(string, float64)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < parser.offset {
		// The child may have reopened/truncated its output. Start parsing the
		// new document rather than carrying fragments across scan generations.
		parser.offset = 0
		parser.pending = ""
	}
	if info.Size() > int64(maxNmapOutput) {
		return errNmapProgressOutputExceeded
	}
	remaining := int64(maxNmapOutput) - parser.offset
	if remaining < 0 {
		return errNmapProgressOutputExceeded
	}
	if _, err := file.Seek(parser.offset, io.SeekStart); err != nil {
		return err
	}
	// The file can grow between Stat and Read. Read at most one byte beyond
	// the remaining cap so a concurrent writer is detected without allocating
	// an unbounded tail in the progress goroutine.
	data, err := io.ReadAll(io.LimitReader(file, remaining+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > remaining {
		return errNmapProgressOutputExceeded
	}
	parser.offset += int64(len(data))
	parser.feed(data, emit)
	return nil
}

// progressOutputWriter lets os/exec (or the pty reader) own the stream-copy
// lifecycle while still exposing complete diagnostic lines to the progress
// callback. It accepts both newline-delimited pipe output and carriage-return
// terminal updates, which Nmap uses when refreshing an interactive status line.
// It retains at most limit bytes of the stream. Once the stream exceeds limit,
// the writer stops retaining and passing on anything, unless streaming is
// set: then it drops what it retained and keeps passing complete lines on.
type progressOutputWriter struct {
	mu         sync.Mutex
	all        strings.Builder
	pending    strings.Builder
	limit      int
	streaming  bool
	exceeded   bool
	onExceeded func()
	exceedOnce sync.Once
	emit       func(string)
}

// maxProgressLine bounds the unterminated line a progressOutputWriter keeps
// while it waits for the line's end; a longer line is passed on as it is.
const maxProgressLine = 64 << 10

func (w *progressOutputWriter) Write(data []byte) (int, error) {
	trigger := false
	w.mu.Lock()
	accepted := data
	if w.limit > 0 && (!w.streaming || !w.exceeded) {
		remaining := w.limit - w.all.Len()
		if remaining <= 0 || len(accepted) > remaining {
			if !w.exceeded {
				trigger = true
			}
			w.exceeded = true
			if w.streaming {
				w.all.Reset()
			} else {
				accepted = accepted[:max(remaining, 0)]
			}
		}
	}
	if len(accepted) > 0 {
		if !w.exceeded || !w.streaming {
			_, _ = w.all.Write(accepted)
		}
		_, _ = w.pending.Write(accepted)
	}
	lines := w.takeLinesLocked()
	w.mu.Unlock()
	if trigger && w.onExceeded != nil {
		w.exceedOnce.Do(w.onExceeded)
	}
	for _, line := range lines {
		if w.emit != nil {
			w.emit(line)
		}
	}
	return len(data), nil
}

// overflowed reports whether the stream exceeded the writer's limit.
func (w *progressOutputWriter) overflowed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exceeded
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

func (w *progressOutputWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return []byte(w.all.String())
}

// takeLinesLocked returns complete lines and leaves an unterminated suffix in
// pending. CRLF is treated as one delimiter; a bare CR is also a delimiter so
// terminal refreshes are surfaced promptly instead of waiting for a newline.
func (w *progressOutputWriter) takeLinesLocked() []string {
	value := w.pending.String()
	w.pending.Reset()
	lines := make([]string, 0, 2)
	for len(value) > 0 {
		index := strings.IndexAny(value, "\r\n")
		if index < 0 {
			w.pending.WriteString(value)
			break
		}
		lines = append(lines, value[:index])
		delimiter := value[index]
		value = value[index+1:]
		if delimiter == '\r' && strings.HasPrefix(value, "\n") {
			value = value[1:]
		}
	}
	if w.pending.Len() > maxProgressLine {
		lines = append(lines, w.pending.String())
		w.pending.Reset()
	}
	return lines
}

func waitErrWithContext(ctx context.Context, waitErr error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return waitErr
}

func trimProgressOutput(line string) string {
	return boundScannerText(line, 240)
}

func looksLikeNmapXML(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	// Compatibility/test binaries sometimes ignore the rewritten -oX path and
	// print XML on stdout. Keep that structured payload available for parsing,
	// but do not present it as human progress detail.
	return strings.HasPrefix(line, "<?xml") || strings.HasPrefix(line, "<!DOCTYPE") || strings.HasPrefix(line, "<nmaprun") || strings.HasPrefix(line, "<host") || strings.Contains(line, "<nmaprun")
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

type nmapHost struct {
	TimedOut string `xml:"timedout,attr"`
	Status   struct {
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
	HostScripts []nmapScript `xml:"hostscript>script"`
	Times       struct {
		SRTT string `xml:"srtt,attr"`
	} `xml:"times"`
	Ports      []nmapPort       `xml:"ports>port"`
	ExtraPorts []nmapExtraPorts `xml:"ports>extraports"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
		TTL    int    `xml:"reason_ttl,attr"`
	} `xml:"state"`
	Service nmapService  `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapService struct {
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
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// nmapExtraPorts is a state Nmap folded instead of listing each port. Nmap
// 7.80 and later attach the folded ports to each reason.
type nmapExtraPorts struct {
	State   string            `xml:"state,attr"`
	Count   int               `xml:"count,attr"`
	Reasons []nmapExtraReason `xml:"extrareasons"`
}

type nmapExtraReason struct {
	Reason   string `xml:"reason,attr"`
	Count    int    `xml:"count,attr"`
	Protocol string `xml:"proto,attr"`
	Ports    string `xml:"ports,attr"`
}

type foldedPort struct {
	port   int
	reason string
}

// nmapPortBitset tracks the complete TCP/UDP port domain without allocating a
// hash table for every selected host or folded state.
type nmapPortBitset [65536 / 64]uint64

func (set *nmapPortBitset) contains(port int) bool {
	if port < 0 || port > 65535 {
		return false
	}
	return set[port/64]&(uint64(1)<<uint(port%64)) != 0
}

func (set *nmapPortBitset) add(port int) {
	if port < 0 || port > 65535 {
		return
	}
	set[port/64] |= uint64(1) << uint(port%64)
}

// foldedPositivePorts expands the port lists of a folded open|filtered (or,
// defensively, open) state. ok is false unless the lists name exactly the
// folded ports for this protocol, with no duplicates. Expansion stops as soon
// as a list names more ports than its count, so a malformed list cannot
// expand beyond 65535 ports.
func foldedPositivePorts(extra nmapExtraPorts, protocol string) (ports []foldedPort, ok bool) {
	ports, ok, _ = foldedPositivePortsContext(context.Background(), extra, protocol)
	return ports, ok
}

func foldedPositivePortsContext(ctx context.Context, extra nmapExtraPorts, protocol string) (ports []foldedPort, ok bool, err error) {
	if ctx == nil {
		return nil, false, errors.New("folded port scan context is nil")
	}
	if extra.Count < 1 || extra.Count > 65535 {
		return nil, false, nil
	}
	ports = make([]foldedPort, 0, extra.Count)
	ok, err = walkFoldedPositivePortsContext(ctx, extra, protocol, func(port foldedPort) error {
		ports = append(ports, port)
		return nil
	})
	if err != nil || !ok {
		return nil, ok, err
	}
	return ports, true, nil
}

// walkFoldedPositivePortsContext validates the complete folded port list with
// a fixed-size bitset before making a second cancellation-aware pass to emit
// records. A malformed list therefore emits nothing, and a valid 65,535-port
// range needs no per-port hash entry or temporary output slice.
func walkFoldedPositivePortsContext(ctx context.Context, extra nmapExtraPorts, protocol string, emit func(foldedPort) error) (ok bool, err error) {
	if ctx == nil {
		return false, errors.New("folded port scan context is nil")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if extra.Count < 1 || extra.Count > 65535 {
		return false, nil
	}
	var seen nmapPortBitset
	visited := 0
	for _, reason := range extra.Reasons {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if reason.Count < 1 || visited+reason.Count > extra.Count || (reason.Protocol != "" && !strings.EqualFold(reason.Protocol, protocol)) {
			return false, nil
		}
		listed := 0
		for item := range strings.SplitSeq(reason.Ports, ",") {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			first, last, isRange := strings.Cut(strings.TrimSpace(item), "-")
			start, err := strconv.Atoi(first)
			end := start
			if err == nil && isRange {
				end, err = strconv.Atoi(last)
			}
			if err != nil || start < 1 || end > 65535 || end < start || listed+end-start+1 > reason.Count {
				return false, nil
			}
			for port := start; port <= end; port++ {
				if visited&255 == 0 {
					if err := ctx.Err(); err != nil {
						return false, err
					}
				}
				if seen.contains(port) {
					return false, nil
				}
				seen.add(port)
				visited++
			}
			listed += end - start + 1
		}
		if listed != reason.Count {
			return false, nil
		}
	}
	if visited != extra.Count {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	for _, reason := range extra.Reasons {
		label := boundScannerMetadata(reason.Reason)
		for item := range strings.SplitSeq(reason.Ports, ",") {
			first, last, isRange := strings.Cut(strings.TrimSpace(item), "-")
			start, _ := strconv.Atoi(first)
			end := start
			if isRange {
				end, _ = strconv.Atoi(last)
			}
			for port := start; port <= end; port++ {
				if visited&255 == 0 {
					if err := ctx.Err(); err != nil {
						return false, err
					}
				}
				if emit != nil {
					if err := emit(foldedPort{port: port, reason: label}); err != nil {
						return false, err
					}
				}
				visited++
			}
		}
	}
	return true, nil
}

type nmapXMLHostSpan struct {
	start int
	end   int
}

type nmapXMLParseStats struct {
	Tokens                     int
	HostElements               int
	SelectedHostSpans          int
	SelectedScriptElements     int
	MaterializedHosts          int
	PortElements               int
	MaterializedPortElements   int
	MaterializedPositivePorts  int
	MaterializedScriptElements int
	RetainedScriptSummaries    int
}

type nmapXMLHostCounts struct {
	start              int
	address            string
	selected           bool
	materialize        bool
	ports              int
	uniquePorts        int
	portIDs            nmapPortBitset
	reportedExtraPorts int
	addresses          int
	hostnames          int
	scripts            int
	cpes               int
	extraPorts         int
	hostState          string
	hostReason         string
	states             map[string]struct{}
	reasons            map[string]map[string]struct{}
}

type nmapXMLFrame struct {
	name             string
	extraState       string
	extraReasonCount int
	serviceCPEs      int
}

type nmapXMLContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r nmapXMLContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

var errNmapXMLAttributeLimit = fmt.Errorf("nmap XML element exceeded %d attribute safety limit", maxNmapXMLAttributes)

type nmapXMLLexState uint8

const (
	nmapXMLLexText nmapXMLLexState = iota
	nmapXMLLexAfterLessThan
	nmapXMLLexEndTag
	nmapXMLLexBang
	nmapXMLLexComment
	nmapXMLLexCDATA
	nmapXMLLexProcessingInstruction
	nmapXMLLexDeclaration
	nmapXMLLexStartTagName
	nmapXMLLexStartTagAttributes
	nmapXMLLexAttributeName
	nmapXMLLexAttributeBeforeEquals
	nmapXMLLexAttributeBeforeValue
	nmapXMLLexAttributeValue
	nmapXMLLexUnquotedAttributeValue
	nmapXMLLexStartTagSlash
)

// nmapXMLAttributeLimitReader counts attribute starts in the byte stream
// before encoding/xml can materialize a StartElement.Attr slice. It only
// treats XML's ASCII markup delimiters as syntax, so UTF-8 element and
// attribute names pass through unchanged. Attribute values are not length
// limited here; the scanner output cap remains their bound.
type nmapXMLAttributeLimitReader struct {
	ctx    context.Context
	reader io.Reader

	state              nmapXMLLexState
	attributeCount     int
	quote              byte
	bangProbe          [7]byte
	bangProbeLength    int
	commentDashRun     int
	cdataCloseRun      int
	declarationQuote   byte
	declarationDepth   int
	declarationPrefix  int
	declarationComment bool
	declarationDashes  int
	declarationPI      bool
	declarationPIQMark bool
	pendingErr         error
}

func newNmapXMLAttributeLimitReader(ctx context.Context, reader io.Reader) *nmapXMLAttributeLimitReader {
	return &nmapXMLAttributeLimitReader{ctx: ctx, reader: reader}
}

func (r *nmapXMLAttributeLimitReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if r.ctx == nil {
		return 0, errors.New("nmap XML attribute reader context is nil")
	}
	if r.pendingErr != nil {
		return 0, r.pendingErr
	}
	n, readErr := r.reader.Read(buffer)
	for index := 0; index < n; index++ {
		if index&255 == 0 {
			if err := r.ctx.Err(); err != nil {
				r.pendingErr = err
				return index, err
			}
		}
		if err := r.consume(buffer[index]); err != nil {
			r.pendingErr = err
			return index, err
		}
	}
	return n, readErr
}

func (r *nmapXMLAttributeLimitReader) consume(value byte) error {
	switch r.state {
	case nmapXMLLexText:
		if value == '<' {
			r.state = nmapXMLLexAfterLessThan
		}
	case nmapXMLLexAfterLessThan:
		switch value {
		case '/':
			r.state = nmapXMLLexEndTag
		case '?':
			r.state = nmapXMLLexProcessingInstruction
			r.commentDashRun = 0
		case '!':
			r.state = nmapXMLLexBang
			r.bangProbeLength = 0
		default:
			r.state = nmapXMLLexStartTagName
			r.attributeCount = 0
			return r.consumeStartTagName(value)
		}
	case nmapXMLLexEndTag:
		if value == '>' {
			r.state = nmapXMLLexText
		}
	case nmapXMLLexBang:
		return r.consumeBang(value)
	case nmapXMLLexComment:
		if value == '>' && r.commentDashRun >= 2 {
			r.state = nmapXMLLexText
			r.commentDashRun = 0
		} else if value == '-' {
			r.commentDashRun = min(r.commentDashRun+1, 2)
		} else {
			r.commentDashRun = 0
		}
	case nmapXMLLexCDATA:
		if value == '>' && r.cdataCloseRun >= 2 {
			r.state = nmapXMLLexText
			r.cdataCloseRun = 0
		} else if value == ']' {
			r.cdataCloseRun = min(r.cdataCloseRun+1, 2)
		} else {
			r.cdataCloseRun = 0
		}
	case nmapXMLLexProcessingInstruction:
		if value == '>' && r.commentDashRun == 1 {
			r.state = nmapXMLLexText
			r.commentDashRun = 0
		} else if value == '?' {
			r.commentDashRun = 1
		} else {
			r.commentDashRun = 0
		}
	case nmapXMLLexDeclaration:
		r.consumeDeclaration(value)
	case nmapXMLLexStartTagName:
		return r.consumeStartTagName(value)
	case nmapXMLLexStartTagAttributes:
		switch {
		case nmapXMLSpace(value):
			return nil
		case value == '>':
			r.state = nmapXMLLexText
		case value == '/':
			r.state = nmapXMLLexStartTagSlash
		default:
			return r.startAttribute()
		}
	case nmapXMLLexAttributeName:
		switch {
		case nmapXMLSpace(value):
			r.state = nmapXMLLexAttributeBeforeEquals
		case value == '=':
			r.state = nmapXMLLexAttributeBeforeValue
		case value == '>':
			r.state = nmapXMLLexText
		case value == '/':
			r.state = nmapXMLLexStartTagSlash
		}
	case nmapXMLLexAttributeBeforeEquals:
		switch {
		case nmapXMLSpace(value):
			return nil
		case value == '=':
			r.state = nmapXMLLexAttributeBeforeValue
		case value == '>':
			r.state = nmapXMLLexText
		case value == '/':
			r.state = nmapXMLLexStartTagSlash
		default:
			// Malformed markup is rejected by encoding/xml. Treat this
			// byte as another attribute start in the meantime so malformed
			// syntax cannot bypass the cardinality guard.
			return r.startAttribute()
		}
	case nmapXMLLexAttributeBeforeValue:
		if nmapXMLSpace(value) {
			return nil
		}
		if value == '\'' || value == '"' {
			r.quote = value
			r.state = nmapXMLLexAttributeValue
		} else {
			r.state = nmapXMLLexUnquotedAttributeValue
		}
	case nmapXMLLexAttributeValue:
		if value == r.quote {
			r.quote = 0
			r.state = nmapXMLLexStartTagAttributes
		}
	case nmapXMLLexUnquotedAttributeValue:
		switch {
		case nmapXMLSpace(value):
			r.state = nmapXMLLexStartTagAttributes
		case value == '>':
			r.state = nmapXMLLexText
		}
	case nmapXMLLexStartTagSlash:
		if value == '>' {
			r.state = nmapXMLLexText
		} else {
			r.state = nmapXMLLexStartTagAttributes
			return r.consume(value)
		}
	}
	return nil
}

func (r *nmapXMLAttributeLimitReader) consumeStartTagName(value byte) error {
	switch {
	case nmapXMLSpace(value):
		r.state = nmapXMLLexStartTagAttributes
	case value == '>':
		r.state = nmapXMLLexText
	case value == '/':
		r.state = nmapXMLLexStartTagSlash
	}
	return nil
}

func (r *nmapXMLAttributeLimitReader) startAttribute() error {
	r.attributeCount++
	if r.attributeCount > maxNmapXMLAttributes {
		return errNmapXMLAttributeLimit
	}
	r.state = nmapXMLLexAttributeName
	return nil
}

func (r *nmapXMLAttributeLimitReader) consumeBang(value byte) error {
	r.bangProbe[r.bangProbeLength] = value
	r.bangProbeLength++
	probe := r.bangProbe[:r.bangProbeLength]
	if nmapXMLPrefixOf("--", probe) {
		if len(probe) == len("--") {
			r.state = nmapXMLLexComment
			r.commentDashRun = 0
			r.bangProbeLength = 0
		}
		return nil
	}
	if nmapXMLPrefixOf("[CDATA[", probe) {
		if len(probe) == len("[CDATA[") {
			r.state = nmapXMLLexCDATA
			r.cdataCloseRun = 0
			r.bangProbeLength = 0
		}
		return nil
	}
	r.state = nmapXMLLexDeclaration
	for _, prefixByte := range probe {
		r.consumeDeclaration(prefixByte)
	}
	r.bangProbeLength = 0
	return nil
}

func (r *nmapXMLAttributeLimitReader) consumeDeclaration(value byte) {
	if r.declarationPI {
		if value == '>' && r.declarationPIQMark {
			r.declarationPI = false
			r.declarationPIQMark = false
		} else {
			r.declarationPIQMark = value == '?'
		}
		return
	}
	if r.declarationComment {
		if value == '>' && r.declarationDashes >= 2 {
			r.declarationComment = false
			r.declarationDashes = 0
		} else if value == '-' {
			r.declarationDashes = min(r.declarationDashes+1, 2)
		} else {
			r.declarationDashes = 0
		}
		return
	}
	if r.declarationQuote != 0 {
		if value == r.declarationQuote {
			r.declarationQuote = 0
		}
		return
	}
	if r.declarationPrefix != 0 {
		switch r.declarationPrefix {
		case 1:
			switch value {
			case '!':
				r.declarationPrefix = 2
				return
			case '?':
				r.declarationPrefix = 0
				r.declarationPI = true
				r.declarationPIQMark = false
				return
			default:
				r.declarationPrefix = 0
			}
		case 2:
			if value == '-' {
				r.declarationPrefix = 3
				return
			}
		case 3:
			if value == '-' {
				r.declarationPrefix = 0
				r.declarationComment = true
				r.declarationDashes = 0
				return
			}
		}
		if value == '<' {
			r.declarationPrefix = 1
			return
		}
		r.declarationPrefix = 0
	}
	if value == '<' {
		r.declarationPrefix = 1
		return
	}
	if value == '\'' || value == '"' {
		r.declarationQuote = value
		return
	}
	switch value {
	case '[':
		r.declarationDepth++
	case ']':
		if r.declarationDepth > 0 {
			r.declarationDepth--
		}
	case '>':
		if r.declarationDepth == 0 {
			r.state = nmapXMLLexText
			r.declarationPrefix = 0
		}
	}
}

func nmapXMLPrefixOf(prefix string, value []byte) bool {
	if len(value) > len(prefix) {
		return false
	}
	for index, current := range value {
		if prefix[index] != current {
			return false
		}
	}
	return true
}

func nmapXMLSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

func nmapPortScopeLimit(scannedPorts int) int {
	if scannedPorts < 1 || scannedPorts > 65535 {
		return 65535
	}
	return scannedPorts
}

func nmapPortRecordLimit(scannedPorts int) int {
	scannedPorts = nmapPortScopeLimit(scannedPorts)
	// XML may repeat a record without expanding the port scope. Allow a small
	// fixed tolerance for such records, but never use it for distinct or folded
	// ports represented in the scan.
	return scannedPorts + maxNmapPortDuplicateSlack
}

func nmapSelectedHostLimit(targetCount int) int {
	if targetCount < 0 {
		targetCount = 0
	}
	return min(nmapBatchSize, targetCount)
}

func nmapCPERecordLimit(scannedPorts int) int {
	scannedPorts = nmapPortScopeLimit(scannedPorts)
	// Keep the existing per-service CPE cap plus its established fixture
	// allowance while allowing a full configured scan's worth of services.
	// The XML token ceiling is the tighter bound for large scans.
	return min(nmapPortRecordLimit(scannedPorts)*maxNmapCPEsPerService, maxNmapXMLTokens/2)
}

func addNmapXMLState(counts *nmapXMLHostCounts, state string) error {
	if !counts.selected {
		return nil
	}
	state = boundScannerMetadata(state)
	if state == "" {
		return nil
	}
	if counts.states == nil {
		counts.states = make(map[string]struct{})
	}
	if _, exists := counts.states[state]; exists {
		return nil
	}
	if len(counts.states) >= maxNmapStateSummaries {
		return fmt.Errorf("nmap XML host exceeded %d state-summary safety limit", maxNmapStateSummaries)
	}
	counts.states[state] = struct{}{}
	return nil
}

func nmapXMLAttribute(start xml.StartElement, name string) (string, bool) {
	for _, attribute := range start.Attr {
		if attribute.Name.Local == name {
			return attribute.Value, true
		}
	}
	return "", false
}

func nmapXMLIntAttribute(start xml.StartElement, name string) (int, bool, error) {
	value, exists := nmapXMLAttribute(start, name)
	if !exists {
		return 0, false, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, true, fmt.Errorf("invalid nmap XML %s attribute: %w", name, err)
	}
	return parsed, true, nil
}

func addNmapXMLReason(counts *nmapXMLHostCounts, state, reason string) error {
	if !counts.selected {
		return nil
	}
	state = boundScannerMetadata(state)
	reason = boundScannerMetadata(reason)
	if state == "" || reason == "" {
		return nil
	}
	if counts.reasons == nil {
		counts.reasons = make(map[string]map[string]struct{})
	}
	reasons := counts.reasons[state]
	if reasons == nil {
		reasons = make(map[string]struct{})
		counts.reasons[state] = reasons
	}
	if _, exists := reasons[reason]; exists {
		return nil
	}
	if len(reasons) >= maxScannerStateReasons+maxNmapMetadataRecordSlack {
		return fmt.Errorf("nmap XML exceeded %d distinct reasons for state %q", maxScannerStateReasons+maxNmapMetadataRecordSlack, boundScannerMetadata(state))
	}
	reasons[reason] = struct{}{}
	return nil
}

func validateNmapSelectedHostMetadataCounts(counts *nmapXMLHostCounts) error {
	if counts.addresses > maxNmapAddressesPerHost {
		return fmt.Errorf("nmap XML host exceeded %d address safety limit", maxNmapAddressesPerHost)
	}
	if counts.hostnames > maxNmapHostnamesPerHost {
		return fmt.Errorf("nmap XML host exceeded %d hostname safety limit", maxNmapHostnamesPerHost)
	}
	return nil
}

// indexNmapXML validates the complete document and records byte spans only for
// hosts the current invocation asked Nmap to scan. Foreign host subtrees are
// still tokenized, counted, bounded, and cancellation-checked, but never
// decoded into host/port objects. Selected host spans are streamed into a
// bounded accumulator one at a time only after the whole result passes these
// bounds.
func indexNmapXML(ctx context.Context, data []byte, protocol string, scannedPorts int, targets []string, stats *nmapXMLParseStats) (string, []nmapXMLHostSpan, error) {
	if ctx == nil {
		return "", nil, errors.New("parse nmap XML context is nil")
	}
	if stats != nil {
		*stats = nmapXMLParseStats{}
	}
	if len(data) > maxNmapOutput {
		return "", nil, fmt.Errorf("nmap XML exceeded %d byte output limit", maxNmapOutput)
	}
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("parse nmap XML cancelled: %w", err)
	}

	if len(targets) > nmapBatchSize {
		return "", nil, fmt.Errorf("nmap XML target batch exceeds the %d-address scanner limit", nmapBatchSize)
	}
	targetSet := make(map[string]struct{}, min(len(targets), nmapBatchSize))
	for _, target := range targets {
		targetSet[normalizeAddress(target)] = struct{}{}
	}
	includeAllHosts := targets == nil
	selectedLimit := maxNmapXMLMaterializedHosts
	if !includeAllHosts {
		selectedLimit = nmapSelectedHostLimit(len(targetSet))
	}
	portRecordLimit := nmapPortRecordLimit(scannedPorts)
	portScopeLimit := nmapPortScopeLimit(scannedPorts)
	stack := make([]nmapXMLFrame, 0, 32)
	var rootName string
	var rootSeen bool
	var runExit string
	var hostCounts *nmapXMLHostCounts
	var spans []nmapXMLHostSpan
	totalHosts := 0
	totalSelectedHosts := 0
	selectedHostAddresses := make(map[string]struct{}, selectedLimit)
	totalPortElements := 0
	totalTokens := 0
	attributeGuard := newNmapXMLAttributeLimitReader(ctx, bytes.NewReader(data))
	decoder := xml.NewDecoder(nmapXMLContextReader{ctx: ctx, reader: attributeGuard})
	decoder.Strict = true
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, fmt.Errorf("parse nmap XML cancelled: %w", err)
		}
		before := decoder.InputOffset()
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return "", nil, fmt.Errorf("parse nmap XML cancelled: %w", ctx.Err())
			}
			if errors.Is(err, errNmapXMLAttributeLimit) {
				return "", nil, errNmapXMLAttributeLimit
			}
			return "", nil, fmt.Errorf("parse nmap XML: %w", err)
		}
		totalTokens++
		if stats != nil {
			stats.Tokens = totalTokens
		}
		if totalTokens > maxNmapXMLTokens {
			return "", nil, fmt.Errorf("nmap XML exceeded %d token safety limit", maxNmapXMLTokens)
		}

		switch element := token.(type) {
		case xml.StartElement:
			if rootSeen && len(stack) == 0 {
				return "", nil, errors.New("parse nmap XML: multiple document elements")
			}
			if len(element.Attr) > maxNmapXMLAttributes {
				return "", nil, fmt.Errorf("nmap XML element exceeded %d attribute safety limit", maxNmapXMLAttributes)
			}
			if len(stack)+1 > maxNmapXMLDepth {
				return "", nil, fmt.Errorf("nmap XML exceeded %d element depth safety limit", maxNmapXMLDepth)
			}
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].name
			}
			if !rootSeen {
				rootSeen = true
				rootName = element.Name.Local
			}
			frame := nmapXMLFrame{name: element.Name.Local}
			if len(stack) > 0 {
				frame.extraState = stack[len(stack)-1].extraState
			}
			if element.Name.Local == "extraports" {
				frame.extraState, _ = nmapXMLAttribute(element, "state")
				frame.extraState = boundScannerMetadata(frame.extraState)
			}

			if element.Name.Local == "host" && rootName == "nmaprun" && parent == "nmaprun" {
				if hostCounts != nil {
					return "", nil, errors.New("nested nmap host element")
				}
				if includeAllHosts && totalHosts >= maxNmapXMLMaterializedHosts {
					return "", nil, fmt.Errorf("nmap XML exceeded %d materialized host safety limit", maxNmapXMLMaterializedHosts)
				}
				totalHosts++
				if stats != nil {
					stats.HostElements = totalHosts
				}
				if totalHosts > maxNmapXMLHosts {
					return "", nil, fmt.Errorf("nmap XML exceeded %d host safety limit", maxNmapXMLHosts)
				}
				hostCounts = &nmapXMLHostCounts{start: int(before), selected: includeAllHosts}
			} else if hostCounts != nil {
				switch element.Name.Local {
				case "address":
					hostCounts.addresses++
					addressType, _ := nmapXMLAttribute(element, "addrtype")
					address, _ := nmapXMLAttribute(element, "addr")
					if addressType == "ipv4" || addressType == "ipv6" {
						if ip := net.ParseIP(strings.TrimSpace(address)); ip != nil {
							canonical := ip.String()
							if hostCounts.address == "" {
								hostCounts.address = canonical
								_, selected := targetSet[canonical]
								if includeAllHosts || selected {
									if !hostCounts.selected {
										hostCounts.selected = true
										if stats != nil {
											stats.SelectedScriptElements += hostCounts.scripts
										}
										if err := validateNmapSelectedHostMetadataCounts(hostCounts); err != nil {
											return "", nil, err
										}
										if err := addNmapXMLState(hostCounts, hostCounts.hostState); err != nil {
											return "", nil, err
										}
										if err := addNmapXMLReason(hostCounts, hostCounts.hostState, hostCounts.hostReason); err != nil {
											return "", nil, err
										}
									}
									if _, duplicate := selectedHostAddresses[canonical]; !duplicate {
										if totalSelectedHosts >= selectedLimit {
											if includeAllHosts {
												return "", nil, fmt.Errorf("nmap XML exceeded %d materialized host safety limit", selectedLimit)
											}
											return "", nil, fmt.Errorf("nmap XML exceeded %d selected host safety limit", selectedLimit)
										}
										nextSelectedHosts := int64(totalSelectedHosts + 1)
										if nextSelectedHosts*int64(portScopeLimit) > maxNmapXMLMaterializedPortSlots {
											return "", nil, fmt.Errorf("nmap XML selected host-port scope exceeded %d materialized slot safety limit", maxNmapXMLMaterializedPortSlots)
										}
										selectedHostAddresses[canonical] = struct{}{}
										totalSelectedHosts++
										hostCounts.materialize = true
									}
								}
							}
						}
					}
					if hostCounts.selected {
						if err := validateNmapSelectedHostMetadataCounts(hostCounts); err != nil {
							return "", nil, err
						}
					}
				case "hostname":
					hostCounts.hostnames++
					if hostCounts.selected {
						if err := validateNmapSelectedHostMetadataCounts(hostCounts); err != nil {
							return "", nil, err
						}
					}
				case "script":
					hostCounts.scripts++
					if hostCounts.selected && stats != nil {
						stats.SelectedScriptElements++
					}
				case "cpe":
					if parent == "service" && hostCounts.selected {
						hostCounts.cpes++
						serviceIndex := len(stack) - 1
						stack[serviceIndex].serviceCPEs++
						if stack[serviceIndex].serviceCPEs > maxNmapCPEsPerService {
							return "", nil, fmt.Errorf("nmap XML service exceeded %d CPE safety limit", maxNmapCPEsPerService)
						}
						if hostCounts.cpes > nmapCPERecordLimit(scannedPorts) {
							return "", nil, fmt.Errorf("nmap XML host exceeded %d CPE safety limit for %d scanned ports", nmapCPERecordLimit(scannedPorts), scannedPorts)
						}
					}
				case "port":
					if hostCounts.address == "" {
						return "", nil, errors.New("nmap XML port records appeared before the host address")
					}
					totalPortElements++
					if stats != nil {
						stats.PortElements = totalPortElements
					}
					if hostCounts.selected {
						portID, exists, intErr := nmapXMLIntAttribute(element, "portid")
						if intErr != nil {
							return "", nil, intErr
						}
						if !exists {
							return "", nil, errors.New("nmap XML port is missing its port id")
						}
						if portID < 1 || portID > 65535 {
							return "", nil, fmt.Errorf("nmap XML contains invalid port id %d", portID)
						}
						hostCounts.ports++
						if hostCounts.ports > portRecordLimit {
							return "", nil, fmt.Errorf("nmap XML %s host exceeded %d port-record safety limit for %d scanned ports", protocol, portRecordLimit, scannedPorts)
						}
						portProtocol, _ := nmapXMLAttribute(element, "protocol")
						if portProtocol == protocol {
							if !hostCounts.portIDs.contains(portID) {
								hostCounts.portIDs.add(portID)
								hostCounts.uniquePorts++
							}
						}
						if hostCounts.uniquePorts+hostCounts.reportedExtraPorts > portScopeLimit {
							return "", nil, fmt.Errorf("nmap XML host exceeded the %d-port scan scope", portScopeLimit)
						}
					}
				case "extraports":
					if hostCounts.address == "" {
						return "", nil, errors.New("nmap XML folded port records appeared before the host address")
					}
					if !hostCounts.selected {
						break
					}
					count, exists, intErr := nmapXMLIntAttribute(element, "count")
					if intErr != nil {
						return "", nil, intErr
					}
					if !exists || count < 0 {
						return "", nil, errors.New("nmap XML contains a missing or negative extraports count")
					}
					hostCounts.extraPorts++
					if hostCounts.extraPorts > maxNmapExtraPortsPerHost {
						return "", nil, fmt.Errorf("nmap XML host exceeded %d folded-state safety limit", maxNmapExtraPortsPerHost)
					}
					if err := addNmapXMLState(hostCounts, frame.extraState); err != nil {
						return "", nil, err
					}
					if count > portScopeLimit-hostCounts.reportedExtraPorts {
						return "", nil, fmt.Errorf("nmap XML host exceeded the %d-port scan scope", portScopeLimit)
					}
					hostCounts.reportedExtraPorts += count
					if hostCounts.selected && hostCounts.uniquePorts+hostCounts.reportedExtraPorts > portScopeLimit {
						return "", nil, fmt.Errorf("nmap XML host exceeded the %d-port scan scope", portScopeLimit)
					}
				case "extrareasons":
					if !hostCounts.selected {
						break
					}
					count, _, intErr := nmapXMLIntAttribute(element, "count")
					if intErr != nil {
						return "", nil, intErr
					}
					if count < 0 {
						return "", nil, errors.New("nmap XML contains a negative extrareasons count")
					}
					if parent == "extraports" {
						parentFrame := &stack[len(stack)-1]
						parentFrame.extraReasonCount++
						if parentFrame.extraReasonCount > maxNmapExtraReasonsPerRecord {
							return "", nil, fmt.Errorf("nmap XML folded state exceeded %d reason safety limit", maxNmapExtraReasonsPerRecord)
						}
						state := parentFrame.extraState
						reason, _ := nmapXMLAttribute(element, "reason")
						if err := addNmapXMLReason(hostCounts, state, reason); err != nil {
							return "", nil, err
						}
					}
					reasonPorts, _ := nmapXMLAttribute(element, "ports")
					if len(reasonPorts) > maxNmapFoldedListBytes {
						return "", nil, fmt.Errorf("nmap XML folded port list exceeded %d byte safety limit", maxNmapFoldedListBytes)
					}
				case "status":
					if !hostCounts.selected {
						state, _ := nmapXMLAttribute(element, "state")
						reason, _ := nmapXMLAttribute(element, "reason")
						hostCounts.hostState = boundScannerMetadata(state)
						hostCounts.hostReason = boundScannerMetadata(reason)
						break
					}
					if _, _, intErr := nmapXMLIntAttribute(element, "reason_ttl"); intErr != nil {
						return "", nil, intErr
					}
					state, _ := nmapXMLAttribute(element, "state")
					reason, _ := nmapXMLAttribute(element, "reason")
					hostCounts.hostState = boundScannerMetadata(state)
					hostCounts.hostReason = boundScannerMetadata(reason)
					if err := addNmapXMLState(hostCounts, state); err != nil {
						return "", nil, err
					}
					if err := addNmapXMLReason(hostCounts, state, reason); err != nil {
						return "", nil, err
					}
				case "state":
					if !hostCounts.selected {
						break
					}
					if _, _, intErr := nmapXMLIntAttribute(element, "reason_ttl"); intErr != nil {
						return "", nil, intErr
					}
					state, _ := nmapXMLAttribute(element, "state")
					if err := addNmapXMLState(hostCounts, state); err != nil {
						return "", nil, err
					}
					reason, _ := nmapXMLAttribute(element, "reason")
					if err := addNmapXMLReason(hostCounts, state, reason); err != nil {
						return "", nil, err
					}
				case "service":
					if !hostCounts.selected {
						break
					}
					if _, _, intErr := nmapXMLIntAttribute(element, "conf"); intErr != nil {
						return "", nil, intErr
					}
				}
			}
			if element.Name.Local == "finished" && parent == "runstats" {
				runExit, _ = nmapXMLAttribute(element, "exit")
			}
			stack = append(stack, frame)

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].name != element.Name.Local {
				return "", nil, errors.New("malformed nmap XML element nesting")
			}
			if element.Name.Local == "host" && hostCounts != nil {
				if hostCounts.materialize {
					spans = append(spans, nmapXMLHostSpan{start: hostCounts.start, end: int(decoder.InputOffset())})
				}
				hostCounts = nil
			}
			stack = stack[:len(stack)-1]
		}
	}
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("parse nmap XML cancelled: %w", err)
	}
	if !rootSeen {
		return "", nil, errors.New("parse nmap XML: no document element")
	}
	if rootName != "nmaprun" {
		// Do not let a success marker under an unrelated wrapper make an empty
		// host set look like a complete Nmap observation.
		return "", nil, fmt.Errorf("parse nmap XML: unexpected document element %q", rootName)
	}
	if len(stack) != 0 || hostCounts != nil {
		return "", nil, errors.New("parse nmap XML: incomplete document")
	}
	if stats != nil {
		stats.SelectedHostSpans = len(spans)
	}
	return runExit, spans, nil
}

type nmapStateSummaryIndexes struct {
	observation *model.ProtocolObservation
	states      map[string]int
	reasons     map[string]map[string]int
}

func newNmapStateSummaryIndexes(observation *model.ProtocolObservation) nmapStateSummaryIndexes {
	return nmapStateSummaryIndexes{
		observation: observation,
		states:      make(map[string]int, maxNmapStateSummaries),
		reasons:     make(map[string]map[string]int, maxNmapStateSummaries),
	}
}

func (indexes *nmapStateSummaryIndexes) addSummary(state, reason string, count int) {
	if count <= 0 {
		return
	}
	state = boundScannerMetadata(state)
	index, exists := indexes.states[state]
	if !exists {
		index = len(indexes.observation.StateSummaries)
		indexes.states[state] = index
		indexes.observation.StateSummaries = append(indexes.observation.StateSummaries, model.StateSummary{State: state})
	}
	indexes.observation.StateSummaries[index].Count += count
	if reason != "" {
		indexes.addReason(state, reason, count)
	}
}

func (indexes *nmapStateSummaryIndexes) addReason(state, reason string, count int) {
	if reason == "" || count <= 0 {
		return
	}
	state = boundScannerMetadata(state)
	reason = boundScannerMetadata(reason)
	stateIndex, exists := indexes.states[state]
	if !exists {
		stateIndex = len(indexes.observation.StateSummaries)
		indexes.states[state] = stateIndex
		indexes.observation.StateSummaries = append(indexes.observation.StateSummaries, model.StateSummary{State: state})
	}
	reasonIndexes := indexes.reasons[state]
	if reasonIndexes == nil {
		reasonIndexes = make(map[string]int, maxScannerStateReasons)
		indexes.reasons[state] = reasonIndexes
	}
	reasonIndex, exists := reasonIndexes[reason]
	if !exists {
		reasonIndex = len(indexes.observation.StateSummaries[stateIndex].Reasons)
		reasonIndexes[reason] = reasonIndex
		indexes.observation.StateSummaries[stateIndex].Reasons = append(indexes.observation.StateSummaries[stateIndex].Reasons, model.StateReason{Reason: reason})
	}
	indexes.observation.StateSummaries[stateIndex].Reasons[reasonIndex].Count += count
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
	scannedPorts := 0
	if ports, err := config.ParsePorts(pc.Ports); err == nil {
		scannedPorts = len(ports)
	}
	return parseXMLWithPortCount(context.Background(), data, protocol, pc, nil, scannedPorts, nil)
}

type nmapPortScriptSummary struct {
	portIndex int
	script    nmapScript
}

// decodeNmapHostBounded materializes one already-validated selected host at a
// time. Ports and CPEs use the preflight's scope/cardinality limits; NSE
// elements are streamed and reduced to summaries as they arrive, so a target
// cannot turn a large script table into a slice of raw script objects.
func decodeNmapHostBounded(ctx context.Context, data []byte, protocol string) (nmapHost, int, int, error) {
	if ctx == nil {
		return nmapHost{}, 0, 0, errors.New("decode nmap XML host context is nil")
	}
	decoder := xml.NewDecoder(nmapXMLContextReader{ctx: ctx, reader: bytes.NewReader(data)})
	decoder.Strict = true
	var host nmapHost
	stack := make([]string, 0, 16)
	currentPort, currentExtra := -1, -1
	portScriptEligible := make([]bool, 0, 16)
	seenPortRecords := make(map[int]struct{})
	portScriptSummaries := make([]nmapPortScriptSummary, 0, maxScannerNSEOutputs)
	scriptElements := 0
	rootSeen := false
	var metadataErr error
	boundMetadata := func(value string) string {
		if metadataErr != nil {
			return ""
		}
		bounded, err := boundNmapXMLMetadata(ctx, value)
		if err != nil {
			metadataErr = err
			return ""
		}
		return bounded
	}

	readToken := func() (xml.Token, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err := decoder.Token()
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return token, err
	}

	for {
		token, err := readToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nmapHost{}, scriptElements, 0, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			parent, grandparent := "", ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			if len(stack) > 1 {
				grandparent = stack[len(stack)-2]
			}
			name := element.Name.Local
			if !rootSeen {
				if name != "host" {
					return nmapHost{}, scriptElements, 0, errors.New("selected nmap XML span does not begin with a host")
				}
				rootSeen = true
				host.TimedOut, _ = nmapXMLAttribute(element, "timedout")
				host.TimedOut = boundMetadata(host.TimedOut)
				if metadataErr != nil {
					return nmapHost{}, scriptElements, 0, metadataErr
				}
				stack = append(stack, name)
				continue
			}

			switch name {
			case "status":
				if parent == "host" {
					host.Status.State, _ = nmapXMLAttribute(element, "state")
					host.Status.Reason, _ = nmapXMLAttribute(element, "reason")
					host.Status.State = boundMetadata(host.Status.State)
					host.Status.Reason = boundMetadata(host.Status.Reason)
					ttl, exists, parseErr := nmapXMLIntAttribute(element, "reason_ttl")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					if exists {
						host.Status.TTL = ttl
					}
				}
			case "address":
				if parent == "host" {
					addr, _ := nmapXMLAttribute(element, "addr")
					addrType, _ := nmapXMLAttribute(element, "addrtype")
					vendor, _ := nmapXMLAttribute(element, "vendor")
					host.Addresses = append(host.Addresses, struct {
						Addr   string `xml:"addr,attr"`
						Type   string `xml:"addrtype,attr"`
						Vendor string `xml:"vendor,attr"`
					}{Addr: boundMetadata(addr), Type: boundMetadata(addrType), Vendor: boundMetadata(vendor)})
				}
			case "hostname":
				if parent == "hostnames" && grandparent == "host" {
					nameValue, _ := nmapXMLAttribute(element, "name")
					typeValue, _ := nmapXMLAttribute(element, "type")
					host.Hostnames = append(host.Hostnames, struct {
						Name string `xml:"name,attr"`
						Type string `xml:"type,attr"`
					}{Name: boundMetadata(nameValue), Type: boundMetadata(typeValue)})
				}
			case "times":
				if parent == "host" {
					host.Times.SRTT, _ = nmapXMLAttribute(element, "srtt")
					host.Times.SRTT = boundMetadata(host.Times.SRTT)
				}
			case "port":
				if parent == "ports" && grandparent == "host" {
					if strings.EqualFold(strings.TrimSpace(host.TimedOut), "true") {
						currentPort = -1
						stack = append(stack, name)
						continue
					}
					portID, exists, parseErr := nmapXMLIntAttribute(element, "portid")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					if !exists {
						return nmapHost{}, scriptElements, 0, errors.New("selected nmap XML port is missing its port id")
					}
					portProtocol, _ := nmapXMLAttribute(element, "protocol")
					host.Ports = append(host.Ports, nmapPort{Protocol: boundMetadata(portProtocol), PortID: portID})
					currentPort = len(host.Ports) - 1
					eligible := false
					if host.Ports[currentPort].Protocol == protocol {
						if _, duplicate := seenPortRecords[portID]; !duplicate {
							seenPortRecords[portID] = struct{}{}
							eligible = true
						}
					}
					portScriptEligible = append(portScriptEligible, eligible)
				}
			case "state":
				if parent == "port" && currentPort >= 0 {
					state, _ := nmapXMLAttribute(element, "state")
					reason, _ := nmapXMLAttribute(element, "reason")
					ttl, exists, parseErr := nmapXMLIntAttribute(element, "reason_ttl")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					host.Ports[currentPort].State.State = boundMetadata(state)
					host.Ports[currentPort].State.Reason = boundMetadata(reason)
					if exists {
						host.Ports[currentPort].State.TTL = ttl
					}
				}
			case "service":
				if parent == "port" && currentPort >= 0 {
					service := &host.Ports[currentPort].Service
					service.Name, _ = nmapXMLAttribute(element, "name")
					service.Product, _ = nmapXMLAttribute(element, "product")
					service.Version, _ = nmapXMLAttribute(element, "version")
					service.Extra, _ = nmapXMLAttribute(element, "extrainfo")
					service.Method, _ = nmapXMLAttribute(element, "method")
					service.Tunnel, _ = nmapXMLAttribute(element, "tunnel")
					service.OSType, _ = nmapXMLAttribute(element, "ostype")
					service.DeviceType, _ = nmapXMLAttribute(element, "devicetype")
					service.Name = boundMetadata(service.Name)
					service.Product = boundMetadata(service.Product)
					service.Version = boundMetadata(service.Version)
					service.Extra = boundMetadata(service.Extra)
					service.Method = boundMetadata(service.Method)
					service.Tunnel = boundMetadata(service.Tunnel)
					service.OSType = boundMetadata(service.OSType)
					service.DeviceType = boundMetadata(service.DeviceType)
					confidence, exists, parseErr := nmapXMLIntAttribute(element, "conf")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					if exists {
						service.Confidence = confidence
					}
				}
			case "cpe":
				if parent == "service" && currentPort >= 0 {
					value, readErr := readNmapXMLTextBounded(ctx, decoder)
					if readErr != nil {
						return nmapHost{}, scriptElements, 0, readErr
					}
					host.Ports[currentPort].Service.CPES = append(host.Ports[currentPort].Service.CPES, value)
					continue
				}
			case "script":
				scriptElements++
				if strings.EqualFold(strings.TrimSpace(host.TimedOut), "true") {
					break
				}
				id, _ := nmapXMLAttribute(element, "id")
				output, _ := nmapXMLAttribute(element, "output")
				summary, summaryErr := summarizeNSEOutputContext(ctx, id, output)
				if summaryErr != nil {
					return nmapHost{}, scriptElements, 0, summaryErr
				}
				if summary != "" && parent == "hostscript" && grandparent == "host" && len(host.HostScripts) < maxScannerNSEOutputs {
					if len(host.HostScripts)+len(portScriptSummaries) >= maxScannerNSEOutputs && len(portScriptSummaries) > 0 {
						portScriptSummaries = portScriptSummaries[:len(portScriptSummaries)-1]
					}
					host.HostScripts = append(host.HostScripts, nmapScript{Output: summary})
				} else if summary != "" && parent == "port" && currentPort >= 0 &&
					(host.Ports[currentPort].State.State == "open" || host.Ports[currentPort].State.State == "open|filtered") && len(portScriptSummaries) < maxScannerNSEOutputs {
					if portScriptEligible[currentPort] && len(host.HostScripts)+len(portScriptSummaries) < maxScannerNSEOutputs {
						portScriptSummaries = append(portScriptSummaries, nmapPortScriptSummary{portIndex: currentPort, script: nmapScript{Output: summary}})
					}
				}
			case "extraports":
				if parent == "ports" && grandparent == "host" && !strings.EqualFold(strings.TrimSpace(host.TimedOut), "true") {
					state, _ := nmapXMLAttribute(element, "state")
					count, exists, parseErr := nmapXMLIntAttribute(element, "count")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					if !exists {
						return nmapHost{}, scriptElements, 0, errors.New("selected nmap XML extraports is missing its count")
					}
					host.ExtraPorts = append(host.ExtraPorts, nmapExtraPorts{State: boundMetadata(state), Count: count})
					currentExtra = len(host.ExtraPorts) - 1
				}
			case "extrareasons":
				if parent == "extraports" && currentExtra >= 0 {
					reason, _ := nmapXMLAttribute(element, "reason")
					count, _, parseErr := nmapXMLIntAttribute(element, "count")
					if parseErr != nil {
						return nmapHost{}, scriptElements, 0, parseErr
					}
					protocol, _ := nmapXMLAttribute(element, "proto")
					ports, _ := nmapXMLAttribute(element, "ports")
					host.ExtraPorts[currentExtra].Reasons = append(host.ExtraPorts[currentExtra].Reasons, nmapExtraReason{
						Reason: boundMetadata(reason), Count: count,
						Protocol: boundMetadata(protocol), Ports: ports,
					})
				}
			}
			if metadataErr != nil {
				return nmapHost{}, scriptElements, 0, metadataErr
			}
			stack = append(stack, name)

		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != element.Name.Local {
				return nmapHost{}, scriptElements, 0, errors.New("malformed selected nmap XML host nesting")
			}
			if element.Name.Local == "host" && len(stack) == 1 {
				for _, summary := range portScriptSummaries {
					host.Ports[summary.portIndex].Scripts = append(host.Ports[summary.portIndex].Scripts, summary.script)
				}
				retained := len(host.HostScripts) + len(portScriptSummaries)
				return host, scriptElements, retained, nil
			}
			if element.Name.Local == "port" {
				currentPort = -1
			}
			if element.Name.Local == "extraports" {
				currentExtra = -1
			}
			stack = stack[:len(stack)-1]
		}
	}
	return nmapHost{}, scriptElements, 0, errors.New("selected nmap XML host is incomplete")
}

func readNmapXMLTextBounded(ctx context.Context, decoder *xml.Decoder) (string, error) {
	const retainedPrefixBytes = maxScannerMetadataBytes + utf8.UTFMax
	var text strings.Builder
	text.Grow(retainedPrefixBytes)
	truncated := false
	seenContent := false
	depth := 1
	for depth > 0 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch part := token.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			for offset := 0; offset < len(part); {
				if offset&4095 == 0 {
					if err := ctx.Err(); err != nil {
						return "", err
					}
				}
				r, size := utf8.DecodeRune(part[offset:])
				offset += size
				if !unicode.IsSpace(r) {
					seenContent = true
					if text.Len() >= retainedPrefixBytes {
						truncated = true
						continue
					}
				}
				if seenContent && text.Len()+size <= retainedPrefixBytes {
					text.Write(part[offset-size : offset])
				}
			}
		}
	}
	value := strings.TrimSpace(strings.ToValidUTF8(text.String(), "�"))
	if truncated {
		return truncateNSESummary(value), nil
	}
	return boundScannerMetadata(value), nil
}

func boundNmapXMLMetadata(ctx context.Context, value string) (string, error) {
	if ctx == nil {
		return "", errors.New("bound nmap XML metadata context is nil")
	}
	start, end := 0, len(value)
	for start < end {
		if start&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		r, size := utf8.DecodeRuneInString(value[start:])
		if !unicode.IsSpace(r) {
			break
		}
		start += size
	}
	for end > start {
		if (len(value)-end)&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		r, size := utf8.DecodeLastRuneInString(value[:end])
		if !unicode.IsSpace(r) {
			break
		}
		end -= size
	}
	trimmed := value[start:end]
	if len(trimmed) <= maxScannerMetadataBytes {
		return boundScannerMetadata(trimmed), ctx.Err()
	}
	limit, prefixEnd := maxScannerMetadataBytes-len("…"), 0
	for index, r := range trimmed {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		size := utf8.RuneLen(r)
		if prefixEnd+size > limit {
			break
		}
		prefixEnd += size
	}
	cleanPrefix := strings.ToValidUTF8(trimmed[:prefixEnd], "�")
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return truncateNSESummary(cleanPrefix), nil
}

func parseXMLWithPortCount(ctx context.Context, data []byte, protocol string, pc config.Protocol, targets []string, scannedPortCount int, stats *nmapXMLParseStats) (parsedRun, error) {
	if ctx == nil {
		return parsedRun{}, errors.New("parse nmap XML context is nil")
	}
	exit, spans, err := indexNmapXML(ctx, data, protocol, scannedPortCount, targets, stats)
	if err != nil {
		return parsedRun{}, err
	}
	if err := ctx.Err(); err != nil {
		return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", err)
	}
	result := parsedRun{Exit: exit, Units: map[string]model.Unit{}, Hosts: map[string]model.HostObservation{}}
	var materializedPositivePorts int64
	for _, span := range spans {
		if err := ctx.Err(); err != nil {
			return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", err)
		}
		if span.start < 0 || span.end > len(data) || span.start >= span.end {
			return parsedRun{}, errors.New("invalid nmap XML host span")
		}
		host, scriptElements, retainedScriptSummaries, err := decodeNmapHostBounded(ctx, data[span.start:span.end], protocol)
		if err != nil {
			if ctx.Err() != nil {
				return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", ctx.Err())
			}
			return parsedRun{}, fmt.Errorf("parse nmap XML host: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", err)
		}
		if stats != nil {
			stats.MaterializedHosts++
			stats.MaterializedPortElements += len(host.Ports)
			stats.MaterializedScriptElements += scriptElements
			stats.RetainedScriptSummaries += retainedScriptSummaries
		}

		if strings.EqualFold(strings.TrimSpace(host.TimedOut), "true") {
			address := ""
			for _, candidate := range host.Addresses {
				if candidate.Type == "ipv4" || candidate.Type == "ipv6" {
					address = normalizeAddress(candidate.Addr)
					break
				}
			}
			if address == "" {
				return parsedRun{}, errors.New("nmap host timed out")
			}
			// A timed-out host must not discard healthy hosts from the same XML
			// document. Retain an explicit incomplete observation and let the
			// scan-level caller reject baseline processing after parsing finishes.
			reason := strings.TrimSpace(host.Status.Reason)
			if reason == "" {
				reason = "nmap-host-timeout"
			}
			observation := unreachableHostObservationWithPortCount(address, protocol, pc, reason, scannedPortCount)
			observation.ReasonTTL = host.Status.TTL
			observation.StatusReason = boundScannerMetadata(reason)
			for _, hostname := range host.Hostnames {
				observation.Hostnames = append(observation.Hostnames, model.Hostname{Name: boundScannerMetadata(hostname.Name), Type: boundScannerMetadata(hostname.Type)})
			}
			for _, candidate := range host.Addresses {
				if candidate.Type == "mac" {
					observation.LinkAddresses = append(observation.LinkAddresses, model.LinkAddress{Address: boundScannerMetadata(candidate.Addr), Type: boundScannerMetadata(candidate.Type), Vendor: boundScannerMetadata(candidate.Vendor)})
				}
			}
			dedupeHostObservation(&observation)
			result.Hosts[address] = observation
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
				links = append(links, model.LinkAddress{Address: boundScannerMetadata(a.Addr), Type: boundScannerMetadata(a.Type), Vendor: boundScannerMetadata(a.Vendor)})
			}
		}
		if address == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(host.Status.State))
		if status == "" {
			status = "unknown"
		}
		hostObservation := model.HostObservation{Address: address, AddressFamily: family, Status: status, StatusReason: boundScannerMetadata(host.Status.Reason), ReasonTTL: host.Status.TTL, LinkAddresses: links}
		for _, hostname := range host.Hostnames {
			hostObservation.Hostnames = append(hostObservation.Hostnames, model.Hostname{Name: boundScannerMetadata(hostname.Name), Type: boundScannerMetadata(hostname.Type)})
		}
		if host.Times.SRTT != "" {
			if srtt, err := strconv.ParseFloat(host.Times.SRTT, 64); err == nil {
				// Nmap reports srtt in microseconds.
				hostObservation.LatencyMS = srtt / 1000
			}
		}
		for _, a := range host.Addresses {
			if a.Type == "mac" {
				hostObservation.LinkAddresses = append(hostObservation.LinkAddresses, model.LinkAddress{Address: boundScannerMetadata(a.Addr), Type: boundScannerMetadata(a.Type), Vendor: boundScannerMetadata(a.Vendor)})
			}
		}
		observation := model.ProtocolObservation{Protocol: protocol, Status: status, StatusReason: boundScannerMetadata(host.Status.Reason), ScanType: scanType(protocol, pc), ScannedPorts: pc.Ports, ScannedPortCount: scannedPortCount, ServiceDetection: pc.ServiceDetection, NSEProfile: strings.TrimSpace(pc.NSEProfile), NSEArgs: cloneStringMap(pc.NSEArgs)}
		if status != "up" {
			// Preserve an explicit Nmap down element as unreachable evidence
			// instead of making the caller guess whether the address was omitted.
			// Only the managed -v host-discovery path makes Nmap emit these for
			// silent addresses; the compact Unit is intentionally absent.
			hostObservation.Status = "unreachable"
			if strings.TrimSpace(hostObservation.StatusReason) == "" {
				hostObservation.StatusReason = "nmap-host-down"
			}
			observation.Status = "unreachable"
			observation.StatusReason = hostObservation.StatusReason
			count := observation.ScannedPortCount
			if count == 0 {
				count = 1
			}
			indexes := newNmapStateSummaryIndexes(&observation)
			indexes.addSummary("unreachable", hostObservation.StatusReason, count)
			hostObservation.Protocols = append(hostObservation.Protocols, observation)
			dedupeHostObservation(&hostObservation)
			result.Hosts[address] = hostObservation
			continue
		}
		unit := model.Unit{Target: address, Protocol: protocol, Addresses: []string{address}}
		stateIndexes := newNmapStateSummaryIndexes(&observation)
		var seenPortRecords nmapPortBitset
		var listedPositivePorts nmapPortBitset
		for _, script := range host.HostScripts {
			observation.NSEOutput, err = appendNSESummaryContext(ctx, observation.NSEOutput, script.ID, script.Output)
			if err != nil {
				return parsedRun{}, fmt.Errorf("parse nmap XML script: %w", err)
			}
		}
		for portIndex, p := range host.Ports {
			if portIndex&255 == 0 {
				if err := ctx.Err(); err != nil {
					return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", err)
				}
			}
			if p.Protocol != protocol {
				continue
			}
			if seenPortRecords.contains(p.PortID) {
				continue
			}
			seenPortRecords.add(p.PortID)
			reason := boundScannerMetadata(p.State.Reason)
			stateIndexes.addSummary(p.State.State, reason, 1)
			if p.State.State != "open" && p.State.State != "open|filtered" {
				continue
			}
			if materializedPositivePorts >= maxNmapXMLMaterializedPortSlots {
				return parsedRun{}, fmt.Errorf("nmap XML exceeded %d materialized positive-port safety limit", maxNmapXMLMaterializedPortSlots)
			}
			materializedPositivePorts++
			for _, script := range p.Scripts {
				observation.NSEOutput, err = appendNSESummaryContext(ctx, observation.NSEOutput, script.ID, script.Output)
				if err != nil {
					return parsedRun{}, fmt.Errorf("parse nmap XML script: %w", err)
				}
			}
			serviceName := boundScannerMetadata(p.Service.Name)
			serviceProduct := boundScannerMetadata(p.Service.Product)
			serviceVersion := boundScannerMetadata(p.Service.Version)
			serviceExtra := boundScannerMetadata(p.Service.Extra)
			serviceMethod := boundScannerMetadata(p.Service.Method)
			serviceTunnel := boundScannerMetadata(p.Service.Tunnel)
			serviceOSType := boundScannerMetadata(p.Service.OSType)
			serviceDeviceType := boundScannerMetadata(p.Service.DeviceType)
			serviceCPES := boundedScannerStrings(p.Service.CPES, maxScannerCPEs)
			state := model.PortState{Port: p.PortID, State: p.State.State, Evidence: []string{address}}
			if pc.ServiceDetection && p.Service.Method == "probed" {
				state.Service = boundScannerMetadata(model.Fingerprint(serviceName, serviceProduct, serviceVersion, serviceExtra, serviceCPES))
			}
			unit.Ports = append(unit.Ports, state)
			listedPositivePorts.add(p.PortID)
			port := model.PortObservation{Port: p.PortID, State: p.State.State, Reason: reason, ReasonTTL: p.State.TTL, Verification: "confirmed"}
			if pc.ServiceDetection && hasServiceEvidence(p.Service) {
				port.Service = &model.ServiceObservation{Name: serviceName, Product: serviceProduct, Version: serviceVersion, ExtraInfo: serviceExtra, Method: serviceMethod, Confidence: p.Service.Confidence, Tunnel: serviceTunnel, OSType: serviceOSType, DeviceType: serviceDeviceType, CPEs: serviceCPES}
			}
			observation.Ports = append(observation.Ports, port)
		}
		for _, extra := range host.ExtraPorts {
			stateIndexes.addSummary(extra.State, "", extra.Count)
			for _, reason := range extra.Reasons {
				stateIndexes.addReason(extra.State, reason.Reason, reason.Count)
			}
			if extra.State != "open" && extra.State != "open|filtered" {
				continue
			}
			// Whether Nmap lists a positive state or folds it depends on how
			// many ports share it and on the verbosity level, so a folded state
			// is recorded exactly like listed ports. Without a usable port list
			// the ports cannot be named; flag the protocol as incomplete rather
			// than letting the missing ports look closed.
			ok, err := walkFoldedPositivePortsContext(ctx, extra, protocol, func(port foldedPort) error {
				if listedPositivePorts.contains(port.port) {
					return nil
				}
				if materializedPositivePorts >= maxNmapXMLMaterializedPortSlots {
					return fmt.Errorf("nmap XML exceeded %d materialized positive-port safety limit", maxNmapXMLMaterializedPortSlots)
				}
				materializedPositivePorts++
				listedPositivePorts.add(port.port)
				unit.Ports = append(unit.Ports, model.PortState{Port: port.port, State: extra.State, Evidence: []string{address}})
				observation.Ports = append(observation.Ports, model.PortObservation{Port: port.port, State: extra.State, Reason: port.reason, Verification: "confirmed"})
				return nil
			})
			if err != nil {
				if ctx.Err() != nil {
					return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", ctx.Err())
				}
				return parsedRun{}, err
			}
			if !ok {
				observation.Status = "unknown"
				observation.StatusReason = nmapUnlistedOpenFilteredReason
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return parsedRun{}, fmt.Errorf("parse nmap XML cancelled: %w", err)
		}
		hostObservation.Protocols = append(hostObservation.Protocols, observation)
		hostObservation.Address = address
		dedupeHostObservation(&hostObservation)
		result.Units[address] = unit
		result.Hosts[address] = hostObservation
		if stats != nil {
			stats.MaterializedPositivePorts = int(materializedPositivePorts)
		}
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

// unreachableHostObservation is the explicit evidence retained when Nmap's
// XML omits an expected address entirely. It carries the configured scope so
// host-detail consumers can distinguish a covered, non-responsive address
// from a legacy snapshot that never recorded host evidence. No compact Unit
// is created for this state because an absent result is not equivalent to a
// closed port.
func unreachableHostObservation(address, protocol string, pc config.Protocol, reason string) model.HostObservation {
	scannedPortCount := 0
	if ports, err := config.ParsePorts(pc.Ports); err == nil {
		scannedPortCount = len(ports)
	}
	return unreachableHostObservationWithPortCount(address, protocol, pc, reason, scannedPortCount)
}

func unreachableHostObservationWithPortCount(address, protocol string, pc config.Protocol, reason string, scannedPortCount int) model.HostObservation {
	address = normalizeAddress(address)
	if strings.TrimSpace(reason) == "" {
		reason = "nmap-omitted"
	}
	count := scannedPortCount
	if count == 0 {
		count = 1
	}
	observation := model.ProtocolObservation{
		Protocol:         protocol,
		Status:           "unreachable",
		StatusReason:     reason,
		ScanType:         scanType(protocol, pc),
		ScannedPorts:     pc.Ports,
		ScannedPortCount: count,
		ServiceDetection: pc.ServiceDetection,
		NSEProfile:       strings.TrimSpace(pc.NSEProfile),
		NSEArgs:          cloneStringMap(pc.NSEArgs),
	}
	addStateSummary(&observation, "unreachable", reason, count)
	return model.HostObservation{
		Address:       address,
		AddressFamily: addressFamily(address),
		Status:        "unreachable",
		StatusReason:  reason,
		Protocols:     []model.ProtocolObservation{observation},
	}
}

// recordNmapDiscoveryState marks only explicit Nmap host-discovery answers.
// Omitted XML, timeout evidence, and -Pn scans cannot distinguish a reachable
// host from a silent one, so they must not become monitored up/down state.
func recordNmapDiscoveryState(host *model.HostObservation, assumeAlive bool) {
	if host == nil || assumeAlive {
		return
	}
	status := strings.ToLower(strings.TrimSpace(host.Status))
	discoveryState := ""
	switch status {
	case "up":
		discoveryState = "up"
	case "down", "unreachable":
		switch strings.ToLower(strings.TrimSpace(host.StatusReason)) {
		case "nmap-host-down", "host-down", "down", "no-response", "host-unreach", "net-unreach", "admin-prohibited":
			discoveryState = "down"
		}
	}
	if discoveryState == "" {
		return
	}
	for index := range host.Protocols {
		// Naabu's no-result is intentionally ambiguous. The optional Nmap
		// enrichment step cannot turn that discovery result into reachability
		// state, even if Nmap itself reports a host-discovery answer.
		if host.Protocols[index].DiscoveryEngine == "naabu" {
			continue
		}
		host.Protocols[index].DiscoveryState = discoveryState
	}
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

// boundScannerMetadata trims and clips scanner-supplied descriptive text by
// UTF-8 byte length. The terminating ellipsis makes truncation visible while
// keeping the returned string valid UTF-8 and within the documented bound.
func boundScannerMetadata(value string) string {
	return boundScannerText(value, maxScannerMetadataBytes)
}

// boundScannerText trims scanner-supplied text and clips it at a UTF-8 rune
// boundary. The maximum includes the visible ellipsis, so callers can safely
// persist or display the returned value without splitting a multi-byte rune.
func boundScannerText(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	value = strings.TrimSpace(strings.ToValidUTF8(value, "�"))
	if len(value) <= maxBytes {
		return value
	}
	const ellipsis = "…"
	suffix := ""
	limit := maxBytes
	if maxBytes >= len(ellipsis) {
		suffix = ellipsis
		limit -= len(suffix)
	}
	end, used := 0, 0
	for index, r := range value {
		size := utf8.RuneLen(r)
		if used+size > limit {
			break
		}
		end = index + size
		used += size
	}
	return value[:end] + suffix
}

func boundedScannerStrings(values []string, maxItems int) []string {
	if len(values) == 0 || maxItems <= 0 {
		return nil
	}
	// Preserve the prior sorted-first-N result without sizing a set from
	// target-controlled input. The retained set stays at maxItems entries even
	// when the scanner emits hundreds of thousands of repeated CPEs.
	seen := make(map[string]struct{}, min(len(values), maxItems))
	bounded := make([]string, 0, min(len(values), maxItems))
	for _, value := range values {
		if value = boundScannerMetadata(value); value != "" {
			if _, exists := seen[value]; exists {
				continue
			}
			if len(bounded) < maxItems {
				seen[value] = struct{}{}
				bounded = append(bounded, value)
				continue
			}
			largestIndex := 0
			for index := 1; index < len(bounded); index++ {
				if bounded[index] > bounded[largestIndex] {
					largestIndex = index
				}
			}
			if value >= bounded[largestIndex] {
				continue
			}
			delete(seen, bounded[largestIndex])
			bounded[largestIndex] = value
			seen[value] = struct{}{}
		}
	}
	sort.Strings(bounded)
	if len(bounded) > maxItems {
		bounded = bounded[:maxItems]
	}
	return bounded
}

func appendNSESummaryContext(ctx context.Context, values []string, id, output string) ([]string, error) {
	if ctx == nil {
		return values, errors.New("summarize NSE output context is nil")
	}
	if len(values) >= maxScannerNSEOutputs {
		return values, nil
	}
	summary, err := summarizeNSEOutputContext(ctx, id, output)
	if err != nil {
		return values, err
	}
	if summary != "" {
		values = append(values, summary)
	}
	return values, nil
}

func summarizeNSEOutputContext(ctx context.Context, id, output string) (string, error) {
	if ctx == nil {
		return "", errors.New("summarize NSE output context is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var err error
	id, err = boundNmapXMLMetadata(ctx, id)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	compact, truncated, err := compactNSEOutputContext(ctx, output, maxScannerMetadataBytes)
	if err != nil {
		return "", err
	}
	if id == "" {
		if truncated {
			return truncateNSESummary(compact), nil
		}
		return boundScannerMetadata(compact), nil
	}
	if compact == "" {
		return id, nil
	}
	combined := id + ": " + compact
	if truncated {
		return truncateNSESummary(combined), nil
	}
	return boundScannerMetadata(combined), nil
}

func compactNSEOutputContext(ctx context.Context, value string, maxBytes int) (string, bool, error) {
	if ctx == nil {
		return "", false, errors.New("compact NSE output context is nil")
	}
	if maxBytes <= 0 {
		return "", value != "", nil
	}
	var compact strings.Builder
	compact.Grow(min(len(value), maxBytes))
	content, pendingSpace := false, false
	for index, r := range value {
		if index&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return "", false, err
			}
		}
		if unicode.IsSpace(r) {
			if content {
				pendingSpace = true
			}
			continue
		}
		if pendingSpace {
			if compact.Len()+1 > maxBytes {
				return compact.String(), true, nil
			}
			compact.WriteByte(' ')
			pendingSpace = false
		}
		if compact.Len()+utf8.RuneLen(r) > maxBytes {
			return compact.String(), true, nil
		}
		compact.WriteRune(r)
		content = true
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	return compact.String(), false, nil
}

func truncateNSESummary(value string) string {
	const ellipsis = "…"
	limit := maxScannerMetadataBytes - len(ellipsis)
	end := 0
	for index, r := range value {
		if index+utf8.RuneLen(r) > limit {
			break
		}
		end = index + utf8.RuneLen(r)
	}
	return value[:end] + ellipsis
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
	// Naabu discovery creates an address inventory before Nmap enrichment. It
	// can mark the host up without carrying Nmap's reason/latency fields, while
	// a later Nmap fragment can prove that part of the address was not covered.
	// Keep the address summary incomplete regardless of merge order; individual
	// ProtocolObservations retain their own status so the engine can protect only
	// the affected protocol.
	current.Status, current.StatusReason = mergeHostStatus(current.Status, current.StatusReason, addition.Status, addition.StatusReason)
	if current.ReasonTTL == 0 && addition.ReasonTTL != 0 {
		current.ReasonTTL = addition.ReasonTTL
	}
	if current.LatencyMS == 0 && addition.LatencyMS != 0 {
		current.LatencyMS = addition.LatencyMS
	}
	hosts[address] = current
}

func mergeHostStatus(currentStatus, currentReason, additionStatus, additionReason string) (string, string) {
	currentStatus = strings.ToLower(strings.TrimSpace(currentStatus))
	additionStatus = strings.ToLower(strings.TrimSpace(additionStatus))
	currentReason = strings.TrimSpace(currentReason)
	additionReason = strings.TrimSpace(additionReason)

	// An explicit incomplete state outranks an up/unknown discovery result.
	// This value summarizes the address for display and scan-completion status;
	// per-protocol comparisons use the corresponding ProtocolObservation.
	currentIncomplete := isIncompleteHostStatus(currentStatus)
	additionIncomplete := isIncompleteHostStatus(additionStatus)
	switch {
	case additionIncomplete && !currentIncomplete:
		// Do not carry a successful discovery reason (for example
		// "arp-response") onto an incomplete result. If the failed fragment did
		// not include a reason, retain an explicit neutral marker instead.
		if additionReason == "" {
			additionReason = "incomplete"
		}
		return "unreachable", additionReason
	case currentIncomplete:
		return "unreachable", chooseHostStatusReason(currentReason, additionReason)
	case currentStatus == "" || currentStatus == "unknown":
		// Unknown discovery is not sticky: a later protocol can provide
		// positive reachability evidence. The engine still treats a persisted
		// unknown/no-response protocol observation as incomplete coverage.
		if additionStatus != "" {
			return additionStatus, chooseHostStatusReason(currentReason, additionReason)
		}
	}
	return currentStatus, chooseHostStatusReason(currentReason, additionReason)
}

func isIncompleteHostStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "unreachable", "down", "timedout", "timed-out", "timeout":
		return true
	default:
		return false
	}
}

// mergeProtocolStatus keeps every incomplete fragment sticky, including
// unknown/no-response. Unlike the address summary, a later positive result for
// the same protocol cannot prove that an earlier fragment covered its scope.
// The completed Naabu full-range marker is the one exception: unknown with
// scan-complete means the entire scope was examined and no positive port was
// emitted, so later fragments may replace it with authoritative evidence.
func mergeProtocolStatus(currentStatus, currentReason, additionStatus, additionReason string) (string, string) {
	currentStatus = strings.ToLower(strings.TrimSpace(currentStatus))
	additionStatus = strings.ToLower(strings.TrimSpace(additionStatus))
	currentReason = strings.TrimSpace(currentReason)
	additionReason = strings.TrimSpace(additionReason)
	currentIncomplete := isIncompleteProtocolStatus(currentStatus, currentReason)
	additionIncomplete := isIncompleteProtocolStatus(additionStatus, additionReason)
	switch {
	case currentIncomplete:
		if !additionIncomplete {
			if currentReason == "" {
				currentReason = "incomplete"
			}
			return currentStatus, currentReason
		}
		return currentStatus, chooseHostStatusReason(currentReason, additionReason)
	case additionIncomplete:
		if additionReason == "" {
			additionReason = "incomplete"
		}
		return additionStatus, additionReason
	case currentStatus == "unknown" && strings.EqualFold(currentReason, naabuFullRangeCompleteReason):
		if additionStatus != "" {
			return additionStatus, additionReason
		}
		return currentStatus, currentReason
	case currentStatus == "":
		return additionStatus, chooseHostStatusReason(currentReason, additionReason)
	default:
		return currentStatus, chooseHostStatusReason(currentReason, additionReason)
	}
}

func isIncompleteProtocolStatus(status, reason string) bool {
	if strings.EqualFold(strings.TrimSpace(status), "unknown") && strings.EqualFold(strings.TrimSpace(reason), naabuFullRangeCompleteReason) {
		return false
	}
	return isIncompleteHostStatus(status) || strings.EqualFold(strings.TrimSpace(status), "unknown")
}

// chooseHostStatusReason keeps the most specific failure reason when several
// fragments describe the same address. The priority makes the result stable
// regardless of whether an omitted, down, or timed-out fragment arrived first.
func chooseHostStatusReason(current, addition string) string {
	current = strings.TrimSpace(current)
	addition = strings.TrimSpace(addition)
	if current == "" {
		return addition
	}
	if addition == "" {
		return current
	}
	reasonRank := func(reason string) int {
		switch strings.ToLower(strings.TrimSpace(reason)) {
		case "nmap-timeout", "nmap-host-timeout", "timedout", "timeout":
			return 5
		case "nmap-omitted", "omitted":
			return 4
		case "nmap-host-down", "down", "no-response", "host-unreach", "net-unreach", "admin-prohibited":
			return 3
		default:
			return 1
		}
	}
	currentRank, additionRank := reasonRank(current), reasonRank(addition)
	if additionRank > currentRank || (additionRank == currentRank && addition < current) {
		return addition
	}
	return current
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
		link.Address = boundScannerMetadata(link.Address)
		link.Type = boundScannerMetadata(link.Type)
		link.Vendor = boundScannerMetadata(link.Vendor)
		host.LinkAddresses = append(host.LinkAddresses, link)
	}
	sort.Slice(host.LinkAddresses, func(i, j int) bool {
		if host.LinkAddresses[i].Type == host.LinkAddresses[j].Type {
			return host.LinkAddresses[i].Address < host.LinkAddresses[j].Address
		}
		return host.LinkAddresses[i].Type < host.LinkAddresses[j].Type
	})
	if len(host.LinkAddresses) > maxScannerLinkAddresses {
		host.LinkAddresses = host.LinkAddresses[:maxScannerLinkAddresses]
	}
	seenNames := map[string]model.Hostname{}
	for _, name := range host.Hostnames {
		name.Name = boundScannerMetadata(name.Name)
		name.Type = boundScannerMetadata(name.Type)
		seenNames[name.Type+"\x00"+name.Name] = name
	}
	host.Hostnames = host.Hostnames[:0]
	for _, name := range seenNames {
		host.Hostnames = append(host.Hostnames, name)
	}
	sort.Slice(host.Hostnames, func(i, j int) bool {
		if host.Hostnames[i].Name == host.Hostnames[j].Name {
			return host.Hostnames[i].Type < host.Hostnames[j].Type
		}
		return host.Hostnames[i].Name < host.Hostnames[j].Name
	})
	if len(host.Hostnames) > maxScannerHostnames {
		host.Hostnames = host.Hostnames[:maxScannerHostnames]
	}
	host.Address = boundScannerMetadata(host.Address)
	host.Status = boundScannerMetadata(host.Status)
	host.StatusReason = boundScannerMetadata(host.StatusReason)
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
		protocol.Status, protocol.StatusReason = mergeProtocolStatus(protocol.Status, protocol.StatusReason, incoming.Status, incoming.StatusReason)
		protocol.DiscoveryState = mergeDiscoveryStates(protocol.DiscoveryState, incoming.DiscoveryState)
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
		protocol.Protocol = boundScannerMetadata(protocol.Protocol)
		protocol.Status = boundScannerMetadata(protocol.Status)
		protocol.StatusReason = boundScannerMetadata(protocol.StatusReason)
		protocol.ScanType = boundScannerMetadata(protocol.ScanType)
		protocol.ScannedPorts = boundScannerMetadata(protocol.ScannedPorts)
		protocol.NSEProfile = boundScannerMetadata(protocol.NSEProfile)
		protocol.NSEOutput = boundedScannerStrings(protocol.NSEOutput, maxScannerNSEOutputs)
		sort.Strings(protocol.NSEOutput)
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
		for _, ports := range []*[]model.PortObservation{&protocol.Ports, &protocol.DiscoveredPorts, &protocol.UnconfirmedPorts} {
			for j := range *ports {
				port := &(*ports)[j]
				port.State = boundScannerMetadata(port.State)
				port.Reason = boundScannerMetadata(port.Reason)
				port.Verification = boundScannerMetadata(port.Verification)
				if port.Service != nil {
					port.Service.Name = boundScannerMetadata(port.Service.Name)
					port.Service.Product = boundScannerMetadata(port.Service.Product)
					port.Service.Version = boundScannerMetadata(port.Service.Version)
					port.Service.ExtraInfo = boundScannerMetadata(port.Service.ExtraInfo)
					port.Service.Method = boundScannerMetadata(port.Service.Method)
					port.Service.Tunnel = boundScannerMetadata(port.Service.Tunnel)
					port.Service.OSType = boundScannerMetadata(port.Service.OSType)
					port.Service.DeviceType = boundScannerMetadata(port.Service.DeviceType)
					port.Service.CPEs = boundedScannerStrings(port.Service.CPEs, maxScannerCPEs)
				}
			}
		}
		for j := range protocol.StateSummaries {
			protocol.StateSummaries[j].State = boundScannerMetadata(protocol.StateSummaries[j].State)
			for k := range protocol.StateSummaries[j].Reasons {
				protocol.StateSummaries[j].Reasons[k].Reason = boundScannerMetadata(protocol.StateSummaries[j].Reasons[k].Reason)
			}
			sort.Slice(protocol.StateSummaries[j].Reasons, func(a, b int) bool {
				return protocol.StateSummaries[j].Reasons[a].Reason < protocol.StateSummaries[j].Reasons[b].Reason
			})
			if len(protocol.StateSummaries[j].Reasons) > maxScannerStateReasons {
				protocol.StateSummaries[j].Reasons = protocol.StateSummaries[j].Reasons[:maxScannerStateReasons]
			}
		}
	}
	// Reuse the model's deterministic ordering rules without exposing scanner
	// internals on the observation type itself.
	snapshot := model.Snapshot{Hosts: []model.HostObservation{*host}}
	snapshot.Normalize()
	*host = snapshot.Hosts[0]
}

func mergeDiscoveryStates(current, addition string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	addition = strings.ToLower(strings.TrimSpace(addition))
	if current == "conflict" || addition == "conflict" {
		return "conflict"
	}
	if current == "" {
		return addition
	}
	if addition == "" || current == addition {
		return current
	}
	// Contradictory completed observations are not authoritative host state.
	return "conflict"
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

// serviceFingerprintSeparator joins the service fingerprints of a logical
// target's addresses into the one service value that the engine compares.
const serviceFingerprintSeparator = " || "

func aggregate(target resolvedTarget, units map[string]model.Unit, protocol string) model.Unit {
	out := model.Unit{Target: target.Name, Protocol: protocol, Addresses: append([]string(nil), target.Addresses...)}
	// A resolved target can share addresses with another logical target. Keep
	// aggregation scoped to this target's effective address set so a unit
	// produced for a sibling DNS/CIDR target cannot leak a port into this
	// logical baseline. The map is intentionally built once per aggregation,
	// not once per port.
	allowed := make(map[string]struct{}, len(target.Addresses))
	for _, address := range target.Addresses {
		allowed[address] = struct{}{}
	}
	type combined struct {
		state    string
		evidence map[string]bool
		services map[string]bool
	}
	ports := map[int]*combined{}
	for address, unit := range units {
		if _, ok := allowed[address]; !ok {
			continue
		}
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
		p.Service = strings.Join(services, serviceFingerprintSeparator)
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
