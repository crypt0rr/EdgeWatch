package app

import (
	"context"
	"errors"
	"log/slog"
	"math/bits"
	"net/netip"
	"sort"
	"time"

	"github.com/crypt0rr/edgewatch/internal/addrspace"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/robfig/cron/v3"
)

// The perimeter report compares the address space a unit declares with what
// its monitors will actually scan, per protocol. Coverage comes from job
// configuration only, never from scan results or DNS answers, and the report
// only reads: it never scans, and it never creates, changes, pauses or
// deletes a job. Its suggestions are sized to the unit's probe budget, and a
// person still reviews and saves each suggested monitor through the job API.

// The states of a monitor, in the order a scheduled run meets their checks.
// Only a covering monitor counts as coverage.
const (
	perimeterCovering       = "covering"
	perimeterPaused         = "paused"
	perimeterInvalidConfig  = "invalid_config"
	perimeterOverBudget     = "over_budget"
	perimeterOverExpansion  = "over_expansion"
	perimeterExcludedTarget = "excluded_target"
)

// The reasons that flag a covering monitor stale.
const (
	// perimeterStaleOverdue is a monitor past the job-silent watchdog's
	// deadline.
	perimeterStaleOverdue = "overdue"
	// perimeterStaleNeverFires is a monitor whose schedule gives the
	// watchdog no deadline, such as one that never fires.
	perimeterStaleNeverFires = "schedule never fires"
)

// The coverage buckets. A covering monitor adds its IP and CIDR targets to
// each bucket that its protocols fill; any TCP includes full TCP.
const (
	perimeterFullTCP = iota
	perimeterAnyTCP
	perimeterUDP
	perimeterBuckets
)

// perimeterBucketNames are the names of the buckets in the API.
var perimeterBucketNames = [perimeterBuckets]string{"full_tcp", "any_tcp", "udp"}

// The bounds of the report's lists.
const (
	// perimeterMaxOutside bounds the outside list of the overview.
	perimeterMaxOutside = 200
	// perimeterMaxUncovered bounds the uncovered CIDRs of one bucket.
	perimeterMaxUncovered = 256
	// perimeterMaxSuggestions bounds the suggestions of one range and mode.
	perimeterMaxSuggestions = 64
	// perimeterMaxCoalescedPrefixBits limits one coalesced target to a /24,
	// or 256 addresses. A smaller monitor budget tightens this further.
	perimeterMaxCoalescedPrefixBits = 24
	// perimeterMaxCoalescedSuggestions bounds the alternative plan per range
	// and mode. An over-limit plan is withheld rather than returned partially.
	perimeterMaxCoalescedSuggestions = 16
	// perimeterMaxCoalescedTargets bounds the target list of one coalesced
	// suggestion, keeping the alternative easy to review in the console.
	perimeterMaxCoalescedTargets = 16
)

// perimeterCountLimit is where every address count of the API saturates:
// 2^53 - 1, JavaScript's Number.MAX_SAFE_INTEGER, the largest count the
// console reads exactly. Only an IPv6 count reaches it.
const perimeterCountLimit = 1<<53 - 1

// perimeterPreset is a suggestion mode: the protocol settings of the monitor
// it suggests, the bucket whose gaps it fills, and its address cap.
type perimeterPreset struct {
	mode     string
	bucket   int
	protocol PerimeterProtocol
	// cap bounds the addresses of one suggested monitor besides the budget
	// and scanner.max_job_hosts; 0 sets no cap. Without it, the Nmap-only
	// modes reach scanner.max_job_hosts at the default budgets.
	cap uint64
}

// perimeterPresets are the suggestion modes, defined only here. The console
// applies a suggestion's protocol as the response gives it, so it holds no
// copy of these settings. full_tcp equals defaultTCP() in src/job-form.ts and
// selected_tcp the guided "Selected TCP ports" preset of MonitorSetup.
var perimeterPresets = [...]perimeterPreset{
	{mode: "full_tcp", bucket: perimeterFullTCP, protocol: PerimeterProtocol{
		Protocol: "tcp", Engine: config.EngineNaabuNmap, Ports: config.NaabuFullPortExpression, Mode: "connect", ProfileID: store.BuiltinNaabuProfileID,
	}},
	{mode: "selected_tcp", bucket: perimeterAnyTCP, cap: 4096, protocol: PerimeterProtocol{
		Protocol: "tcp", Engine: config.EngineNmap, Ports: "22,443", Mode: "connect",
	}},
	{mode: "udp", bucket: perimeterUDP, cap: 1024, protocol: PerimeterProtocol{
		Protocol: "udp", Engine: config.EngineNmap, Ports: "53,123,161,500,1194,4500", ServiceDetection: true,
	}},
}

// PerimeterReport is the perimeter overview of a unit: its declared ranges
// with their coverage, the monitors that touch them or scan outside them,
// and the monitored targets outside them.
type PerimeterReport struct {
	Ranges []PerimeterRange `json:"ranges"`
	// Monitors holds, once the unit declares a range, the unarchived
	// monitors that touch a declared range or have a target outside the
	// declared ranges, in name order. It is empty while the unit declares
	// none.
	Monitors []PerimeterMonitorRef `json:"monitors"`
	// Outside holds at most 200 of the IP and CIDR targets that lie fully or
	// partly outside the declared ranges; OutsideTruncated reports that
	// Totals.OutsideTargets is more.
	Outside          []PerimeterOutsideTarget `json:"outside"`
	OutsideTruncated bool                     `json:"outside_truncated"`
	Totals           PerimeterTotals          `json:"totals"`
	Limits           PerimeterLimits          `json:"limits"`
	GeneratedAt      time.Time                `json:"generated_at"`
}

// PerimeterRange is one declared range with its coverage.
type PerimeterRange struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Label     string    `json:"label"`
	Family    int       `json:"family"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	// Addresses and Excluded count an IPv4 range's addresses and those of
	// them in scanner.target_exclusions; both are 0 for IPv6.
	Addresses uint64 `json:"addresses"`
	Excluded  uint64 `json:"excluded"`
	// Coverage counts the covered addresses of an IPv4 range, excluded
	// addresses left out, and is zero for IPv6. IPv6Monitored is the same
	// count for an IPv6 range, saturating at perimeterCountLimit, and zero
	// for IPv4.
	Coverage      PerimeterCoverage `json:"coverage"`
	IPv6Monitored PerimeterCoverage `json:"ipv6_monitored"`
	// MonitorIDs are the unarchived monitors, in every state, with a target
	// that shares an address with the range.
	MonitorIDs []string `json:"monitor_ids"`
}

// PerimeterCoverage counts addresses per coverage bucket.
type PerimeterCoverage struct {
	FullTCP uint64 `json:"full_tcp"`
	AnyTCP  uint64 `json:"any_tcp"`
	UDP     uint64 `json:"udp"`
}

// PerimeterTotals sums the overview. The address counts are over the merged
// IPv4 union of the declared ranges, so overlapping ranges count once, and
// every monitor and target count is taken before any list is cut.
type PerimeterTotals struct {
	DeclaredIPv4   uint64 `json:"declared_ipv4"`
	ExcludedIPv4   uint64 `json:"excluded_ipv4"`
	CoveredFullTCP uint64 `json:"covered_full_tcp"`
	CoveredAnyTCP  uint64 `json:"covered_any_tcp"`
	CoveredUDP     uint64 `json:"covered_udp"`
	// Ranges counts every declared range and IPv6Ranges those of IPv6.
	Ranges     int `json:"ranges"`
	IPv6Ranges int `json:"ipv6_ranges"`
	// CannotScanMonitors counts the monitors that touch the perimeter and
	// are not covering. UnprovenMonitors counts the covering monitors that
	// touch it and are stale, have a stalled cycle, changed security scope, or
	// have no successful scan for their current scope, or whose latest attempt
	// failed or was incomplete without recent resumable progress.
	CannotScanMonitors int `json:"cannot_scan_monitors"`
	UnprovenMonitors   int `json:"unproven_monitors"`
	OutsideTargets     int `json:"outside_targets"`
}

// PerimeterLimits are the limits the report and the declarations apply. The
// probe budgets are the unit's, read once with the states they decided.
type PerimeterLimits struct {
	MaxJobHosts          int   `json:"max_job_hosts"`
	MaxProbeCount        int64 `json:"max_probe_count"`
	MaxNaabuProbeCount   int64 `json:"max_naabu_probe_count"`
	MaxRanges            int   `json:"max_ranges"`
	MaxEntriesPerRequest int   `json:"max_entries_per_request"`
}

// PerimeterMonitorRef is the state of one monitor in the report.
type PerimeterMonitorRef struct {
	JobID string `json:"job_id"`
	Name  string `json:"name"`
	// State is the first of Reasons, or covering when there is none.
	// Reasons lists every failing check in the order a scheduled run meets
	// them.
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
	// Stale and StalledCycle flag only a covering monitor. StaleReason is
	// "overdue" once the job-silent watchdog's deadline has passed, and
	// "schedule never fires" when its schedule gives the watchdog no
	// deadline.
	Stale        bool   `json:"stale"`
	StaleReason  string `json:"stale_reason"`
	StalledCycle bool   `json:"stalled_cycle"`
	// ScopeChanged means the latest successful scan does not match this
	// monitor's current security scope. Name and schedule edits do not set it.
	ScopeChanged bool `json:"scope_changed,omitempty"`
	// Cycle progress is shown separately from failed or unproven coverage.
	CycleInProgress     bool `json:"cycle_in_progress,omitempty"`
	CycleCompletedUnits int  `json:"cycle_completed_units,omitempty"`
	CycleTotalUnits     int  `json:"cycle_total_units,omitempty"`
	// LastAttemptStatus is the status of the latest scan, or empty.
	LastAttemptStatus string     `json:"last_attempt_status"`
	LastSuccessAt     *time.Time `json:"last_success_at"`
	// HostDiscovery reports a monitor that port-scans only the hosts that
	// answer host discovery: its assume_alive is false.
	HostDiscovery bool `json:"host_discovery"`
	// Protocols are the buckets the monitor's settings fill, from full_tcp,
	// any_tcp and udp, whatever its state.
	Protocols []string `json:"protocols"`
	// DNSTargets counts the targets that are DNS names, which never cover
	// addresses.
	DNSTargets int `json:"dns_targets"`
}

// PerimeterOutsideTarget is an IP or CIDR target of a monitor that lies
// fully or partly outside the declared ranges.
type PerimeterOutsideTarget struct {
	JobID   string `json:"job_id"`
	JobName string `json:"job_name"`
	State   string `json:"state"`
	Target  string `json:"target"`
	Partial bool   `json:"partial"`
	// OutsideAddresses counts the target's addresses outside the declared
	// ranges, saturating at perimeterCountLimit.
	OutsideAddresses uint64 `json:"outside_addresses"`
}

// PerimeterRangeDetail is one declared range with the monitors that touch it,
// its uncovered blocks, and the monitors suggested to cover its IPv4 gaps.
type PerimeterRangeDetail struct {
	Range     PerimeterRange        `json:"range"`
	Monitors  []PerimeterMonitorRef `json:"monitors"`
	Uncovered PerimeterUncovered    `json:"uncovered"`
	// AddressesPerMonitor is the most addresses one suggested monitor of
	// each mode holds, and BudgetTooLow reports a mode whose probe budget
	// does not fit one address. Both describe the unit, for every range.
	AddressesPerMonitor PerimeterModeCounts `json:"addresses_per_monitor"`
	// MonitorsNeeded counts the monitors each mode needs to fill the gaps
	// of an IPv4 range. Suggestions holds at most 64 of them per mode, and
	// SuggestionsTruncated reports a mode that needs more.
	MonitorsNeeded       PerimeterModeCounts   `json:"monitors_needed"`
	Suggestions          []PerimeterSuggestion `json:"suggestions"`
	SuggestionsTruncated PerimeterModeFlags    `json:"suggestions_truncated"`
	// CoalescedSuggestions is a complete alternative that may include already
	// covered, but never excluded, addresses. It is withheld when more than
	// 16 monitors would be needed; then CoalescedSuggestionsTruncated is true
	// and CoalescedMonitorsNeeded is 17 (meaning 17 or more).
	CoalescedMonitorsNeeded       PerimeterModeCounts   `json:"coalesced_monitors_needed"`
	CoalescedSuggestions          []PerimeterSuggestion `json:"coalesced_suggestions"`
	CoalescedSuggestionsTruncated PerimeterModeFlags    `json:"coalesced_suggestions_truncated"`
	BudgetTooLow                  PerimeterModeFlags    `json:"budget_too_low"`
}

// PerimeterUncovered holds the uncovered blocks of a range per bucket.
type PerimeterUncovered struct {
	FullTCP PerimeterBlocks `json:"full_tcp"`
	AnyTCP  PerimeterBlocks `json:"any_tcp"`
	UDP     PerimeterBlocks `json:"udp"`
}

// PerimeterBlocks are the fewest aligned CIDRs that hold the uncovered,
// scannable addresses of a range, in address order: at most 256 of them, and
// Total, the number before the cut.
type PerimeterBlocks struct {
	CIDRs     []string `json:"cidrs"`
	Truncated bool     `json:"truncated"`
	Total     int      `json:"total"`
}

// PerimeterModeCounts holds a number per suggestion mode.
type PerimeterModeCounts struct {
	FullTCP     int `json:"full_tcp"`
	SelectedTCP int `json:"selected_tcp"`
	UDP         int `json:"udp"`
}

// PerimeterModeFlags holds a flag per suggestion mode.
type PerimeterModeFlags struct {
	FullTCP     bool `json:"full_tcp"`
	SelectedTCP bool `json:"selected_tcp"`
	UDP         bool `json:"udp"`
}

// PerimeterSuggestion is one suggested monitor: its targets, the addresses
// they hold, the probes a run of them is estimated to send, and the exact
// protocol settings the console applies to the new monitor.
type PerimeterSuggestion struct {
	Mode                    string            `json:"mode"`
	Targets                 []string          `json:"targets"`
	Addresses               int               `json:"addresses"`
	AlreadyCoveredAddresses int               `json:"already_covered_addresses"`
	EstimatedProbes         int64             `json:"estimated_probes"`
	// MinimumDurationSeconds is Full TCP's probe-rate lower bound. It excludes
	// response time, retries, and Nmap confirmation.
	MinimumDurationSeconds int64             `json:"minimum_duration_seconds,omitempty"`
	Protocol               PerimeterProtocol `json:"protocol"`
}

// PerimeterProtocol is the protocol setting of a suggestion mode. Protocol is
// tcp or udp, and the other fields are the job's protocol settings: Mode is
// empty for udp, and ProfileID names the built-in Naabu profile for full_tcp
// only.
type PerimeterProtocol struct {
	Protocol         string `json:"protocol"`
	Engine           string `json:"engine"`
	Ports            string `json:"ports"`
	Mode             string `json:"mode,omitempty"`
	ServiceDetection bool   `json:"service_detection"`
	ProfileID        string `json:"profile_id,omitempty"`
}

// perimeterMonitor is a classified monitor with its IP and CIDR targets.
type perimeterMonitor struct {
	ref PerimeterMonitorRef
	// targets are the IP and CIDR targets, in target order.
	targets []perimeterTarget
	// ranges are the addresses of targets, merged.
	ranges []addrspace.Range
}

// perimeterTarget is one IP or CIDR target of a monitor.
type perimeterTarget struct {
	value  string
	ranged addrspace.Range
}

// perimeterState is what one perimeter request reads, with its monitors
// classified.
type perimeterState struct {
	now         time.Time
	budget      probeBudget
	maxJobHosts int
	// exclusions are the addresses of scanner.target_exclusions, merged.
	exclusions []addrspace.Range
	monitors   []perimeterMonitor
	// buckets are the merged ranges that the covering monitors fill, per
	// bucket.
	buckets [perimeterBuckets][]addrspace.Range
}

// PerimeterReport returns the perimeter overview of the unit of ts. A budget
// that cannot be read wraps ErrProbeBudgetUnavailable, and no report is
// returned with any error: a monitor is never classified without its budget.
func (a *App) PerimeterReport(ctx context.Context, ts *store.TenantStore) (PerimeterReport, error) {
	seeds, err := ts.ListPerimeterSeeds(ctx)
	if err != nil {
		return PerimeterReport{}, err
	}
	state, err := a.readPerimeterState(ctx, ts)
	if err != nil {
		return PerimeterReport{}, err
	}
	report := PerimeterReport{
		Ranges: []PerimeterRange{}, Monitors: []PerimeterMonitorRef{}, Outside: []PerimeterOutsideTarget{},
		Limits: state.limits(), GeneratedAt: state.now,
	}
	var declared []addrspace.Range
	for _, seed := range seeds {
		prefix, ok := perimeterSeedPrefix(seed)
		if !ok {
			continue
		}
		view := state.rangeView(seed, prefix)
		report.Ranges = append(report.Ranges, view)
		if view.Family == 6 {
			report.Totals.IPv6Ranges++
		}
		declared = append(declared, addrspace.FromPrefix(prefix))
	}
	report.Totals.Ranges = len(report.Ranges)
	union := addrspace.Merge(declared)

	ipv4 := perimeterIPv4(union)
	excluded := addrspace.Intersect(ipv4, state.exclusions)
	base := addrspace.Subtract(ipv4, excluded)
	report.Totals.DeclaredIPv4 = perimeterCount(ipv4)
	report.Totals.ExcludedIPv4 = perimeterCount(excluded)
	covered := state.coveredCounts(base)
	report.Totals.CoveredFullTCP, report.Totals.CoveredAnyTCP, report.Totals.CoveredUDP = covered.FullTCP, covered.AnyTCP, covered.UDP

	for _, monitor := range state.monitors {
		touches := perimeterOverlaps(union, monitor.ranges)
		outside := false
		for _, target := range monitor.targets {
			// A unit without declared ranges has no perimeter to be
			// outside of.
			if len(union) == 0 {
				break
			}
			rest := addrspace.Subtract([]addrspace.Range{target.ranged}, perimeterClip(union, target.ranged))
			if len(rest) == 0 {
				continue
			}
			outside = true
			report.Totals.OutsideTargets++
			if len(report.Outside) == perimeterMaxOutside {
				report.OutsideTruncated = true
				continue
			}
			report.Outside = append(report.Outside, PerimeterOutsideTarget{
				JobID: monitor.ref.JobID, JobName: monitor.ref.Name, State: monitor.ref.State, Target: target.value,
				Partial:          len(rest) != 1 || rest[0] != target.ranged,
				OutsideAddresses: perimeterCount(rest),
			})
		}
		if touches || outside {
			report.Monitors = append(report.Monitors, monitor.ref)
		}
		switch {
		case !touches:
		case monitor.ref.State != perimeterCovering:
			report.Totals.CannotScanMonitors++
		case monitor.unproven():
			report.Totals.UnprovenMonitors++
		}
	}
	return report, nil
}

// PerimeterRangeDetail returns one declared range of the unit of ts with the
// monitors that touch it, its uncovered blocks per bucket, and the monitors
// suggested to fill the IPv4 gaps of each mode. An unknown ID and another
// unit's ID are both store.ErrNotFound, unwrapped. A budget that cannot be
// read wraps ErrProbeBudgetUnavailable, and no detail is returned with any
// error.
func (a *App) PerimeterRangeDetail(ctx context.Context, ts *store.TenantStore, id string) (PerimeterRangeDetail, error) {
	seed, err := ts.GetPerimeterSeed(ctx, id)
	if err != nil {
		return PerimeterRangeDetail{}, err
	}
	prefix, ok := perimeterSeedPrefix(seed)
	if !ok {
		// The overview does not list such a row either.
		return PerimeterRangeDetail{}, store.ErrNotFound
	}
	state, err := a.readPerimeterState(ctx, ts)
	if err != nil {
		return PerimeterRangeDetail{}, err
	}
	whole := addrspace.FromPrefix(prefix)
	detail := PerimeterRangeDetail{
		Range: state.rangeView(seed, prefix), Monitors: []PerimeterMonitorRef{},
		Suggestions: []PerimeterSuggestion{}, CoalescedSuggestions: []PerimeterSuggestion{},
	}
	for _, monitor := range state.monitors {
		if perimeterOverlaps(monitor.ranges, []addrspace.Range{whole}) {
			detail.Monitors = append(detail.Monitors, monitor.ref)
		}
	}
	base := state.scannable(whole)
	var gaps [perimeterBuckets][]addrspace.Range
	var blocks [perimeterBuckets]PerimeterBlocks
	for bucket := range perimeterBuckets {
		gaps[bucket] = addrspace.Subtract(base, perimeterClip(state.buckets[bucket], whole))
		blocks[bucket] = perimeterBlocks(gaps[bucket])
	}
	detail.Uncovered = PerimeterUncovered{FullTCP: blocks[perimeterFullTCP], AnyTCP: blocks[perimeterAnyTCP], UDP: blocks[perimeterUDP]}

	var perMonitor, needed, coalescedNeeded [len(perimeterPresets)]int
	var truncated, coalescedTruncated, tooLow [len(perimeterPresets)]bool
	for index, preset := range perimeterPresets {
		size, err := state.addressesPerMonitor(preset)
		if err != nil {
			return PerimeterRangeDetail{}, err
		}
		perMonitor[index], tooLow[index] = int(size), size == 0
		// There are no IPv6 suggestions, and Pack is never called with 0.
		if size == 0 || !prefix.Addr().Is4() {
			continue
		}
		sets, total := addrspace.Pack(gaps[preset.bucket], size, perimeterMaxSuggestions)
		needed[index], truncated[index] = total, total > len(sets)
		for _, set := range sets {
			suggestion, err := perimeterSuggestion(preset, set)
			if err != nil {
				return PerimeterRangeDetail{}, err
			}
			detail.Suggestions = append(detail.Suggestions, suggestion)
		}
		coalescedSets, coalescedCount, coalescedCut := perimeterCoalescedSuggestionSets(base, gaps[preset.bucket], size)
		coalescedNeeded[index], coalescedTruncated[index] = coalescedCount, coalescedCut
		for _, set := range coalescedSets {
			suggestion, err := perimeterSuggestion(preset, set.targets)
			if err != nil {
				return PerimeterRangeDetail{}, err
			}
			suggestion.AlreadyCoveredAddresses = set.alreadyCovered
			detail.CoalescedSuggestions = append(detail.CoalescedSuggestions, suggestion)
		}
	}
	detail.AddressesPerMonitor = PerimeterModeCounts{FullTCP: perMonitor[0], SelectedTCP: perMonitor[1], UDP: perMonitor[2]}
	detail.MonitorsNeeded = PerimeterModeCounts{FullTCP: needed[0], SelectedTCP: needed[1], UDP: needed[2]}
	detail.SuggestionsTruncated = PerimeterModeFlags{FullTCP: truncated[0], SelectedTCP: truncated[1], UDP: truncated[2]}
	detail.CoalescedMonitorsNeeded = PerimeterModeCounts{FullTCP: coalescedNeeded[0], SelectedTCP: coalescedNeeded[1], UDP: coalescedNeeded[2]}
	detail.CoalescedSuggestionsTruncated = PerimeterModeFlags{FullTCP: coalescedTruncated[0], SelectedTCP: coalescedTruncated[1], UDP: coalescedTruncated[2]}
	detail.BudgetTooLow = PerimeterModeFlags{FullTCP: tooLow[0], SelectedTCP: tooLow[1], UDP: tooLow[2]}
	return detail, nil
}

// readPerimeterState reads, once each, the unit's unarchived jobs, their
// latest scans, active cycles and silence references, and its probe budget,
// and classifies every job as a monitor. The reads are separate queries, so
// a job edited between two of them can show briefly stale data until the
// console refetches; the report never writes.
func (a *App) readPerimeterState(ctx context.Context, ts *store.TenantStore) (perimeterState, error) {
	jobs, err := ts.ListJobs(ctx, false)
	if err != nil {
		return perimeterState{}, err
	}
	executions, err := ts.ListJobExecutionSummaries(ctx, false)
	if err != nil {
		return perimeterState{}, err
	}
	cycles, err := ts.ListActiveScanCycleSummaries(ctx, false)
	if err != nil {
		return perimeterState{}, err
	}
	references, err := ts.ListJobSilenceReferences(ctx)
	if err != nil {
		return perimeterState{}, err
	}
	// The budget is read once: it decides the states, the suggestion sizes
	// and the limits the response shows, so they never disagree.
	budget, err := a.tenantProbeBudget(ctx, ts)
	if err != nil {
		return perimeterState{}, err
	}
	state := perimeterState{now: a.nowUTC(), budget: budget, maxJobHosts: a.Config.Scanner.MaxJobHostsValue(), monitors: make([]perimeterMonitor, 0, len(jobs))}
	exclusions, _ := addrspace.TargetRanges(a.Config.Scanner.TargetExclusions)
	state.exclusions = addrspace.Merge(exclusions)
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	var covered [perimeterBuckets][]addrspace.Range
	for _, record := range jobs {
		monitor, err := a.classifyPerimeterMonitor(&state, record)
		if err != nil {
			return perimeterState{}, err
		}
		execution := executions[record.ID]
		if attempt := execution.LatestAttempt; attempt != nil {
			monitor.ref.LastAttemptStatus = attempt.Status
		}
		if success := execution.LatestSuccessfulScan; success != nil {
			currentHash := record.Job.SecurityHash()
			legacyHash := record.Job.LegacySecurityHash()
			monitor.ref.ScopeChanged = success.ConfigHash != currentHash && (legacyHash == "" || success.ConfigHash != legacyHash)
		}
		// The watchdog measures silence from the latest of the job's
		// creation, its eligibility and its latest successful scan.
		reference := record.CreatedAt
		if eligible := references[record.ID]; eligible.After(reference) {
			reference = eligible
		}
		if success := execution.LatestSuccessfulScan; success != nil && !success.FinishedAt.IsZero() {
			finished := success.FinishedAt.UTC()
			monitor.ref.LastSuccessAt = &finished
			if finished.After(reference) {
				reference = finished
			}
		}
		if monitor.ref.State == perimeterCovering {
			var silenceThreshold time.Duration
			monitor.ref.Stale, monitor.ref.StaleReason, silenceThreshold = perimeterStale(parser, record.Job, reference, state.now)
			cycle, active := cycles[record.ID]
			monitor.ref.StalledCycle = active && cycle.Status == "stalled"
			if active && ScanCycleHasRecentProgress(cycle, state.now, silenceThreshold) {
				attempt := execution.LatestAttempt
				if attempt != nil && attempt.Resumable && attempt.CycleID == cycle.ID && attempt.CycleStatus == "paused" {
					monitor.ref.CycleInProgress = true
					monitor.ref.CycleCompletedUnits = cycle.CompletedUnits
					monitor.ref.CycleTotalUnits = cycle.TotalUnits
				}
			}
			for _, bucket := range perimeterJobBuckets(record.Job) {
				covered[bucket] = append(covered[bucket], monitor.ranges...)
			}
		}
		state.monitors = append(state.monitors, monitor)
	}
	for bucket := range perimeterBuckets {
		state.buckets[bucket] = addrspace.Merge(covered[bucket])
	}
	return state, nil
}

// classifyPerimeterMonitor gives a job its state: every check a scheduled
// run would fail, in the order the run meets them.
func (a *App) classifyPerimeterMonitor(state *perimeterState, record store.JobRecord) (perimeterMonitor, error) {
	monitor := perimeterMonitor{ref: PerimeterMonitorRef{
		JobID: record.ID, Name: record.Job.Name, Reasons: []string{}, Protocols: []string{},
		HostDiscovery: record.Job.AssumeAlive != nil && !*record.Job.AssumeAlive,
	}}
	var ranges []addrspace.Range
	for _, target := range record.Job.Targets {
		ranged, ok := addrspace.TargetRange(target)
		if !ok {
			monitor.ref.DNSTargets++
			continue
		}
		monitor.targets = append(monitor.targets, perimeterTarget{value: target, ranged: ranged})
		ranges = append(ranges, ranged)
	}
	monitor.ranges = addrspace.Merge(ranges)
	for _, bucket := range perimeterJobBuckets(record.Job) {
		monitor.ref.Protocols = append(monitor.ref.Protocols, perimeterBucketNames[bucket])
	}

	if !record.Enabled {
		monitor.ref.Reasons = append(monitor.ref.Reasons, perimeterPaused)
	}
	// One estimate per job. Hosts is the scanner's own count: every IP and
	// CIDR target in full, overlapping targets again, as resolveTargets
	// counts them, and one per DNS name, as JobsBeyondHostCeiling counts.
	// Merged ranges never decide the expansion.
	estimate, err := config.EstimateJobWork(record.Job)
	if err != nil {
		a.perimeterLogger().Warn("a stored job no longer passes the scan work estimate, so the perimeter report counts it as invalid", "category", perimeterInvalidConfig, "job_id", record.ID, "error", err)
		monitor.ref.Reasons = append(monitor.ref.Reasons, perimeterInvalidConfig)
	} else {
		// The scheduler's preflight check, with the allow_high_cost ceiling.
		var budgetErr *ScanWorkBudgetError
		if err := checkEstimatedProbeBudget(state.budget, record.Job, estimate); errors.As(err, &budgetErr) {
			monitor.ref.Reasons = append(monitor.ref.Reasons, perimeterOverBudget)
		} else if err != nil {
			return perimeterMonitor{}, err
		}
		if estimate.Hosts > int64(min(record.Job.MaxExpandedHosts, state.maxJobHosts)) {
			monitor.ref.Reasons = append(monitor.ref.Reasons, perimeterOverExpansion)
		}
	}
	if perimeterOverlaps(state.exclusions, monitor.ranges) {
		monitor.ref.Reasons = append(monitor.ref.Reasons, perimeterExcludedTarget)
	}
	monitor.ref.State = perimeterCovering
	if len(monitor.ref.Reasons) > 0 {
		monitor.ref.State = monitor.ref.Reasons[0]
	}
	return monitor, nil
}

// unproven reports a covering monitor that has not proven its current scope:
// it has no successful scan for that scope, is stale, its cycle is stalled,
// or its latest attempt failed, timed out or was incomplete without recent
// resumable progress. Progress only preserves existing coverage proof; it
// cannot establish coverage before the first successful scan.
func (m perimeterMonitor) unproven() bool {
	if m.ref.State != perimeterCovering {
		return false
	}
	if m.ref.ScopeChanged || m.ref.LastSuccessAt == nil {
		return true
	}
	if !m.ref.CycleInProgress {
		switch m.ref.LastAttemptStatus {
		case "failed", "timed_out", "incomplete":
			return true
		}
	}
	return m.ref.Stale || m.ref.StalledCycle
}

// perimeterStale applies the job-silent watchdog's deadline to a monitor: it
// is overdue once reference is jobSilenceThreshold behind now. Unlike the
// watchdog, which waits while a scan holds the job's lease, it does not wait
// for a running scan: the coverage is unproven until that scan succeeds. A
// schedule that gives the watchdog no threshold, such as one that never
// fires, is stale too, because nothing ever scans it on schedule.
func perimeterStale(parser cron.Parser, job config.Job, reference, now time.Time) (bool, string, time.Duration) {
	if reference.IsZero() {
		// The watchdog skips a job without a reference.
		return false, "", 0
	}
	threshold, err := jobSilenceThreshold(parser, job, reference)
	if err != nil {
		return true, perimeterStaleNeverFires, 0
	}
	if now.Sub(reference) >= threshold {
		return true, perimeterStaleOverdue, threshold
	}
	return false, "", threshold
}

// perimeterJobBuckets returns the buckets a job's protocols fill: full TCP
// for Naabu or for Nmap over every port, any TCP for every TCP scan, and UDP
// for every UDP scan.
func perimeterJobBuckets(job config.Job) []int {
	var buckets []int
	if job.TCP != nil {
		engine := job.TCP.Engine
		if engine == config.EngineNaabuNmap || ((engine == "" || engine == config.EngineNmap) && config.CanonicalPortExpression(job.TCP.Ports) == config.NaabuFullPortExpression) {
			buckets = append(buckets, perimeterFullTCP)
		}
		buckets = append(buckets, perimeterAnyTCP)
	}
	if job.UDP != nil {
		buckets = append(buckets, perimeterUDP)
	}
	return buckets
}

// rangeView returns a declared range with its coverage and the monitors that
// touch it.
func (s *perimeterState) rangeView(seed store.PerimeterSeed, prefix netip.Prefix) PerimeterRange {
	whole := addrspace.FromPrefix(prefix)
	view := PerimeterRange{
		ID: seed.ID, Kind: seed.Kind, Value: seed.Value, Label: seed.Label, Family: 4,
		CreatedAt: seed.CreatedAt, CreatedBy: seed.CreatedBy, MonitorIDs: []string{},
	}
	covered := s.coveredCounts(s.scannable(whole))
	if prefix.Addr().Is4() {
		view.Addresses = perimeterCount([]addrspace.Range{whole})
		view.Excluded = perimeterCount(addrspace.Intersect([]addrspace.Range{whole}, perimeterClip(s.exclusions, whole)))
		view.Coverage = covered
	} else {
		view.Family = 6
		view.IPv6Monitored = covered
	}
	for _, monitor := range s.monitors {
		if perimeterOverlaps(monitor.ranges, []addrspace.Range{whole}) {
			view.MonitorIDs = append(view.MonitorIDs, monitor.ref.JobID)
		}
	}
	return view
}

// scannable returns the addresses of r outside scanner.target_exclusions.
func (s *perimeterState) scannable(r addrspace.Range) []addrspace.Range {
	return addrspace.Subtract([]addrspace.Range{r}, perimeterClip(s.exclusions, r))
}

// coveredCounts counts the addresses of base, which is merged, that each
// bucket covers.
func (s *perimeterState) coveredCounts(base []addrspace.Range) PerimeterCoverage {
	var counts [perimeterBuckets]uint64
	for bucket := range perimeterBuckets {
		var covered []addrspace.Range
		for _, r := range base {
			covered = append(covered, addrspace.Intersect([]addrspace.Range{r}, perimeterClip(s.buckets[bucket], r))...)
		}
		counts[bucket] = perimeterCount(covered)
	}
	return PerimeterCoverage{FullTCP: counts[perimeterFullTCP], AnyTCP: counts[perimeterAnyTCP], UDP: counts[perimeterUDP]}
}

// limits returns the limits the report applied.
func (s *perimeterState) limits() PerimeterLimits {
	return PerimeterLimits{
		MaxJobHosts: s.maxJobHosts, MaxProbeCount: s.budget.nmap, MaxNaabuProbeCount: s.budget.naabu,
		MaxRanges: store.MaxPerimeterRanges, MaxEntriesPerRequest: store.MaxPerimeterEntriesPerRequest,
	}
}

// addressesPerMonitor returns the most addresses that one monitor of the
// preset may hold: the lowest of scanner.max_job_hosts, each budget divided
// by the probes one address costs with that engine, and the mode's cap. The
// budgets are the unit's normal ones, never the high-cost ceiling. It is 0
// when one address does not fit the budget.
func (s *perimeterState) addressesPerMonitor(preset perimeterPreset) (uint64, error) {
	estimate, err := config.EstimateJobWork(preset.job([]string{"192.0.2.1"}))
	if err != nil {
		return 0, err
	}
	size := uint64(max(s.maxJobHosts, 0))
	for _, engine := range []struct{ budget, probes int64 }{{s.budget.naabu, estimate.NaabuProbes}, {s.budget.nmap, estimate.NmapProbes}} {
		if engine.probes > 0 {
			size = min(size, uint64(max(engine.budget, 0)/engine.probes))
		}
	}
	if preset.cap > 0 {
		size = min(size, preset.cap)
	}
	return size, nil
}

// job returns a job of the preset's protocol with targets, for an estimate.
func (preset perimeterPreset) job(targets []string) config.Job {
	protocol := &config.Protocol{Ports: preset.protocol.Ports, Mode: preset.protocol.Mode, ServiceDetection: preset.protocol.ServiceDetection, Engine: preset.protocol.Engine, ProfileID: preset.protocol.ProfileID}
	job := config.Job{Targets: targets}
	if preset.protocol.Protocol == "udp" {
		job.UDP = protocol
	} else {
		job.TCP = protocol
	}
	return job
}

// perimeterSuggestion returns the suggested monitor of one packed set.
func perimeterSuggestion(preset perimeterPreset, set []netip.Prefix) (PerimeterSuggestion, error) {
	suggestion := PerimeterSuggestion{Mode: preset.mode, Targets: make([]string, 0, len(set)), Protocol: preset.protocol}
	for _, prefix := range set {
		// A single address is a bare IP, as a saved job stores it.
		suggestion.Targets = append(suggestion.Targets, config.CanonicalTarget(prefix.String()))
		suggestion.Addresses += 1 << (prefix.Addr().BitLen() - prefix.Bits())
	}
	estimate, err := config.EstimateJobWork(preset.job(suggestion.Targets))
	if err != nil {
		return PerimeterSuggestion{}, err
	}
	suggestion.EstimatedProbes = estimate.Probes
	if preset.mode == "full_tcp" {
		// The built-in Naabu profile rate gives only a lower bound: host
		// response time, retries and Nmap enrichment can extend a real run.
		rate := int64(config.BuiltinNaabuProfile().Naabu.Rate)
		if rate > 0 && estimate.NaabuProbes > 0 {
			suggestion.MinimumDurationSeconds = estimate.NaabuProbes / rate
			if estimate.NaabuProbes%rate != 0 {
				suggestion.MinimumDurationSeconds++
			}
		}
	}
	return suggestion, nil
}

type perimeterCoalescedSet struct {
	targets        []netip.Prefix
	alreadyCovered int
}

// perimeterCoalescedSuggestionSets returns a complete alternative plan for
// gaps. It may expand a gap prefix to include already-covered addresses, but
// only while the larger prefix stays inside the scannable space. Targets are
// no larger than a /24 (and no larger than the mode's budget), suggestions
// hold at most 16 targets, and a plan needing more than 16 suggestions is
// withheld. A returned count of 17 means at least 17 suggestions were needed.
func perimeterCoalescedSuggestionSets(base, gaps []addrspace.Range, perMonitor uint64) (sets []perimeterCoalescedSet, total int, truncated bool) {
	if len(gaps) == 0 || perMonitor == 0 {
		return nil, 0, false
	}
	maxAddresses := min(perMonitor, uint64(1<<(32-perimeterMaxCoalescedPrefixBits)))
	minPrefixBits := max(perimeterMaxCoalescedPrefixBits, 32-(bits.Len64(maxAddresses)-1))
	seen := make(map[netip.Prefix]struct{})
	var current perimeterCoalescedSet
	var currentAddresses uint64
	hasOverlap := false
	tooMany := false

	flush := func() {
		if len(current.targets) == 0 {
			return
		}
		sets = append(sets, current)
		current = perimeterCoalescedSet{}
		currentAddresses = 0
	}
	add := func(piece netip.Prefix) bool {
		candidate := piece
		for candidate.Bits() > minPrefixBits {
			parent := netip.PrefixFrom(candidate.Addr(), candidate.Bits()-1).Masked()
			parentRange := addrspace.FromPrefix(parent)
			if len(addrspace.Subtract([]addrspace.Range{parentRange}, base)) != 0 {
				break
			}
			candidate = parent
		}
		if _, exists := seen[candidate]; exists {
			return true
		}

		candidateRange := addrspace.FromPrefix(candidate)
		addresses := uint64(1) << uint(32-candidate.Bits())
		gapAddresses, _ := addrspace.CountCapped(addrspace.Intersect([]addrspace.Range{candidateRange}, gaps), addresses)
		alreadyCovered := int(addresses - gapAddresses)
		hasOverlap = hasOverlap || alreadyCovered > 0
		if tooMany {
			// Keep scanning only until an overlap proves this is a coalesced
			// alternative. A covered block can come after the output limit.
			return !hasOverlap
		}
		if len(current.targets) > 0 && (currentAddresses+addresses > perMonitor || len(current.targets) >= perimeterMaxCoalescedTargets) {
			flush()
			if len(sets) >= perimeterMaxCoalescedSuggestions {
				tooMany = true
				return !hasOverlap
			}
		}
		seen[candidate] = struct{}{}
		current.targets = append(current.targets, candidate)
		currentAddresses += addresses
		current.alreadyCovered += alreadyCovered
		return true
	}

	var walkPrefix func(netip.Prefix, func(netip.Prefix) bool) bool
	walkPrefix = func(prefix netip.Prefix, visit func(netip.Prefix) bool) bool {
		if prefix.Bits() >= minPrefixBits {
			return visit(prefix)
		}
		childBits := prefix.Bits() + 1
		left := netip.PrefixFrom(prefix.Addr(), childBits).Masked()
		right := netip.PrefixFrom(addrspace.FromPrefix(left).To.Next(), childBits).Masked()
		return walkPrefix(left, visit) && walkPrefix(right, visit)
	}
	for _, gap := range gaps {
		for _, prefix := range addrspace.Cover(gap) {
			if !walkPrefix(prefix, add) {
				break
			}
		}
		if tooMany && hasOverlap {
			break
		}
	}
	if !hasOverlap {
		return nil, 0, false
	}
	if tooMany {
		return nil, perimeterMaxCoalescedSuggestions + 1, true
	}
	flush()
	return sets, len(sets), false
}

// perimeterBlocks returns the fewest aligned CIDRs that hold gaps, which is
// merged, at most perimeterMaxUncovered of them.
func perimeterBlocks(gaps []addrspace.Range) PerimeterBlocks {
	blocks := PerimeterBlocks{CIDRs: []string{}}
	for _, gap := range gaps {
		for _, prefix := range addrspace.Cover(gap) {
			blocks.Total++
			if len(blocks.CIDRs) < perimeterMaxUncovered {
				blocks.CIDRs = append(blocks.CIDRs, prefix.String())
			}
		}
	}
	blocks.Truncated = blocks.Total > len(blocks.CIDRs)
	return blocks
}

// perimeterSeedPrefix returns the prefix of a declared range, and false for a
// row the report does not cover: a kind other than prefix or authorized, or
// a value that is not a CIDR.
func perimeterSeedPrefix(seed store.PerimeterSeed) (netip.Prefix, bool) {
	if seed.Kind != store.PerimeterKindPrefix && seed.Kind != store.PerimeterKindAuthorized {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(seed.Value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// perimeterIPv4 returns the IPv4 ranges of merged, which Merge orders before
// the IPv6 ranges.
func perimeterIPv4(merged []addrspace.Range) []addrspace.Range {
	end := sort.Search(len(merged), func(i int) bool { return merged[i].From.Is6() })
	return merged[:end]
}

// perimeterClip returns the ranges of merged, in the form Merge returns, that
// share an address with r. Compare orders every IPv4 address before every
// IPv6 address, so a range of the other family is never returned.
func perimeterClip(merged []addrspace.Range, r addrspace.Range) []addrspace.Range {
	start := sort.Search(len(merged), func(i int) bool { return merged[i].To.Compare(r.From) >= 0 })
	end := start + sort.Search(len(merged)-start, func(i int) bool { return merged[start+i].From.Compare(r.To) > 0 })
	return merged[start:end]
}

// perimeterOverlaps reports whether any range of ranges shares an address
// with merged, which Merge returned.
func perimeterOverlaps(merged, ranges []addrspace.Range) bool {
	for _, r := range ranges {
		if len(perimeterClip(merged, r)) > 0 {
			return true
		}
	}
	return false
}

// perimeterCount counts the addresses of ranges, saturating.
func perimeterCount(ranges []addrspace.Range) uint64 {
	count, _ := addrspace.CountCapped(ranges, perimeterCountLimit)
	return count
}

func (a *App) perimeterLogger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}
