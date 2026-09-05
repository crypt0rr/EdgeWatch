package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}
type Nmap struct {
	Path     string
	Resolver Resolver
}

// Progress describes the bounded, operator-facing work completed by a scan.
// Counts are based on resolved addresses and ports, and are deliberately
// estimates of Nmap probes rather than an SLA for network response time.
type Progress struct {
	CompletedProbes      int64
	TotalProbes          int64
	CompletedInvocations int64
	TotalInvocations     int64
	Phase                string
}

// ProgressReporter receives scan progress after resolution and each completed
// Nmap invocation. Implementations must not retain or call it after Scan
// returns.
type ProgressReporter func(Progress)

func New(path string) *Nmap {
	if path == "" {
		path = "nmap"
	}
	return &Nmap{Path: path, Resolver: net.DefaultResolver}
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

func (n *Nmap) Scan(ctx context.Context, job config.Job) (model.Snapshot, error) {
	return n.ScanWithProgress(ctx, job, nil)
}

// ScanWithProgress is the cancellable scanner entry point used by the web
// console. The legacy Scan method delegates here so test and plugin scanners
// do not need to implement progress reporting.
func (n *Nmap) ScanWithProgress(ctx context.Context, job config.Job, report ProgressReporter) (model.Snapshot, error) {
	reportProgress(report, Progress{Phase: "resolving"})
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
	totalProbes, totalInvocations := progressTotals(targets, job)
	progress := Progress{TotalProbes: totalProbes, TotalInvocations: totalInvocations, Phase: "scanning"}
	reportProgress(report, progress)
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
		result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "tcp", *job.TCP, job.Timing, job.AssumesAlive(), func(invocations, probes int64) {
			progress.CompletedInvocations += invocations
			progress.CompletedProbes += probes
			reportProgress(report, progress)
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
		result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, "udp", *job.UDP, job.Timing, job.AssumesAlive(), func(invocations, probes int64) {
			progress.CompletedInvocations += invocations
			progress.CompletedProbes += probes
			reportProgress(report, progress)
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
	reportProgress(report, progress)
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
	result, err := n.scanProtocolBatchDetailedProgress(ctx, targets, protocol, pc, timing, assumeAlive, report)
	return result.Units, err
}

type protocolScanResult struct {
	Units []model.Unit
	Hosts map[string]model.HostObservation
}

// scanProtocolBatchDetailedProgress retains the compact units used by the
// comparison engine and, alongside them, detailed per-effective-address
// observations for the host explorer. The two representations intentionally
// have separate lifecycles: descriptive host evidence never affects hashes.
func (n *Nmap) scanProtocolBatchDetailedProgress(ctx context.Context, targets []resolvedTarget, protocol string, pc config.Protocol, timing string, assumeAlive bool, report func(int64, int64)) (protocolScanResult, error) {
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
	for _, family := range []int{4, 6} {
		addresses := byFamily[family]
		for start := 0; start < len(addresses); start += nmapBatchSize {
			end := min(start+nmapBatchSize, len(addresses))
			batch := addresses[start:end]
			args := nmapArgs(family, protocol, pc, timing, assumeAlive, batch)
			cmd := exec.CommandContext(ctx, n.Path, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if ctx.Err() != nil {
				return protocolScanResult{}, fmt.Errorf("scan timed out or cancelled: %w", ctx.Err())
			}
			if err != nil {
				return protocolScanResult{}, fmt.Errorf("nmap failed: %v: %s", err, sanitizeStderr(stderr.String()))
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
					mergeHostObservationMap(allHosts, address, host)
				}
			}
			if report != nil {
				ports, _ := config.ParsePorts(pc.Ports)
				factor := int64(1)
				if pc.ServiceDetection {
					factor = 2
				}
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
	args := []string{"-n", "-oX", "-", "-p", pc.Ports, timingArg(timing), "--reason"}
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
	return append(args, addresses...)
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
		observation := model.ProtocolObservation{Protocol: protocol, ScanType: scanType(protocol, pc), ScannedPorts: pc.Ports, ServiceDetection: pc.ServiceDetection}
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
			state := model.PortState{Port: p.PortID, State: p.State.State, Evidence: []string{address}}
			if pc.ServiceDetection && p.Service.Method == "probed" {
				state.Service = model.Fingerprint(p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Extra, p.Service.CPES)
			}
			unit.Ports = append(unit.Ports, state)
			port := model.PortObservation{Port: p.PortID, State: p.State.State, Reason: p.State.Reason, ReasonTTL: p.State.TTL}
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
	if current.Status == "" {
		current.Status, current.StatusReason, current.ReasonTTL, current.LatencyMS = addition.Status, addition.StatusReason, addition.ReasonTTL, addition.LatencyMS
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
		if protocol.ScanType == "" {
			protocol.ScanType = incoming.ScanType
		}
		if protocol.ScannedPorts == "" {
			protocol.ScannedPorts = incoming.ScannedPorts
		}
		if incoming.ScannedPortCount > protocol.ScannedPortCount {
			protocol.ScannedPortCount = incoming.ScannedPortCount
		}
		protocol.ServiceDetection = protocol.ServiceDetection || incoming.ServiceDetection
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
