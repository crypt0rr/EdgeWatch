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

func New(path string) *Nmap {
	if path == "" {
		path = "nmap"
	}
	return &Nmap{Path: path, Resolver: net.DefaultResolver}
}

type resolvedTarget struct {
	Name      string
	Addresses []string
	Aggregate bool
	Hostname  bool
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
	targets, err := n.resolve(ctx, job)
	if err != nil {
		return model.Snapshot{}, err
	}
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
		units, err := n.scanProtocolBatch(ctx, targets, "tcp", *job.TCP, job.Timing, job.AssumesAlive())
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("tcp scan: %w", err)
		}
		snap.Units = append(snap.Units, units...)
	}
	if job.UDP != nil {
		for _, rt := range targets {
			snap.Scopes = append(snap.Scopes, model.Scope{Target: rt.Name, Protocol: "udp", Ports: job.UDP.Ports, ServiceDetection: job.UDP.ServiceDetection})
		}
		units, err := n.scanProtocolBatch(ctx, targets, "udp", *job.UDP, job.Timing, job.AssumesAlive())
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("udp scan: %w", err)
		}
		snap.Units = append(snap.Units, units...)
	}
	snap.Normalize()
	return snap, nil
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
			out = append(out, resolvedTarget{Name: ip.String(), Addresses: []string{ip.String()}})
			continue
		}
		if ip, network, err := net.ParseCIDR(raw); err == nil {
			for current := ip.Mask(network.Mask); network.Contains(current); incrementIP(current) {
				count++
				if count > job.MaxExpandedHosts {
					return nil, fmt.Errorf("expanded targets exceed max_expanded_hosts=%d", job.MaxExpandedHosts)
				}
				value := current.String()
				out = append(out, resolvedTarget{Name: value, Addresses: []string{value}})
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
		out = append(out, resolvedTarget{Name: strings.ToLower(raw), Addresses: addresses, Aggregate: true, Hostname: true})
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
				return nil, fmt.Errorf("scan timed out or cancelled: %w", ctx.Err())
			}
			if err != nil {
				return nil, fmt.Errorf("nmap failed: %v: %s", err, sanitizeStderr(stderr.String()))
			}
			parsed, err := parseXML(stdout, protocol, pc.ServiceDetection)
			if err != nil {
				return nil, err
			}
			if parsed.Exit != "success" {
				return nil, fmt.Errorf("nmap run incomplete: %s", parsed.Exit)
			}
			for _, address := range batch {
				unit, ok := parsed.Units[address]
				if !ok {
					return nil, fmt.Errorf("nmap output omitted expected address %s", address)
				}
				all[address] = unit
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
	return units, nil
}

func nmapArgs(family int, protocol string, pc config.Protocol, timing string, assumeAlive bool, addresses []string) []string {
	args := []string{"-n", "-oX", "-", "-p", pc.Ports, timingArg(timing)}
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
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string   `xml:"name,attr"`
				Product string   `xml:"product,attr"`
				Version string   `xml:"version,attr"`
				Extra   string   `xml:"extrainfo,attr"`
				Method  string   `xml:"method,attr"`
				CPES    []string `xml:"cpe"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
	RunStats struct {
		Exit string `xml:"exit,attr"`
	} `xml:"runstats>finished"`
}
type parsedRun struct {
	Exit  string
	Units map[string]model.Unit
}

func parseXML(data []byte, protocol string, detectService bool) (parsedRun, error) {
	var raw nmapRun
	if err := xml.Unmarshal(data, &raw); err != nil {
		return parsedRun{}, fmt.Errorf("parse nmap XML: %w", err)
	}
	result := parsedRun{Exit: raw.RunStats.Exit, Units: map[string]model.Unit{}}
	for _, host := range raw.Hosts {
		if host.Status.State != "up" {
			continue
		}
		var address string
		for _, a := range host.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				address = a.Addr
				break
			}
		}
		if address == "" {
			continue
		}
		unit := model.Unit{Target: address, Protocol: protocol, Addresses: []string{address}}
		for _, p := range host.Ports {
			if p.Protocol != protocol || p.State.State != "open" && p.State.State != "open|filtered" {
				continue
			}
			state := model.PortState{Port: p.PortID, State: p.State.State, Evidence: []string{address}}
			if detectService && p.Service.Method == "probed" {
				state.Service = model.Fingerprint(p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Extra, p.Service.CPES)
			}
			unit.Ports = append(unit.Ports, state)
		}
		result.Units[address] = unit
	}
	return result, nil
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
