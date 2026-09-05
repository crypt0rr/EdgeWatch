package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type PortState struct {
	Port     int      `json:"port"`
	State    string   `json:"state"`
	Service  string   `json:"service,omitempty"`
	Evidence []string `json:"addresses,omitempty"`
}

type Unit struct {
	Target    string      `json:"target"`
	Protocol  string      `json:"protocol"`
	Addresses []string    `json:"addresses,omitempty"`
	Ports     []PortState `json:"ports,omitempty"`
}

// HostObservation is the technical, per-effective-address evidence captured
// from one or more protocol scans. Units remain the compact logical view used
// by the baseline/change engine; observations deliberately do not participate
// in that comparison.
type HostObservation struct {
	Address       string                `json:"address"`
	SourceTargets []string              `json:"source_targets,omitempty"`
	DNSNames      []string              `json:"dns_names,omitempty"`
	AddressFamily string                `json:"address_family,omitempty"`
	Status        string                `json:"status,omitempty"`
	StatusReason  string                `json:"status_reason,omitempty"`
	ReasonTTL     int                   `json:"reason_ttl,omitempty"`
	LatencyMS     float64               `json:"latency_ms,omitempty"`
	LinkAddresses []LinkAddress         `json:"link_addresses,omitempty"`
	Hostnames     []Hostname            `json:"hostnames,omitempty"`
	Protocols     []ProtocolObservation `json:"protocols,omitempty"`
}

type LinkAddress struct {
	Address string `json:"address"`
	Type    string `json:"type,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
}

type Hostname struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type ProtocolObservation struct {
	Protocol         string            `json:"protocol"`
	ScanType         string            `json:"scan_type,omitempty"`
	ScannedPorts     string            `json:"scanned_ports"`
	ScannedPortCount int               `json:"scanned_port_count"`
	ServiceDetection bool              `json:"service_detection"`
	Ports            []PortObservation `json:"ports,omitempty"`
	StateSummaries   []StateSummary    `json:"state_summaries,omitempty"`
}

type PortObservation struct {
	Port      int                 `json:"port"`
	State     string              `json:"state"`
	Reason    string              `json:"reason,omitempty"`
	ReasonTTL int                 `json:"reason_ttl,omitempty"`
	Service   *ServiceObservation `json:"service,omitempty"`
}

type ServiceObservation struct {
	Name       string   `json:"name,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	ExtraInfo  string   `json:"extra_info,omitempty"`
	Method     string   `json:"method,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Tunnel     string   `json:"tunnel,omitempty"`
	OSType     string   `json:"os_type,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

type StateSummary struct {
	State   string        `json:"state"`
	Count   int           `json:"count"`
	Reasons []StateReason `json:"reasons,omitempty"`
}

type StateReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type Scope struct {
	Target           string `json:"target"`
	Protocol         string `json:"protocol"`
	Ports            string `json:"ports"`
	ServiceDetection bool   `json:"service_detection"`
}

type Snapshot struct {
	Units  []Unit              `json:"units"`
	Scopes []Scope             `json:"scopes"`
	DNS    map[string][]string `json:"dns,omitempty"`
	Hosts  []HostObservation   `json:"hosts,omitempty"`
}

type Scan struct {
	ID          string    `json:"id"`
	JobID       string    `json:"job_id,omitempty"`
	Job         string    `json:"job"`
	JobRevision int64     `json:"job_revision,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
	NmapVersion string    `json:"nmap_version,omitempty"`
	ConfigHash  string    `json:"config_hash"`
	// BaselineScanID and BaselineConfigHash identify the comparison used when
	// this scan was processed. Changes is the immutable scan-time diff; list
	// endpoints intentionally use ScanSummary instead of loading it.
	BaselineScanID     string   `json:"baseline_scan_id,omitempty"`
	BaselineConfigHash string   `json:"baseline_config_hash,omitempty"`
	Changes            []Change `json:"changes,omitempty"`
	Snapshot           Snapshot `json:"snapshot"`
}

// ScanSummary is the metadata needed for history and dashboard lists. Full
// snapshots remain available through the scan detail/results endpoints and are
// intentionally not loaded for paginated list responses.
type ScanSummary struct {
	ID                 string    `json:"id"`
	JobID              string    `json:"job_id,omitempty"`
	Job                string    `json:"job"`
	JobRevision        int64     `json:"job_revision,omitempty"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
	Status             string    `json:"status"`
	Error              string    `json:"error,omitempty"`
	NmapVersion        string    `json:"nmap_version,omitempty"`
	ConfigHash         string    `json:"config_hash"`
	BaselineScanID     string    `json:"baseline_scan_id,omitempty"`
	BaselineConfigHash string    `json:"baseline_config_hash,omitempty"`
}

// ActiveScan describes a scan that has acquired its lease and is currently
// executing. It intentionally contains metadata only; the result is not
// persisted until the scanner reaches a terminal state.
type ActiveScan struct {
	ID                   string    `json:"id"`
	JobID                string    `json:"job_id,omitempty"`
	Job                  string    `json:"job"`
	JobRevision          int64     `json:"job_revision,omitempty"`
	StartedAt            time.Time `json:"started_at"`
	EstimatedProbes      int64     `json:"estimated_probes,omitempty"`
	NmapInvocations      int64     `json:"nmap_invocations,omitempty"`
	EstimatedSeconds     int64     `json:"estimated_seconds,omitempty"`
	CompletedProbes      int64     `json:"completed_probes,omitempty"`
	TotalProbes          int64     `json:"total_probes,omitempty"`
	CompletedInvocations int64     `json:"completed_invocations,omitempty"`
	TotalInvocations     int64     `json:"total_invocations,omitempty"`
	ProgressPercent      int       `json:"progress_percent"`
	Phase                string    `json:"phase,omitempty"`
}

type Change struct {
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	Old      string `json:"old,omitempty"`
	New      string `json:"new,omitempty"`
}

type Pending struct {
	Change Change `json:"change"`
	Count  int    `json:"count"`
}

type ValueCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type Incident struct {
	Change        Change    `json:"change"`
	OpenedAt      time.Time `json:"opened_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	RecoveryCount int       `json:"recovery_count"`
}

type JobState struct {
	Baseline              *Snapshot             `json:"baseline,omitempty"`
	BaselineScanID        string                `json:"baseline_scan_id,omitempty"`
	BaselineConfigHash    string                `json:"baseline_config_hash,omitempty"`
	Candidate             *Snapshot             `json:"candidate,omitempty"`
	CandidateHash         string                `json:"candidate_hash,omitempty"`
	CandidateCount        int                   `json:"candidate_count"`
	CandidateAttempts     int                   `json:"candidate_attempts"`
	Pending               map[string]Pending    `json:"pending,omitempty"`
	Incidents             map[string]Incident   `json:"incidents,omitempty"`
	FingerprintCandidates map[string]ValueCount `json:"fingerprint_candidates,omitempty"`
	ConsecutiveFailures   int                   `json:"consecutive_failures"`
	LastFailureAlert      int                   `json:"last_failure_alert"`
}

type Event struct {
	Type             string    `json:"type"`
	JobID            string    `json:"job_id,omitempty"`
	Job              string    `json:"job"`
	ScanID           string    `json:"scan_id,omitempty"`
	Message          string    `json:"message"`
	Changes          []Change  `json:"changes,omitempty"`
	ChangesCount     int       `json:"changes_count,omitempty"`
	ChangesTruncated bool      `json:"changes_truncated,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// EventPayloadLimit is the maximum serialized size of a durable event or
// notification outbox payload. Change details remain available on the scan
// history endpoint; oversized alert events carry a bounded summary instead.
const EventPayloadLimit = 64 << 10

// MarshalBoundedEvent serializes an event under the product payload ceiling.
// If its change list or message is too large, it replaces the detail with an
// explicit summary so callers never write an unbounded event/outbox row.
func MarshalBoundedEvent(event Event, max int) (Event, []byte, error) {
	if max <= 0 {
		max = EventPayloadLimit
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return event, nil, err
	}
	if len(payload) <= max {
		return event, payload, nil
	}
	if len(event.Changes) > 0 {
		event.ChangesCount = len(event.Changes)
		event.Changes = nil
		event.ChangesTruncated = true
	}
	if event.Message == "" {
		event.Message = "Event details exceeded the payload limit"
	} else {
		event.Message += " (details truncated)"
	}
	payload, err = json.Marshal(event)
	if err != nil {
		return event, nil, err
	}
	if len(payload) <= max {
		return event, payload, nil
	}
	// A caller could supply an arbitrarily large message even without changes.
	// Trim it by runes so the fallback remains valid UTF-8 and retain enough
	// metadata to diagnose the overflow.
	runes := []rune(event.Message)
	for len(payload) > max && len(runes) > 0 {
		runes = runes[:len(runes)-1]
		event.Message = string(runes)
		payload, err = json.Marshal(event)
		if err != nil {
			return event, nil, err
		}
	}
	if len(payload) <= max {
		return event, payload, nil
	}
	// The fixed metadata fields are comfortably below the default ceiling. If
	// a caller passes an unusually tiny max, return the marshal error rather
	// than silently exceeding the requested contract.
	return event, nil, fmt.Errorf("event payload exceeds %d bytes", max)
}

func (s *Snapshot) Normalize() {
	for i := range s.Units {
		sort.Strings(s.Units[i].Addresses)
		for j := range s.Units[i].Ports {
			sort.Strings(s.Units[i].Ports[j].Evidence)
		}
		sort.Slice(s.Units[i].Ports, func(a, b int) bool { return s.Units[i].Ports[a].Port < s.Units[i].Ports[b].Port })
	}
	sort.Slice(s.Units, func(i, j int) bool {
		return s.Units[i].Target+"\x00"+s.Units[i].Protocol < s.Units[j].Target+"\x00"+s.Units[j].Protocol
	})
	sort.Slice(s.Scopes, func(i, j int) bool {
		return s.Scopes[i].Target+"\x00"+s.Scopes[i].Protocol < s.Scopes[j].Target+"\x00"+s.Scopes[j].Protocol
	})
	for key := range s.DNS {
		sort.Strings(s.DNS[key])
	}
	for i := range s.Hosts {
		host := &s.Hosts[i]
		if ip := net.ParseIP(strings.TrimSpace(host.Address)); ip != nil {
			host.Address = ip.String()
		} else {
			host.Address = strings.TrimSpace(host.Address)
		}
		sort.Strings(host.SourceTargets)
		sort.Strings(host.DNSNames)
		sort.Slice(host.LinkAddresses, func(a, b int) bool {
			if host.LinkAddresses[a].Type == host.LinkAddresses[b].Type {
				return host.LinkAddresses[a].Address < host.LinkAddresses[b].Address
			}
			return host.LinkAddresses[a].Type < host.LinkAddresses[b].Type
		})
		sort.Slice(host.Hostnames, func(a, b int) bool {
			if host.Hostnames[a].Name == host.Hostnames[b].Name {
				return host.Hostnames[a].Type < host.Hostnames[b].Type
			}
			return host.Hostnames[a].Name < host.Hostnames[b].Name
		})
		for j := range host.Protocols {
			protocol := &host.Protocols[j]
			sort.Slice(protocol.Ports, func(a, b int) bool { return protocol.Ports[a].Port < protocol.Ports[b].Port })
			for k := range protocol.Ports {
				if protocol.Ports[k].Service != nil {
					sort.Strings(protocol.Ports[k].Service.CPEs)
				}
			}
			for k := range protocol.StateSummaries {
				sort.Slice(protocol.StateSummaries[k].Reasons, func(a, b int) bool {
					return protocol.StateSummaries[k].Reasons[a].Reason < protocol.StateSummaries[k].Reasons[b].Reason
				})
			}
			sort.Slice(protocol.StateSummaries, func(a, b int) bool { return protocol.StateSummaries[a].State < protocol.StateSummaries[b].State })
		}
		sort.Slice(host.Protocols, func(a, b int) bool { return host.Protocols[a].Protocol < host.Protocols[b].Protocol })
	}
	sort.Slice(s.Hosts, func(i, j int) bool { return s.Hosts[i].Address < s.Hosts[j].Address })
}

func (s Snapshot) Hash() string {
	b, _ := json.Marshal(s)
	var stable Snapshot
	_ = json.Unmarshal(b, &stable)
	for i := range stable.Units {
		for j := range stable.Units[i].Ports {
			stable.Units[i].Ports[j].Service = ""
			stable.Units[i].Ports[j].Evidence = nil
		}
	}
	// Host observations are descriptive evidence (latency, discovery reason,
	// service metadata, and state summaries), not baseline identity. Keep them
	// out of convergence and security hashes so richer output never creates a
	// false change or forces a rebaseline.
	stable.Hosts = nil
	stable.Normalize()
	b, _ = json.Marshal(stable)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Fingerprint(name, product, version, extra string, cpes []string) string {
	parts := []string{name, product, version, extra}
	sort.Strings(cpes)
	parts = append(parts, cpes...)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, " | ")
}

func ChangeSummary(c Change) string {
	switch c.Kind {
	case "dns-added", "dns-removed":
		return fmt.Sprintf("%s %s: %s", c.Target, c.Kind, nonempty(c.New, c.Old))
	case "service":
		return fmt.Sprintf("%s %s/%d service: %s -> %s", c.Target, c.Protocol, c.Port, c.Old, c.New)
	default:
		return fmt.Sprintf("%s %s/%d: %s -> %s", c.Target, c.Protocol, c.Port, c.Old, c.New)
	}
}

func nonempty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return "unknown"
}
