package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
}

// ActiveScan describes a scan that has acquired its lease and is currently
// executing. It intentionally contains metadata only; the result is not
// persisted until the scanner reaches a terminal state.
type ActiveScan struct {
	ID          string    `json:"id"`
	JobID       string    `json:"job_id,omitempty"`
	Job         string    `json:"job"`
	JobRevision int64     `json:"job_revision,omitempty"`
	StartedAt   time.Time `json:"started_at"`
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
	Type      string    `json:"type"`
	JobID     string    `json:"job_id,omitempty"`
	Job       string    `json:"job"`
	ScanID    string    `json:"scan_id,omitempty"`
	Message   string    `json:"message"`
	Changes   []Change  `json:"changes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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
