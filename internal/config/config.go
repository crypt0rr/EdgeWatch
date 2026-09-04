package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	raw := node.Value
	if strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(raw, "d"), 64)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", node.Value, err)
		}
		*d = Duration(days * float64(24*time.Hour))
		return nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(v)
	return nil
}
func (d Duration) Value() time.Duration { return time.Duration(d) }

type Config struct {
	Version       int           `yaml:"version"`
	Database      string        `yaml:"database"`
	Retention     Duration      `yaml:"retention"`
	Scheduler     Scheduler     `yaml:"scheduler"`
	Web           Web           `yaml:"web"`
	Notifications Notifications `yaml:"notifications"`
	Jobs          []Job         `yaml:"jobs"`
}

// Web contains the local administrative HTTP listener settings. The v0.3
// appliance deliberately only permits loopback listeners; users who need
// remote access should put a TLS reverse proxy or an SSH tunnel in front of it.
type Web struct {
	Listen      string `yaml:"listen"`
	AuthKeyFile string `yaml:"auth_key_file"`
}
type Scheduler struct {
	MaxConcurrent int   `yaml:"max_concurrent_scans"`
	MaxProbeCount int64 `yaml:"max_probe_count"`
}
type Notifications struct {
	URLs              []string `yaml:"urls"`
	URLsFile          string   `yaml:"urls_file"`
	EncryptionKeyFile string   `yaml:"encryption_key_file"`
}
type Job struct {
	Name             string    `yaml:"name"`
	Schedule         string    `yaml:"schedule"`
	Timezone         string    `yaml:"timezone"`
	RunOnStart       *bool     `yaml:"run_on_start"`
	AssumeAlive      *bool     `yaml:"assume_alive"`
	Targets          []string  `yaml:"targets"`
	MaxExpandedHosts int       `yaml:"max_expanded_hosts"`
	TCP              *Protocol `yaml:"tcp"`
	UDP              *Protocol `yaml:"udp"`
	Timing           string    `yaml:"timing"`
	Timeout          Duration  `yaml:"timeout"`
	Baseline         Baseline  `yaml:"baseline"`
	Change           Change    `yaml:"change"`
	AllowHighCost    bool      `yaml:"allow_high_cost,omitempty"`
}
type Protocol struct {
	Ports            string `yaml:"ports"`
	Mode             string `yaml:"mode,omitempty"`
	ServiceDetection bool   `yaml:"service_detection"`
}
type Baseline struct {
	Samples int `yaml:"samples"`
}
type Change struct {
	Confirmations int `yaml:"confirmations"`
}

var envOnly = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

func Load(path string) (*Config, error) {
	cfg, err := decode(path)
	if err != nil {
		return nil, err
	}
	if err := resolveNotifications(cfg); err != nil {
		return nil, err
	}
	// YAML jobs are retained only as inactive migration hints. Their shape is
	// still decoded strictly, but semantic validation belongs to web-managed
	// jobs and must not prevent an installation from starting.
	if err := cfg.ValidateDeployment(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadForAdmin reads only the deployment values required to open the database
// for host-authorized recovery commands. It deliberately skips notification
// secret loading, web-listener validation, and inactive legacy-job validation so
// recovery remains available when monitor configuration is broken.
func LoadForAdmin(path string) (*Config, error) {
	cfg, err := decode(path)
	if err != nil {
		return nil, err
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Database == "" {
		return nil, fmt.Errorf("database path is required")
	}
	return cfg, nil
}

func decode(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	var trailing yaml.Node
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("configuration must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("read trailing YAML document: %w", err)
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func resolveNotifications(cfg *Config) error {
	for i, raw := range cfg.Notifications.URLs {
		if match := envOnly.FindStringSubmatch(raw); match != nil {
			value, ok := os.LookupEnv(match[1])
			if !ok {
				return fmt.Errorf("environment variable %s is not set", match[1])
			}
			cfg.Notifications.URLs[i] = value
		}
	}
	if cfg.Notifications.URLsFile != "" {
		secret, err := os.ReadFile(cfg.Notifications.URLsFile)
		if err != nil {
			return fmt.Errorf("read notification URLs file: %w", err)
		}
		for _, line := range strings.Split(string(secret), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				cfg.Notifications.URLs = append(cfg.Notifications.URLs, line)
			}
		}
	}
	return nil
}

func applyDefaults(c *Config) {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Database == "" {
		c.Database = "/var/lib/edgewatch/edgewatch.db"
	}
	if c.Retention == 0 {
		c.Retention = Duration(90 * 24 * time.Hour)
	}
	if c.Scheduler.MaxConcurrent == 0 {
		c.Scheduler.MaxConcurrent = 1
	}
	if c.Scheduler.MaxProbeCount == 0 {
		c.Scheduler.MaxProbeCount = DefaultMaxProbeCount
	}
	if c.Web.Listen == "" {
		c.Web.Listen = "127.0.0.1:8080"
	}
	for i := range c.Jobs {
		j := &c.Jobs[i]
		if j.RunOnStart == nil {
			runOnStart := true
			j.RunOnStart = &runOnStart
		}
		if j.Timezone == "" {
			j.Timezone = "UTC"
		}
		if j.MaxExpandedHosts == 0 {
			j.MaxExpandedHosts = 256
		}
		if j.Timing == "" {
			j.Timing = "balanced"
		}
		if j.Timeout == 0 {
			j.Timeout = Duration(time.Hour)
		}
		if j.AssumeAlive == nil {
			assumeAlive := true
			j.AssumeAlive = &assumeAlive
		}
		if j.Baseline.Samples == 0 {
			j.Baseline.Samples = 1
		}
		if j.Change.Confirmations == 0 {
			j.Change.Confirmations = 1
		}
		if j.TCP != nil && j.TCP.Mode == "" {
			j.TCP.Mode = "syn"
		}
	}
}

func (c Config) Validate() error {
	if err := c.ValidateDeployment(); err != nil {
		return err
	}
	seen := map[string]bool{}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	for _, j := range c.Jobs {
		if j.Name == "" || seen[j.Name] {
			return fmt.Errorf("job names must be non-empty and unique: %q", j.Name)
		}
		seen[j.Name] = true
		if _, err := time.LoadLocation(j.Timezone); err != nil {
			return fmt.Errorf("job %s: invalid timezone: %w", j.Name, err)
		}
		schedule := strings.TrimSpace(j.Schedule)
		if strings.HasPrefix(schedule, "TZ=") || strings.HasPrefix(schedule, "CRON_TZ=") {
			return fmt.Errorf("job %s: schedule must contain five cron fields; set timezone in the timezone field", j.Name)
		}
		if _, err := parser.Parse(schedule); err != nil {
			return fmt.Errorf("job %s: invalid schedule: %w", j.Name, err)
		}
		if len(j.Targets) == 0 {
			return fmt.Errorf("job %s: at least one target is required", j.Name)
		}
		if j.TCP == nil && j.UDP == nil {
			return fmt.Errorf("job %s: tcp or udp must be configured", j.Name)
		}
		if j.MaxExpandedHosts < 1 || j.MaxExpandedHosts > 1_000_000 {
			return fmt.Errorf("job %s: max_expanded_hosts out of range", j.Name)
		}
		if j.Baseline.Samples < 1 || j.Baseline.Samples > 100 {
			return fmt.Errorf("job %s: baseline samples must be 1..100", j.Name)
		}
		if j.Change.Confirmations < 1 || j.Change.Confirmations > 100 {
			return fmt.Errorf("job %s: change confirmations must be 1..100", j.Name)
		}
		if j.Timeout.Value() < time.Second {
			return fmt.Errorf("job %s: timeout must be at least 1s", j.Name)
		}
		if j.Timing != "conservative" && j.Timing != "balanced" && j.Timing != "fast" {
			return fmt.Errorf("job %s: timing must be conservative, balanced, or fast", j.Name)
		}
		targets := map[string]bool{}
		for _, target := range j.Targets {
			if err := validateTarget(target); err != nil {
				return fmt.Errorf("job %s: %w", j.Name, err)
			}
			canonical := CanonicalTarget(target)
			if targets[canonical] {
				return fmt.Errorf("job %s: duplicate target %q", j.Name, target)
			}
			targets[canonical] = true
		}
		if j.TCP != nil {
			if _, err := ParsePorts(j.TCP.Ports); err != nil {
				return fmt.Errorf("job %s tcp: %w", j.Name, err)
			}
			if j.TCP.Mode != "syn" && j.TCP.Mode != "connect" {
				return fmt.Errorf("job %s: tcp mode must be syn or connect", j.Name)
			}
		}
		if j.UDP != nil {
			if _, err := ParsePorts(j.UDP.Ports); err != nil {
				return fmt.Errorf("job %s udp: %w", j.Name, err)
			}
			if j.UDP.Mode != "" {
				return fmt.Errorf("job %s: udp mode is not configurable", j.Name)
			}
		}
	}
	return nil
}

// ValidateDeployment checks only settings used to run the appliance itself.
// YAML jobs are intentionally excluded because those entries are inactive in
// web-managed mode.
func (c Config) ValidateDeployment() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Database == "" {
		return fmt.Errorf("database path is required")
	}
	if c.Retention.Value() < 24*time.Hour {
		return fmt.Errorf("retention must be at least 24h")
	}
	if c.Scheduler.MaxConcurrent < 1 || c.Scheduler.MaxConcurrent > 64 {
		return fmt.Errorf("max_concurrent_scans must be between 1 and 64")
	}
	probeBudget := c.Scheduler.MaxProbeCount
	if probeBudget == 0 {
		probeBudget = DefaultMaxProbeCount
	}
	if probeBudget < 1 || probeBudget > 100_000_000 {
		return fmt.Errorf("max_probe_count must be between 1 and 100000000")
	}
	if err := validateWebListen(c.Web.Listen); err != nil {
		return err
	}
	return nil
}

// ValidateJob validates a job using the same rules as a complete configuration.
// It is used by the web API before a job is persisted.
func ValidateJob(j Job) error {
	c := Config{
		Version:   1,
		Database:  "web-managed",
		Retention: Duration(24 * time.Hour),
		Scheduler: Scheduler{MaxConcurrent: 1},
		Web:       Web{Listen: "127.0.0.1:8080"},
		Jobs:      []Job{j},
	}
	applyDefaults(&c)
	return c.Validate()
}

// NormalizeJob applies the same defaults used when loading YAML.
func NormalizeJob(j Job) Job {
	c := Config{Jobs: []Job{j}}
	applyDefaults(&c)
	j = c.Jobs[0]
	j.Name = strings.TrimSpace(j.Name)
	j.Schedule = strings.TrimSpace(j.Schedule)
	j.Timezone = strings.TrimSpace(j.Timezone)
	for i := range j.Targets {
		j.Targets[i] = CanonicalTarget(j.Targets[i])
	}
	return j
}

// CanonicalTarget gives semantically equivalent IP and network inputs one
// stable identity. Host-bit CIDRs are masked, single-host CIDRs collapse to
// their IP form, IPs use net.IP.String's compressed representation, and DNS
// names are case-insensitive. The canonical form is persisted in web-managed
// jobs so scanner output and baseline keys remain deterministic.
func CanonicalTarget(target string) string {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		if ones, bits := network.Mask.Size(); ones == bits {
			return network.IP.String()
		}
		return network.String()
	}
	return strings.ToLower(target)
}

const (
	// DefaultMaxProbeCount is a conservative product-level guard for one
	// execution. Jobs may explicitly opt into a larger workload with
	// allow_high_cost; the estimate is still shown before every run.
	DefaultMaxProbeCount int64 = 5_000_000
	workBatchSize        int64 = 128
)

// WorkEstimate describes the approximate cost of a job before DNS resolution
// and scanning. DNS names are counted as one address (and marked unknown) so
// the estimate is deterministic and useful in the editor without performing
// network I/O. Service detection uses a two-probe multiplier.
type WorkEstimate struct {
	Hosts            int64 `json:"hosts"`
	TCPPorts         int   `json:"tcp_ports"`
	UDPPorts         int   `json:"udp_ports"`
	Probes           int64 `json:"probes"`
	NmapInvocations  int64 `json:"nmap_invocations"`
	EstimatedSeconds int64 `json:"estimated_seconds"`
	UnknownDNS       int   `json:"unknown_dns"`
}

// EstimateJobWork computes a bounded preflight estimate from validated job
// intent. It never resolves DNS or expands every address, so it is safe to
// call from API requests and before a scan lease is acquired.
func EstimateJobWork(j Job) (WorkEstimate, error) {
	j = NormalizeJob(j)
	var estimate WorkEstimate
	var ipv4, ipv6, unknown int64
	for _, target := range j.Targets {
		if ip := net.ParseIP(target); ip != nil {
			estimate.Hosts = saturatingAdd(estimate.Hosts, 1)
			if ip.To4() != nil {
				ipv4 = saturatingAdd(ipv4, 1)
			} else {
				ipv6 = saturatingAdd(ipv6, 1)
			}
			continue
		}
		if _, network, err := net.ParseCIDR(target); err == nil {
			bits := networkAddressCount(network)
			estimate.Hosts = saturatingAdd(estimate.Hosts, bits)
			if network.IP.To4() != nil {
				ipv4 = saturatingAdd(ipv4, bits)
			} else {
				ipv6 = saturatingAdd(ipv6, bits)
			}
			continue
		}
		// DNS expansion depends on the resolver at run time. Count one logical
		// address and account for both address families in process estimates.
		estimate.Hosts = saturatingAdd(estimate.Hosts, 1)
		unknown++
	}
	estimate.UnknownDNS = int(minInt64(unknown, int64(^uint(0)>>1)))
	if j.TCP != nil {
		ports, err := ParsePorts(j.TCP.Ports)
		if err != nil {
			return estimate, fmt.Errorf("tcp: %w", err)
		}
		estimate.TCPPorts = len(ports)
	}
	if j.UDP != nil {
		ports, err := ParsePorts(j.UDP.Ports)
		if err != nil {
			return estimate, fmt.Errorf("udp: %w", err)
		}
		estimate.UDPPorts = len(ports)
	}
	var probes int64
	if j.TCP != nil {
		factor := int64(1)
		if j.TCP.ServiceDetection {
			factor = 2
		}
		probes = saturatingAdd(probes, saturatingMul(saturatingMul(estimate.Hosts, int64(estimate.TCPPorts)), factor))
	}
	if j.UDP != nil {
		factor := int64(1)
		if j.UDP.ServiceDetection {
			factor = 2
		}
		probes = saturatingAdd(probes, saturatingMul(saturatingMul(estimate.Hosts, int64(estimate.UDPPorts)), factor))
	}
	estimate.Probes = probes
	for _, addresses := range []int64{ipv4, ipv6} {
		estimate.NmapInvocations = saturatingAdd(estimate.NmapInvocations, ceilDiv(addresses, workBatchSize))
	}
	if unknown > 0 {
		estimate.NmapInvocations = saturatingAdd(estimate.NmapInvocations, saturatingMul(ceilDiv(unknown, workBatchSize), 2))
	}
	// This is intentionally a rough operator-facing estimate, not an SLA. It
	// scales with probes and process launches while remaining stable across
	// machines and provider timing.
	estimate.EstimatedSeconds = maxInt64(1, saturatingAdd(ceilDiv(probes, 20_000), estimate.NmapInvocations))
	return estimate, nil
}

func networkAddressCount(network *net.IPNet) int64 {
	ones, bits := network.Mask.Size()
	if ones < 0 || bits-ones >= 62 {
		return int64(^uint64(0) >> 1)
	}
	return int64(1) << uint(bits-ones)
}

func saturatingAdd(a, b int64) int64 {
	if b > 0 && a > int64(^uint64(0)>>1)-b {
		return int64(^uint64(0) >> 1)
	}
	return a + b
}

func saturatingMul(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > int64(^uint64(0)>>1)/b {
		return int64(^uint64(0) >> 1)
	}
	return a * b
}

func ceilDiv(a, b int64) int64 {
	if a <= 0 {
		return 0
	}
	result := a / b
	if a%b != 0 {
		result++
	}
	return result
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func validateWebListen(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("web.listen must be a host:port address")
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("web.listen must be a loopback address")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("web.listen port must be between 1 and 65535")
	}
	return nil
}

func validateTarget(target string) error {
	if net.ParseIP(target) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	if len(target) > 253 || strings.ContainsAny(target, " /\\\t\n\r") {
		return fmt.Errorf("invalid target %q", target)
	}
	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid target %q", target)
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return fmt.Errorf("invalid target %q", target)
			}
		}
	}
	return nil
}

func ParsePorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("ports are required")
	}
	set := map[int]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid port expression %q", item)
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", parts[0])
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", parts[1])
			}
		}
		if start < 1 || end > 65535 || end < start {
			return nil, fmt.Errorf("port range %q must be within 1..65535", item)
		}
		for p := start; p <= end; p++ {
			set[p] = true
		}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func PortContains(raw string, port int) bool {
	ports, err := ParsePorts(raw)
	if err != nil {
		return false
	}
	i := sort.SearchInts(ports, port)
	return i < len(ports) && ports[i] == port
}

func (j Job) RunsOnStart() bool { return j.RunOnStart == nil || *j.RunOnStart }

func (j Job) AssumesAlive() bool { return j.AssumeAlive == nil || *j.AssumeAlive }

func (j Job) SecurityHash() string {
	type securityJob struct {
		Targets     []string
		Max         int
		AssumeAlive bool
		TCP, UDP    *Protocol
	}
	v := securityJob{append([]string(nil), j.Targets...), j.MaxExpandedHosts, j.AssumesAlive(), j.TCP, j.UDP}
	sort.Strings(v.Targets)
	b, _ := yaml.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
