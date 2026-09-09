package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Enrichment    Enrichment    `yaml:"enrichment"`
	Updates       Updates       `yaml:"updates"`
	Notifications Notifications `yaml:"notifications"`
	Jobs          []Job         `yaml:"jobs"`
}

// Updates controls the optional outbound GitHub release check. The pointer
// preserves an omission-defaulted setting in the same way as RDAP.Enabled.
type Updates struct {
	Enabled *bool `yaml:"enabled"`
}

// Enrichment controls optional, on-demand metadata lookups. RDAP is enabled
// by default for backwards-compatible appliance installs; a pointer lets an
// operator explicitly disable outbound registry requests with enabled:false.
type Enrichment struct {
	RDAP RDAP `yaml:"rdap"`
}

type RDAP struct {
	Enabled *bool `yaml:"enabled"`
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
	ResumeWindow     Duration  `yaml:"resume_window"`
	Baseline         Baseline  `yaml:"baseline"`
	Change           Change    `yaml:"change"`
	AllowHighCost    bool      `yaml:"allow_high_cost,omitempty"`
	// NotificationDestinations contains stable destination identifiers selected
	// for this job. A nil value preserves the legacy behavior of delivering to
	// every globally enabled destination; an explicit empty list disables
	// notifications for the job. Destination secrets never live in the job.
	// Keep the JSON field when the slice is explicitly empty. The nil versus
	// empty distinction is the difference between legacy global routing and a
	// deliberately silent job, so persistence must not let encoding/json's
	// omitempty collapse the two states.
	NotificationDestinations []string `yaml:"notification_destinations,omitempty" json:"notification_destinations"`
}
type Protocol struct {
	Ports            string `yaml:"ports"`
	Mode             string `yaml:"mode,omitempty"`
	ServiceDetection bool   `yaml:"service_detection"`
	// Engine selects the TCP scanner. An empty value is intentionally treated
	// as nmap so legacy jobs and direct callers retain their exact behaviour;
	// the web editor explicitly selects the Naabu profile for new jobs. UDP is
	// always handled by Nmap.
	Engine          string        `yaml:"engine,omitempty" json:"engine,omitempty"`
	ProfileID       string        `yaml:"profile_id,omitempty" json:"profile_id,omitempty"`
	ProfileRevision int64         `yaml:"profile_revision,omitempty" json:"profile_revision,omitempty"`
	Naabu           *NaabuOptions `yaml:"naabu,omitempty" json:"naabu,omitempty"`
	NaabuArgs       []string      `yaml:"naabu_args,omitempty" json:"naabu_args,omitempty"`
	// NmapArgs and EnrichmentArgs are validated argv fragments from an
	// administrator-managed scanner profile. They are never interpreted by a
	// shell and are intentionally kept separate so a discovery profile cannot
	// alter target selection or output handling.
	NmapArgs       []string          `yaml:"nmap_args,omitempty" json:"nmap_args,omitempty"`
	EnrichmentArgs []string          `yaml:"enrichment_args,omitempty" json:"enrichment_args,omitempty"`
	NSEProfile     string            `yaml:"nse_profile,omitempty" json:"nse_profile,omitempty"`
	NSEArgs        map[string]string `yaml:"nse_args,omitempty" json:"nse_args,omitempty"`
}

// NaabuOptions are the bounded execution controls that can be captured in a
// job revision. The scanner profile API validates these values before they
// reach a job; keeping the type in config also makes persisted job JSON
// forwards-compatible with older binaries (unknown fields are ignored when
// reading historical JSON).
type NaabuOptions struct {
	// JSON intentionally keeps zero/false values present. A profile is an
	// explicit revisioned contract, so `retries: 0`, `warm_up_seconds: 0`, and
	// `verify: false` must survive a SQLite round trip instead of being
	// mistaken for an omitted value and defaulted back on load. YAML retains
	// omission-friendly tags for deployment compatibility.
	ScanType         string `yaml:"scan_type,omitempty" json:"scan_type"`
	Rate             int    `yaml:"rate,omitempty" json:"rate"`
	Workers          int    `yaml:"workers,omitempty" json:"workers"`
	Retries          int    `yaml:"retries,omitempty" json:"retries"`
	TimeoutMS        int    `yaml:"timeout_ms,omitempty" json:"timeout_ms"`
	WarmUpSeconds    int    `yaml:"warm_up_seconds,omitempty" json:"warm_up_seconds"`
	Verify           bool   `yaml:"verify,omitempty" json:"verify"`
	AddressBatchSize int    `yaml:"address_batch_size,omitempty" json:"address_batch_size"`
	// Presence markers let YAML/JSON distinguish an intentional zero from an
	// omitted value for fields whose safe default is non-zero. They are kept
	// out of the public representation and only influence default resolution.
	RateSet             bool `yaml:"-" json:"-"`
	WorkersSet          bool `yaml:"-" json:"-"`
	RetriesSet          bool `yaml:"-" json:"-"`
	TimeoutMSSet        bool `yaml:"-" json:"-"`
	WarmUpSecondsSet    bool `yaml:"-" json:"-"`
	VerifySet           bool `yaml:"-" json:"-"`
	AddressBatchSizeSet bool `yaml:"-" json:"-"`
}

// UnmarshalYAML keeps deployment configuration strict even though the
// presence markers above are implementation details. yaml.Decoder's
// KnownFields setting does not recurse through a custom unmarshaler, so check
// the supported keys explicitly before decoding the alias.
func (o *NaabuOptions) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("naabu options must be a mapping")
	}
	allowed := map[string]bool{"scan_type": true, "rate": true, "workers": true, "retries": true, "timeout_ms": true, "warm_up_seconds": true, "verify": true, "address_batch_size": true}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index].Value
		if !allowed[key] {
			return fmt.Errorf("naabu options: field %q not found", key)
		}
	}
	type plain NaabuOptions
	var value plain
	if err := node.Decode(&value); err != nil {
		return err
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		switch node.Content[index].Value {
		case "rate":
			value.RateSet = true
		case "workers":
			value.WorkersSet = true
		case "retries":
			value.RetriesSet = true
		case "timeout_ms":
			value.TimeoutMSSet = true
		case "warm_up_seconds":
			value.WarmUpSecondsSet = true
		case "verify":
			value.VerifySet = true
		case "address_batch_size":
			value.AddressBatchSizeSet = true
		}
	}
	*o = NaabuOptions(value)
	return nil
}

// UnmarshalJSON mirrors UnmarshalYAML for profile API payloads. The markers
// are deliberately not marshaled back to clients.
func (o *NaabuOptions) UnmarshalJSON(data []byte) error {
	type plain NaabuOptions
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	value.RetriesSet = fields["retries"] != nil
	value.RateSet = fields["rate"] != nil
	value.WorkersSet = fields["workers"] != nil
	value.TimeoutMSSet = fields["timeout_ms"] != nil
	value.WarmUpSecondsSet = fields["warm_up_seconds"] != nil
	value.VerifySet = fields["verify"] != nil
	value.AddressBatchSizeSet = fields["address_batch_size"] != nil
	*o = NaabuOptions(value)
	return nil
}

// ScannerProfile describes the safe command surface exposed to the web
// console. Profiles are persisted by the store package; the config shape is
// shared with jobs so a job revision contains the exact effective settings.
type ScannerProfile struct {
	Engine             string                  `json:"engine"`
	Naabu              NaabuOptions            `json:"naabu"`
	NaabuArgs          []string                `json:"naabu_args,omitempty"`
	NmapArgs           []string                `json:"nmap_args,omitempty"`
	EnrichmentArgs     []string                `json:"enrichment_args,omitempty"`
	NSEProfile         string                  `json:"nse_profile,omitempty"`
	NSEArgs            map[string]string       `json:"nse_args,omitempty"`
	OperatorAdjustable []string                `json:"operator_adjustable,omitempty"`
	OperatorBounds     map[string]NumericBound `json:"operator_bounds,omitempty"`
	Description        string                  `json:"description,omitempty"`
}

// NumericBound is an administrator-selected inclusive range for a Naabu
// execution field that operators may tune on an individual job. Bounds are
// validated against the product-wide safety limits before a profile is saved.
type NumericBound struct {
	Min int `json:"min"`
	Max int `json:"max"`
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
	if c.Enrichment.RDAP.Enabled == nil {
		enabled := true
		c.Enrichment.RDAP.Enabled = &enabled
	}
	if c.Updates.Enabled == nil {
		enabled := true
		c.Updates.Enabled = &enabled
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
		if j.ResumeWindow == 0 {
			j.ResumeWindow = Duration(8 * 24 * time.Hour)
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
		if j.TCP != nil {
			if j.TCP.Engine == "" {
				j.TCP.Engine = "nmap"
			}
			if j.TCP.Mode == "" {
				// Naabu discovery and its Nmap confirmation share the
				// least-privilege connect default. Nmap-only jobs retain the
				// historical SYN default. Explicit modes are never changed.
				if j.TCP.Engine == EngineNaabuNmap {
					j.TCP.Mode = "connect"
				} else {
					j.TCP.Mode = "syn"
				}
			}
			if j.TCP.Engine == "naabu_nmap" {
				// Naabu's discovery scope is deliberately not user-tunable. Keep
				// the job model truthful even when an older API/client persisted a
				// custom Nmap-looking port expression.
				j.TCP.Ports = NaabuFullPortExpression
				if j.TCP.Naabu == nil {
					j.TCP.Naabu = &NaabuOptions{}
				}
				applyNaabuDefaults(j.TCP.Naabu)
			}
		}
	}
}

const (
	EngineNmap      = "nmap"
	EngineNaabuNmap = "naabu_nmap"
	// Naabu always owns a complete TCP discovery pass. The Nmap port
	// expression on a Naabu job is normalized to this value so persisted jobs,
	// API responses, estimates, and security hashes cannot imply a partial
	// discovery scope.
	NaabuFullPortExpression = "1-65535"
)

func applyNaabuDefaults(options *NaabuOptions) {
	if options == nil {
		return
	}
	if options.ScanType == "" {
		options.ScanType = "connect"
	}
	if options.Rate == 0 && !options.RateSet {
		options.Rate = 1000
	}
	if options.Workers == 0 && !options.WorkersSet {
		options.Workers = 25
	}
	if options.Retries == 0 && !options.RetriesSet {
		options.Retries = 3
	}
	if options.TimeoutMS == 0 && !options.TimeoutMSSet {
		options.TimeoutMS = 1000
	}
	if options.WarmUpSeconds == 0 && !options.WarmUpSecondsSet {
		options.WarmUpSeconds = 2
	}
	if !options.VerifySet && !options.Verify {
		options.Verify = true
	}
	if options.AddressBatchSize == 0 && !options.AddressBatchSizeSet {
		options.AddressBatchSize = 16
	}
}

// ApplyNaabuDefaultsForScanner is kept as a small exported adapter for the
// scanner package. Job normalization normally applies these defaults, but
// callers may execute a standalone profile/options value in tests or tooling.
func ApplyNaabuDefaultsForScanner(options *NaabuOptions) { applyNaabuDefaults(options) }

// RDAPEnabled resolves the omission-defaulted deployment setting.
func (c Config) RDAPEnabled() bool {
	return c.Enrichment.RDAP.Enabled == nil || *c.Enrichment.RDAP.Enabled
}

// UpdatesEnabled resolves the omission-defaulted deployment setting.
func (c Config) UpdatesEnabled() bool {
	return c.Updates.Enabled == nil || *c.Updates.Enabled
}

func (c Config) Validate() error {
	if err := c.ValidateDeployment(); err != nil {
		return err
	}
	seen := map[string]bool{}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	for _, rawJob := range c.Jobs {
		// Apply the same omission defaults here as Load/ValidateJob. Direct
		// callers frequently construct a Config value in tests or recovery
		// tooling, and legacy TCP records omit the engine field by design.
		j := NormalizeJob(rawJob)
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
		if j.ResumeWindow.Value() < time.Hour || j.ResumeWindow.Value() > 30*24*time.Hour {
			return fmt.Errorf("job %s: resume_window must be between 1h and 30d", j.Name)
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
			if j.TCP.Engine != "" && j.TCP.Engine != EngineNmap && j.TCP.Engine != EngineNaabuNmap {
				return fmt.Errorf("job %s: tcp engine must be nmap or naabu_nmap", j.Name)
			}
			if j.TCP.Engine == EngineNaabuNmap {
				if j.TCP.Naabu == nil {
					return fmt.Errorf("job %s: naabu options are required for naabu_nmap", j.Name)
				}
				if err := ValidateNaabuOptions(*j.TCP.Naabu); err != nil {
					return fmt.Errorf("job %s tcp naabu: %w", j.Name, err)
				}
				if j.TCP.Mode != "syn" && j.TCP.Mode != "connect" {
					return fmt.Errorf("job %s: tcp mode must be syn or connect", j.Name)
				}
			}
			profile := ScannerProfile{Engine: j.TCP.Engine, NaabuArgs: j.TCP.NaabuArgs, NmapArgs: j.TCP.NmapArgs, EnrichmentArgs: j.TCP.EnrichmentArgs, NSEProfile: j.TCP.NSEProfile, NSEArgs: j.TCP.NSEArgs}
			if j.TCP.Naabu != nil {
				profile.Naabu = *j.TCP.Naabu
			}
			if err := ValidateScannerProfile(profile); err != nil {
				return fmt.Errorf("job %s scanner profile: %w", j.Name, err)
			}
		}
		if j.UDP != nil {
			if _, err := ParsePorts(j.UDP.Ports); err != nil {
				return fmt.Errorf("job %s udp: %w", j.Name, err)
			}
			if j.UDP.Mode != "" {
				return fmt.Errorf("job %s: udp mode is not configurable", j.Name)
			}
			if j.UDP.Engine != "" && j.UDP.Engine != EngineNmap {
				return fmt.Errorf("job %s: udp engine must be nmap", j.Name)
			}
			if err := ValidateScannerProfile(ScannerProfile{Engine: EngineNmap, NmapArgs: j.UDP.NmapArgs, EnrichmentArgs: j.UDP.EnrichmentArgs, NSEProfile: j.UDP.NSEProfile, NSEArgs: j.UDP.NSEArgs}); err != nil {
				return fmt.Errorf("job %s udp scanner profile: %w", j.Name, err)
			}
		}
	}
	return nil
}

// ValidateNaabuOptions constrains the command surface exposed through job
// profiles. EdgeWatch deliberately supports only the controls it can report,
// cancel, and resume safely; arbitrary Naabu flags remain unavailable.
func ValidateNaabuOptions(options NaabuOptions) error {
	if options.ScanType != "connect" && options.ScanType != "syn" {
		return fmt.Errorf("scan_type must be connect or syn")
	}
	if options.Rate < 1 || options.Rate > 100_000 {
		return fmt.Errorf("rate must be between 1 and 100000")
	}
	if options.Workers < 1 || options.Workers > 1024 {
		return fmt.Errorf("workers must be between 1 and 1024")
	}
	if options.Retries < 0 || options.Retries > 10 {
		return fmt.Errorf("retries must be between 0 and 10")
	}
	if options.TimeoutMS < 100 || options.TimeoutMS > 60_000 {
		return fmt.Errorf("timeout_ms must be between 100 and 60000")
	}
	if options.WarmUpSeconds < 0 || options.WarmUpSeconds > 60 {
		return fmt.Errorf("warm_up_seconds must be between 0 and 60")
	}
	if options.AddressBatchSize < 1 || options.AddressBatchSize > 256 {
		return fmt.Errorf("address_batch_size must be between 1 and 256")
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
	if j.NotificationDestinations != nil {
		seen := make(map[string]struct{}, len(j.NotificationDestinations))
		selected := make([]string, 0, len(j.NotificationDestinations))
		for _, destination := range j.NotificationDestinations {
			destination = strings.TrimSpace(destination)
			if destination == "" {
				continue
			}
			if _, exists := seen[destination]; exists {
				continue
			}
			seen[destination] = struct{}{}
			selected = append(selected, destination)
		}
		sort.Strings(selected)
		// Keep an explicitly supplied empty list non-nil so callers can
		// distinguish "deliver nowhere" from the legacy nil default.
		if selected == nil {
			selected = []string{}
		}
		j.NotificationDestinations = selected
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
		if j.TCP.Engine == EngineNaabuNmap {
			// Naabu owns a fixed full-range discovery pass regardless of the
			// configured Nmap enrichment expression. Keep the estimate honest so
			// operators see the cost before a lease is acquired.
			estimate.TCPPorts = 65535
			_ = ports
		}
		if j.TCP.Engine != EngineNaabuNmap {
			estimate.TCPPorts = len(ports)
		}
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

// ResumeWindowValue is the maximum age of a resumable scan cycle. It is
// separate from Timeout: Timeout bounds one attempt, while ResumeWindow
// bounds the complete coverage window assembled from multiple attempts.
func (j Job) ResumeWindowValue() time.Duration {
	if j.ResumeWindow == 0 {
		return 8 * 24 * time.Hour
	}
	return j.ResumeWindow.Value()
}

func (j Job) SecurityHash() string {
	// Hash the effective job rather than the raw struct. Jobs loaded from the
	// web store are normally normalized already, but callers such as recovery
	// tooling and scheduler fixtures may construct a value directly. Treat an
	// omitted engine/default as the same scope as its explicit default.
	j = NormalizeJob(j)
	type securityJob struct {
		Targets     []string
		Max         int
		AssumeAlive bool
		TCP, UDP    *securityProtocol
	}
	toSecurity := func(protocol *Protocol) *securityProtocol {
		if protocol == nil {
			return nil
		}
		// A profile revision is execution provenance, not monitored scope. A
		// profile may change rate/workers/retries without requiring a fresh
		// baseline; only the effective security fields below participate in the
		// scope hash. Applying a profile to a job still records its ID/revision
		// in the execution hash and scan metadata.
		value := &securityProtocol{Ports: protocol.Ports, Mode: protocol.Mode, ServiceDetection: protocol.ServiceDetection, Engine: protocol.Engine, NSEProfile: protocol.NSEProfile, NSEArgs: protocol.NSEArgs}
		// Naabu controls only the Naabu→Nmap engine. A stale pointer on an
		// Nmap-only job is legacy/persistence noise and must not change the
		// monitored scope hash or force a rebaseline.
		if protocol.Engine == EngineNaabuNmap && protocol.Naabu != nil {
			value.Naabu = &securityNaabu{ScanType: protocol.Naabu.ScanType, Verify: protocol.Naabu.Verify}
		}
		return value
	}
	v := securityJob{append([]string(nil), j.Targets...), j.MaxExpandedHosts, j.AssumesAlive(), toSecurity(j.TCP), toSecurity(j.UDP)}
	sort.Strings(v.Targets)
	b, _ := yaml.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type securityProtocol struct {
	Ports            string
	Mode             string
	ServiceDetection bool
	Engine           string
	NSEProfile       string
	NSEArgs          map[string]string
	Naabu            *securityNaabu
}

type securityNaabu struct {
	ScanType string
	Verify   bool
}

// ExecutionHash identifies the settings that affect how a pinned scan plan is
// executed without changing the monitored security scope. It is kept separate
// from SecurityHash so schedule, timeout, and resume-window edits can safely
// leave an in-progress cycle intact while still recording the execution
// settings that created a persisted plan.
func (j Job) ExecutionHash() string {
	// Callers often construct a Job value directly (for example, a scheduler
	// fixture or a recovery command) instead of passing it through NormalizeJob.
	// Hash the effective execution settings so omitted defaults and explicit
	// defaults cannot create a false cycle mismatch.
	j = NormalizeJob(j)
	type executionJob struct {
		SecurityHash  string
		Timing        string
		Timeout       Duration
		ResumeWindow  Duration
		TCPProfileID  string
		TCPProfileRev int64
		UDPProfileID  string
		UDPProfileRev int64
		TCPNaabu      *NaabuOptions
		TCPArgs       []string
		TCPEnrichment []string
		UDPArgs       []string
		UDPEnrichment []string
	}
	cloneNaabu := func(value *NaabuOptions) *NaabuOptions {
		if value == nil {
			return nil
		}
		copy := *value
		return &copy
	}
	v := executionJob{SecurityHash: j.SecurityHash(), Timing: j.Timing, Timeout: j.Timeout, ResumeWindow: j.ResumeWindow}
	if j.TCP != nil {
		v.TCPProfileID = j.TCP.ProfileID
		v.TCPProfileRev = j.TCP.ProfileRevision
		if j.TCP.Engine == EngineNaabuNmap {
			v.TCPNaabu = cloneNaabu(j.TCP.Naabu)
			v.TCPArgs = append([]string(nil), j.TCP.NaabuArgs...)
			v.TCPEnrichment = append([]string(nil), j.TCP.EnrichmentArgs...)
		} else {
			v.TCPArgs = append([]string(nil), j.TCP.NmapArgs...)
		}
	}
	if j.UDP != nil {
		v.UDPProfileID = j.UDP.ProfileID
		v.UDPProfileRev = j.UDP.ProfileRevision
		v.UDPArgs = append([]string(nil), j.UDP.NmapArgs...)
	}
	b, _ := yaml.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
