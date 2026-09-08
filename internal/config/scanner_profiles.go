package config

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type CommandPreview struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
}

// Scanner profile placeholders are deliberately small and whole-argument
// based. They make the administrator's intent visible without turning the
// profile editor into a shell or arbitrary process execution surface.
const (
	PlaceholderTargetsFile      = "{targets_file}"
	PlaceholderAddress          = "{address}"
	PlaceholderAddresses        = "{addresses}"
	PlaceholderAddressFamily    = "{address_family}"
	PlaceholderHostDiscovery    = "{host_discovery}"
	PlaceholderScanType         = "{scan_type}"
	PlaceholderPorts            = "{ports}"
	PlaceholderStructuredOutput = "{structured_output}"
	PlaceholderServiceDetection = "{service_detection}"
	PlaceholderNSE              = "{nse}"
)

var allowedScannerPlaceholders = map[string]struct{}{
	PlaceholderTargetsFile: {}, PlaceholderAddress: {}, PlaceholderAddresses: {},
	PlaceholderAddressFamily: {}, PlaceholderHostDiscovery: {}, PlaceholderScanType: {},
	PlaceholderPorts: {}, PlaceholderStructuredOutput: {}, PlaceholderServiceDetection: {},
	PlaceholderNSE: {},
}

// BuiltinNmapProfile and BuiltinNaabuProfile are immutable definitions seeded
// into SQLite on first open. The scanner still owns the mandatory output and
// target arguments; these arrays are the safe, reviewable profile surface.
func BuiltinNmapProfile() ScannerProfile {
	return ScannerProfile{Engine: EngineNmap, Description: "Standard Nmap TCP/UDP scanning"}
}

func BuiltinNaabuProfile() ScannerProfile {
	return ScannerProfile{Engine: EngineNaabuNmap, Description: "Naabu full TCP discovery followed by Nmap enrichment", Naabu: NaabuOptions{ScanType: "connect", Rate: 1000, Workers: 25, Retries: 3, TimeoutMS: 1000, WarmUpSeconds: 2, Verify: true, AddressBatchSize: 16}}
}

// NormalizeScannerProfile materializes the safe Naabu defaults so API
// responses and persisted definitions are self-describing. It does not relax
// validation or change the fixed executable/argument contract.
func NormalizeScannerProfile(profile ScannerProfile) ScannerProfile {
	if profile.Engine == EngineNaabuNmap {
		ApplyNaabuDefaultsForScanner(&profile.Naabu)
	}
	if profile.NSEProfile != "" {
		profile.NSEProfile = strings.TrimSpace(profile.NSEProfile)
	}
	if len(profile.OperatorAdjustable) > 0 {
		fields := make([]string, len(profile.OperatorAdjustable))
		for index, field := range profile.OperatorAdjustable {
			fields[index] = strings.TrimSpace(field)
		}
		profile.OperatorAdjustable = fields
	}
	if len(profile.OperatorBounds) > 0 {
		bounds := make(map[string]NumericBound, len(profile.OperatorBounds))
		for field, bound := range profile.OperatorBounds {
			bounds[strings.TrimSpace(field)] = bound
		}
		profile.OperatorBounds = bounds
	}
	if profile.NmapArgs == nil {
		profile.NmapArgs = []string{}
	}
	if profile.NaabuArgs == nil {
		profile.NaabuArgs = []string{}
	}
	if profile.EnrichmentArgs == nil {
		profile.EnrichmentArgs = []string{}
	}
	return profile
}

// ValidateScannerProfile enforces the fixed executable and argv-only command
// contract. It intentionally rejects shell metacharacters, environment
// expansion and flags that could replace targets/output or execute arbitrary
// binaries. Empty arrays are allowed for compatibility with the built-in
// profiles created by older databases.
func ValidateScannerProfile(profile ScannerProfile) error {
	if profile.Engine != EngineNmap && profile.Engine != EngineNaabuNmap {
		return fmt.Errorf("engine must be nmap or naabu_nmap")
	}
	if profile.Engine == EngineNaabuNmap {
		options := profile.Naabu
		ApplyNaabuDefaultsForScanner(&options)
		if err := ValidateNaabuOptions(options); err != nil {
			return fmt.Errorf("naabu: %w", err)
		}
	}
	if err := validateArgTemplate(profile.NmapArgs, "nmap"); err != nil {
		return err
	}
	if profile.Engine != EngineNaabuNmap && len(profile.NaabuArgs) > 0 {
		return fmt.Errorf("naabu arguments require the naabu_nmap engine")
	}
	if err := validateArgTemplate(profile.NaabuArgs, "naabu"); err != nil {
		return err
	}
	if err := validateArgTemplate(profile.EnrichmentArgs, "nmap enrichment"); err != nil {
		return err
	}
	// Runtime-owned target, port, and structured-output arguments must be
	// declared explicitly by a managed template. The built-ins intentionally
	// leave all arrays empty because EdgeWatch supplies their complete safe
	// argv itself; an empty set is therefore the only compatibility exception.
	if profile.Engine == EngineNaabuNmap && len(profile.NaabuArgs) > 0 {
		if err := requirePlaceholders(profile.NaabuArgs, "naabu", PlaceholderTargetsFile, PlaceholderPorts, PlaceholderStructuredOutput); err != nil {
			return err
		}
	}
	if len(profile.NmapArgs) > 0 {
		if err := requireAddressPlaceholder(profile.NmapArgs, "nmap"); err != nil {
			return err
		}
		if err := requirePlaceholders(profile.NmapArgs, "nmap", PlaceholderPorts, PlaceholderStructuredOutput); err != nil {
			return err
		}
	}
	if len(profile.EnrichmentArgs) > 0 {
		if err := requireAddressPlaceholder(profile.EnrichmentArgs, "nmap enrichment"); err != nil {
			return err
		}
		if err := requirePlaceholders(profile.EnrichmentArgs, "nmap enrichment", PlaceholderPorts, PlaceholderStructuredOutput); err != nil {
			return err
		}
	}
	if strings.TrimSpace(profile.NSEProfile) != "" {
		if err := validateNSEName(profile.NSEProfile); err != nil {
			return err
		}
	} else if len(profile.NSEArgs) > 0 {
		return fmt.Errorf("nse_args requires an approved nse_profile")
	}
	if err := validateNSEArgs(profile.NSEArgs); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, field := range profile.OperatorAdjustable {
		field = strings.TrimSpace(field)
		if field == "" {
			return fmt.Errorf("operator_adjustable contains an empty field")
		}
		if _, ok := seen[field]; ok {
			return fmt.Errorf("operator_adjustable contains duplicate field %q", field)
		}
		seen[field] = struct{}{}
		if _, ok := operatorBoundFields[field]; ok {
			bound, boundOK := profile.OperatorBounds[field]
			if !boundOK {
				return fmt.Errorf("operator_adjustable field %q requires an operator bound", field)
			}
			if err := validateOperatorBound(field, bound); err != nil {
				return err
			}
			continue
		}
		if _, ok := operatorTypedFields[field]; ok {
			if _, hasBound := profile.OperatorBounds[field]; hasBound {
				return fmt.Errorf("operator-adjustable field %q does not accept a numeric bound", field)
			}
			continue
		}
		return fmt.Errorf("operator_adjustable field %q is not supported", field)
	}
	for field := range profile.OperatorBounds {
		if _, ok := seen[field]; !ok {
			return fmt.Errorf("operator bound %q is not marked operator-adjustable", field)
		}
	}
	return nil
}

var operatorBoundFields = map[string]struct{}{
	"rate": {}, "workers": {}, "retries": {}, "timeout_ms": {},
	"warm_up_seconds": {}, "address_batch_size": {},
}

// These controls are typed rather than numeric. They can be exposed to an
// operator without a range map: scan_type is restricted to connect/syn and
// verify is an explicit boolean. Keeping them separate from numeric bounds
// avoids accepting nonsensical min/max values for an enum or bool.
var operatorTypedFields = map[string]struct{}{
	"scan_type": {}, "verify": {},
}

func validateOperatorBound(field string, bound NumericBound) error {
	if bound.Min > bound.Max {
		return fmt.Errorf("operator bound %q has min greater than max", field)
	}
	limits := map[string]NumericBound{
		"rate": {Min: 1, Max: 100_000}, "workers": {Min: 1, Max: 1024},
		"retries": {Min: 0, Max: 10}, "timeout_ms": {Min: 100, Max: 60_000},
		"warm_up_seconds": {Min: 0, Max: 60}, "address_batch_size": {Min: 1, Max: 256},
	}
	limit := limits[field]
	if bound.Min < limit.Min || bound.Max > limit.Max {
		return fmt.Errorf("operator bound %q must stay within %d..%d", field, limit.Min, limit.Max)
	}
	return nil
}

// RenderScannerProfilePreview substitutes fixed, non-sensitive examples for
// placeholders. It is suitable for the UI only; the runtime scanner still
// constructs target/output arguments itself and never executes this preview.
func RenderScannerProfilePreview(profile ScannerProfile) ([]CommandPreview, error) {
	profile = NormalizeScannerProfile(profile)
	if err := ValidateScannerProfile(profile); err != nil {
		return nil, err
	}
	// The fixed portion mirrors the runtime-owned arguments closely enough for
	// an administrator to review the effective shape. It intentionally uses
	// documentation addresses and ports; no target or secret from a job is
	// ever returned by this endpoint.
	nsePreview := func(result []string) []string {
		if profile.NSEProfile == "" {
			return result
		}
		result = append(result, "--script", profile.NSEProfile)
		if len(profile.NSEArgs) == 0 {
			return result
		}
		keys := make([]string, 0, len(profile.NSEArgs))
		for key := range profile.NSEArgs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make([]string, 0, len(keys))
		for _, key := range keys {
			values = append(values, key+"=example")
		}
		return append(result, "--script-args", strings.Join(values, ","))
	}
	var nmap func([]string, string, bool) []string
	nmap = func(values []string, protocol string, serviceDetection bool) []string {
		if len(values) == 0 {
			result := []string{"-n", "-oX", "-", "-p", "22,443", "-T3", "--reason", "--stats-every", "1s", "-Pn"}
			if protocol == "udp" {
				result = append(result, "-sU")
			} else {
				result = append(result, "-sS")
			}
			if serviceDetection {
				result = append(result, "-sV", "--version-light")
			}
			return nsePreview(append(result, "192.0.2.10"))
		}
		result := []string{"-n", "-T3", "--reason", "--stats-every", "1s"}
		// Keep the preview aligned with runtime rendering. Optional managed
		// placeholders have the same typed defaults as the built-in command when
		// omitted, so a profile that only adds a safe tuning flag cannot hide a
		// changed discovery or service-detection policy from its administrator.
		if !containsPreviewPlaceholder(values, PlaceholderHostDiscovery) {
			result = append(result, "-Pn")
		}
		if !containsPreviewPlaceholder(values, PlaceholderScanType) {
			if protocol == "udp" {
				result = append(result, "-sU")
			} else {
				result = append(result, "-sS")
			}
		}
		if !containsPreviewPlaceholder(values, PlaceholderServiceDetection) && serviceDetection {
			result = append(result, "-sV", "--version-light")
		}
		for _, value := range values {
			switch value {
			case PlaceholderAddress:
				result = append(result, "192.0.2.10")
			case PlaceholderAddresses:
				result = append(result, "192.0.2.10", "2001:db8::10")
			case PlaceholderAddressFamily:
				result = append(result, "-4")
			case PlaceholderHostDiscovery:
				result = append(result, "-Pn")
			case PlaceholderScanType:
				if protocol == "udp" {
					result = append(result, "-sU")
				} else {
					result = append(result, "-sS")
				}
			case PlaceholderPorts:
				result = append(result, "-p", "22,443")
			case PlaceholderStructuredOutput:
				result = append(result, "-oX", "-")
			case PlaceholderServiceDetection:
				if serviceDetection {
					result = append(result, "-sV", "--version-light")
				}
			case PlaceholderNSE:
				result = nsePreview(result)
			case PlaceholderTargetsFile:
				// Target files are Naabu-only; shared profile tooling may carry
				// the declaration, but an Nmap preview never exposes it.
			default:
				result = append(result, value)
			}
		}
		if !containsPreviewAddress(values) {
			result = append(result, "192.0.2.10")
		}
		if !containsPreviewPlaceholder(values, PlaceholderNSE) {
			result = nsePreview(result)
		}
		return result
	}
	previews := []CommandPreview{{Executable: "/usr/bin/nmap", Args: nmap(profile.NmapArgs, "tcp", true)}}
	if profile.Engine == EngineNaabuNmap {
		options := profile.Naabu
		scanType := "c"
		if options.ScanType == "syn" {
			scanType = "s"
		}
		var naabu []string
		if len(profile.NaabuArgs) == 0 {
			naabu = []string{"-list", "/tmp/edgewatch-targets.txt", "-p", "-", "-json", "-silent", "-no-stdin", "-disable-update-check", "-scan-type", scanType, "-rate", strconv.Itoa(options.Rate), "-c", strconv.Itoa(options.Workers), "-retries", strconv.Itoa(options.Retries), "-timeout", strconv.Itoa(options.TimeoutMS), "-warm-up-time", strconv.Itoa(options.WarmUpSeconds)}
			if options.Verify {
				naabu = append(naabu, "-verify")
			}
			naabu = append(naabu, "-skip-host-discovery")
		} else {
			// Keep the preview compact; the runtime additionally forces the
			// non-interactive authentication/passive-discovery switches.
			naabu = []string{"-silent", "-no-stdin", "-disable-update-check", "-auth=false", "-pd=false"}
			if !containsPreviewPlaceholder(profile.NaabuArgs, PlaceholderScanType) {
				naabu = append(naabu, "-scan-type", scanType)
			}
			naabu = append(naabu, "-rate", strconv.Itoa(options.Rate), "-c", strconv.Itoa(options.Workers), "-retries", strconv.Itoa(options.Retries), "-timeout", strconv.Itoa(options.TimeoutMS), "-warm-up-time", strconv.Itoa(options.WarmUpSeconds))
			if options.Verify {
				naabu = append(naabu, "-verify")
			}
			if !containsPreviewPlaceholder(profile.NaabuArgs, PlaceholderHostDiscovery) {
				naabu = append(naabu, "-skip-host-discovery")
			}
			for _, value := range profile.NaabuArgs {
				switch value {
				case PlaceholderTargetsFile:
					naabu = append(naabu, "-list", "/tmp/edgewatch-targets.txt")
				case PlaceholderPorts:
					naabu = append(naabu, "-p", "-")
				case PlaceholderStructuredOutput:
					naabu = append(naabu, "-json")
				case PlaceholderHostDiscovery:
					naabu = append(naabu, "-skip-host-discovery")
				case PlaceholderScanType:
					naabu = append(naabu, "-scan-type", scanType)
				case PlaceholderAddress, PlaceholderAddresses, PlaceholderServiceDetection, PlaceholderNSE:
					// Nmap-only declarations are harmless in a shared profile and
					// are intentionally omitted from the Naabu preview.
				default:
					naabu = append(naabu, value)
				}
			}
		}
		previews = append([]CommandPreview{{Executable: "/usr/local/bin/naabu", Args: naabu}}, previews...)
	}
	if len(profile.EnrichmentArgs) > 0 {
		previews = append(previews, CommandPreview{Executable: "/usr/bin/nmap", Args: nmap(profile.EnrichmentArgs, "tcp", true)})
	}
	return previews, nil
}

func containsPreviewPlaceholder(values []string, placeholder string) bool {
	for _, value := range values {
		if value == placeholder {
			return true
		}
	}
	return false
}

func containsPreviewAddress(values []string) bool {
	return containsPreviewPlaceholder(values, PlaceholderAddress) || containsPreviewPlaceholder(values, PlaceholderAddresses)
}

func validateNSEName(value string) error {
	if strings.ContainsAny(value, "/\\*@?[]{}()!|;&$<>`\x00\n\r\t ") {
		return fmt.Errorf("nse_profile must be an approved profile name")
	}
	if _, ok := approvedNSEProfiles[value]; !ok {
		return fmt.Errorf("nse_profile %q is not installed or approved", value)
	}
	return nil
}

var nseArgumentKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// validateNSEArgs accepts only scalar, structured values. Script paths,
// @file references, boolean expressions, wildcards, and shell syntax are
// deliberately excluded from the profile contract.
func validateNSEArgs(values map[string]string) error {
	for key, value := range values {
		if !nseArgumentKey.MatchString(strings.TrimSpace(key)) {
			return fmt.Errorf("nse argument key %q is invalid", key)
		}
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, "\x00\n\r@*?[]{}()!|;&$<>`\\/") || strings.Contains(value, "=") {
			return fmt.Errorf("nse argument %q contains unsafe characters", key)
		}
	}
	return nil
}

// Only a small, non-invasive catalog is exposed. The catalog is kept in the
// application rather than accepting Nmap categories/expressions so profile
// input cannot expand into arbitrary scripts or filesystem paths.
var approvedNSEProfiles = map[string]struct{}{
	"banner": {}, "dns-recursion": {}, "http-headers": {}, "http-title": {},
	"ssl-cert": {}, "ssh-hostkey": {},
}

func requirePlaceholders(args []string, label string, required ...string) error {
	counts := make(map[string]int, len(required))
	for _, value := range args {
		if _, ok := allowedScannerPlaceholders[value]; ok {
			counts[value]++
		}
	}
	for _, placeholder := range required {
		if counts[placeholder] != 1 {
			return fmt.Errorf("%s must contain %s exactly once", label, placeholder)
		}
	}
	return nil
}

func requireAddressPlaceholder(args []string, label string) error {
	addressCount := 0
	for _, value := range args {
		if value == PlaceholderAddress || value == PlaceholderAddresses {
			addressCount++
		}
	}
	if addressCount != 1 {
		return fmt.Errorf("%s must contain %s or %s exactly once", label, PlaceholderAddress, PlaceholderAddresses)
	}
	return nil
}

func validateArgTemplate(args []string, label string) error {
	pendingOperand := ""
	seenPlaceholders := make(map[string]struct{})
	for _, arg := range args {
		if arg == "" {
			return fmt.Errorf("%s arguments cannot contain empty values", label)
		}
		if strings.ContainsAny(arg, "\x00\n\r") {
			return fmt.Errorf("%s arguments cannot contain NUL or newline characters", label)
		}
		if strings.ContainsAny(arg, "|;&$<>`\n\r") || strings.Contains(arg, "${") || strings.Contains(arg, "$PATH") {
			return fmt.Errorf("%s arguments cannot contain shell syntax or environment expansion", label)
		}
		// A literal is only safe as the operand of one of the explicitly
		// allow-listed tuning flags. Without this state check a bare numeric
		// value (for example "123") would pass the scalar validator and then
		// be interpreted by Nmap as an unmanaged target.
		if pendingOperand != "" {
			if strings.HasPrefix(arg, "-") || strings.Contains(arg, "{") || strings.Contains(arg, "}") || !safeScannerScalar(arg) {
				return fmt.Errorf("%s flag %q requires a safe scalar operand", label, pendingOperand)
			}
			pendingOperand = ""
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flag, operand, hasOperand := strings.Cut(arg, "=")
			flag = strings.ToLower(flag)
			if forbiddenScannerFlag(flag) {
				return fmt.Errorf("%s flag %q is not allowed", label, arg)
			}
			if !allowedScannerProfileFlag(label, flag) {
				return fmt.Errorf("%s flag %q is not an approved scanner option", label, arg)
			}
			if hasOperand && !safeScannerScalar(operand) {
				return fmt.Errorf("%s flag %q has an unsafe operand", label, arg)
			}
			if scannerFlagNeedsOperand(label, flag) && !hasOperand {
				pendingOperand = arg
			}
		}
		managedPlaceholder := false
		if strings.Contains(arg, "{") || strings.Contains(arg, "}") {
			if _, ok := allowedScannerPlaceholders[arg]; !ok {
				return fmt.Errorf("%s contains an unsupported placeholder %q", label, arg)
			}
			if _, exists := seenPlaceholders[arg]; exists {
				return fmt.Errorf("%s placeholder %q may appear only once", label, arg)
			}
			seenPlaceholders[arg] = struct{}{}
			managedPlaceholder = true
		} else if strings.HasPrefix(arg, "{") || strings.HasSuffix(arg, "}") {
			return fmt.Errorf("%s placeholders must occupy a complete argument", label)
		}
		if !managedPlaceholder && (forbiddenPositionalLiteral(arg) || !strings.HasPrefix(arg, "-")) {
			return fmt.Errorf("%s positional argument %q is not allowed", label, arg)
		}
	}
	if pendingOperand != "" {
		return fmt.Errorf("%s flag %q requires an operand", label, pendingOperand)
	}
	return nil
}

func scannerFlagNeedsOperand(label, flag string) bool {
	if label == "naabu" {
		return false
	}
	switch flag {
	case "--host-timeout", "--min-rate", "--max-rate", "--max-retries",
		"--scan-delay", "--max-scan-delay", "--initial-rtt-timeout",
		"--min-rtt-timeout", "--max-rtt-timeout", "--min-hostgroup",
		"--max-hostgroup", "--min-parallelism", "--max-parallelism":
		return true
	default:
		return false
	}
}

// The profile editor is intentionally an allow-list rather than a general
// Nmap/Naabu argument passthrough. Runtime-owned scope, discovery, output,
// scripts, and probe-shaping flags are rejected above; this list contains only
// bounded, non-invasive tuning switches whose operands are still checked by
// forbiddenPositionalLiteral. Unknown flags are rejected before they can
// become an accidental new command surface when either scanner changes.
var approvedNmapProfileFlags = map[string]struct{}{
	"-v": {}, "-vv": {}, "-vvv": {}, "--verbose": {},
	"--host-timeout": {}, "--min-rate": {}, "--max-rate": {}, "--max-retries": {},
	"--scan-delay": {}, "--max-scan-delay": {},
	"--initial-rtt-timeout": {}, "--min-rtt-timeout": {}, "--max-rtt-timeout": {},
	"--min-hostgroup": {}, "--max-hostgroup": {},
	"--min-parallelism": {}, "--max-parallelism": {},
}

var approvedNaabuProfileFlags = map[string]struct{}{
	"-v": {}, "-verbose": {}, "--verbose": {},
}

func allowedScannerProfileFlag(label, flag string) bool {
	if label == "naabu" {
		_, ok := approvedNaabuProfileFlags[flag]
		return ok
	}
	_, ok := approvedNmapProfileFlags[flag]
	return ok
}

// forbiddenPositionalLiteral closes the remaining argv escape hatches after
// flag validation. The profile editor accepts argument arrays, but a literal
// executable, path, target, or command separator would still let an operator
// smuggle an alternate process or an unmanaged target into the fixed command.
// Safe scalar values (for example "connect", "1s", or "5") remain valid
// only as operands of an approved tuning flag; a bare scalar is still a
// positional argument and is rejected by validateArgTemplate.
func forbiddenPositionalLiteral(arg string) bool {
	arg = strings.TrimSpace(arg)
	if arg == "" || arg == "-" || arg == "--" {
		return true
	}
	if host, _, err := net.SplitHostPort(arg); err == nil {
		if net.ParseIP(host) != nil || validateTarget(strings.Trim(host, "[]")) == nil {
			return true
		}
	}
	if net.ParseIP(arg) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(arg); err == nil {
		return true
	}
	if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") || strings.ContainsAny(arg, `/\\`) {
		return true
	}
	switch strings.ToLower(arg) {
	case "nmap", "naabu", "sh", "bash", "zsh", "fish", "dash", "ash", "busybox", "env", "exec", "command", "cmd", "powershell", "pwsh", "curl", "wget", "python", "python3", "perl", "ruby", "node", "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback":
		return true
	}
	// Decimal durations (for example 0.5s) are legitimate values for some
	// safe Nmap timing switches. Do not mistake those numeric scalars for a
	// hostname merely because they contain a dot.
	if numericDuration.MatchString(arg) {
		return false
	}
	// Numeric operands are safe values for the bounded switches that remain
	// available to a profile (for example --min-rate 1000 or --host-timeout
	// 5m). A bare, otherwise arbitrary word would become an
	// unmanaged Nmap/Naabu target because EdgeWatch appends its managed target
	// list after the profile arguments. Reject it unless it is one of the small
	// enum vocabulary used by the fixed scanners.
	if numericScalar.MatchString(arg) {
		return false
	}
	switch strings.ToLower(arg) {
	case "c", "s", "4", "6", "true", "false", "tcp", "udp", "connect", "syn", "normal", "light", "version-light", "default", "open", "closed", "filtered", "unfiltered", "unknown", "balanced", "conservative", "fast":
		return false
	}
	// A hostname-like scalar is a target, not a tuning value. Reuse the
	// deployment target validator so this check stays aligned with the target
	// grammar (and does not reject ordinary values such as "version-light").
	if validateTarget(arg) == nil {
		return true
	}
	// Any remaining bare token is not a value EdgeWatch needs to pass. Treat it
	// as a positional target rather than relying on Nmap's interpretation of
	// the custom argument array.
	if !strings.HasPrefix(arg, "-") {
		return true
	}
	return false
}

var numericDuration = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h)$`)
var numericScalar = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?$`)

func safeScannerScalar(arg string) bool {
	if numericDuration.MatchString(arg) || numericScalar.MatchString(arg) {
		return true
	}
	switch strings.ToLower(arg) {
	case "c", "s", "4", "6", "true", "false", "tcp", "udp", "connect", "syn", "normal", "light", "version-light", "default", "open", "closed", "filtered", "unfiltered", "unknown", "balanced", "conservative", "fast":
		return true
	default:
		return false
	}
}

func forbiddenScannerFlag(flag string) bool {
	for _, blocked := range []string{
		// Naabu input, port-scope, output, updater, cloud, proxy, resume,
		// discovery, and target-expansion switches are runtime-owned. Keep
		// both spellings because Naabu exposes most as short/long aliases.
		"-nmap", "-nmap-cli", "-update", "-updater", "-up", "-duc", "-disable-update-check", "-dashboard", "-cloud", "-auth", "-ac", "-auth-config", "-pd", "-tid", "-team-id", "-aid", "-asset-id", "-aname", "-asset-name", "-pdu", "-dashboard-upload", "-passive", "-proxy", "-proxy-auth", "-proxy-credentials", "-config", "-json", "-jsonl", "-j", "-csv", "-o", "-output", "-lof", "-list-output-fields", "-eof", "-exclude-output-fields", "-list", "-l", "-host", "-target", "-exclude-hosts", "-eh", "-exclude-file", "-ef", "-p", "-port", "-ports", "-top-ports", "-tp", "-exclude-ports", "-ep", "-ports-file", "-pf", "-port-threshold", "-pts", "-exclude-cdn", "-ec", "-display-cdn", "-cdn", "-stream", "-smart-scan", "-ss", "-resume", "-resume-file", "-random-targets", "-randomize-hosts", "-scan-all-ips", "-sa", "-ip-version", "-iv", "-exclude-host", "-dns-servers", "-system-dns", "-source-ip", "-connect-payload", "-cp", "-interface-list", "-il", "-interface", "-i", "-resolver", "-r", "-dns-order", "-sr", "-system-resolver", "-irt", "-input-read-timeout", "-sn", "-host-discovery", "-sp", "-sl", "-sL", "-pn", "-skip-host-discovery", "-wn", "-with-host-discovery", "-ps", "-probe-tcp-syn", "-pa", "-probe-tcp-ack", "-pe", "-probe-icmp-echo", "-pp", "-probe-icmp-timestamp", "-pm", "-probe-icmp-address-mask", "-arp", "-arp-ping", "-nd", "-nd-ping", "-rev-ptr", "-sD", "-sd", "-service-discovery", "-sV", "-sv", "-service-version", "-ping", "-pt", "-prediction-threshold", "-health-check", "-hc", "-debug", "-no-color", "-nc", "-version", "-stats", "-si", "-stats-interval", "-mp", "-metrics-port", "-script", "--script", "--script-args", "-datadir", "--datadir", "-stylesheet", "--stylesheet", "-d", "--data", "--data-string", "--data-length", "--input", "--proxies", "--source-port", "--interface", "--traceroute", "--script-trace", "--script-updatedb", "--packet-trace", "--version-trace", "-on", "-og", "-os", "-oa", "-ox", "-a", "-oN", "-oG", "-oS", "-oX", "-O", "-R", "-r", "--resolve-all", "--dns-servers", "--system-dns", "-sn", "-sp", "-sl", "-sL", "-pn", "-sN", "-sf", "-sF", "-sx", "-sX", "-sy", "-sY", "-sz", "-sZ", "-so", "-sO", "-sw", "-sW", "-sm", "-sM", "-b", "--osscan", "-osscan", "--osscan-limit", "--osscan-guess", "--osscan-force", "--send-ip", "--send-eth", "--badsum", "--ip-options", "--ttl", "--spoof-mac", "--defeat-rst-ratelimit", "--version-all", "--version-intensity",
		// These settings have typed fields and are rendered by EdgeWatch. A
		// duplicate profile flag could silently defeat the visible bounds or
		// host-discovery policy, so keep them out of free-form arrays.
		"-rate", "-c", "-retries", "-timeout", "-warm-up-time", "-scan-type", "-verify", "-skip-host-discovery", "-with-host-discovery", "-no-stdin", "-disable-update-check", "-ss", "-st", "-su", "-sv", "-sc", "--version-light", "-6", "-4", "--reason", "--stats-every"} {
		if flag == blocked {
			return true
		}
	}
	// Nmap and Naabu both expose short forms for target lists, output files,
	// and scan-type switches. Treat those families as managed even when an
	// administrator spells them with a suffix (for example -iL or -oX).
	for _, prefix := range []string{"-il", "-ir", "-on", "-og", "-os", "-oa", "-ox", "-p-", "-ss", "-st", "-su", "-sv"} {
		if strings.HasPrefix(flag, prefix) {
			return true
		}
	}
	return false
}
