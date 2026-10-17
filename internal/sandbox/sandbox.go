// Package sandbox starts every scanner invocation under a unique leased
// unprivileged identity and a no-escape seccomp filter, keeping only the
// network capabilities the scan needs. When available, Landlock further
// restricts the files the scanner can open. The notification process uses its
// own fixed identity without capabilities.
//
// Nmap, its NSE scripts, and Naabu parse responses from the networks they
// scan. When the daemon runs as UID 0, a scanner process started the ordinary
// way inherits that identity and can read the database and encryption keys.
// Scanner invocations instead use a UID/GID pair leased from a bounded pool,
// with no supplementary groups. The pool gives concurrent scans separate
// filesystem identities; the seccomp filter prevents descendants from
// escaping their process group. Scanner processes hold only the container's
// NET_RAW and, when granted, NET_ADMIN capabilities. Private scanner files
// are passed as inherited descriptors.
//
// Failure to establish the leased identity or seccomp filter prevents a scan
// from starting, including in auto mode. Landlock is independently optional
// in auto mode. The explicit scanner.sandbox off mode disables all scanner
// isolation. A trusted supervisor keeps the identity lease until it proves
// the scanner process tree is gone and private artifact cleanup succeeds;
// otherwise the lease is quarantined.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// The scanner.sandbox and scanner.landlock modes. Auto and required both
// require a leased scanner identity and no-escape seccomp. Auto can continue
// without Landlock; required refuses scanner work unless Landlock is also
// enforced. Off disables scanner isolation, including Landlock.
const (
	ModeAuto     = "auto"
	ModeRequired = "required"
	ModeOff      = "off"
)

// The states a Status reports.
const (
	StateEnforced    = "enforced"
	StateDisabled    = "disabled"
	StateUnavailable = "unavailable"
)

// UID and GID are the legacy scanner identity and the fixed notification
// identity. Scanner invocations use ScannerIdentityPoolUIDStart through
// ScannerIdentityPoolUIDEnd instead. Keep UID for code that handles the
// legacy identity explicitly; it is not the identity reported by scanner
// status or used by production scanner invocations.
const (
	UID = 65532
	GID = 65532
)

// ScannerIdentityPoolUIDStart and ScannerIdentityPoolUIDEnd bound the
// per-invocation scanner UID/GID pool. ScannerIdentityPoolCapacity is its
// maximum concurrent scanner count, not the number of currently free leases.
const (
	ScannerIdentityPoolUIDStart = 60000
	ScannerIdentityPoolUIDEnd   = 60063
	ScannerIdentityPoolCapacity = ScannerIdentityPoolUIDEnd - ScannerIdentityPoolUIDStart + 1
)

// The resource limits of a scanner process restricted with Landlock, which
// the sandbox-exec command sets before it restricts the process.
const (
	// ScannerOOMScoreAdj is the oom_score_adj of a restricted scanner
	// process, the highest there is: when memory runs out, the kernel's
	// out-of-memory killer stops a scanner before the daemon, which every
	// business unit shares.
	ScannerOOMScoreAdj = 1000
	// ScannerMaxOpenFiles bounds the descriptors a restricted scanner process
	// can hold, and so the sockets it can open at once. Nmap raises its own
	// soft limit to the hard limit; Naabu holds about one socket for each of
	// at most 1024 workers.
	ScannerMaxOpenFiles = 65536
)

// NotifierUID and NotifierGID identify the confined notification process. It
// has an identity of its own, so a compromised scanner process can neither
// signal it nor read the destination URL from its memory.
const (
	NotifierUID = 65531
	NotifierGID = 65531
)

// Profile names the kind of process a policy confines.
type Profile string

const (
	// Scanner confines Nmap and Naabu as UID and GID, with the raw-packet
	// capabilities the daemon holds.
	Scanner Profile = "scanner"
	// Notifier confines the notification process as NotifierUID and
	// NotifierGID, without capabilities and without any file it can write.
	Notifier Profile = "notifier"
)

// profileSpec describes how a profile confines its processes.
type profileSpec struct {
	uid, gid int
	// keepsNetwork keeps the raw-packet capabilities the daemon holds.
	keepsNetwork bool
	// processes names the confined processes, and testProcess the probe that
	// confirms the identity change, in reasons.
	processes, testProcess string
	// sandboxSetting and landlockSetting select the identity and Landlock
	// modes.
	sandboxSetting, landlockSetting string
}

func (profile Profile) spec() profileSpec {
	if profile == Notifier {
		return profileSpec{
			uid: NotifierUID, gid: NotifierGID, processes: "the notification process", testProcess: "a test notification process",
			sandboxSetting: "notifications.sandbox", landlockSetting: "notifications.sandbox",
		}
	}
	return profileSpec{
		uid: UID, gid: GID, keepsNetwork: true, processes: "scanner processes", testProcess: "a test process",
		sandboxSetting: "scanner.sandbox", landlockSetting: "scanner.landlock",
	}
}

func (profile Profile) valid() bool {
	return profile == Scanner || profile == Notifier
}

func profileOrScanner(profile Profile) Profile {
	if profile == "" {
		return Scanner
	}
	return profile
}

// seccompWithoutLandlock is why the notifier's seccomp filter does not apply:
// its existing sandbox-exec path installs the filter with Landlock.
const seccompWithoutLandlock = "the seccomp filter applies only with Landlock"

// ExecCommand is the hidden EdgeWatch command through which a process
// restricted with Landlock starts.
const ExecCommand = "sandbox-exec"

// ErrUnavailable reports that a sandbox setting, such as scanner.sandbox, is
// required but the processes cannot be confined that way.
var ErrUnavailable = errors.New("the sandbox is unavailable")

// Status describes how the processes of a profile start.
type Status struct {
	// Mode is the configured mode, such as scanner.sandbox.
	Mode string `json:"mode"`
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// UID and GID identify a fixed confined identity, such as the notifier.
	// Scanner processes use a per-invocation pool and leave these fields empty.
	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`
	// ProcessUID is the observed/configured UID for a process with one stable
	// identity. It is omitted for scanner status because there is no single
	// process UID across per-invocation leases.
	ProcessUID *int `json:"process_uid,omitempty"`
	// IdentityPool describes the scanner's fixed per-invocation identity
	// strategy. It does not report current free or quarantined leases.
	IdentityPool *ScannerIdentityPoolStatus `json:"identity_pool,omitempty"`
	// Capabilities are the capabilities a confined process keeps.
	Capabilities []string `json:"capabilities,omitempty"`
	// NoNewPrivileges reports whether the processes run with
	// no_new_privs: the daemon's, which they inherit, or the one the Landlock
	// restriction sets.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`
	// Reason explains a disabled or unavailable sandbox.
	Reason string `json:"reason,omitempty"`
	// Landlock describes the restriction of the files the processes can
	// open.
	Landlock LandlockStatus `json:"landlock"`
	// Seccomp describes the filter of the system calls the processes can make.
	// Scanner invocation seccomp is independent of Landlock.
	Seccomp SeccompStatus `json:"seccomp"`
	// Limits are the resource limits the Landlock restriction gives scanner
	// processes. Nil when it does not apply them. Naabu's private-temporary
	// helper also applies these limits when Landlock is disabled; that
	// per-process behavior is not represented by this Landlock status field.
	// The Nmap-only per-file size limit is also not reported here.
	Limits *ProcessLimits `json:"limits,omitempty"`
}

// ScannerIdentityPoolStatus describes the bounded scanner identity pool.
// MaxParallel is the pool's fixed capacity; it is not a live free-slot count.
type ScannerIdentityPoolStatus struct {
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// Strategy identifies per-invocation leases.
	Strategy string `json:"strategy"`
	// UIDStart and UIDEnd are the inclusive scanner UID/GID range.
	UIDStart int `json:"uid_start"`
	UIDEnd   int `json:"uid_end"`
	// MaxParallel is the maximum number of simultaneous scanner leases.
	MaxParallel int `json:"max_parallel"`
	// Reason explains a disabled or unavailable pool.
	Reason string `json:"reason,omitempty"`
}

func scannerIdentityPoolStatus(state, reason string) *ScannerIdentityPoolStatus {
	return &ScannerIdentityPoolStatus{
		State: state, Strategy: "per_invocation",
		UIDStart: ScannerIdentityPoolUIDStart, UIDEnd: ScannerIdentityPoolUIDEnd,
		MaxParallel: ScannerIdentityPoolCapacity, Reason: reason,
	}
}

func uidPointer(uid int) *int { return &uid }

// ProcessLimits are the resource limits of a restricted scanner process.
type ProcessLimits struct {
	// OOMScoreAdj is the process's oom_score_adj.
	OOMScoreAdj int `json:"oom_score_adj"`
	// MaxOpenFiles is the most descriptors the process can hold.
	MaxOpenFiles int `json:"max_open_files"`
}

// SeccompStatus describes the seccomp filter of the processes.
type SeccompStatus struct {
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// Reason explains a disabled or unavailable filter.
	Reason string `json:"reason,omitempty"`
}

// LandlockStatus describes how the files the processes can open are
// restricted.
type LandlockStatus struct {
	// Mode is the configured Landlock mode, such as scanner.landlock.
	Mode string `json:"mode"`
	// State is enforced, disabled, or unavailable.
	State string `json:"state"`
	// ABI is the kernel's Landlock ABI version, which decides the access
	// rights the restriction covers.
	ABI int `json:"abi,omitempty"`
	// Reason explains a disabled or unavailable restriction.
	Reason string `json:"reason,omitempty"`
}

// Options configures Detect.
type Options struct {
	// Profile is the kind of process to confine. Empty is Scanner.
	Profile Profile
	// Mode is the identity mode, such as scanner.sandbox.
	Mode string
	// Landlock is the Landlock mode, such as scanner.landlock.
	Landlock string
	// IdentityProbe is a short non-scanner command Detect runs as the confined
	// identity, without Landlock, to confirm that the runtime allows the
	// identity change. Empty uses /bin/true for scanners and the EdgeWatch
	// version command for the notifier.
	IdentityProbe Probe
	// Probes are short fixed commands Detect runs confined as the processes
	// would be, to confirm compatibility with the configured restrictions.
	// Scanner identity and seccomp are checked separately with a harmless
	// command; scanner compatibility probes run through a leased invocation.
	Probes []Probe
}

// Probe is a short-lived command that Detect runs confined. A probe whose
// executable does not exist is skipped unless Required is true.
type Probe struct {
	// Name names the probed process in reasons. Empty uses the
	// executable's name.
	Name string
	// Args is the command and its arguments. With Self, they are the
	// arguments of the EdgeWatch executable.
	Args []string
	Self bool
	// Required makes a missing executable a failed probe. Optional scanner
	// programs can remain absent without preventing the other probes from
	// passing.
	Required bool
	// Env is the command's environment. Nil gives it only a fixed PATH and
	// HOME.
	Env []string
}

// The platform hooks. Only Linux installs them, because the sandbox relies on
// Linux identity changes, ambient capabilities, and Landlock; elsewhere Detect
// reports the sandbox as unavailable, Confine leaves commands unchanged, and
// Exec fails.
var (
	detectPlatform              func(options Options) *Policy
	confineProcess              func(cmd *exec.Cmd, uid, gid int, ambient []uintptr)
	nameCapability              func(capability uintptr) string
	execRestricted              func(args []string) error
	hardenProcess               func() error
	prepareScannerInvocation    func(context.Context, *exec.Cmd, *Policy, bool) (*ScannerInvocation, error)
	reserveScannerIdentity      func(context.Context, *Policy) (*ScannerIdentityReservation, error)
	recoverScannerIdentityState func(bool) error
)

type identityLease interface {
	identity() (int, int, bool)
	release() error
	quarantine() error
}

type scannerLivenessLease interface {
	inheritedScannerLivenessFile() (*os.File, error)
}

// ScannerIdentityReservation keeps a durable scanner identity reserved while
// Naabu's invocation directory is prepared. PrepareScannerInvocation consumes
// it and releases it only after the supervisor proves that the process tree
// and temporary artifacts are gone.
type ScannerIdentityReservation struct {
	mu       sync.Mutex
	lease    identityLease
	claimed  bool
	finished bool
}

// ReserveScannerIdentity reserves one scanner UID/GID before invocation
// resources such as Naabu's leaf directory are created. A nil result means
// that the policy explicitly runs unconfined.
func ReserveScannerIdentity(ctx context.Context, policy *Policy) (*ScannerIdentityReservation, error) {
	if policy == nil || policy.status.Mode == ModeOff {
		return nil, nil
	}
	if reserveScannerIdentity == nil {
		return nil, errors.New("scanner identity isolation is unavailable on this platform")
	}
	return reserveScannerIdentity(ctx, policy)
}

// Identity returns the reserved UID/GID for creation of per-invocation
// scanner-owned resources.
func (reservation *ScannerIdentityReservation) Identity() (uint32, uint32, bool) {
	if reservation == nil {
		return 0, 0, false
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finished || reservation.lease == nil {
		return 0, 0, false
	}
	uid, gid, ok := reservation.lease.identity()
	return uint32(uid), uint32(gid), ok
}

// livenessFile returns the lease's exact read-only OFD reference so launchers
// can pass that open file description through the supervisor and scanner
// helper. The reservation remains the owner and closes it only after its
// process-tree proof and artifact cleanup finish.
func (reservation *ScannerIdentityReservation) livenessFile() (*os.File, error) {
	if reservation == nil {
		return nil, errors.New("scanner identity reservation is unavailable")
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finished || reservation.lease == nil {
		return nil, errors.New("scanner identity reservation is unavailable")
	}
	lease, ok := reservation.lease.(scannerLivenessLease)
	if !ok {
		return nil, errors.New("scanner identity liveness reference is unavailable")
	}
	return lease.inheritedScannerLivenessFile()
}

// WithScannerIdentityReservation returns a policy copy associated with the
// reservation. The original policy remains immutable.
func (policy *Policy) WithScannerIdentityReservation(reservation *ScannerIdentityReservation) *Policy {
	if policy == nil {
		return nil
	}
	copied := *policy
	copied.status.Capabilities = append([]string(nil), policy.status.Capabilities...)
	copied.ambient = append([]uintptr(nil), policy.ambient...)
	if reservation != nil {
		if uid, gid, ok := reservation.Identity(); ok {
			copied.status.UID, copied.status.GID = int(uid), int(gid)
			// This reservation identifies a future invocation, not an observed
			// scanner process.
			copied.status.ProcessUID = nil
		}
	}
	copied.identityReservation = reservation
	return &copied
}

func (reservation *ScannerIdentityReservation) take() identityLease {
	if reservation == nil {
		return nil
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finished || reservation.claimed || reservation.lease == nil {
		return nil
	}
	reservation.claimed = true
	return reservation.lease
}

// Finish releases an unclaimed reservation after setup failure, or quarantines
// it if invocation-local cleanup could not be proven.
func (reservation *ScannerIdentityReservation) Finish(cleanupSucceeded bool) error {
	if reservation == nil {
		return nil
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.finished || reservation.claimed || reservation.lease == nil {
		return errors.New("scanner identity reservation is unavailable")
	}
	reservation.finished = true
	if cleanupSucceeded {
		if err := reservation.lease.release(); err != nil {
			_ = reservation.lease.quarantine()
			return err
		}
		return nil
	}
	return reservation.lease.quarantine()
}

// ScannerInvocation tracks one supervised scanner process tree. A Linux
// policy uses it to reserve an invocation identity and release that identity
// only after the trusted supervisor confirms that every scanner descendant
// has exited and any invocation temporary files were cleaned. Other platforms
// do not provide this guarantee.
type ScannerInvocation struct {
	implementation scannerInvocationImplementation
}

type scannerInvocationImplementation interface {
	started() error
	startFailed(cleanupSucceeded bool) error
	cancel(*exec.Cmd) error
	verifyProcessTree() error
	finish(cleanupSucceeded bool) error
}

// PrepareScannerInvocation wraps a scanner command in the platform's
// supervised process lifecycle. session requests a controlling terminal for
// the scanner child, as Nmap uses for progress output. A nil result means the
// policy explicitly leaves the command unconfined (or is nil).
func PrepareScannerInvocation(ctx context.Context, cmd *exec.Cmd, policy *Policy, session bool) (*ScannerInvocation, error) {
	if prepareScannerInvocation != nil {
		return prepareScannerInvocation(ctx, cmd, policy, session)
	}
	if policy != nil && policy.status.Mode != ModeOff {
		return nil, errors.New("scanner identity isolation is unavailable on this platform")
	}
	return nil, nil
}

// Started sends the bounded launch request after the wrapper process starts.
func (invocation *ScannerInvocation) Started() error {
	if invocation == nil || invocation.implementation == nil {
		return nil
	}
	return invocation.implementation.started()
}

// StartFailed releases a reservation when the outer supervisor could not
// start, so no scanner child could exist.
func (invocation *ScannerInvocation) StartFailed(cleanupSucceeded bool) error {
	if invocation == nil || invocation.implementation == nil {
		return nil
	}
	return invocation.implementation.startFailed(cleanupSucceeded)
}

// Cancel asks the supervisor to terminate and reap the scanner process tree.
func (invocation *ScannerInvocation) Cancel(cmd *exec.Cmd) error {
	if invocation == nil || invocation.implementation == nil {
		if cmd == nil || cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return invocation.implementation.cancel(cmd)
}

// VerifyProcessTree waits for the trusted supervisor's positive ECHILD proof
// without releasing the identity lease. Callers that own invocation-local
// files use it before cleanup, then call Finish with the cleanup result.
func (invocation *ScannerInvocation) VerifyProcessTree() error {
	if invocation == nil || invocation.implementation == nil {
		return nil
	}
	return invocation.implementation.verifyProcessTree()
}

// InstallCancellation replaces the command's ordinary direct-child cancel
// with the supervisor's bounded process-tree shutdown. Call it after the
// scanner package configures its process group and before Start.
func (invocation *ScannerInvocation) InstallCancellation(cmd *exec.Cmd) {
	if invocation == nil || invocation.implementation == nil || cmd == nil {
		return
	}
	cmd.Cancel = func() error { return invocation.Cancel(cmd) }
}

// Finish releases the identity only when the supervisor proves the process
// tree is empty and the caller confirms invocation cleanup succeeded.
func (invocation *ScannerInvocation) Finish(cleanupSucceeded bool) error {
	if invocation == nil || invocation.implementation == nil {
		return nil
	}
	return invocation.implementation.finish(cleanupSucceeded)
}

// HardenProcess sets Linux's core-file size limit and coredump filter, then
// makes the calling process non-dumpable so that a process of the same
// identity without CAP_SYS_PTRACE can neither trace it nor read its memory.
// A re-executed EdgeWatch child may verify an already-zero inherited filter
// when Landlock prevents rewriting the proc control file; it fails if that
// value is nonzero or cannot be read. The zero coredump filter excludes
// normal memory mappings from core data; it does not prevent a configured
// piped core handler from being invoked, and Linux always includes the vDSO
// mapping. Elsewhere than Linux it does nothing.
func HardenProcess() error {
	if hardenProcess == nil {
		return nil
	}
	return hardenProcess()
}

// RecoverScannerIdentityStateOffline migrates an occupied legacy scanner
// identity journal only after the operator confirms that every process using
// the volume has stopped. New-format live scanner trees are additionally
// protected by the kernel liveness lock; older processes did not hold it.
func RecoverScannerIdentityStateOffline(confirmAllVolumeUsersStopped bool) error {
	if recoverScannerIdentityState == nil {
		return errors.New("scanner identity recovery requires Linux")
	}
	return recoverScannerIdentityState(confirmAllVolumeUsersStopped)
}

// Detect decides how the processes of a profile start in this runtime for the
// configured modes. Unless a mode is off, it starts short-lived confined
// processes to confirm that the runtime allows the identity change, the
// capabilities, and the Landlock restriction.
func Detect(options Options) *Policy {
	options.Profile = profileOrScanner(options.Profile)
	options.Mode = normalizedMode(options.Mode)
	options.Landlock = normalizedMode(options.Landlock)
	if detectPlatform != nil {
		return detectPlatform(options)
	}
	spec := options.Profile.spec()
	status := Status{
		Mode: options.Mode, State: StateUnavailable, Reason: "the sandbox requires Linux",
		Landlock: LandlockStatus{Mode: options.Landlock, State: StateUnavailable, Reason: "Landlock requires Linux"},
		Seccomp:  SeccompStatus{State: StateUnavailable, Reason: "scanner seccomp requires Linux"},
	}
	if options.Profile != Scanner {
		status.ProcessUID = uidPointer(os.Geteuid())
	} else if options.Mode == ModeOff {
		status.IdentityPool = scannerIdentityPoolStatus(StateDisabled, "scanner.sandbox is off")
	} else {
		status.IdentityPool = scannerIdentityPoolStatus(StateUnavailable, "scanner identity leases require Linux")
	}
	switch {
	case options.Mode == ModeOff:
		status.ProcessUID = uidPointer(os.Geteuid())
		status.State, status.Reason = StateDisabled, spec.sandboxSetting+" is off"
		status.Landlock.State, status.Landlock.Reason = StateDisabled, spec.sandboxSetting+" is off"
		status.Seccomp.State, status.Seccomp.Reason = StateDisabled, spec.sandboxSetting+" is off"
	case options.Landlock == ModeOff:
		status.Landlock.State, status.Landlock.Reason = StateDisabled, spec.landlockSetting+" is off"
	}
	return &Policy{profile: options.Profile, status: status}
}

// Exec runs the sandbox-exec command: it restricts its own process with
// Landlock and then executes the program in its place. It returns only when
// the program cannot be started.
func Exec(args []string) error {
	if execRestricted == nil {
		return errors.New(ExecCommand + " requires Linux")
	}
	return execRestricted(args)
}

// Confine makes cmd start its process confined. Call it after InheritFile:
// a process restricted with Landlock can reopen only the files it inherits by
// then, and creates no file. Confine keeps any process attributes already
// set, such as the session and controlling terminal of a pseudo-terminal.
// When the policy confines nothing, cmd is unchanged.
func (p *Policy) Confine(cmd *exec.Cmd) {
	p.confine(cmd)
}

// ConfineWithFileSizeLimit confines cmd and, when a sandbox-exec helper is
// available, sets an inherited hard and soft RLIMIT_FSIZE before the program
// starts. A resource-only helper is used when Landlock is not available. It
// reports whether a helper was configured; when no helper is available, the
// caller must retain its output checks.
func (p *Policy) ConfineWithFileSizeLimit(cmd *exec.Cmd, limit uint64) bool {
	if p == nil {
		return false
	}
	if p.enforce && confineProcess != nil {
		spec := p.profileName().spec()
		confineProcess(cmd, spec.uid, spec.gid, p.ambient)
	}
	if p.profileName() != Scanner {
		cmd.Err = errors.New("file-size limit is only supported for the scanner profile")
		return false
	}
	if limit == 0 {
		cmd.Err = errors.New("scanner file-size limit must be greater than zero")
		return false
	}
	if p.helper != "" {
		startThroughHelperWithFileSizeLimit(cmd, p.helper, p.profileName(), p.seccomp, limit, false)
		return cmd.Err == nil && cmd.Path == p.helper
	}
	if p.temporaryHelper != "" {
		startThroughHelperWithFileSizeLimit(cmd, p.temporaryHelper, p.profileName(), false, limit, true)
		return cmd.Err == nil && cmd.Path == p.temporaryHelper
	}
	return false
}

func (p *Policy) confine(cmd *exec.Cmd) {
	if p == nil {
		return
	}
	if p.enforce && confineProcess != nil {
		spec := p.profileName().spec()
		confineProcess(cmd, spec.uid, spec.gid, p.ambient)
	}
	if p.helper != "" {
		startThroughHelper(cmd, p.helper, p.profileName(), p.seccomp)
		return
	}
	if p.identityOnlyHelper != "" {
		startThroughIdentityOnlyHelper(cmd, p.identityOnlyHelper, p.identityOnlyLivenessFile)
	}
}

// startThroughIdentityOnlyHelper makes cmd start the EdgeWatch helper that
// installs the scanner no-escape seccomp filter without applying Landlock.
// Detect uses this only to verify that seccomp independently of the
// Landlock-backed scanner helper.
func startThroughIdentityOnlyHelper(cmd *exec.Cmd, helper string, livenessProvider func() (*os.File, error)) {
	if cmd == nil {
		return
	}
	if cmd.Err != nil {
		return
	}
	if _, err := os.Stat(cmd.Path); err != nil {
		cmd.Err = err
		return
	}
	if livenessProvider == nil {
		cmd.Err = errors.New("scanner seccomp probe has no liveness reference")
		return
	}
	livenessFile, err := livenessProvider()
	if err != nil || validateScannerLivenessParentFile(livenessFile) != nil {
		cmd.Err = errors.New("scanner seccomp probe liveness reference is unavailable")
		return
	}
	livenessFD, err := appendScannerLivenessFile(cmd, livenessFile)
	if err != nil {
		cmd.Err = errors.New("scanner seccomp probe liveness reference is invalid")
		return
	}
	args := []string{helper, ExecCommand, "--profile", string(Scanner), "--files", strconv.Itoa(len(cmd.ExtraFiles)), "--identity-only", "--seccomp", "--liveness-fd", strconv.Itoa(livenessFD), "--", cmd.Path}
	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Path = helper
}

// startThroughHelper makes cmd start the sandbox-exec command of the EdgeWatch
// executable helper, which restricts itself for profile and installs the
// seccomp filter when requested, then executes cmd's program with its arguments
// and descriptors. A program that does not exist makes cmd's start fail with
// that error instead, so callers still recognize a missing scanner and never
// start it without the restriction.
func startThroughHelper(cmd *exec.Cmd, helper string, profile Profile, seccomp bool) {
	startThroughHelperWithFileSizeLimit(cmd, helper, profile, seccomp, 0, false)
}

func startThroughHelperWithFileSizeLimit(cmd *exec.Cmd, helper string, profile Profile, seccomp bool, fileSizeLimit uint64, resourceOnly bool) {
	if cmd.Err != nil {
		return
	}
	if _, err := os.Stat(cmd.Path); err != nil {
		cmd.Err = err
		return
	}
	args := []string{helper, ExecCommand, "--profile", string(profile), "--files", strconv.Itoa(len(cmd.ExtraFiles))}
	if resourceOnly {
		args = append(args, "--resource-only")
	}
	if fileSizeLimit > 0 {
		args = append(args, "--file-size-limit", strconv.FormatUint(fileSizeLimit, 10))
	}
	if seccomp {
		args = append(args, "--seccomp")
	}
	args = append(args, "--", cmd.Path)
	cmd.Args = append(args, cmd.Args[1:]...)
	cmd.Path = helper
}

func capabilityName(capability uintptr) string {
	if nameCapability != nil {
		return nameCapability(capability)
	}
	return fmt.Sprintf("CAP_%d", capability)
}

// Policy decides how the processes of a profile start. A nil Policy, like a
// policy that confines nothing, starts them unconfined.
type Policy struct {
	profile Profile
	status  Status
	enforce bool
	ambient []uintptr
	// identityAllocator is unset in production. A scanner invocation then uses
	// the fixed durable production allocator; tests may supply a per-policy
	// allocator without a package-global hook.
	identityAllocator   func(context.Context) (identityLease, error)
	identityReservation *ScannerIdentityReservation
	// helper is the EdgeWatch executable whose sandbox-exec command restricts
	// the processes with Landlock. Empty starts them without it.
	helper string
	// identityOnlyHelper is used only by Detect's independent scanner-seccomp
	// probe. It installs the no-escape filter without Landlock.
	identityOnlyHelper       string
	identityOnlyLivenessFile func() (*os.File, error)
	// temporaryHelper is the EdgeWatch executable used to create and confine
	// one Naabu invocation's temporary directory. It is available even when
	// Landlock is not, so the helper can still create and later clean the
	// directory as the scanner identity. Such a directory is not private from
	// another process of that identity without Landlock.
	temporaryHelper string
	// seccomp makes sandbox-exec also install the seccomp filter.
	seccomp bool
}

func (p *Policy) profileName() Profile {
	if p == nil {
		return Scanner
	}
	return profileOrScanner(p.profile)
}

// Access is how a confined process uses a file it inherits.
type Access int

const (
	// Read lets the process open the file for reading.
	Read Access = iota
	// Write lets the process open the file for writing.
	Write
)

// ValidMode reports whether mode is a scanner.sandbox value. The empty value
// is auto.
func ValidMode(mode string) bool {
	switch normalizedMode(mode) {
	case ModeAuto, ModeRequired, ModeOff:
		return true
	default:
		return false
	}
}

func normalizedMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return ModeAuto
	}
	return mode
}

// NewEnforced returns a policy that confines scanner processes with the given
// ambient capabilities, without Landlock and without checking that the
// runtime allows it. Detect is the entry point that checks.
func NewEnforced(ambient ...uintptr) *Policy {
	return NewEnforcedFor(Scanner, ambient...)
}

// NewEnforcedFor returns a policy that confines the processes of profile as
// its identity with the given ambient capabilities, without Landlock and
// without checking that the runtime allows it.
func NewEnforcedFor(profile Profile, ambient ...uintptr) *Policy {
	profile = profileOrScanner(profile)
	spec := profile.spec()
	names := make([]string, 0, len(ambient))
	for _, capability := range ambient {
		names = append(names, capabilityName(capability))
	}
	status := Status{
		Mode: ModeAuto, State: StateEnforced, UID: spec.uid, GID: spec.gid, ProcessUID: uidPointer(spec.uid), Capabilities: names,
		Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: spec.landlockSetting + " is off"},
		Seccomp:  SeccompStatus{State: StateDisabled, Reason: seccompWithoutLandlock},
	}
	if profile == Scanner {
		status.UID, status.GID, status.ProcessUID = 0, 0, nil
		status.IdentityPool = scannerIdentityPoolStatus(StateEnforced, "")
		status.Seccomp = SeccompStatus{State: StateEnforced}
	}
	return &Policy{
		profile: profile,
		status:  status,
		enforce: true,
		ambient: append([]uintptr(nil), ambient...),
	}
}

// WithLandlock returns a copy of p that also starts its processes through the
// sandbox-exec command of the EdgeWatch executable helper, which restricts
// them with Landlock ABI abi, without checking that the kernel allows it. A
// nil p gives a policy that only restricts scanner processes with Landlock.
func (p *Policy) WithLandlock(helper string, abi int) *Policy {
	restricted := &Policy{profile: Scanner, status: Status{Mode: ModeOff, State: StateDisabled, ProcessUID: uidPointer(os.Geteuid()), Reason: "scanner.sandbox is off"}}
	if p != nil {
		copied := *p
		copied.status.Capabilities = append([]string(nil), p.status.Capabilities...)
		copied.ambient = append([]uintptr(nil), p.ambient...)
		restricted = &copied
	}
	restricted.helper = helper
	restricted.temporaryHelper = helper
	restricted.seccomp = false
	restricted.status.NoNewPrivileges = true
	restricted.status.Landlock = LandlockStatus{Mode: ModeAuto, State: StateEnforced, ABI: abi}
	restricted.status.Seccomp = SeccompStatus{State: StateUnavailable, Reason: "the seccomp filter was not requested"}
	restricted.status.Limits = nil
	if restricted.profileName() == Scanner {
		restricted.status.Limits = &ProcessLimits{OOMScoreAdj: ScannerOOMScoreAdj, MaxOpenFiles: ScannerMaxOpenFiles}
	}
	return restricted
}

// WithSeccomp returns a copy of p, which must restrict its processes with
// Landlock, whose sandbox-exec command also installs the seccomp filter,
// without checking that the kernel allows it.
func (p *Policy) WithSeccomp() *Policy {
	filtered := *p
	filtered.status.Capabilities = append([]string(nil), p.status.Capabilities...)
	filtered.ambient = append([]uintptr(nil), p.ambient...)
	filtered.seccomp = true
	filtered.status.Seccomp = SeccompStatus{State: StateEnforced}
	return &filtered
}

// Enforced reports whether the processes start as the confined identity with
// only the ambient capabilities.
func (p *Policy) Enforced() bool {
	return p != nil && p.enforce
}

// Restricted reports whether the processes start restricted with Landlock.
func (p *Policy) Restricted() bool {
	return p != nil && p.helper != ""
}

// InheritsFiles reports whether scanner processes open their private files
// through inherited descriptors, because the confined identity or the
// Landlock restriction keeps them out of the scanner's temporary directory.
func (p *Policy) InheritsFiles() bool {
	return p.Enforced() || p.Restricted()
}

// Status reports how the processes start.
func (p *Policy) Status() Status {
	if p == nil {
		return Status{
			Mode: ModeOff, State: StateDisabled, ProcessUID: uidPointer(os.Geteuid()), Reason: "the processes are not confined",
			Landlock: LandlockStatus{Mode: ModeOff, State: StateDisabled, Reason: "the processes are not confined"},
			Seccomp:  SeccompStatus{State: StateDisabled, Reason: "the processes are not confined"},
		}
	}
	status := p.status
	status.Capabilities = append([]string(nil), p.status.Capabilities...)
	if p.status.IdentityPool != nil {
		identityPool := *p.status.IdentityPool
		status.IdentityPool = &identityPool
	}
	if p.status.Limits != nil {
		limits := *p.status.Limits
		status.Limits = &limits
	}
	return status
}

// Require reports ErrUnavailable, with the reason, when the configured
// sandbox cannot meet its fail-closed contract. Scanner modes other than off
// require the per-invocation identity and no-escape seccomp filter even when
// their mode is auto; notifier auto mode retains its same-identity fallback.
func (p *Policy) Require() error {
	if p == nil {
		return nil
	}
	spec := p.profileName().spec()
	if p.profileName() == Scanner && p.status.Mode != ModeOff && !p.enforce && p.status.Mode != ModeAuto {
		return fmt.Errorf("%w: %s; set %s to auto to keep the daemon available while scanner launches remain fail closed", ErrUnavailable, p.status.Reason, spec.sandboxSetting)
	}
	if p.status.Mode == ModeRequired && !p.enforce {
		return fmt.Errorf("%w: %s; set %s to auto to start %s unconfined", ErrUnavailable, p.status.Reason, spec.sandboxSetting, spec.processes)
	}
	if p.status.Landlock.Mode == ModeRequired && p.helper == "" {
		return fmt.Errorf("%w: %s; set %s to auto to start %s without Landlock", ErrUnavailable, p.status.Landlock.Reason, spec.landlockSetting, spec.processes)
	}
	return nil
}

// InheritFile passes f to the process cmd starts and returns the path by which
// that process opens it. A confined process cannot reach the scanner's
// temporary directory inside the data directory, so it opens the file through
// its inherited descriptor. For the confined identity, the file's
// other-permission bits allow exactly the access it needs; the Landlock
// restriction lets the process reopen the file with the access f was opened
// with, so open f read-only for Read and write-only for Write. The caller
// keeps f open until the process has exited. When the policy confines
// nothing, the process opens f by its name, as before.
func (p *Policy) InheritFile(cmd *exec.Cmd, f *os.File, access Access) (string, error) {
	if !p.InheritsFiles() {
		return f.Name(), nil
	}
	if p.enforce {
		mode := os.FileMode(0o604)
		if access == Write {
			mode = 0o602
		}
		if err := f.Chmod(mode); err != nil {
			return "", fmt.Errorf("share scanner file: %w", err)
		}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	return fmt.Sprintf("/dev/fd/%d", 2+len(cmd.ExtraFiles)), nil
}
