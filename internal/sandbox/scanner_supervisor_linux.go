//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	scannerSupervisorFlag      = "--supervise-scanner"
	scannerSupervisorMagic     = "EWSUP001"
	scannerSupervisorMaxConfig = 1 << 20
	scannerSupervisorTimeout   = 5 * time.Second
)

type scannerLaunchRequest struct {
	Version     int       `json:"version"`
	Path        string    `json:"path"`
	Args        []string  `json:"args"`
	Env         []string  `json:"env"`
	Dir         string    `json:"dir,omitempty"`
	Files       int       `json:"files"`
	LivenessFD  int       `json:"liveness_fd"`
	UID         uint32    `json:"uid"`
	GID         uint32    `json:"gid"`
	AmbientCaps []uintptr `json:"ambient_caps,omitempty"`
	Session     bool      `json:"session,omitempty"`
}

type scannerSupervisorInvocation struct {
	lease         identityLease
	request       scannerLaunchRequest
	config        []byte
	configRead    *os.File
	configWrite   *os.File
	resultRead    *os.File
	resultWrite   *os.File
	startedOK     bool
	startFailedOK bool
	proofChecked  bool
	proofErr      error
	finished      bool
}

type scannerSupervisorRequest struct {
	files     int
	requestFD int
	resultFD  int
}

func init() {
	prepareScannerInvocation = prepareLinuxScannerInvocation
	reserveScannerIdentity = reserveLinuxScannerIdentity
	recoverScannerIdentityState = recoverScannerIdentityStateOfflineLinux
}

func reserveLinuxScannerIdentity(ctx context.Context, policy *Policy) (*ScannerIdentityReservation, error) {
	if ctx == nil {
		return nil, errors.New("reserve scanner identity: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if policy == nil || policy.status.Mode == ModeOff {
		return nil, nil
	}
	if policy.profileName() != Scanner || !policy.enforce {
		return nil, errors.New("reserve scanner identity: a distinct scanner identity is unavailable")
	}
	lease, err := acquireScannerIdentity(ctx, policy)
	if err != nil {
		return nil, err
	}
	return &ScannerIdentityReservation{lease: lease}, nil
}

func acquireScannerIdentity(ctx context.Context, policy *Policy) (identityLease, error) {
	if policy != nil && policy.identityAllocator != nil {
		return policy.identityAllocator(ctx)
	}
	return productionScannerIdentityAllocator().acquire(ctx)
}

func prepareLinuxScannerInvocation(ctx context.Context, cmd *exec.Cmd, policy *Policy, session bool) (*ScannerInvocation, error) {
	if policy == nil || policy.status.Mode == ModeOff {
		return nil, nil
	}
	if ctx == nil {
		return nil, errors.New("prepare scanner invocation: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cmd == nil || cmd.Path == "" || len(cmd.Args) == 0 || cmd.Err != nil {
		return nil, errors.New("prepare scanner invocation: command is invalid")
	}
	if policy.profileName() != Scanner || !policy.enforce {
		return nil, errors.New("prepare scanner invocation: a distinct scanner identity is unavailable")
	}
	if len(cmd.ExtraFiles) > maxInheritedFiles-2 {
		return nil, errors.New("prepare scanner invocation: too many inherited scanner descriptors")
	}
	if !filepath.IsAbs(cmd.Path) || strings.ContainsRune(cmd.Path, '\x00') {
		return nil, errors.New("prepare scanner invocation: executable path is invalid")
	}
	helper := policy.helper
	if helper == "" {
		helper = policy.temporaryHelper
	}
	if helper == "" {
		var err error
		helper, err = os.Executable()
		if err != nil {
			return nil, errors.New("prepare scanner invocation: supervisor executable is unavailable")
		}
	}
	if !filepath.IsAbs(helper) {
		return nil, errors.New("prepare scanner invocation: supervisor executable path is invalid")
	}
	if _, err := os.Stat(helper); err != nil {
		return nil, fmt.Errorf("prepare scanner invocation: supervisor executable is unavailable: %w", err)
	}

	if err := seccompSupport(); err != nil {
		return nil, fmt.Errorf("prepare scanner invocation: required no-escape filter is unavailable: %w", err)
	}
	var lease identityLease
	var uid, gid int
	var err error
	reservation := policy.identityReservation
	var livenessFile *os.File
	if reservation != nil {
		reservedUID, reservedGID, ok := reservation.Identity()
		if !ok {
			return nil, errors.New("prepare scanner invocation: reserved identity is unavailable")
		}
		uid, gid = int(reservedUID), int(reservedGID)
		livenessFile, err = reservation.livenessFile()
		if err != nil {
			return nil, errors.New("prepare scanner invocation: scanner liveness reference is unavailable")
		}
	} else {
		lease, err = acquireScannerIdentity(ctx, policy)
		if err != nil {
			return nil, err
		}
		var ok bool
		uid, gid, ok = lease.identity()
		if !ok {
			_ = lease.quarantine()
			return nil, errors.New("prepare scanner invocation: identity lease is unavailable")
		}
		livenessFile, err = scannerLivenessFileForLease(lease)
		if err != nil {
			_ = lease.quarantine()
			return nil, errors.New("prepare scanner invocation: scanner liveness reference is unavailable")
		}
	}
	releaseUnreservedLease := func() {
		if lease != nil {
			_ = lease.release()
		}
	}
	livenessFD, err := appendScannerLivenessFile(cmd, livenessFile)
	if err != nil {
		releaseUnreservedLease()
		return nil, err
	}
	if err := addScannerNoEscapeHelper(cmd, helper, livenessFD); err != nil {
		releaseUnreservedLease()
		return nil, err
	}

	var ambient []uintptr
	if cmd.SysProcAttr != nil {
		ambient = append(ambient, cmd.SysProcAttr.AmbientCaps...)
	}
	request := scannerLaunchRequest{
		Version: 1, Path: cmd.Path, Args: append([]string(nil), cmd.Args...), Env: append([]string(nil), cmd.Env...),
		Dir: cmd.Dir, Files: len(cmd.ExtraFiles), LivenessFD: livenessFD, UID: uint32(uid), GID: uint32(gid),
		AmbientCaps: ambient, Session: session,
	}
	configuration, err := json.Marshal(request)
	if err != nil || len(configuration) == 0 || len(configuration) > scannerSupervisorMaxConfig {
		releaseUnreservedLease()
		return nil, errors.New("prepare scanner invocation: launch request is too large")
	}
	configRead, configWrite, err := os.Pipe()
	if err != nil {
		releaseUnreservedLease()
		return nil, errors.New("prepare scanner invocation: launch channel is unavailable")
	}
	resultFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = configRead.Close()
		_ = configWrite.Close()
		releaseUnreservedLease()
		return nil, errors.New("prepare scanner invocation: result channel is unavailable")
	}
	if reservation != nil {
		lease = reservation.take()
		if lease == nil {
			_ = configRead.Close()
			_ = configWrite.Close()
			_ = unix.Close(resultFDs[0])
			_ = unix.Close(resultFDs[1])
			return nil, errors.New("prepare scanner invocation: reserved identity is unavailable")
		}
		leasedUID, leasedGID, ok := lease.identity()
		if !ok || leasedUID != uid || leasedGID != gid {
			_ = lease.quarantine()
			_ = configRead.Close()
			_ = configWrite.Close()
			_ = unix.Close(resultFDs[0])
			_ = unix.Close(resultFDs[1])
			return nil, errors.New("prepare scanner invocation: reserved identity changed")
		}
	}
	resultRead := os.NewFile(uintptr(resultFDs[0]), "scanner supervisor result")
	resultWrite := os.NewFile(uintptr(resultFDs[1]), "scanner supervisor result child")
	dataFiles := len(cmd.ExtraFiles)
	requestFD, resultFD := 3+dataFiles, 4+dataFiles
	cmd.ExtraFiles = append(cmd.ExtraFiles, configRead, resultWrite)
	cmd.Path = helper
	cmd.Args = []string{helper, ExecCommand, scannerSupervisorFlag, "--files", strconv.Itoa(dataFiles), "--request-fd", strconv.Itoa(requestFD), "--result-fd", strconv.Itoa(resultFD)}
	// The supervisor remains the daemon identity. It starts a separate scanner
	// child with the durable invocation UID/GID from the bounded request.
	cmd.SysProcAttr = nil
	invocation := &scannerSupervisorInvocation{
		lease: lease, request: request, configRead: configRead, configWrite: configWrite,
		resultRead: resultRead, resultWrite: resultWrite,
		config: configuration,
	}
	return &ScannerInvocation{implementation: invocation}, nil
}

func addScannerNoEscapeHelper(cmd *exec.Cmd, helper string, livenessFD int) error {
	if cmd.Path == helper && len(cmd.Args) >= 2 && cmd.Args[1] == ExecCommand {
		separator := -1
		filesIndex, livenessIndex, seccompIndex := -1, -1, -1
		privateTemporary := false
		for index := 2; index < len(cmd.Args); index++ {
			if cmd.Args[index] == "--" {
				separator = index
				break
			}
			switch cmd.Args[index] {
			case "--private-tmp":
				privateTemporary = true
			case "--files":
				if filesIndex >= 0 || index+1 >= len(cmd.Args) {
					return errors.New("prepare scanner invocation: sandbox helper file count is invalid")
				}
				filesIndex = index + 1
				index++
			case "--liveness-fd":
				if livenessIndex >= 0 || index+1 >= len(cmd.Args) {
					return errors.New("prepare scanner invocation: sandbox helper liveness descriptor is invalid")
				}
				livenessIndex = index + 1
				index++
			case "--seccomp":
				if seccompIndex >= 0 {
					return errors.New("prepare scanner invocation: sandbox helper seccomp flag is duplicated")
				}
				seccompIndex = index
			case "--seccomp-notify-fd":
				return errors.New("prepare scanner invocation: helper notification descriptor is already set")
			}
		}
		if separator < 0 || filesIndex < 0 {
			return errors.New("prepare scanner invocation: sandbox helper arguments are invalid")
		}
		if privateTemporary {
			dataFiles, err := strconv.Atoi(cmd.Args[filesIndex])
			if err != nil || dataFiles < 0 || dataFiles+scannerPrivateControlFDCount(execRequest{privateTemp: true}) != len(cmd.ExtraFiles) {
				return errors.New("prepare scanner invocation: private temporary descriptor layout is invalid")
			}
		} else {
			cmd.Args[filesIndex] = strconv.Itoa(len(cmd.ExtraFiles))
		}
		if livenessIndex >= 0 {
			if cmd.Args[livenessIndex] != strconv.Itoa(livenessFD) {
				return errors.New("prepare scanner invocation: sandbox helper liveness descriptor changed")
			}
		} else {
			cmd.Args = append(cmd.Args[:separator], append([]string{"--liveness-fd", strconv.Itoa(livenessFD)}, cmd.Args[separator:]...)...)
			separator += 2
		}
		if seccompIndex < 0 {
			cmd.Args = append(cmd.Args[:separator], append([]string{"--seccomp"}, cmd.Args[separator:]...)...)
		}
		return nil
	}
	originalPath := cmd.Path
	originalArgs := append([]string(nil), cmd.Args...)
	files := len(cmd.ExtraFiles)
	args := []string{helper, ExecCommand, "--profile", string(Scanner), "--files", strconv.Itoa(files), "--identity-only", "--seccomp", "--liveness-fd", strconv.Itoa(livenessFD), "--", originalPath}
	if len(originalArgs) > 1 {
		args = append(args, originalArgs[1:]...)
	}
	cmd.Path, cmd.Args = helper, args
	return nil
}

func appendSeccompNotificationControl(args []string, notifyFD int) ([]string, error) {
	if notifyFD < 3 || len(args) < 3 || args[1] != ExecCommand {
		return nil, errors.New("scanner helper notification descriptor is invalid")
	}
	request, err := parseExecArgs(args[2:])
	if err != nil || request.profile != Scanner || !request.seccomp || request.notifyFD != 0 {
		return nil, errors.New("scanner helper request cannot accept a notification descriptor")
	}
	separator := -1
	for index := 2; index < len(args); index++ {
		if args[index] == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || notifyFD != 3+request.files+scannerPrivateControlFDCount(request) {
		return nil, errors.New("scanner helper notification descriptor layout is invalid")
	}
	updated := append([]string(nil), args[:separator]...)
	updated = append(updated, "--seccomp-notify-fd", strconv.Itoa(notifyFD))
	updated = append(updated, args[separator:]...)
	return updated, nil
}

func receiveScannerNotificationListener(controlFD int, child *exec.Cmd, uid, gid uint32, signals <-chan os.Signal, timeout time.Duration) (int, bool, error) {
	if controlFD < 0 || child == nil || child.Process == nil || timeout <= 0 {
		return -1, false, errors.New("scanner supervisor: notification listener wait is unavailable")
	}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return -1, false, errors.New("seccomp notification listener startup timed out")
		}
		wait := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if wait > int(seccompNotificationPollTimeout/time.Millisecond) {
			wait = int(seccompNotificationPollTimeout / time.Millisecond)
		}
		poll := []unix.PollFd{{Fd: int32(controlFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, false, errors.New("poll seccomp notification listener channel failed")
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			listenerFD, receiveErr := receiveSeccompNotificationListenerPacket(controlFD, child.Process.Pid, uid, gid)
			return listenerFD, false, receiveErr
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return -1, false, errors.New("scanner helper exited before sending its seccomp notification listener")
		}
		select {
		case <-signals:
			return -1, true, errors.New("scanner process tree was cancelled during sandbox setup")
		default:
		}
		var info unix.Siginfo
		waitErr := unix.Waitid(unix.P_PID, child.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if waitErr != nil && !errors.Is(waitErr, unix.EINTR) {
			return -1, false, errors.New("scanner helper exit could not be verified")
		}
		if info.Signo != 0 {
			return -1, false, errors.New("scanner helper exited before sending its seccomp notification listener")
		}
	}
}

func scannerLivenessFileForLease(lease identityLease) (*os.File, error) {
	provider, ok := lease.(scannerLivenessLease)
	if !ok {
		return nil, errors.New("scanner identity lease has no liveness reference")
	}
	file, err := provider.inheritedScannerLivenessFile()
	if err != nil || file == nil {
		return nil, errors.New("scanner identity lease has no liveness reference")
	}
	if err := validateScannerLivenessParentFile(file); err != nil {
		return nil, errors.New("scanner identity lease liveness reference is invalid")
	}
	return file, nil
}

func appendScannerLivenessFile(cmd *exec.Cmd, file *os.File) (int, error) {
	if cmd == nil || file == nil {
		return -1, errors.New("prepare scanner invocation: scanner liveness reference is unavailable")
	}
	if len(cmd.ExtraFiles) >= maxInheritedFiles {
		return -1, errors.New("prepare scanner invocation: too many inherited scanner descriptors")
	}
	index := -1
	fileInfo, err := file.Stat()
	if err != nil {
		return -1, errors.New("prepare scanner invocation: scanner liveness reference is unavailable")
	}
	for current, existing := range cmd.ExtraFiles {
		if existing == nil {
			return -1, errors.New("prepare scanner invocation: inherited scanner descriptor is unavailable")
		}
		if existing == file {
			if index >= 0 {
				return -1, errors.New("prepare scanner invocation: scanner liveness reference is duplicated")
			}
			index = current
			continue
		}
		otherInfo, statErr := existing.Stat()
		if statErr == nil && os.SameFile(fileInfo, otherInfo) {
			return -1, errors.New("prepare scanner invocation: scanner liveness reference has an alias")
		}
	}
	if index < 0 {
		index = len(cmd.ExtraFiles)
		cmd.ExtraFiles = append(cmd.ExtraFiles, file)
	}
	return 3 + index, nil
}

func (invocation *scannerSupervisorInvocation) started() error {
	if invocation == nil || invocation.startedOK {
		return errors.New("start scanner supervisor: invocation is unavailable")
	}
	invocation.startedOK = true
	_ = invocation.configRead.Close()
	invocation.configRead = nil
	_ = invocation.resultWrite.Close()
	invocation.resultWrite = nil
	if err := writeAll(invocation.configWrite, invocation.config); err != nil {
		_ = invocation.configWrite.Close()
		invocation.configWrite = nil
		return errors.New("start scanner supervisor: launch request failed")
	}
	if err := invocation.configWrite.Close(); err != nil {
		invocation.configWrite = nil
		return errors.New("start scanner supervisor: close launch request failed")
	}
	invocation.configWrite = nil
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func (invocation *scannerSupervisorInvocation) startFailed(cleanupSucceeded bool) error {
	if invocation == nil || invocation.finished {
		return nil
	}
	if invocation.startedOK {
		return errors.New("start scanner supervisor: invocation already started")
	}
	invocation.startFailedOK = true
	invocation.finished = true
	invocation.closeParentFiles()
	if cleanupSucceeded {
		if err := invocation.lease.release(); err != nil {
			_ = invocation.lease.quarantine()
			return err
		}
		return nil
	}
	return invocation.lease.quarantine()
}

func (invocation *scannerSupervisorInvocation) cancel(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (invocation *scannerSupervisorInvocation) verifyProcessTree() error {
	if invocation == nil {
		return errors.New("scanner supervisor result is unavailable")
	}
	if invocation.proofChecked {
		return invocation.proofErr
	}
	invocation.proofChecked = true
	if !invocation.startedOK || invocation.resultRead == nil {
		invocation.proofErr = errors.New("scanner supervisor result is unavailable")
		return invocation.proofErr
	}
	if err := waitScannerSupervisorResult(int(invocation.resultRead.Fd()), scannerSupervisorTimeout); err != nil {
		invocation.proofErr = errors.New("scanner supervisor did not prove process-tree cleanup")
		return invocation.proofErr
	}
	message := make([]byte, 16)
	n, _, flags, _, err := unix.Recvmsg(int(invocation.resultRead.Fd()), message, nil, 0)
	if err != nil || flags&unix.MSG_TRUNC != 0 || n != len(message) || validateScannerSupervisorResult(message) != nil {
		invocation.proofErr = errors.New("scanner supervisor did not prove process-tree cleanup")
		return invocation.proofErr
	}
	return nil
}

// validateScannerSupervisorResult accepts only the complete success frame
// emitted by the trusted supervisor. The fixed private socketpair binds the
// response to this invocation; reserved bytes must stay zero so malformed or
// future protocol frames fail closed until explicitly versioned.
func validateScannerSupervisorResult(message []byte) error {
	if len(message) != 16 || string(message[:8]) != scannerSupervisorMagic || message[8] != 1 {
		return errors.New("invalid scanner supervisor completion frame")
	}
	for _, value := range message[9:] {
		if value != 0 {
			return errors.New("invalid scanner supervisor completion frame")
		}
	}
	return nil
}

func (invocation *scannerSupervisorInvocation) finish(cleanupSucceeded bool) error {
	if invocation == nil || invocation.finished {
		return nil
	}
	invocation.finished = true
	defer invocation.closeParentFiles()
	if !invocation.startedOK {
		if invocation.startFailedOK && cleanupSucceeded {
			return invocation.lease.release()
		}
		return invocation.lease.quarantine()
	}
	if !cleanupSucceeded {
		_ = invocation.lease.quarantine()
		return errors.New("scanner invocation cleanup failed; identity quarantined")
	}
	if err := invocation.verifyProcessTree(); err != nil {
		_ = invocation.lease.quarantine()
		return fmt.Errorf("%w; identity quarantined", err)
	}
	if err := invocation.lease.release(); err != nil {
		_ = invocation.lease.quarantine()
		return fmt.Errorf("release scanner identity: %w", err)
	}
	return nil
}

func waitScannerSupervisorResult(fd int, timeout time.Duration) error {
	if fd < 0 || timeout <= 0 {
		return errors.New("invalid scanner supervisor result wait")
	}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("scanner supervisor result timed out")
		}
		milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			return nil
		}
	}
}

func (invocation *scannerSupervisorInvocation) closeParentFiles() {
	for _, file := range []*os.File{invocation.configRead, invocation.configWrite, invocation.resultRead, invocation.resultWrite} {
		if file != nil {
			_ = file.Close()
		}
	}
	invocation.configRead, invocation.configWrite, invocation.resultRead, invocation.resultWrite = nil, nil, nil, nil
}

func parseScannerSupervisorArgs(args []string) (scannerSupervisorRequest, error) {
	const usage = "usage: sandbox-exec --supervise-scanner --files N --request-fd FD --result-fd FD"
	values := make(map[string]string, 3)
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) || !strings.HasPrefix(args[index], "--") {
			return scannerSupervisorRequest{}, errors.New(usage)
		}
		key := args[index]
		if _, exists := values[key]; exists {
			return scannerSupervisorRequest{}, errors.New(usage)
		}
		values[key] = args[index+1]
		index++
	}
	if len(values) != 3 {
		return scannerSupervisorRequest{}, errors.New(usage)
	}
	files, filesErr := strconv.Atoi(values["--files"])
	requestFD, requestErr := strconv.Atoi(values["--request-fd"])
	resultFD, resultErr := strconv.Atoi(values["--result-fd"])
	if filesErr != nil || requestErr != nil || resultErr != nil || files < 0 || files > maxInheritedFiles-2 ||
		requestFD != 3+files || resultFD != requestFD+1 || len(values["--files"]) == 0 || len(values["--request-fd"]) == 0 || len(values["--result-fd"]) == 0 {
		return scannerSupervisorRequest{}, errors.New(usage)
	}
	for key := range values {
		if key != "--files" && key != "--request-fd" && key != "--result-fd" {
			return scannerSupervisorRequest{}, errors.New(usage)
		}
	}
	return scannerSupervisorRequest{files: files, requestFD: requestFD, resultFD: resultFD}, nil
}

func execScannerSupervisor(args []string) error {
	return execScannerSupervisorWithBrokerFactory(args, nil)
}

// execScannerSupervisorWithBrokerFactory keeps the production supervisor
// control flow identical while allowing privileged re-exec tests to pause at
// the real ADDFD/NOTIF_SEND boundary. A nil factory selects the production
// broker; the test factory is confined to a separate test-binary process.
func execScannerSupervisorWithBrokerFactory(args []string, brokerFactory func(listenerFD int) *seccompNotificationBroker) error {
	request, err := parseScannerSupervisorArgs(args)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("%s: establish child reaper: %w", ExecCommand, err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("%s: protect supervisor process: %w", ExecCommand, err)
	}
	configFile := os.NewFile(uintptr(request.requestFD), "scanner launch request")
	if configFile == nil {
		return errors.New("scanner supervisor: launch request descriptor is unavailable")
	}
	configuration, err := io.ReadAll(io.LimitReader(configFile, scannerSupervisorMaxConfig+1))
	_ = configFile.Close()
	if err != nil || len(configuration) == 0 || len(configuration) > scannerSupervisorMaxConfig {
		return errors.New("scanner supervisor: launch request is unavailable or too large")
	}
	launch, err := decodeScannerLaunchRequest(configuration, request)
	if err != nil {
		return fmt.Errorf("scanner supervisor: %w", err)
	}
	if err := validateScannerLivenessDescriptor(launch.LivenessFD); err != nil {
		return errors.New("scanner supervisor: inherited liveness descriptor is invalid")
	}
	result := os.NewFile(uintptr(request.resultFD), "scanner supervisor result")
	defer result.Close()
	unix.CloseOnExec(request.resultFD)

	childFiles := make([]*os.File, launch.Files)
	for index := range childFiles {
		fd := 3 + index
		childFiles[index] = os.NewFile(uintptr(fd), fmt.Sprintf("scanner data descriptor %d", index))
	}
	childArgs, err := appendSeccompNotificationControl(launch.Args, 3+launch.Files)
	if err != nil {
		for _, file := range childFiles {
			_ = file.Close()
		}
		_ = sendScannerSupervisorResult(request.resultFD, true)
		return fmt.Errorf("scanner supervisor: %w", err)
	}
	channels, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		for _, file := range childFiles {
			_ = file.Close()
		}
		_ = sendScannerSupervisorResult(request.resultFD, true)
		return errors.New("scanner supervisor: seccomp notification channel is unavailable")
	}
	notificationRead := channels[0]
	if err := unix.SetsockoptInt(notificationRead, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		_ = unix.Close(channels[0])
		_ = unix.Close(channels[1])
		for _, file := range childFiles {
			_ = file.Close()
		}
		_ = sendScannerSupervisorResult(request.resultFD, true)
		return errors.New("scanner supervisor: seccomp notification credentials are unavailable")
	}
	notificationWrite := os.NewFile(uintptr(channels[1]), "scanner seccomp notification channel child")
	childFiles = append(childFiles, notificationWrite)
	launch.Args = childArgs
	child := buildScannerChildCommand(launch, childFiles)

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		_ = unix.Close(notificationRead)
		for _, file := range childFiles {
			_ = file.Close()
		}
		_ = sendScannerSupervisorResult(request.resultFD, true)
		return fmt.Errorf("scanner supervisor: start scanner child: %w", err)
	}
	for _, file := range childFiles {
		_ = file.Close()
	}
	listenerFD, startupInterrupted, err := receiveScannerNotificationListener(notificationRead, child, launch.UID, launch.GID, signals, scannerSupervisorTimeout)
	if err != nil {
		_ = unix.Close(notificationRead)
		cleanupErr := terminateAndReapScannerChild(child, request.resultFD, err)
		if startupInterrupted {
			return fmt.Errorf("scanner supervisor: scanner process tree was cancelled during sandbox setup: %w", cleanupErr)
		}
		return cleanupErr
	}
	defer unix.Close(notificationRead)
	defer unix.Close(listenerFD)
	interrupted := false
	broker := &seccompNotificationBroker{listenerFD: listenerFD}
	if brokerFactory != nil {
		broker = brokerFactory(listenerFD)
	}
	if broker == nil || broker.listenerFD != listenerFD {
		return terminateAndReapScannerChild(child, request.resultFD, errors.New("scanner supervisor: seccomp notification broker is invalid"))
	}
	watchdog := time.NewTicker(20 * time.Millisecond)
	defer watchdog.Stop()
	interrupted, childErr, err := superviseScannerChild(child, request.resultFD, signals, watchdog.C, scannerSupervisorOps{
		waitForExit: func(pid int) (bool, error) {
			var info unix.Siginfo
			err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
			return info.Signo != 0, err
		},
		killGroup: func(pid int, signal syscall.Signal) error {
			return syscall.Kill(-pid, signal)
		},
		waitChild:            func(child *exec.Cmd) error { return child.Wait() },
		reapChildren:         reapScannerChildren,
		sendResult:           sendScannerSupervisorResult,
		now:                  time.Now,
		serviceNotifications: broker.serveOne,
	})
	if err != nil {
		return err
	}
	if interrupted {
		return errors.New("scanner supervisor: scanner process tree was cancelled")
	}
	if childErr != nil {
		return fmt.Errorf("scanner supervisor: scanner exited unsuccessfully: %w", childErr)
	}
	return nil
}

// buildScannerChildCommand turns a validated request into the exact process
// attributes used by the trusted supervisor. Keeping this construction
// separate lets tests assert the child identity, descriptor, capability, and
// parent-death contracts without executing an alternate test-only path.
func buildScannerChildCommand(launch scannerLaunchRequest, childFiles []*os.File) *exec.Cmd {
	child := exec.Command(launch.Path, launch.Args[1:]...)
	child.Args = append([]string(nil), launch.Args...)
	child.Env, child.Dir = append([]string(nil), launch.Env...), launch.Dir
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = childFiles
	child.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: launch.UID, Gid: launch.GID, Groups: []uint32{}},
		AmbientCaps: append([]uintptr(nil), launch.AmbientCaps...),
		Pdeathsig:   syscall.SIGKILL,
	}
	if launch.Session {
		child.SysProcAttr.Setsid, child.SysProcAttr.Setctty, child.SysProcAttr.Ctty = true, true, 0
	} else {
		child.SysProcAttr.Setpgid = true
	}
	return child
}

// decodeScannerLaunchRequest validates the bounded parent-to-supervisor
// protocol without changing thread or process state. Keep this separate from
// execScannerSupervisor's subreaper and dumpability setup so its input contract
// can be exercised directly without weakening those process protections.
func decodeScannerLaunchRequest(configuration []byte, request scannerSupervisorRequest) (scannerLaunchRequest, error) {
	if len(configuration) == 0 || len(configuration) > scannerSupervisorMaxConfig {
		return scannerLaunchRequest{}, errors.New("launch request is unavailable or too large")
	}
	var launch scannerLaunchRequest
	decoder := json.NewDecoder(strings.NewReader(string(configuration)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&launch); err != nil {
		return scannerLaunchRequest{}, errors.New("launch request is malformed")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || launch.Version != 1 || !filepath.IsAbs(launch.Path) || len(launch.Args) == 0 || launch.Args[0] != launch.Path ||
		launch.Files != request.files || launch.UID < scannerIdentityStart || launch.UID >= scannerIdentityStart+scannerIdentityCount || launch.GID != launch.UID {
		return scannerLaunchRequest{}, errors.New("launch request is invalid")
	}
	if launch.Args[0] == "" || strings.ContainsRune(launch.Path, '\x00') || len(launch.AmbientCaps) > 8 || launch.LivenessFD < 3 || launch.LivenessFD >= 3+launch.Files || len(launch.Args) < 3 || launch.Args[1] != ExecCommand {
		return scannerLaunchRequest{}, errors.New("launch request is invalid")
	}
	helperRequest, err := parseExecArgs(launch.Args[2:])
	if err != nil || helperRequest.profile != Scanner || !helperRequest.seccomp || helperRequest.notifyFD != 0 ||
		helperRequest.files+scannerPrivateControlFDCount(helperRequest) != launch.Files || helperRequest.livenessFD != launch.LivenessFD {
		return scannerLaunchRequest{}, errors.New("launch request is invalid")
	}
	return launch, nil
}

func terminateAndReapScannerChild(child *exec.Cmd, resultFD int, cause error) error {
	if child == nil || child.Process == nil {
		return fmt.Errorf("scanner supervisor: child process is unavailable: %w", cause)
	}
	killErr := syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	if errors.Is(killErr, syscall.ESRCH) {
		killErr = nil
	}
	waitErr := child.Wait()
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		waitErr = nil
	}
	reapErr := reapScannerChildren(scannerSupervisorTimeout)
	if killErr == nil && waitErr == nil && reapErr == nil {
		if sendErr := sendScannerSupervisorResult(resultFD, true); sendErr != nil {
			return fmt.Errorf("scanner supervisor: cleanup proof write failed after %v: %w", cause, sendErr)
		}
		return fmt.Errorf("scanner supervisor: %w", cause)
	}
	return fmt.Errorf("scanner supervisor: %v; process-tree cleanup is unproven (kill=%v wait=%v reap=%v)", cause, killErr, waitErr, reapErr)
}

func reapScannerChildren(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if pid > 0 {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return nil
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("descendant reaping deadline expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sendScannerSupervisorResult(fd int, clean bool) error {
	message := make([]byte, 16)
	copy(message, scannerSupervisorMagic)
	if clean {
		message[8] = 1
	}
	n, err := unix.SendmsgN(fd, message, nil, nil, 0)
	if err != nil || n != len(message) {
		return errors.New("scanner supervisor: result channel write failed")
	}
	return nil
}

type scannerSupervisorOps struct {
	waitForExit          func(pid int) (bool, error)
	killGroup            func(pid int, signal syscall.Signal) error
	waitChild            func(*exec.Cmd) error
	reapChildren         func(time.Duration) error
	sendResult           func(fd int, clean bool) error
	now                  func() time.Time
	serviceNotifications func() error
}

// superviseScannerChild owns the process-tree proof ordering after Start:
// observe leader exit without reaping it, kill its process group, wait the
// leader, reap adopted descendants, then send the success frame. Keeping the
// per-call operations explicit lets unit tests exercise cancellation and
// failure ordering without starting a second supervisor process.
func superviseScannerChild(child *exec.Cmd, resultFD int, signals <-chan os.Signal, watchdog <-chan time.Time, ops scannerSupervisorOps) (interrupted bool, childErr error, err error) {
	if child == nil || child.Process == nil || ops.waitForExit == nil || ops.killGroup == nil || ops.waitChild == nil || ops.reapChildren == nil || ops.sendResult == nil || ops.now == nil {
		return false, nil, errors.New("scanner supervisor: process lifecycle is unavailable")
	}
	var cancellationDeadline time.Time
	var notificationErr error
	for {
		if !cancellationDeadline.IsZero() && !ops.now().Before(cancellationDeadline) {
			_ = ops.killGroup(child.Process.Pid, syscall.SIGKILL)
			return interrupted, nil, errors.New("scanner supervisor: scanner did not exit before the cancellation deadline; process-tree cleanup is unproven")
		}
		exited, waitErr := ops.waitForExit(child.Process.Pid)
		if waitErr != nil && !errors.Is(waitErr, unix.EINTR) {
			_ = ops.killGroup(child.Process.Pid, syscall.SIGKILL)
			return interrupted, nil, fmt.Errorf("scanner supervisor: wait for scanner exit: %w", waitErr)
		}
		if exited {
			break
		}
		if notificationErr == nil && ops.serviceNotifications != nil {
			if err := ops.serviceNotifications(); err != nil {
				notificationErr = err
				_ = ops.killGroup(child.Process.Pid, syscall.SIGKILL)
				if cancellationDeadline.IsZero() {
					cancellationDeadline = ops.now().Add(scannerSupervisorTimeout)
				}
			}
		}
		select {
		case <-signals:
			interrupted = true
			if cancellationDeadline.IsZero() {
				cancellationDeadline = ops.now().Add(scannerSupervisorTimeout)
			}
			_ = ops.killGroup(child.Process.Pid, syscall.SIGKILL)
		case <-watchdog:
		}
	}
	// Keep the leader unreaped until its process group is killed, so the group
	// ID cannot be recycled between observing exit and terminating descendants.
	if killErr := ops.killGroup(child.Process.Pid, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
		_ = ops.waitChild(child)
		return interrupted, nil, fmt.Errorf("scanner supervisor: terminate scanner process group: %w", killErr)
	}
	childErr = ops.waitChild(child)
	if reapErr := ops.reapChildren(scannerSupervisorTimeout); reapErr != nil {
		return interrupted, childErr, fmt.Errorf("scanner supervisor: descendant cleanup is unproven: %w", reapErr)
	}
	if sendErr := ops.sendResult(resultFD, true); sendErr != nil {
		return interrupted, childErr, fmt.Errorf("scanner supervisor: send cleanup proof: %w", sendErr)
	}
	if notificationErr != nil {
		return interrupted, childErr, fmt.Errorf("scanner supervisor: seccomp notification failed: %w", notificationErr)
	}
	return interrupted, childErr, nil
}
