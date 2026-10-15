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
	if reservation != nil {
		reservedUID, reservedGID, ok := reservation.Identity()
		if !ok {
			return nil, errors.New("prepare scanner invocation: reserved identity is unavailable")
		}
		uid, gid = int(reservedUID), int(reservedGID)
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
	}
	releaseUnreservedLease := func() {
		if lease != nil {
			_ = lease.release()
		}
	}
	if err := addScannerNoEscapeHelper(cmd, helper); err != nil {
		releaseUnreservedLease()
		return nil, err
	}

	var ambient []uintptr
	if cmd.SysProcAttr != nil {
		ambient = append(ambient, cmd.SysProcAttr.AmbientCaps...)
	}
	request := scannerLaunchRequest{
		Version: 1, Path: cmd.Path, Args: append([]string(nil), cmd.Args...), Env: append([]string(nil), cmd.Env...),
		Dir: cmd.Dir, Files: len(cmd.ExtraFiles), UID: uint32(uid), GID: uint32(gid),
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

func addScannerNoEscapeHelper(cmd *exec.Cmd, helper string) error {
	if cmd.Path == helper && len(cmd.Args) >= 2 && cmd.Args[1] == ExecCommand {
		separator := -1
		for index := 2; index < len(cmd.Args); index++ {
			if cmd.Args[index] == "--" {
				separator = index
				break
			}
			if cmd.Args[index] == "--seccomp" {
				return nil
			}
		}
		if separator < 0 {
			return errors.New("prepare scanner invocation: sandbox helper arguments are invalid")
		}
		cmd.Args = append(cmd.Args[:separator], append([]string{"--seccomp"}, cmd.Args[separator:]...)...)
		return nil
	}
	originalPath := cmd.Path
	originalArgs := append([]string(nil), cmd.Args...)
	files := len(cmd.ExtraFiles)
	args := []string{helper, ExecCommand, "--profile", string(Scanner), "--files", strconv.Itoa(files), "--identity-only", "--seccomp", "--", originalPath}
	if len(originalArgs) > 1 {
		args = append(args, originalArgs[1:]...)
	}
	cmd.Path, cmd.Args = helper, args
	return nil
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
	if err != nil || flags&unix.MSG_TRUNC != 0 || n != len(message) || string(message[:8]) != scannerSupervisorMagic || message[8] != 1 {
		invocation.proofErr = errors.New("scanner supervisor did not prove process-tree cleanup")
		return invocation.proofErr
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
	var launch scannerLaunchRequest
	decoder := json.NewDecoder(strings.NewReader(string(configuration)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&launch); err != nil {
		return errors.New("scanner supervisor: launch request is malformed")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || launch.Version != 1 || !filepath.IsAbs(launch.Path) || len(launch.Args) == 0 || launch.Args[0] != launch.Path ||
		launch.Files != request.files || launch.UID < scannerIdentityStart || launch.UID >= scannerIdentityStart+scannerIdentityCount || launch.GID != launch.UID {
		return errors.New("scanner supervisor: launch request is invalid")
	}
	if launch.Args[0] == "" || strings.ContainsRune(launch.Path, '\x00') || len(launch.AmbientCaps) > 8 {
		return errors.New("scanner supervisor: launch request is invalid")
	}
	result := os.NewFile(uintptr(request.resultFD), "scanner supervisor result")
	defer result.Close()
	unix.CloseOnExec(request.resultFD)

	childFiles := make([]*os.File, launch.Files)
	for index := range childFiles {
		fd := 3 + index
		childFiles[index] = os.NewFile(uintptr(fd), fmt.Sprintf("scanner data descriptor %d", index))
	}
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

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		_ = sendScannerSupervisorResult(request.resultFD, true)
		return fmt.Errorf("scanner supervisor: start scanner child: %w", err)
	}
	for _, file := range childFiles {
		_ = file.Close()
	}
	interrupted := false
	var cancellationDeadline time.Time
	watchdog := time.NewTicker(20 * time.Millisecond)
	defer watchdog.Stop()
	for {
		if !cancellationDeadline.IsZero() && !time.Now().Before(cancellationDeadline) {
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			return errors.New("scanner supervisor: scanner did not exit before the cancellation deadline; process-tree cleanup is unproven")
		}
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, child.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if err != nil && !errors.Is(err, unix.EINTR) {
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			return fmt.Errorf("scanner supervisor: wait for scanner exit: %w", err)
		}
		if info.Signo != 0 {
			break
		}
		select {
		case <-signals:
			interrupted = true
			if cancellationDeadline.IsZero() {
				cancellationDeadline = time.Now().Add(scannerSupervisorTimeout)
			}
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		case <-watchdog.C:
		}
	}
	// Keep the leader unreaped until its process group is killed, so the group
	// ID cannot be recycled between observing exit and terminating descendants.
	if err := syscall.Kill(-child.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		_ = child.Wait()
		return fmt.Errorf("scanner supervisor: terminate scanner process group: %w", err)
	}
	childErr := child.Wait()
	if err := reapScannerChildren(scannerSupervisorTimeout); err != nil {
		return fmt.Errorf("scanner supervisor: descendant cleanup is unproven: %w", err)
	}
	if err := sendScannerSupervisorResult(request.resultFD, true); err != nil {
		return fmt.Errorf("scanner supervisor: send cleanup proof: %w", err)
	}
	if interrupted {
		return errors.New("scanner supervisor: scanner process tree was cancelled")
	}
	if childErr != nil {
		return fmt.Errorf("scanner supervisor: scanner exited unsuccessfully: %w", childErr)
	}
	return nil
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
