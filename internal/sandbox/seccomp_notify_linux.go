//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompNotificationProbeFlag = "--seccomp-notification-probe"
	seccompNotificationControlFD = 3
)

var (
	seccompNotificationProbeOnce sync.Once
	seccompNotificationProbeErr  error
)

func installScannerSeccomp(request execRequest) error {
	if request.notifyFD > 0 {
		return installAndSendSeccompNotificationListener(request.livenessFD, request.notifyFD)
	}
	return installSeccompFilter(request.livenessFD)
}

func validateSeccompNotificationControlDescriptor(fd int) error {
	if fd < 3 {
		return errors.New("scanner seccomp notification control descriptor is unavailable")
	}
	domain, domainErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	socketType, typeErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if domainErr != nil || typeErr != nil || domain != unix.AF_UNIX || socketType != unix.SOCK_SEQPACKET {
		return errors.New("scanner seccomp notification control socket is invalid")
	}
	return nil
}

func validateScannerSocketDescriptorsForRequest(request execRequest) error {
	if request.notifyFD > 0 {
		if err := validateSeccompNotificationControlDescriptor(request.notifyFD); err != nil {
			return err
		}
	}
	if !request.privateTemp {
		return validateScannerSocketDescriptors(request.files)
	}
	if request.controlFD != 3+request.files+2 {
		return errors.New("scanner private temporary control descriptor is outside its inherited range")
	}
	for fd := 0; fd < 3+request.files; fd++ {
		if err := validateScannerSocketDescriptor(fd); err != nil {
			return err
		}
	}
	secondDirectoryFD := request.privateLeafFD
	if request.privateCreate {
		secondDirectoryFD = request.privateNamespaceFD
	}
	for _, fd := range []int{request.privateRootFD, secondDirectoryFD} {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("scanner private temporary directory descriptor is invalid")
		}
	}
	domain, domainErr := unix.GetsockoptInt(request.controlFD, unix.SOL_SOCKET, unix.SO_DOMAIN)
	socketType, typeErr := unix.GetsockoptInt(request.controlFD, unix.SOL_SOCKET, unix.SO_TYPE)
	if domainErr != nil || typeErr != nil || domain != unix.AF_UNIX || socketType != unix.SOCK_SEQPACKET {
		return errors.New("scanner private temporary control socket is invalid")
	}
	return nil
}

func execSeccompNotificationProbe(args []string) error {
	if len(args) != 2 || args[0] != "--control-fd" || args[1] != strconv.Itoa(seccompNotificationControlFD) {
		return errors.New("seccomp notification probe arguments are invalid")
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp notification probe set no_new_privs: %w", err)
	}
	if err := installAndSendSeccompNotificationListener(-1, seccompNotificationControlFD); err != nil {
		return err
	}
	for count := 0; count < 2; count++ {
		fd, err := unix.Socket(unix.AF_UNIX, seccompNotificationSocketType, 0)
		if err != nil {
			return fmt.Errorf("seccomp notification probe socket was not mediated: %w", err)
		}
		domain, domainErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		socketType, typeErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		fdFlags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		closeErr := unix.Close(fd)
		if domainErr != nil || typeErr != nil || flagErr != nil || closeErr != nil || domain != unix.AF_INET || socketType != unix.SOCK_DGRAM || fdFlags&unix.FD_CLOEXEC == 0 {
			return errors.New("seccomp notification probe did not receive the verified AF_INET datagram descriptor")
		}
	}
	if _, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("seccomp notification probe Unix stream socket result = %v, want EPERM", err)
	}
	if _, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("seccomp notification probe Unix socketpair result = %v, want EPERM", err)
	}
	return nil
}

func probeSeccompNotificationSupport() error {
	return probeSeccompNotificationSupportWithBrokerFactory(func(listenerFD int) *seccompNotificationBroker {
		return &seccompNotificationBroker{listenerFD: listenerFD}
	})
}

func probeSeccompNotificationSupportWithBrokerFactory(brokerFactory func(listenerFD int) *seccompNotificationBroker) error {
	if brokerFactory == nil {
		return errors.New("seccomp notification broker factory is unavailable")
	}
	if err := seccompNotificationSizesSupported(); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil || executable == "" || executable[0] != '/' {
		return errors.New("seccomp notification probe executable is unavailable")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create seccomp notification probe channel: %w", err)
	}
	parent := os.NewFile(uintptr(pair[0]), "seccomp notification probe parent")
	child := os.NewFile(uintptr(pair[1]), "seccomp notification probe child")
	defer parent.Close()
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		_ = child.Close()
		return fmt.Errorf("enable seccomp notification probe credentials: %w", err)
	}
	command := exec.Command(executable, ExecCommand, seccompNotificationProbeFlag, "--control-fd", strconv.Itoa(seccompNotificationControlFD))
	command.Env = []string{}
	command.Dir = "/"
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = child.Close()
		return fmt.Errorf("start seccomp notification probe: %w", err)
	}
	_ = child.Close()
	listenerFD, err := receiveSeccompNotificationListener(pair[0], command.Process.Pid, uint32(os.Geteuid()), uint32(os.Getegid()), scannerSupervisorTimeout)
	if err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return err
	}
	defer unix.Close(listenerFD)
	broker := brokerFactory(listenerFD)
	if broker == nil || broker.listenerFD != listenerFD {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return errors.New("seccomp notification broker factory returned an invalid listener")
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(scannerSupervisorTimeout)
	defer timer.Stop()
	for {
		select {
		case err := <-waitResult:
			if err != nil {
				return fmt.Errorf("seccomp notification probe child failed: %w", err)
			}
			return nil
		case <-ticker.C:
			if err := broker.serveOne(); err != nil {
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				<-waitResult
				return fmt.Errorf("seccomp notification probe broker failed: %w", err)
			}
		case <-timer.C:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-waitResult
			return errors.New("seccomp notification probe timed out")
		}
	}
}

// Keep the Linux notification ABI definitions and the helper above in this
// file so the feature probe and production broker use the same code path.
// The probe is cached because it launches a short-lived helper process.
func seccompNotificationSupport() error {
	seccompNotificationProbeOnce.Do(func() {
		seccompNotificationProbeErr = probeSeccompNotificationSupport()
	})
	return seccompNotificationProbeErr
}

const (
	seccompNotificationMagic           = "EWSCN001"
	seccompNotificationLimit           = 4096
	seccompNotificationPollTimeout     = 100 * time.Millisecond
	seccompNotificationSocketType      = unix.SOCK_DGRAM | unix.SOCK_CLOEXEC
	seccompNotificationAddFDRetryLimit = 4
)

// These structures mirror linux/seccomp.h. The startup feature probe rejects
// kernels whose reported sizes differ, so these fixed Go layouts are never
// passed to a kernel expecting a larger or incompatible structure.
type seccompNotificationData struct {
	Number             int32
	Architecture       uint32
	InstructionPointer uint64
	Arguments          [6]uint64
}

type seccompNotificationRequest struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompNotificationData
}

type seccompNotificationSizes struct {
	Request  uint16
	Response uint16
	Data     uint16
}

type seccompNotificationAddFD struct {
	ID         uint64
	Flags      uint32
	SourceFD   uint32
	TargetFD   uint32
	TargetFlag uint32
}

// seccompNotificationBroker owns the listener in the trusted scanner
// supervisor. It only replaces the exact AF_UNIX datagram socket used by
// Nmap's SIOCGIFNAME ioctl with a fresh AF_INET datagram socket. It never
// reads tracee memory, continues a syscall, or accepts any other request.
type seccompNotificationBroker struct {
	listenerFD int
	served     uint32
	ioctl      func(fd int, request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno)
	afterAddFD func(notificationID uint64, traceePID uint32, sourceFD, targetFD int) error
}

func (broker *seccompNotificationBroker) notificationIoctl(request uintptr, argument unsafe.Pointer) (uintptr, syscall.Errno) {
	if broker != nil && broker.ioctl != nil {
		return broker.ioctl(broker.listenerFD, request, argument)
	}
	value, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(broker.listenerFD), request, uintptr(argument))
	return value, errno
}

func seccompNotificationSizesSupported() error {
	var sizes seccompNotificationSizes
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_NOTIF_SIZES, 0, uintptr(unsafe.Pointer(&sizes)))
	if errno != 0 {
		return fmt.Errorf("query seccomp notification sizes: %w", errno)
	}
	if sizes.Request != uint16(unsafe.Sizeof(seccompNotificationRequest{})) ||
		sizes.Response != uint16(unsafe.Sizeof(seccompNotificationResponse{})) ||
		sizes.Data != uint16(unsafe.Sizeof(seccompNotificationData{})) {
		return errors.New("kernel seccomp notification ABI size is unsupported")
	}
	return nil
}

type seccompNotificationResponse struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}

// sendSeccompNotificationListener passes exactly one listener descriptor over
// the supervisor-created private seqpacket socket. The helper must be locked
// to its OS thread and must close both descriptors before exec.
func sendSeccompNotificationListener(controlFD, listenerFD int) error {
	if controlFD < 0 || listenerFD < 0 {
		return errors.New("seccomp notification control descriptor is unavailable")
	}
	message := []byte(seccompNotificationMagic)
	control := unix.UnixRights(listenerFD)
	n, err := unix.SendmsgN(controlFD, message, control, nil, 0)
	if err != nil {
		return fmt.Errorf("send seccomp notification listener: %w", err)
	}
	if n != len(message) {
		return fmt.Errorf("send seccomp notification listener: sent %d of %d bytes", n, len(message))
	}
	return nil
}

// receiveSeccompNotificationListener accepts one listener only from the
// direct scanner helper, after its credentials have been changed to the
// reserved scanner identity. SO_PASSCRED must already be enabled on controlFD.
func receiveSeccompNotificationListener(controlFD, helperPID int, uid, gid uint32, timeout time.Duration) (int, error) {
	if controlFD < 0 || helperPID <= 0 || timeout <= 0 {
		return -1, errors.New("seccomp notification listener receive parameters are invalid")
	}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return -1, errors.New("seccomp notification listener startup timed out")
		}
		wait := int(remaining / time.Millisecond)
		if wait < 1 {
			wait = 1
		}
		if wait > int(seccompNotificationPollTimeout/time.Millisecond) {
			wait = int(seccompNotificationPollTimeout / time.Millisecond)
		}
		poll := []unix.PollFd{{Fd: int32(controlFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
		_, err := unix.Poll(poll, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, errors.New("poll seccomp notification listener channel failed")
		}
		if poll[0].Revents&unix.POLLIN != 0 {
			return receiveSeccompNotificationListenerPacket(controlFD, helperPID, uid, gid)
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return -1, errors.New("scanner helper exited before sending its seccomp notification listener")
		}
	}
}

func receiveSeccompNotificationListenerPacket(controlFD, helperPID int, uid, gid uint32) (listenerFD int, resultErr error) {
	message := make([]byte, len(seccompNotificationMagic))
	control := make([]byte, unix.CmsgSpace(4*4)+unix.CmsgSpace(unix.SizeofUcred))
	// Set close-on-exec as the kernel installs the received descriptor. The
	// listener belongs only to this supervisor and must never survive another
	// exec, even if a future error path forgets an explicit CloseOnExec call.
	n, controlN, flags, _, err := unix.Recvmsg(controlFD, message, control, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, errors.New("receive seccomp notification listener failed")
	}
	var rights []int
	defer func() {
		for _, fd := range rights {
			if fd != listenerFD {
				_ = unix.Close(fd)
			}
		}
	}()
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != len(message) || string(message) != seccompNotificationMagic {
		return -1, errors.New("seccomp notification listener frame is invalid")
	}
	cmsgs, err := unix.ParseSocketControlMessage(control[:controlN])
	if err != nil {
		return -1, errors.New("seccomp notification listener control data is invalid")
	}
	var credentials *unix.Ucred
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level != unix.SOL_SOCKET {
			return -1, errors.New("seccomp notification listener control data is unsupported")
		}
		switch cmsg.Header.Type {
		case unix.SCM_RIGHTS:
			fds, parseErr := unix.ParseUnixRights(&cmsg)
			if parseErr != nil {
				return -1, errors.New("seccomp notification listener descriptor is invalid")
			}
			rights = append(rights, fds...)
		case unix.SCM_CREDENTIALS:
			if credentials != nil {
				return -1, errors.New("seccomp notification listener credentials are duplicated")
			}
			credentials, err = unix.ParseUnixCredentials(&cmsg)
			if err != nil {
				return -1, errors.New("seccomp notification listener credentials are invalid")
			}
		default:
			return -1, errors.New("seccomp notification listener control data is unsupported")
		}
	}
	if len(rights) != 1 || credentials == nil || int(credentials.Pid) != helperPID || credentials.Uid != uid || credentials.Gid != gid {
		return -1, errors.New("seccomp notification listener sender identity is invalid")
	}
	if err := seccompNotificationSizesSupported(); err != nil {
		return -1, err
	}
	fdFlags, err := unix.FcntlInt(uintptr(rights[0]), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		return -1, errors.New("seccomp notification listener is not close-on-exec")
	}
	listenerFD = rights[0]
	return listenerFD, nil
}

// serveOne handles at most one pending notification so scanner cancellation
// and process-exit checks remain responsive under a malicious request flood.
// It is called only by the trusted supervisor while it owns the listener.
func (broker *seccompNotificationBroker) serveOne() error {
	if broker == nil || broker.listenerFD < 0 {
		return errors.New("seccomp notification listener is unavailable")
	}
	poll := []unix.PollFd{{Fd: int32(broker.listenerFD), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	_, err := unix.Poll(poll, 0)
	if errors.Is(err, unix.EINTR) {
		return nil
	}
	if err != nil {
		return errors.New("poll seccomp notification listener failed")
	}
	if poll[0].Revents&unix.POLLIN == 0 {
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("seccomp notification listener failed")
		}
		// POLLHUP without POLLIN means no task still uses this filter, so
		// there can be no further notification to service. This is not process-
		// tree cleanup proof: the supervisor still observes the leader, kills
		// its process group, waits, and reaps descendants before proving cleanup.
		return nil
	}
	var notification seccompNotificationRequest
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(broker.listenerFD), uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV), uintptr(unsafe.Pointer(&notification)))
	if errno != 0 {
		if errors.Is(errno, unix.EINTR) || errors.Is(errno, unix.EAGAIN) {
			return nil
		}
		return fmt.Errorf("receive seccomp notification: %w", errno)
	}
	if broker.served >= seccompNotificationLimit {
		return errors.New("seccomp notification request limit exceeded")
	}
	arch, err := currentSeccompArchitecture()
	if err != nil {
		return err
	}
	if notification.Flags != 0 || notification.Data.Architecture != arch.audit ||
		uint32(notification.Data.Number) != arch.numbers["socket"] ||
		notification.Data.Arguments[0] != unix.AF_UNIX ||
		notification.Data.Arguments[1] != seccompNotificationSocketType ||
		notification.Data.Arguments[2] != 0 {
		return errors.New("unexpected seccomp notification request")
	}
	return broker.injectINETDatagram(notification.ID, notification.PID)
}

func (broker *seccompNotificationBroker) injectINETDatagram(notificationID uint64, traceePID uint32) (resultErr error) {
	sourceFD, err := unix.Socket(unix.AF_INET, seccompNotificationSocketType, 0)
	if err != nil {
		return fmt.Errorf("create broker datagram socket: %w", err)
	}
	defer func() {
		if sourceFD >= 0 {
			if closeErr := unix.Close(sourceFD); closeErr != nil && resultErr == nil {
				resultErr = errors.New("close broker datagram socket failed")
			}
		}
	}()
	domain, domainErr := unix.GetsockoptInt(sourceFD, unix.SOL_SOCKET, unix.SO_DOMAIN)
	socketType, typeErr := unix.GetsockoptInt(sourceFD, unix.SOL_SOCKET, unix.SO_TYPE)
	fdFlags, fdErr := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFD, 0)
	if domainErr != nil || typeErr != nil || fdErr != nil || domain != unix.AF_INET || socketType != unix.SOCK_DGRAM || fdFlags&unix.FD_CLOEXEC == 0 {
		return errors.New("broker datagram socket verification failed")
	}
	var add seccompNotificationAddFD
	add.ID = notificationID
	add.SourceFD = uint32(sourceFD)
	add.TargetFlag = unix.O_CLOEXEC
	var targetFD uintptr
	for attempt := 0; attempt < seccompNotificationAddFDRetryLimit; attempt++ {
		var errno syscall.Errno
		targetFD, errno = broker.notificationIoctl(unix.SECCOMP_IOCTL_NOTIF_ADDFD, unsafe.Pointer(&add))
		if errno == 0 {
			break
		}
		if errno != syscall.EINTR {
			return fmt.Errorf("inject broker datagram socket: %w", errno)
		}
		if attempt+1 == seccompNotificationAddFDRetryLimit {
			return errors.New("inject broker datagram socket: interrupted retry limit exceeded")
		}
		runtime.Gosched()
	}
	if targetFD > uintptr(^uint(0)>>1) {
		return errors.New("kernel returned an invalid scanner socket descriptor")
	}
	remoteFD := int(targetFD)
	closeFD := sourceFD
	sourceFD = -1 // Linux releases a descriptor even when close reports an error; never retry a possibly reused number.
	if err := unix.Close(closeFD); err != nil {
		return errors.New("close broker datagram socket failed")
	}
	if broker.afterAddFD != nil {
		if err := broker.afterAddFD(notificationID, traceePID, closeFD, remoteFD); err != nil {
			return fmt.Errorf("seccomp notification pre-reply hook failed: %w", err)
		}
	}
	response := seccompNotificationResponse{ID: notificationID, Value: int64(remoteFD)}
	if _, errno := broker.notificationIoctl(unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); errno != 0 {
		return fmt.Errorf("reply to seccomp notification with injected socket: %w", errno)
	}
	broker.served++
	return nil
}

// installAndSendSeccompNotificationListener is the final helper transition
// before exec. The caller must already be locked to its OS thread, have set
// no_new_privs, applied Landlock/resource limits, and closed every private
// file/setup control descriptor except the one-shot listener channel.
func installAndSendSeccompNotificationListener(livenessFD, controlFD int) error {
	if err := seccompNotificationSizesSupported(); err != nil {
		return err
	}
	listenerFD, err := installSeccompNotificationFilter(livenessFD)
	if err != nil {
		return err
	}
	if err := sendSeccompNotificationListener(controlFD, listenerFD); err != nil {
		_ = unix.Close(listenerFD)
		unix.Exit(126)
	}
	if err := unix.Close(listenerFD); err != nil {
		unix.Exit(126)
	}
	if err := unix.Close(controlFD); err != nil {
		unix.Exit(126)
	}
	runtime.KeepAlive(listenerFD)
	return nil
}
