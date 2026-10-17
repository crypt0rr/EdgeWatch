//go:build linux

package sandbox

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSeccompNumbersMatchTheSystemCallTables compares the filter's numbers
// with the tables golang.org/x/sys generates from the kernel, for every
// release architecture, whatever this test runs on.
func TestSeccompNumbersMatchTheSystemCallTables(t *testing.T) {
	t.Parallel()
	output, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "golang.org/x/sys").Output()
	if err != nil {
		t.Skipf("the golang.org/x/sys source is not available: %v", err)
	}
	directory := strings.TrimSpace(string(output))
	definition := regexp.MustCompile(`SYS_([A-Z0-9_]+)\s*=\s*(\d+)`)
	for goarch, arch := range seccompArchitectures {
		source, err := os.ReadFile(filepath.Join(directory, "unix", "zsysnum_linux_"+goarch+".go"))
		if err != nil {
			t.Fatal(err)
		}
		table := map[string]uint32{}
		for _, match := range definition.FindAllStringSubmatch(string(source), -1) {
			number, _ := strconv.ParseUint(match[2], 10, 32)
			table[strings.ToLower(match[1])] = uint32(number)
		}
		names := append(append([]string{"clone", "clone3", "close", "close_range", "dup", "dup2", "dup3", "fcntl", "ioctl", "socket", "socketpair", "sendmsg", "sendmmsg", "flock"}, seccompDenied...), seccompDeniedX86...)
		for _, name := range names {
			want, exists := table[name]
			got, listed := arch.numbers[name]
			if exists != listed || got != want {
				t.Errorf("%s %s = %d (listed %v), want %d (exists %v)", goarch, name, got, listed, want, exists)
			}
		}
	}
}

// runBPF evaluates a seccomp filter for one system call, as the kernel would.
func runBPF(t *testing.T, filter []unix.SockFilter, data [64]byte) uint32 {
	t.Helper()
	var accumulator uint32
	for pc := 0; pc < len(filter); pc++ {
		instruction := filter[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			accumulator = binary.LittleEndian.Uint32(data[instruction.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			var taken bool
			switch instruction.Code &^ (unix.BPF_JMP | unix.BPF_K) {
			case unix.BPF_JEQ:
				taken = accumulator == instruction.K
			case unix.BPF_JGE:
				taken = accumulator >= instruction.K
			case unix.BPF_JGT:
				taken = accumulator > instruction.K
			default:
				taken = accumulator&instruction.K != 0
			}
			if taken {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatalf("unexpected instruction %#x", instruction.Code)
		}
	}
	t.Fatal("the filter ended without a result")
	return 0
}

func seccompData(arch, number, firstArg uint32) [64]byte {
	var data [64]byte
	binary.LittleEndian.PutUint32(data[seccompNumber:], number)
	binary.LittleEndian.PutUint32(data[seccompArch:], arch)
	binary.LittleEndian.PutUint32(data[seccompArg0Low:], firstArg)
	return data
}

func seccompDataWideArgs(arch, number uint32, args ...uint64) [64]byte {
	var data [64]byte
	binary.LittleEndian.PutUint32(data[seccompNumber:], number)
	binary.LittleEndian.PutUint32(data[seccompArch:], arch)
	for index, value := range args {
		binary.LittleEndian.PutUint64(data[int(seccompArg0Low)+index*8:], value)
	}
	return data
}

func TestSeccompFilterProtectsInheritedLivenessDescriptor(t *testing.T) {
	t.Parallel()
	const protectedFD = uint32(7)
	deny := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for goarch, arch := range seccompArchitectures {
		filter, err := seccompFilterForLivenessFD(arch, int(protectedFD))
		if err != nil {
			t.Fatalf("%s liveness filter: %v", goarch, err)
		}
		decide := func(name string, args ...uint64) uint32 {
			t.Helper()
			return runBPF(t, filter, seccompDataWideArgs(arch.audit, arch.numbers[name], args...))
		}
		cases := []struct {
			name       string
			call       string
			args       []uint64
			wantResult uint32
		}{
			{name: "close protected descriptor", call: "close", args: []uint64{uint64(protectedFD)}, wantResult: deny},
			{name: "close another descriptor", call: "close", args: []uint64{uint64(protectedFD + 1)}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "close range includes protected start", call: "close_range", args: []uint64{uint64(protectedFD), ^uint64(0), 0}, wantResult: deny},
			{name: "close range includes protected end", call: "close_range", args: []uint64{0, uint64(protectedFD), 0}, wantResult: deny},
			{name: "close range excludes protected below", call: "close_range", args: []uint64{0, uint64(protectedFD - 1), 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "close range excludes protected above", call: "close_range", args: []uint64{uint64(protectedFD + 1), ^uint64(0), 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "close range low words include protected despite high bits", call: "close_range", args: []uint64{1<<32 | uint64(protectedFD), 1<<32 | uint64(protectedFD), unix.CLOSE_RANGE_CLOEXEC}, wantResult: deny},
			{name: "close range unshare cannot split protected descriptor", call: "close_range", args: []uint64{uint64(protectedFD), uint64(protectedFD), unix.CLOSE_RANGE_UNSHARE}, wantResult: deny},
			{name: "dup2 cannot replace protected descriptor", call: "dup2", args: []uint64{8, uint64(protectedFD)}, wantResult: deny},
			{name: "dup allocates a separate descriptor", call: "dup", args: []uint64{uint64(protectedFD)}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "dup3 cannot replace protected descriptor", call: "dup3", args: []uint64{8, uint64(protectedFD), 0}, wantResult: deny},
			{name: "OFD lock change denied through alias", call: "fcntl", args: []uint64{uint64(protectedFD + 1), seccompFOFDSetLK}, wantResult: deny},
			{name: "blocking OFD lock change denied globally", call: "fcntl", args: []uint64{uint64(protectedFD + 1), seccompFOFDSetLKW}, wantResult: deny},
			{name: "cannot mark protected descriptor close on exec", call: "fcntl", args: []uint64{uint64(protectedFD), seccompFSetFD, uint64(unix.FD_CLOEXEC)}, wantResult: deny},
			{name: "other descriptor may change close on exec", call: "fcntl", args: []uint64{uint64(protectedFD + 1), seccompFSetFD, uint64(unix.FD_CLOEXEC)}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "FIOCLEX denied on protected descriptor", call: "ioctl", args: []uint64{uint64(protectedFD), seccompFIOCLEX, 0}, wantResult: deny},
			{name: "other ioctl remains available", call: "ioctl", args: []uint64{uint64(protectedFD), 0x5401, 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "Unix socket creation denied", call: "socket", args: []uint64{seccompAFUnix, uint64(unix.SOCK_STREAM), 0}, wantResult: deny},
			{name: "Unix socket domain low word remains denied", call: "socket", args: []uint64{1<<32 | seccompAFUnix, uint64(unix.SOCK_STREAM), 0}, wantResult: deny},
			{name: "network socket creation remains available", call: "socket", args: []uint64{unix.AF_INET, uint64(unix.SOCK_DGRAM), 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "Unix socketpair creation denied", call: "socketpair", args: []uint64{seccompAFUnix, uint64(unix.SOCK_SEQPACKET), 0, 0}, wantResult: deny},
			{name: "Unix socketpair domain low word remains denied", call: "socketpair", args: []uint64{1<<32 | seccompAFUnix, uint64(unix.SOCK_SEQPACKET), 0, 0}, wantResult: deny},
			{name: "sendmsg remains available for netlink", call: "sendmsg", args: []uint64{0, 0, 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "sendmmsg remains available for netlink", call: "sendmmsg", args: []uint64{0, 0, 0, 0}, wantResult: unix.SECCOMP_RET_ALLOW},
			{name: "Naabu flock remains available", call: "flock", args: []uint64{uint64(protectedFD + 1), uint64(unix.LOCK_EX)}, wantResult: unix.SECCOMP_RET_ALLOW},
		}
		for _, test := range cases {
			if _, exists := arch.numbers[test.call]; !exists {
				continue
			}
			if got := decide(test.call, test.args...); got != test.wantResult {
				t.Errorf("%s %s = %#x, want %#x", goarch, test.name, got, test.wantResult)
			}
		}
	}
}

func TestSeccompNotificationFilterMediatesOnlyExactNmapDatagramRequest(t *testing.T) {
	t.Parallel()
	const protectedFD = uint32(7)
	deny := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for goarch, arch := range seccompArchitectures {
		filter, err := seccompFilterWithNotification(arch, int(protectedFD), true)
		if err != nil {
			t.Fatalf("%s notification filter: %v", goarch, err)
		}
		decide := func(name string, args ...uint64) uint32 {
			t.Helper()
			return runBPF(t, filter, seccompDataWideArgs(arch.audit, arch.numbers[name], args...))
		}
		cases := []struct {
			name string
			call string
			args []uint64
			want uint32
		}{
			{name: "exact Nmap AF_UNIX datagram", call: "socket", args: []uint64{unix.AF_UNIX, seccompNotificationSocketType, 0}, want: unix.SECCOMP_RET_USER_NOTIF},
			{name: "Unix stream denied", call: "socket", args: []uint64{unix.AF_UNIX, unix.SOCK_STREAM, 0}, want: deny},
			{name: "Unix datagram without cloexec denied", call: "socket", args: []uint64{unix.AF_UNIX, unix.SOCK_DGRAM, 0}, want: deny},
			{name: "Unix datagram with nonzero protocol denied", call: "socket", args: []uint64{unix.AF_UNIX, seccompNotificationSocketType, 1}, want: deny},
			{name: "network datagram allowed", call: "socket", args: []uint64{unix.AF_INET, seccompNotificationSocketType, 0}, want: unix.SECCOMP_RET_ALLOW},
			{name: "Unix socketpair denied", call: "socketpair", args: []uint64{unix.AF_UNIX, unix.SOCK_SEQPACKET, 0, 0}, want: deny},
			{name: "liveness close remains denied", call: "close", args: []uint64{uint64(protectedFD)}, want: deny},
			{name: "liveness lock conversion remains denied", call: "fcntl", args: []uint64{uint64(protectedFD + 1), seccompFOFDSetLK}, want: deny},
		}
		for _, test := range cases {
			if _, exists := arch.numbers[test.call]; !exists {
				continue
			}
			if got := decide(test.call, test.args...); got != test.want {
				t.Errorf("%s %s: %s = %#x, want %#x", goarch, test.name, test.call, got, test.want)
			}
		}
	}
	if _, err := seccompFilterWithNotification(seccompArchitectures["amd64"], -1, true); err != nil {
		t.Fatalf("notification filter without liveness reference: %v", err)
	}
}

func TestSeccompFilterFailsClosedWithoutRequiredSystemCallNumbers(t *testing.T) {
	for _, invalidFD := range []int{-2, 2, 3 + maxInheritedFiles} {
		if _, err := seccompFilterWithNotification(seccompArchitectures["amd64"], invalidFD, true); err == nil || !strings.Contains(err.Error(), "outside the inherited range") {
			t.Errorf("notification filter with liveness fd %d = %v; want range refusal", invalidFD, err)
		}
	}

	for _, test := range []struct {
		name     string
		missing  string
		liveness int
		notify   bool
	}{
		{name: "protected close map entry", missing: "close", liveness: 3, notify: true},
		{name: "protected close-range map entry", missing: "close_range", liveness: 3, notify: true},
		{name: "protected dup3 map entry", missing: "dup3", liveness: 3, notify: true},
		{name: "protected fcntl map entry", missing: "fcntl", liveness: 3, notify: true},
		{name: "protected ioctl map entry", missing: "ioctl", liveness: 3, notify: true},
		{name: "socket map entry", missing: "socket", liveness: -1, notify: true},
		{name: "socketpair map entry", missing: "socketpair", liveness: -1, notify: true},
		{name: "optional arm64 dup2 entry", missing: "dup2", liveness: 3, notify: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for goarch, original := range seccompArchitectures {
				numbers := make(map[string]uint32, len(original.numbers))
				for name, number := range original.numbers {
					numbers[name] = number
				}
				delete(numbers, test.missing)
				arch := original
				arch.numbers = numbers
				_, err := seccompFilterWithNotification(arch, test.liveness, test.notify)
				if test.missing == "dup2" {
					if err != nil {
						t.Errorf("%s filter without optional dup2 = %v; want supported filter", goarch, err)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), "no system call number for "+test.missing) {
					t.Errorf("%s filter without %s = %v; want fail-closed missing-number error", goarch, test.missing, err)
				}
			}
		})
	}
}

func TestValidateScannerSocketDescriptors(t *testing.T) {
	if err := validateScannerSocketDescriptors(0); err != nil {
		t.Fatalf("standard descriptors without Unix sockets: %v", err)
	}
	unixPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateScannerSocketDescriptor(unixPair[0]); err == nil || !strings.Contains(err.Error(), "Unix socket") {
		_ = unix.Close(unixPair[0])
		_ = unix.Close(unixPair[1])
		t.Fatalf("inherited Unix socket validation = %v, want refusal", err)
	}
	if err := unix.Close(unixPair[0]); err != nil {
		_ = unix.Close(unixPair[1])
		t.Fatal(err)
	}
	if err := unix.Close(unixPair[1]); err != nil {
		t.Fatal(err)
	}
	netlinkFD, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Skipf("kernel does not permit an unprivileged route-netlink socket: %v", err)
	}
	defer unix.Close(netlinkFD)
	if err := validateScannerSocketDescriptor(netlinkFD); err != nil {
		t.Fatalf("route-netlink descriptor was refused: %v", err)
	}
}

func TestSeccompFilterDecidesEachSystemCall(t *testing.T) {
	t.Parallel()
	deny := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for goarch, arch := range seccompArchitectures {
		filter, err := seccompFilter(arch)
		if err != nil {
			t.Fatalf("%s: %v", goarch, err)
		}
		decide := func(number, firstArg uint32) uint32 {
			return runBPF(t, filter, seccompData(arch.audit, number, firstArg))
		}
		for _, name := range seccompDenied {
			if got := decide(arch.numbers[name], 0); got != deny {
				t.Errorf("%s %s = %#x, want EPERM", goarch, name, got)
			}
		}
		// read and write are 0 and 1 on amd64, and 63 and 64 on arm64.
		for _, number := range []uint32{0, 1, 63, 64} {
			if got := decide(number, 0); got != unix.SECCOMP_RET_ALLOW {
				t.Errorf("%s call %d = %#x, want allowed", goarch, number, got)
			}
		}
		clone := arch.numbers["clone"]
		if got := decide(clone, unix.CLONE_VM|unix.CLONE_FS|unix.CLONE_FILES|unix.CLONE_SIGHAND|unix.CLONE_THREAD); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("%s clone of a thread = %#x, want allowed", goarch, got)
		}
		for _, flag := range []uint32{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWNET, unix.CLONE_NEWPID, unix.CLONE_NEWTIME} {
			if got := decide(clone, flag|unix.CLONE_VFORK); got != deny {
				t.Errorf("%s clone with %#x = %#x, want EPERM", goarch, flag, got)
			}
		}
		if got := decide(arch.numbers["clone3"], 0); got != unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS) {
			t.Errorf("%s clone3 = %#x, want ENOSYS", goarch, got)
		}
		if got := runBPF(t, filter, seccompData(unix.AUDIT_ARCH_I386, 1, 0)); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Errorf("%s call of another architecture = %#x, want the process killed", goarch, got)
		}
		x32 := decide(x32Bit|1, 0)
		if arch.x32 && x32 != deny {
			t.Errorf("%s x32 call = %#x, want EPERM", goarch, x32)
		}
		if !arch.x32 && x32 != unix.SECCOMP_RET_ALLOW {
			t.Errorf("%s high call number = %#x, want allowed", goarch, x32)
		}
	}
	if _, err := seccompFilter(seccompArchitecture{audit: unix.AUDIT_ARCH_X86_64, numbers: map[string]uint32{}}); err == nil {
		t.Fatal("a filter without numbers compiled")
	}
	missingClone := seccompArchitecture{numbers: map[string]uint32{}}
	for name, number := range seccompArchitectures["arm64"].numbers {
		if name != "clone" && name != "clone3" {
			missingClone.numbers[name] = number
		}
	}
	if _, err := seccompFilter(missingClone); err == nil || !strings.Contains(err.Error(), "clone3") {
		t.Fatalf("a filter without clone3 = %v", err)
	}
	missingClone.numbers["clone3"] = 435
	if _, err := seccompFilter(missingClone); err == nil || !strings.Contains(err.Error(), "for clone") {
		t.Fatalf("a filter without clone = %v", err)
	}
}

func TestResolveBPFRefusesBadJumps(t *testing.T) {
	t.Parallel()
	ret := unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K}
	jump := unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K}
	if _, err := resolveBPF([]bpfStep{{instruction: jump, jumpTrue: "missing"}, {instruction: ret}}); err == nil {
		t.Fatal("a jump to a missing label resolved")
	}
	if _, err := resolveBPF([]bpfStep{{label: "back", instruction: ret}, {instruction: jump, jumpFalse: "back"}}); err == nil {
		t.Fatal("a backward jump resolved")
	}
	far := []bpfStep{{instruction: jump, jumpTrue: "end"}}
	for range 300 {
		far = append(far, bpfStep{instruction: ret})
	}
	far = append(far, bpfStep{label: "end", instruction: ret})
	if _, err := resolveBPF(far); err == nil {
		t.Fatal("a jump beyond 255 instructions resolved")
	}
}

func TestSeccompUnavailableReasons(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		unix.ENOSYS:           "the kernel does not provide seccomp filters, or the container's seccomp profile blocks them",
		unix.EINVAL:           "the kernel does not provide seccomp filters, or the container's seccomp profile blocks them",
		unix.EOPNOTSUPP:       "the kernel lacks the seccomp actions the filter uses",
		errors.New("strange"): "seccomp could not be detected: strange",
	} {
		if got := seccompUnavailableReason(err); got != want {
			t.Errorf("reason for %v = %q, want %q", err, got, want)
		}
	}
}

// TestInstalledSeccompFilterRefusesTheDeniedCalls installs the filter on a
// locked thread, which ends with its goroutine.
func TestInstalledSeccompFilterRefusesTheDeniedCalls(t *testing.T) {
	t.Parallel()
	if err := seccompSupport(); err != nil {
		t.Skipf("this kernel cannot run the filter: %v", err)
	}
	results := make(chan map[string]error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			results <- map[string]error{"no_new_privs": err}
			return
		}
		if err := installSeccompFilter(-1); err != nil {
			results <- map[string]error{"install": err}
			return
		}
		call := func(number uintptr, args ...uintptr) error {
			args = append(args, 0, 0, 0)
			if _, _, errno := unix.RawSyscall6(number, args[0], args[1], args[2], 0, 0, 0); errno != 0 {
				return errno
			}
			return nil
		}
		got := map[string]error{
			"getpid":  call(unix.SYS_GETPID),
			"ptrace":  call(unix.SYS_PTRACE, unix.PTRACE_PEEKUSR, uintptr(os.Getppid()), 0),
			"unshare": call(unix.SYS_UNSHARE, unix.CLONE_NEWUSER),
			// The kernel refuses CLONE_NEWUSER with CLONE_FS, so this clone
			// never creates a process; only the filter turns its EINVAL
			// into EPERM.
			"clone":          call(unix.SYS_CLONE, unix.CLONE_NEWUSER|unix.CLONE_FS),
			"clone3":         call(unix.SYS_CLONE3, 0, 0),
			"io_uring_setup": call(unix.SYS_IO_URING_SETUP, 0, 0),
			// A negative process group fails with EINVAL, so this call
			// never moves the test process; only the filter makes it EPERM.
			"setpgid": call(unix.SYS_SETPGID, 0, ^uintptr(0)),
		}
		if runtime.GOARCH == "amd64" {
			got["x32"] = call(x32Bit | unix.SYS_GETPID)
		}
		results <- got
	}()
	got := <-results
	for _, step := range []string{"no_new_privs", "install"} {
		if err := got[step]; err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	if got["getpid"] != nil {
		t.Fatalf("getpid = %v, want allowed", got["getpid"])
	}
	for _, name := range []string{"ptrace", "unshare", "clone", "io_uring_setup", "setpgid", "x32"} {
		if err, ok := got[name]; ok && !errors.Is(err, unix.EPERM) {
			t.Errorf("%s = %v, want EPERM", name, err)
		}
	}
	if !errors.Is(got["clone3"], unix.ENOSYS) {
		t.Errorf("clone3 = %v, want ENOSYS", got["clone3"])
	}
}

func TestSeccompArchitectureOfThisBuild(t *testing.T) {
	t.Parallel()
	arch, err := currentSeccompArchitecture()
	if _, known := seccompArchitectures[runtime.GOARCH]; known != (err == nil) {
		t.Fatalf("architecture %s = %+v, %v", runtime.GOARCH, arch, err)
	}
}

// TestHardenProcessDisablesCoreMappings verifies the hardening and checks
// that the core limit and mapping filter survive an actual exec.
func TestHardenProcessDisablesCoreMappings(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(executable, hardenNonzeroCheck).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "inherited core limit 0/0 and coredump filter 0" {
		t.Fatalf("hardened exec child after nonzero filter = %q, %v; want zero core limit and coredump filter", output, err)
	}
}

func TestHardenProcessAcceptsVerifiedZeroFilterAfterLandlockExec(t *testing.T) {
	t.Parallel()
	requireLandlock(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := commandWithoutGoCoverDir(executable, hardenZeroLandlock).Output()
	if err != nil || strings.TrimSpace(string(output)) != "inherited core limit 0/0 and coredump filter 0" {
		t.Fatalf("zero-filter Landlock exec child = %q, %v (stderr %q); want verified inherited zero filter", output, err, commandErrorStderr(err))
	}
}

func TestHardenProcessRejectsNonzeroFilterItCannotChangeAfterLandlock(t *testing.T) {
	t.Parallel()
	requireLandlock(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := commandWithoutGoCoverDir(executable, hardenNonzeroLandlock).Output()
	if err != nil || strings.TrimSpace(string(output)) != "nonzero inherited coredump filter refused" {
		t.Fatalf("nonzero-filter Landlock exec child = %q, %v (stderr %q); want refusal before startup", output, err, commandErrorStderr(err))
	}
}

func commandWithoutGoCoverDir(executable, argument string) *exec.Cmd {
	cmd := exec.Command(executable, argument)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "GOCOVERDIR=") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	return cmd
}

func commandErrorStderr(err error) []byte {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Stderr
	}
	return nil
}
