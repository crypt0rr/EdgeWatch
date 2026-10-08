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
		names := append(append([]string{"clone", "clone3"}, seccompDenied...), seccompDeniedX86...)
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
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			var taken bool
			switch instruction.Code &^ (unix.BPF_JMP | unix.BPF_K) {
			case unix.BPF_JEQ:
				taken = accumulator == instruction.K
			case unix.BPF_JGE:
				taken = accumulator >= instruction.K
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
	binary.LittleEndian.PutUint32(data[seccompFirstArgLow:], firstArg)
	return data
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
		for _, flag := range []uint32{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWNET, unix.CLONE_NEWPID} {
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
		if err := installSeccompFilter(); err != nil {
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
	for _, name := range []string{"ptrace", "unshare", "clone", "io_uring_setup", "x32"} {
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

// TestHardenProcessStopsCoreDumps runs the hardening in a test binary of its
// own, which then reports its dumpable flag and core file size limits.
func TestHardenProcessStopsCoreDumps(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(executable, hardenCheck).CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "0 0 0" {
		t.Fatalf("hardened process = %q, %v; want non-dumpable with no core dumps", output, err)
	}
}
