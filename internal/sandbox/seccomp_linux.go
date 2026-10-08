//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompDenied are the system calls the seccomp filter refuses with EPERM.
// No scanner or notification process needs them, and each reaches other
// processes or a large part of the kernel: tracing another process and
// reading its memory, io_uring, user-space page faults, performance events,
// BPF programs, the kernel keyring, loading kernels and modules, mounts and
// namespaces, a new root directory, and the host's swap, reboot, accounting,
// quota, file handle, and log controls. Docker's default profile refuses most
// of them already; the filter keeps them refused where it does not.
var seccompDenied = []string{
	"ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"userfaultfd", "perf_event_open", "bpf",
	"keyctl", "add_key", "request_key",
	"kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
	"mount", "umount2", "pivot_root", "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
	"unshare", "setns", "chroot",
	"swapon", "swapoff", "reboot", "acct", "quotactl", "quotactl_fd",
	"name_to_handle_at", "open_by_handle_at", "lookup_dcookie", "syslog",
}

// seccompDeniedX86 are the x86-64 calls without an arm64 counterpart: port
// I/O and loading a shared library.
var seccompDeniedX86 = []string{"iopl", "ioperm", "uselib"}

// cloneNamespaces are the clone flags that create namespaces. clone with any
// of them is refused like unshare. clone3 passes its flags in memory, which a
// filter cannot read, so it fails with ENOSYS and the C libraries fall back to
// clone; Go uses clone3 only for cgroup and time namespace options.
const cloneNamespaces = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// x32Bit marks the system call numbers of the x32 ABI on x86-64.
const x32Bit = 0x40000000

// seccompArchitecture is how the filter recognizes one architecture's system
// calls.
type seccompArchitecture struct {
	audit uint32
	// x32 refuses the x32 ABI, which numbers its calls from x32Bit.
	x32     bool
	numbers map[string]uint32
}

// seccompArchitectures are the release architectures. Their numbers come from
// the kernel's system call tables, which golang.org/x/sys mirrors; a test
// compares them.
var seccompArchitectures = map[string]seccompArchitecture{
	"amd64": {audit: unix.AUDIT_ARCH_X86_64, x32: true, numbers: map[string]uint32{
		"ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
		"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"userfaultfd": 323, "perf_event_open": 298, "bpf": 321,
		"keyctl": 250, "add_key": 248, "request_key": 249,
		"kexec_load": 246, "kexec_file_load": 320, "init_module": 175, "finit_module": 313, "delete_module": 176,
		"mount": 165, "umount2": 166, "pivot_root": 155, "move_mount": 429, "open_tree": 428, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
		"unshare": 272, "setns": 308, "chroot": 161,
		"swapon": 167, "swapoff": 168, "reboot": 169, "acct": 163, "quotactl": 179, "quotactl_fd": 443,
		"name_to_handle_at": 303, "open_by_handle_at": 304, "lookup_dcookie": 212, "syslog": 103,
		"iopl": 172, "ioperm": 173, "uselib": 134,
		"clone": 56, "clone3": 435,
	}},
	"arm64": {audit: unix.AUDIT_ARCH_AARCH64, numbers: map[string]uint32{
		"ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272,
		"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"userfaultfd": 282, "perf_event_open": 241, "bpf": 280,
		"keyctl": 219, "add_key": 217, "request_key": 218,
		"kexec_load": 104, "kexec_file_load": 294, "init_module": 105, "finit_module": 273, "delete_module": 106,
		"mount": 40, "umount2": 39, "pivot_root": 41, "move_mount": 429, "open_tree": 428, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
		"unshare": 97, "setns": 268, "chroot": 51,
		"swapon": 224, "swapoff": 225, "reboot": 142, "acct": 89, "quotactl": 60, "quotactl_fd": 443,
		"name_to_handle_at": 264, "open_by_handle_at": 265, "lookup_dcookie": 18, "syslog": 116,
		"clone": 220, "clone3": 435,
	}},
}

// The offsets of struct seccomp_data that the filter reads. Both release
// architectures are little-endian, so the clone flags are the low word of the
// first argument.
const (
	seccompNumber      = 0
	seccompArch        = 4
	seccompFirstArgLow = 16
)

// bpfStep is one filter instruction whose conditional jumps name labels; an
// empty label continues with the next instruction.
type bpfStep struct {
	label       string
	instruction unix.SockFilter
	jumpTrue    string
	jumpFalse   string
}

// seccompFilter compiles the filter for arch: a call of another architecture
// kills the process, a denied call or a namespace-creating clone fails with
// EPERM, clone3 fails with ENOSYS, and every other call is allowed.
func seccompFilter(arch seccompArchitecture) ([]unix.SockFilter, error) {
	load := func(offset uint32) bpfStep {
		return bpfStep{instruction: unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset}}
	}
	jump := func(code uint16, value uint32, jumpTrue, jumpFalse string) bpfStep {
		return bpfStep{instruction: unix.SockFilter{Code: unix.BPF_JMP | code | unix.BPF_K, K: value}, jumpTrue: jumpTrue, jumpFalse: jumpFalse}
	}
	result := func(label string, value uint32) bpfStep {
		return bpfStep{label: label, instruction: unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: value}}
	}
	number := func(name string) (uint32, error) {
		value, ok := arch.numbers[name]
		if !ok {
			return 0, fmt.Errorf("no system call number for %s", name)
		}
		return value, nil
	}
	steps := []bpfStep{load(seccompArch), jump(unix.BPF_JEQ, arch.audit, "", "kill"), load(seccompNumber)}
	denied := seccompDenied
	if arch.x32 {
		steps = append(steps, jump(unix.BPF_JGE, x32Bit, "deny", ""))
		denied = append(append([]string(nil), seccompDenied...), seccompDeniedX86...)
	}
	for _, name := range denied {
		value, err := number(name)
		if err != nil {
			return nil, err
		}
		steps = append(steps, jump(unix.BPF_JEQ, value, "deny", ""))
	}
	clone3, err := number("clone3")
	if err != nil {
		return nil, err
	}
	clone, err := number("clone")
	if err != nil {
		return nil, err
	}
	steps = append(steps,
		jump(unix.BPF_JEQ, clone3, "nosys", ""),
		jump(unix.BPF_JEQ, clone, "", "allow"),
		load(seccompFirstArgLow),
		jump(unix.BPF_JSET, cloneNamespaces, "deny", "allow"),
		result("allow", unix.SECCOMP_RET_ALLOW),
		result("deny", unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM)),
		result("nosys", unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)),
		result("kill", unix.SECCOMP_RET_KILL_PROCESS),
	)
	return resolveBPF(steps)
}

// resolveBPF turns the labels of steps into the forward jump offsets that
// classic BPF requires.
func resolveBPF(steps []bpfStep) ([]unix.SockFilter, error) {
	labels := map[string]int{}
	for index, step := range steps {
		if step.label != "" {
			labels[step.label] = index
		}
	}
	offset := func(from int, label string) (uint8, error) {
		if label == "" {
			return 0, nil
		}
		target, ok := labels[label]
		distance := target - from - 1
		if !ok || distance < 0 || distance > 255 {
			return 0, fmt.Errorf("cannot jump from instruction %d to %q", from, label)
		}
		return uint8(distance), nil
	}
	filter := make([]unix.SockFilter, len(steps))
	for index, step := range steps {
		instruction := step.instruction
		var err error
		if instruction.Jt, err = offset(index, step.jumpTrue); err != nil {
			return nil, err
		}
		if instruction.Jf, err = offset(index, step.jumpFalse); err != nil {
			return nil, err
		}
		filter[index] = instruction
	}
	return filter, nil
}

// currentSeccompArchitecture is the filter's description of this build's
// architecture.
func currentSeccompArchitecture() (seccompArchitecture, error) {
	arch, ok := seccompArchitectures[runtime.GOARCH]
	if !ok {
		return seccompArchitecture{}, fmt.Errorf("EdgeWatch has no seccomp filter for %s", runtime.GOARCH)
	}
	return arch, nil
}

// seccompSupport reports whether the kernel accepts the filter's actions.
func seccompSupport() error {
	if _, err := currentSeccompArchitecture(); err != nil {
		return err
	}
	for _, action := range []uint32{unix.SECCOMP_RET_ERRNO, unix.SECCOMP_RET_KILL_PROCESS} {
		if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_GET_ACTION_AVAIL, 0, uintptr(unsafe.Pointer(&action))); errno != 0 {
			return errno
		}
	}
	return nil
}

// seccompUnavailableReason explains why the filter cannot be used.
func seccompUnavailableReason(err error) string {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return "the kernel does not provide seccomp filters, or the container's seccomp profile blocks them"
	case errors.Is(err, unix.EOPNOTSUPP):
		return "the kernel lacks the seccomp actions the filter uses"
	default:
		return fmt.Sprintf("seccomp could not be detected: %v", err)
	}
}

// installSeccompFilter installs the filter on the calling thread, which must
// have no_new_privs set. The program it executes inherits the filter.
func installSeccompFilter() error {
	arch, err := currentSeccompArchitecture()
	if err != nil {
		return err
	}
	filter, err := seccompFilter(arch)
	if err != nil {
		return err
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program))); errno != 0 {
		return fmt.Errorf("install the seccomp filter: %w", errno)
	}
	return nil
}
