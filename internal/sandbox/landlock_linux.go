//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The Landlock access rights a rule grants.
const (
	landlockRead    = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	landlockExecute = landlockRead | unix.LANDLOCK_ACCESS_FS_EXECUTE
	landlockWrite   = unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	// landlockTemporary lets a process create, change, rename, and remove
	// its own files and directories, but not execute them or create
	// devices, sockets, pipes, or links.
	landlockTemporary = landlockRead | landlockWrite | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REFER
	// landlockFileAccess are the rights that apply to a file rather than a
	// directory.
	landlockFileAccess = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | landlockWrite
)

// maxInheritedFiles bounds the descriptors sandbox-exec accepts. Scanner
// processes inherit one or two.
const maxInheritedFiles = 16

// landlockPath is a file or directory a restricted scanner process can open
// with the given rights, and everything beneath a directory.
type landlockPath struct {
	path   string
	access uint64
}

// landlockPaths are what every restricted process opens besides the files it
// inherits. Paths that do not exist on a host are skipped. A restricted
// process can write only to /dev/null, the files it inherits, and the paths
// its profile adds, and execute only programs below the system directories.
var landlockPaths = []landlockPath{
	// Programs, the dynamic loader, shared libraries, and scanner data such
	// as /usr/share/nmap.
	{"/usr", landlockExecute},
	{"/bin", landlockExecute},
	{"/sbin", landlockExecute},
	{"/lib", landlockExecute},
	{"/lib32", landlockExecute},
	{"/lib64", landlockExecute},
	{"/libx32", landlockExecute},
	// Name resolution, service and protocol names, user and group names,
	// time zones, the dynamic loader's search path, and TLS settings and
	// trust. The rest of /etc, such as the EdgeWatch configuration, stays
	// closed.
	{"/etc/hosts", landlockRead},
	{"/etc/resolv.conf", landlockRead},
	{"/etc/nsswitch.conf", landlockRead},
	{"/etc/host.conf", landlockRead},
	{"/etc/gai.conf", landlockRead},
	{"/etc/services", landlockRead},
	{"/etc/protocols", landlockRead},
	{"/etc/networks", landlockRead},
	{"/etc/passwd", landlockRead},
	{"/etc/group", landlockRead},
	{"/etc/localtime", landlockRead},
	{"/etc/timezone", landlockRead},
	{"/etc/ld.so.cache", landlockRead},
	{"/etc/ld.so.conf", landlockRead},
	{"/etc/ld.so.conf.d", landlockRead},
	{"/etc/ssl", landlockRead},
	{"/etc/pki", landlockRead},
	{"/etc/ca-certificates", landlockRead},
	{"/etc/crypto-policies", landlockRead},
	// Interfaces, routes, and the process's own state. Landlock keeps a
	// restricted process from tracing other processes, so /proc shows it
	// no other process's memory, environment, or descriptors.
	{"/proc", landlockRead},
	{"/sys", landlockRead},
	{"/dev/null", unix.LANDLOCK_ACCESS_FS_READ_FILE | landlockWrite},
	{"/dev/zero", unix.LANDLOCK_ACCESS_FS_READ_FILE},
	{"/dev/random", unix.LANDLOCK_ACCESS_FS_READ_FILE},
	{"/dev/urandom", unix.LANDLOCK_ACCESS_FS_READ_FILE},
}

// scannerLandlockPaths are what a scanner opens besides landlockPaths. A
// restricted scanner creates no file, unless it is started with temporary
// files.
var scannerLandlockPaths = []landlockPath{
	// Nmap reads keyboard commands from its controlling terminal, which is
	// the daemon's private pseudo-terminal.
	{"/dev/tty", unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
}

// landlockVersion reports the kernel's Landlock ABI version.
func landlockVersion() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	if int(abi) < 1 {
		return 0, fmt.Errorf("unexpected Landlock ABI version %d", abi)
	}
	return int(abi), nil
}

// handledAccess are the filesystem rights the restriction controls for an
// ABI: every right it defines except IOCTL_DEV. Device ioctls stay allowed
// because a scanner's terminal settings use them, and the only devices it
// can open are the ones landlockPaths lists.
func handledAccess(abi int) uint64 {
	access := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return access
}

// handledScopes keeps a restricted process, from ABI 6, from signaling or
// connecting to abstract UNIX sockets of processes outside its domain, such
// as the daemon.
func handledScopes(abi int) uint64 {
	if abi >= 6 {
		return unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
	}
	return 0
}

// execLandlocked is the sandbox-exec command:
//
//	sandbox-exec --profile PROFILE --files N [--seccomp] -- PROGRAM [ARGUMENT...]
//
// It restricts its own process with Landlock to the paths of PROFILE and its
// N inherited descriptors, starting at 3, sets
// no_new_privs, installs the seccomp filter with --seccomp, and then executes
// PROGRAM in place. A scanner also gets the resource limits of
// limitScannerResources first. The process keeps its identity, capabilities,
// descriptors, and environment, and the daemon's handle on it stays valid.
func execLandlocked(args []string) error {
	if len(args) > 0 && args[0] == "--cleanup-private-tmp" {
		request, err := parsePrivateTemporaryCleanupArgs(args[1:])
		if err != nil {
			return err
		}
		// The cleanup helper runs as the scanner identity in both Landlock and
		// identity-only modes. Keep the same core/open-file resource safeguards
		// in either mode; only the filesystem restriction is conditional.
		runtime.LockOSThread()
		limitScannerResources()
		return cleanupPrivateTemporaryDirectoryRequestWithDescriptor(request, 3)
	}
	request, err := parseExecArgs(args)
	if err != nil {
		return err
	}
	if request.privateTemp {
		return execPrivateTemporary(request)
	}
	profile, files, argv := request.profile, request.files, request.argv
	// no_new_privs and the Landlock domain belong to the calling thread, and
	// PROGRAM executes from it, so the goroutine must not move to another
	// thread. The process ends with the exec, so the thread stays locked.
	runtime.LockOSThread()
	inherited := make([]int, files)
	for index := range inherited {
		inherited[index] = 3 + index
	}
	if profile == Scanner {
		limitScannerResources()
	}
	if err := restrictSelf(profilePaths(profile, os.Getenv), inherited); err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	if request.seccomp {
		if err := installSeccompFilter(); err != nil {
			return fmt.Errorf("%s: %w", ExecCommand, err)
		}
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		return fmt.Errorf("%s: execute %s: %w", ExecCommand, argv[0], err)
	}
	return nil
}

// execPrivateTemporary verifies the parent-pinned temporary leaf, restricts
// the helper to that leaf when Landlock is enabled, and waits for the parent
// to acknowledge readiness before Naabu can start. Control descriptors are
// separate from scanner data descriptors and none reaches Naabu.
func execPrivateTemporary(request execRequest) error {
	runtime.LockOSThread()
	limitScannerResources()
	namespaceFD, leafFD, controlFD := request.privateRootFD, request.privateLeafFD, request.controlFD
	defer func() {
		_ = closePrivateTemporaryControlDescriptors(namespaceFD, leafFD, controlFD)
	}()
	setup, err := preparePrivateTemporaryExec(request)
	if err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	if request.landlock {
		// Landlock's EXECUTE right authorizes executing files beneath a rule.
		// DAC search permissions resolve /tmp/<namespace>/<leaf>; no EXECUTE
		// rule is granted on either ancestor.
		if err := restrictPrivateTemporary(request, leafFD); err != nil {
			return fmt.Errorf("%s: %w", ExecCommand, err)
		}
	}
	if err := helperSendPrivateTemporaryReady(controlFD, setup.initialization.name, setup.initialization.nonce, &setup.stat); err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	// Only the scanner's intended data descriptors survive exec. The namespace,
	// leaf, and handshake socket are control state and never inherit into Naabu.
	if err := closePrivateTemporaryControlDescriptors(namespaceFD, leafFD, controlFD); err != nil {
		return fmt.Errorf("%s: close private temporary control descriptor: %w", ExecCommand, err)
	}
	namespaceFD, leafFD, controlFD = -1, -1, -1
	if request.seccomp {
		if err := installSeccompFilter(); err != nil {
			return fmt.Errorf("%s: %w", ExecCommand, err)
		}
	}
	if err := syscall.Exec(request.argv[0], request.argv, setup.environment); err != nil {
		return fmt.Errorf("%s: execute %s: %w", ExecCommand, request.argv[0], err)
	}
	return nil
}

// execRequest is what the sandbox-exec arguments ask for.
type execRequest struct {
	profile       Profile
	files         int
	privateTemp   bool
	privateRootFD int
	privateLeafFD int
	controlFD     int
	landlock      bool
	seccomp       bool
	argv          []string
}

func parseExecArgs(args []string) (execRequest, error) {
	usage := fmt.Errorf("usage: %s --profile scanner|notifier --files N [--private-tmp --private-root-fd FD --private-leaf-fd FD --control-fd FD [--landlock]] [--seccomp] -- PROGRAM [ARGUMENT...]", ExecCommand)
	request := execRequest{files: -1, privateRootFD: -1, privateLeafFD: -1, controlFD: -1}
	privateSeen, rootSeen, leafSeen, controlSeen, landlockSeen, seccompSeen := false, false, false, false, false, false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--profile":
			if index+1 >= len(args) || request.profile != "" {
				return execRequest{}, usage
			}
			index++
			request.profile = Profile(args[index])
		case "--files":
			if index+1 >= len(args) || request.files >= 0 {
				return execRequest{}, usage
			}
			index++
			files, err := strconv.Atoi(args[index])
			if err != nil || files < 0 || files > maxInheritedFiles {
				return execRequest{}, usage
			}
			request.files = files
		case "--private-tmp":
			if privateSeen {
				return execRequest{}, usage
			}
			request.privateTemp = true
			privateSeen = true
		case "--private-root-fd":
			if index+1 >= len(args) || rootSeen {
				return execRequest{}, usage
			}
			index++
			fd, err := strconv.Atoi(args[index])
			if err != nil || fd < 3 {
				return execRequest{}, usage
			}
			request.privateRootFD = fd
			rootSeen = true
		case "--private-leaf-fd":
			if index+1 >= len(args) || leafSeen {
				return execRequest{}, usage
			}
			index++
			fd, err := strconv.Atoi(args[index])
			if err != nil || fd < 3 {
				return execRequest{}, usage
			}
			request.privateLeafFD = fd
			leafSeen = true
		case "--control-fd":
			if index+1 >= len(args) || controlSeen {
				return execRequest{}, usage
			}
			index++
			fd, err := strconv.Atoi(args[index])
			if err != nil || fd < 3 {
				return execRequest{}, usage
			}
			request.controlFD = fd
			controlSeen = true
		case "--landlock":
			if landlockSeen {
				return execRequest{}, usage
			}
			request.landlock = true
			landlockSeen = true
		case "--seccomp":
			if seccompSeen {
				return execRequest{}, usage
			}
			request.seccomp = true
			seccompSeen = true
		case "--":
			request.argv = args[index+1:]
			index = len(args)
		default:
			return execRequest{}, usage
		}
	}
	if !request.profile.valid() || request.files < 0 || len(request.argv) == 0 ||
		(request.landlock && !privateSeen) ||
		(privateSeen && (request.profile != Scanner || request.privateRootFD != 3+request.files || request.privateLeafFD != request.privateRootFD+1 || request.controlFD != request.privateLeafFD+1 || !rootSeen || !leafSeen || !controlSeen)) ||
		(!privateSeen && (rootSeen || leafSeen || request.privateRootFD != -1 || request.privateLeafFD != -1 || request.controlFD != -1 || request.landlock)) ||
		(request.seccomp && privateSeen && !request.landlock) {
		return execRequest{}, usage
	}
	if !filepath.IsAbs(request.argv[0]) {
		return execRequest{}, fmt.Errorf("%s: the program %q is not an absolute path", ExecCommand, request.argv[0])
	}
	return request, nil
}

// profilePaths are landlockPaths, the search path files of musl's dynamic
// loader, which are named after the architecture, and the paths of profile.
// The notification process also
// reads the certificate authorities that the SSL_CERT_FILE and SSL_CERT_DIR
// variables of its environment name, which the daemon passes on from its
// own.
func profilePaths(profile Profile, getenv func(string) string) []landlockPath {
	paths := append([]landlockPath(nil), landlockPaths...)
	musl, _ := filepath.Glob("/etc/ld-musl-*.path")
	for _, path := range musl {
		paths = append(paths, landlockPath{path, landlockRead})
	}
	switch profile {
	case Scanner:
		paths = append(paths, scannerLandlockPaths...)
	case Notifier:
		if file := getenv("SSL_CERT_FILE"); file != "" {
			paths = append(paths, landlockPath{file, landlockRead})
		}
		for _, directory := range filepath.SplitList(getenv("SSL_CERT_DIR")) {
			if directory != "" {
				paths = append(paths, landlockPath{directory, landlockRead})
			}
		}
	}
	return paths
}

// restrictSelf restricts the calling thread with Landlock to paths and the
// files behind the inherited descriptors.
func restrictSelf(paths []landlockPath, inherited []int) error {
	return restrictSelfWithPrivateDirectory(paths, inherited, -1)
}

func restrictSelfWithPrivateDirectory(paths []landlockPath, inherited []int, privateDirectory int) error {
	abi, err := landlockVersion()
	if err != nil {
		return fmt.Errorf("detect Landlock: %w", err)
	}
	handled := handledAccess(abi)
	ruleset, err := createRuleset(abi)
	if err != nil {
		return err
	}
	defer unix.Close(ruleset)
	for _, path := range paths {
		if err := addPathRule(ruleset, path.path, path.access&handled); err != nil {
			return err
		}
	}
	for _, descriptor := range inherited {
		if err := addDescriptorRule(ruleset, descriptor, handled); err != nil {
			return err
		}
	}
	if privateDirectory >= 0 {
		if err := addRule(ruleset, privateDirectory, landlockTemporary&handled); err != nil {
			return fmt.Errorf("allow private temporary directory: %w", err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("enforce the Landlock ruleset: %w", errno)
	}
	return nil
}

// createRuleset creates a ruleset that handles every right and scope ABI abi
// restricts.
func createRuleset(abi int) (int, error) {
	attr := unix.LandlockRulesetAttr{Handled_access_fs: handledAccess(abi), Scoped: handledScopes(abi)}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return -1, fmt.Errorf("create the Landlock ruleset: %w", errno)
	}
	return int(fd), nil
}

// addPathRule grants access to path. A path that does not exist, or that the
// process may not reach, is skipped.
func addPathRule(ruleset int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EACCES) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s for the Landlock ruleset: %w", path, err)
	}
	defer unix.Close(fd)
	if err := addRule(ruleset, fd, access); err != nil {
		return fmt.Errorf("allow %s: %w", path, err)
	}
	return nil
}

// addDescriptorRule lets the process reopen the file behind an inherited
// descriptor, through /dev/fd, with the access the descriptor has.
func addDescriptorRule(ruleset, descriptor int, handled uint64) error {
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("inherited descriptor %d: %w", descriptor, err)
	}
	var access uint64
	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		access = unix.LANDLOCK_ACCESS_FS_READ_FILE
	case unix.O_WRONLY:
		access = landlockWrite
	default:
		access = unix.LANDLOCK_ACCESS_FS_READ_FILE | landlockWrite
	}
	if err := addRule(ruleset, descriptor, access&handled); err != nil {
		return fmt.Errorf("allow inherited descriptor %d: %w", descriptor, err)
	}
	return nil
}

// addRule grants access beneath the directory, or to the file or device, fd
// refers to; a file or device takes only file rights. Other descriptors, such
// as pipes, take no rule.
func addRule(ruleset, fd int, access uint64) error {
	if fd < 0 || fd > math.MaxInt32 {
		return fmt.Errorf("descriptor %d is outside the Landlock parent fd range", fd)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFREG, unix.S_IFCHR:
		access &= landlockFileAccess
	default:
		return nil
	}
	if access == 0 {
		return nil
	}
	rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
