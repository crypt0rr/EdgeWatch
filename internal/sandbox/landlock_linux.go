//go:build linux

package sandbox

import (
	"errors"
	"fmt"
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

// landlockPaths are what a scanner opens besides the files it inherits.
// Paths that do not exist on a host are skipped. A restricted process can
// create files only below /tmp, write elsewhere only to /dev/null, /dev/tty,
// and the files it inherits, and execute only programs below the system
// directories.
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
	// Nmap reads keyboard commands from its controlling terminal, which is
	// the daemon's private pseudo-terminal.
	{"/dev/tty", unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE},
	// Naabu keeps its target list and address map in temporary files. The
	// scanner environment sets no TMPDIR, so they go to /tmp, a private
	// tmpfs in the container; the daemon keeps its own temporary files in
	// the data directory.
	{"/tmp", landlockTemporary},
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
//	sandbox-exec --files N -- PROGRAM [ARGUMENT...]
//
// It restricts its own process with Landlock to landlockPaths and its N
// inherited descriptors, starting at 3, sets no_new_privs, and then executes
// PROGRAM in place. The process keeps its identity, capabilities,
// descriptors, and environment, and the daemon's handle on it stays valid.
func execLandlocked(args []string) error {
	files, argv, err := parseExecArgs(args)
	if err != nil {
		return err
	}
	// no_new_privs and the Landlock domain belong to the calling thread, and
	// PROGRAM executes from it, so the goroutine must not move to another
	// thread. The process ends with the exec, so the thread stays locked.
	runtime.LockOSThread()
	inherited := make([]int, files)
	for index := range inherited {
		inherited[index] = 3 + index
	}
	if err := restrictSelf(scannerPaths(), inherited); err != nil {
		return fmt.Errorf("%s: %w", ExecCommand, err)
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		return fmt.Errorf("%s: execute %s: %w", ExecCommand, argv[0], err)
	}
	return nil
}

func parseExecArgs(args []string) (int, []string, error) {
	usage := fmt.Errorf("usage: %s --files N -- PROGRAM [ARGUMENT...]", ExecCommand)
	if len(args) < 4 || args[0] != "--files" || args[2] != "--" {
		return 0, nil, usage
	}
	files, err := strconv.Atoi(args[1])
	if err != nil || files < 0 || files > maxInheritedFiles {
		return 0, nil, usage
	}
	if !filepath.IsAbs(args[3]) {
		return 0, nil, fmt.Errorf("%s: the program %q is not an absolute path", ExecCommand, args[3])
	}
	return files, args[3:], nil
}

// scannerPaths are landlockPaths and the search path files of musl's dynamic
// loader, which are named after the architecture.
func scannerPaths() []landlockPath {
	paths := append([]landlockPath(nil), landlockPaths...)
	musl, _ := filepath.Glob("/etc/ld-musl-*.path")
	for _, path := range musl {
		paths = append(paths, landlockPath{path, landlockRead})
	}
	return paths
}

// restrictSelf restricts the calling thread with Landlock to paths and the
// files behind the inherited descriptors.
func restrictSelf(paths []landlockPath, inherited []int) error {
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
	attr := unix.LandlockRulesetAttr{Access_fs: handledAccess(abi), Scoped: handledScopes(abi)}
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
