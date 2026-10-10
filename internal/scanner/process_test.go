//go:build linux

package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/crypt0rr/edgewatch/internal/config"
)

// xmlOutputScript is a stand-in Nmap prologue that sets $out to the path
// after -oX.
const xmlOutputScript = "#!/bin/sh\nout=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -oX ]; then out=\"$2\"; shift 2; else shift; fi\ndone\n"

// leaveBackgroundProcess starts a process that ignores the hangup of the
// scanner's terminal, as a forking scanner could, and records its ID.
func leaveBackgroundProcess(pidFile string) string {
	return "(trap '' HUP; exec sleep 30) &\necho $! > '" + pidFile + "'\n"
}

// waitUntilGone waits until the process recorded in pidFile has exited.
func waitUntilGone(t *testing.T, pidFile string) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		// An exited process that its new parent has not reaped yet is a
		// zombie: state Z, after the command name in parentheses.
		if err != nil || strings.HasPrefix(strings.TrimSpace(string(stat[strings.LastIndexByte(string(stat), ')')+1:])), "Z") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("the scanner's background process %d kept running", pid)
}

func TestNmapInvocationStopsTheScannersProcessGroupWhenCancelled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "background")
	nmap := filepath.Join(dir, "nmap")
	writeScript(t, nmap, "#!/bin/sh\n"+leaveBackgroundProcess(pidFile)+"sleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nmap, "-oX", "-", "192.0.2.1")
	started := time.Now()
	if _, _, err := runNmapInvocation(ctx, cmd, nil, "", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled invocation = %v", err)
	}
	// The background process holds the terminal and stderr. Had it survived,
	// the invocation would have waited scannerWaitDelay for each.
	if elapsed := time.Since(started); elapsed > time.Second+scannerWaitDelay/2 {
		t.Fatalf("the cancelled invocation returned after %s", elapsed)
	}
	waitUntilGone(t, pidFile)
}

func TestNmapInvocationStopsWhatAScannerLeavesBehind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "background")
	nmap := filepath.Join(dir, "nmap")
	writeScript(t, nmap, xmlOutputScript+"printf '%s' '"+sampleXML+"' > \"$out\"\n"+leaveBackgroundProcess(pidFile))
	cmd := exec.CommandContext(context.Background(), nmap, "-oX", "-", "192.0.2.1")
	started := time.Now()
	stdout, stderr, err := runNmapInvocation(context.Background(), cmd, nil, "", nil, nil)
	if err != nil || string(stdout) != sampleXML {
		t.Fatalf("invocation = %q, %v (stderr %q)", stdout, err, stderr)
	}
	if elapsed := time.Since(started); elapsed > scannerWaitDelay/2 {
		t.Fatalf("the invocation waited %s for a process the scanner left behind", elapsed)
	}
	waitUntilGone(t, pidFile)
}

// A process that leaves the scanner's session, which the seccomp filter
// refuses a sandboxed scanner, keeps the terminal open: the invocation waits
// for it only until the deadline that the scanner's stderr had, and fails.
func TestNmapInvocationFailsWhenAProcessKeepsTheTerminal(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "escaped")
	nmap := filepath.Join(dir, "nmap")
	writeScript(t, nmap, xmlOutputScript+"printf '%s' '"+sampleXML+"' > \"$out\"\nsetsid sh -c 'echo $$ > \""+pidFile+"\"; exec sleep 30' 2>/dev/null &\nwhile [ ! -s '"+pidFile+"' ]; do sleep 0.05; done\n")
	t.Cleanup(func() {
		if raw, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	cmd := exec.CommandContext(context.Background(), nmap, "-oX", "-", "192.0.2.1")
	started := time.Now()
	_, _, err := runNmapInvocation(context.Background(), cmd, nil, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nmap left a process holding its terminal open") {
		t.Fatalf("invocation with a held terminal = %v", err)
	}
	if elapsed := time.Since(started); elapsed > scannerWaitDelay+scannerWaitDelay/2 {
		t.Fatalf("the invocation waited %s, beyond one deadline of %s", elapsed, scannerWaitDelay)
	}
}

func TestNaabuStopsItsProcessGroupWhenCancelled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "background")
	naabu := filepath.Join(dir, "naabu")
	writeScript(t, naabu, "#!/bin/sh\n"+leaveBackgroundProcess(pidFile)+"sleep 30\n")
	n := NewWithNaabu("nmap", naabu)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if _, _, err := n.runNaabu(ctx, testNaabuOptions(), nil, []string{"192.0.2.1"}, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Naabu = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second+scannerWaitDelay/2 {
		t.Fatalf("cancelled Naabu returned after %s", elapsed)
	}
	waitUntilGone(t, pidFile)
}

func TestScannerWaitErrorExplainsALingeringProcess(t *testing.T) {
	t.Parallel()
	if err := scannerWaitError("naabu", exec.ErrWaitDelay); !errors.Is(err, exec.ErrWaitDelay) || !strings.Contains(err.Error(), "naabu left a process holding its output open") {
		t.Fatalf("wait delay error = %v", err)
	}
	other := errors.New("exit status 1")
	if err := scannerWaitError("nmap", other); err != other {
		t.Fatalf("other wait error = %v", err)
	}
}

func TestNmapInvocationCopiesTheSandboxAttributes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nmap := filepath.Join(dir, "nmap")
	// The stand-in reports whether it leads its own session with the
	// terminal as its stdin and stdout.
	writeScript(t, nmap, xmlOutputScript+"session=$(cut -d' ' -f6 /proc/$$/stat)\nif [ \"$session\" = $$ ] && [ -t 0 ] && [ -t 1 ]; then echo 'session leader on a terminal'; fi\nprintf '%s' '"+sampleXML+"' > \"$out\"\n")
	credential := &syscall.Credential{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid()), NoSetGroups: true}
	original := &syscall.SysProcAttr{Credential: credential}
	cmd := exec.CommandContext(context.Background(), nmap, "-oX", "-", "192.0.2.1")
	cmd.SysProcAttr = original
	var mu sync.Mutex
	var lines []string
	stdout, _, err := runNmapInvocation(context.Background(), cmd, nil, "", func(line string, _ float64) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)
	}, nil)
	if err != nil || string(stdout) != sampleXML {
		t.Fatalf("invocation = %q, %v", stdout, err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "session leader on a terminal") {
		t.Fatalf("Nmap did not start in a session of its own on the terminal: %q", lines)
	}
	if original.Setsid || original.Setctty || original.Setpgid {
		t.Fatalf("the invocation changed the sandbox's attributes: %+v", original)
	}
	if cmd.SysProcAttr == original || cmd.SysProcAttr.Credential != credential || !cmd.SysProcAttr.Setsid || !cmd.SysProcAttr.Setctty || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("started attributes = %+v", cmd.SysProcAttr)
	}
}

// TestNmapInvocationFallsBackToAPipeWithoutATerminal replaces openTerminal,
// so it does not run in parallel.
func TestNmapInvocationFallsBackToAPipeWithoutATerminal(t *testing.T) {
	previous := openTerminal
	openTerminal = func(*pty.Winsize) (*os.File, *os.File, error) {
		return nil, nil, errors.New("no pseudo-terminal is available")
	}
	t.Cleanup(func() { openTerminal = previous })
	dir := t.TempDir()
	nmap := filepath.Join(dir, "nmap")
	writeScript(t, nmap, xmlOutputScript+"if [ -t 1 ]; then echo terminal; else echo 'Connect Scan Timing: About 25.00% done'; fi\nprintf '%s' '"+sampleXML+"' > \"$out\"\n")
	credential := &syscall.Credential{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid()), NoSetGroups: true}
	// A sandboxed Nmap starts with the attributes Confine set.
	original := &syscall.SysProcAttr{Credential: credential}
	cmd := exec.CommandContext(context.Background(), nmap, "-oX", "-", "192.0.2.1")
	cmd.SysProcAttr = original
	var mu sync.Mutex
	var lines []string
	stdout, stderr, err := runNmapInvocation(context.Background(), cmd, nil, "", func(line string, _ float64) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line)
	}, nil)
	if err != nil || string(stdout) != sampleXML {
		t.Fatalf("invocation without a terminal = %q, %v (stderr %q)", stdout, err, stderr)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "About 25.00% done") {
		t.Fatalf("progress through the pipe = %q", lines)
	}
	attrs := cmd.SysProcAttr
	if attrs.Credential != credential || attrs.Setsid || attrs.Setctty || !attrs.Setpgid || original.Setpgid || attrs.Pdeathsig != syscall.SIGKILL || original.Pdeathsig != 0 {
		t.Fatalf("attributes without a terminal = %+v (original %+v)", attrs, original)
	}
}

func TestNmapInvocationKeepsTheXMLFileAfterLongTerminalOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nmap := filepath.Join(dir, "nmap")
	// More status lines than maxProgressOutput, as a long scan prints, after
	// a complete XML file.
	writeScript(t, nmap, xmlOutputScript+"printf '%s' '"+sampleXML+"' > \"$out\"\nhead -c "+strconv.Itoa(maxProgressOutput+(1<<20))+" /dev/zero | tr '\\0' 's' | fold -w 150\necho 'Connect Scan Timing: About 99.50% done'\n")
	cmd := exec.CommandContext(context.Background(), nmap, "-oX", "-", "192.0.2.1")
	var mu sync.Mutex
	last := ""
	stdout, stderr, err := runNmapInvocation(context.Background(), cmd, nil, "", func(line string, _ float64) {
		mu.Lock()
		defer mu.Unlock()
		last = line
	}, nil)
	if err != nil || string(stdout) != sampleXML {
		t.Fatalf("long scan = %d bytes, %v (stderr %q)", len(stdout), err, stderr)
	}
	if !strings.Contains(last, "About 99.50% done") {
		t.Fatalf("the last progress line = %q, want the one after the bound", last)
	}
}

func TestNmapInvocationOutputBounds(t *testing.T) {
	t.Parallel()
	overStatus := strconv.Itoa(maxProgressOutput + (1 << 20))
	overXML := strconv.Itoa(maxNmapOutput + (1 << 20))
	for name, test := range map[string]struct {
		script string
		// fileXML passes -oX -, which writes the XML to a file.
		fileXML bool
		want    string
		notWant string
	}{
		"XML file": {
			script: "head -c " + overXML + " /dev/zero > \"$out\"\nsleep 300\n", fileXML: true,
			want: "nmap XML output exceeded 16777216 bytes",
		},
		"XML on stdout": {
			script: "head -c " + overXML + " /dev/zero | tr '\\0' 'x'\nsleep 300\n",
			want:   "nmap XML output exceeded 16777216 bytes",
		},
		"terminal output without an XML file": {
			script: "head -c " + overStatus + " /dev/zero | tr '\\0' 's' | fold -w 150\n", fileXML: true,
			want: "nmap wrote no XML file, and its terminal output exceeded 8388608 bytes", notWant: "XML output exceeded",
		},
		"diagnostic output": {
			script: "printf '%s' '" + sampleXML + "' > \"$out\"\nhead -c " + overStatus + " /dev/zero | tr '\\0' 'd' | fold -w 150 >&2\nsleep 300\n", fileXML: true,
			want: "nmap diagnostic output exceeded 8388608 bytes", notWant: "XML output exceeded",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			nmap := filepath.Join(dir, "nmap")
			writeScript(t, nmap, xmlOutputScript+test.script)
			args := []string{"-n", "192.0.2.1"}
			if test.fileXML {
				args = append(args, "-oX", "-")
			}
			// A pseudo-terminal passes the output at a few megabytes a
			// second; the scanners sleep for longer than the deadline once
			// they have written it, so only a bound stops them in time.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			_, _, err := runNmapInvocation(ctx, exec.CommandContext(ctx, nmap, args...), nil, "", nil, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) || (test.notWant != "" && strings.Contains(err.Error(), test.notWant)) {
				t.Fatalf("invocation = %v, want %q", err, test.want)
			}
			if ctx.Err() != nil {
				t.Fatal("the bound did not stop the scanner before its deadline")
			}
		})
	}
}

func TestProgressOutputWriterBoundsAnUnterminatedLine(t *testing.T) {
	t.Parallel()
	var lines []string
	writer := &progressOutputWriter{limit: 16, streaming: true, emit: func(line string) { lines = append(lines, line) }}
	_, _ = writer.Write([]byte(strings.Repeat("x", maxProgressLine+1)))
	if len(lines) != 1 || len(lines[0]) != maxProgressLine+1 {
		t.Fatalf("an overlong line was not passed on: %d lines", len(lines))
	}
	_, _ = writer.Write([]byte("Stats: 0:00:01 elapsed\n"))
	if !writer.overflowed() || writer.String() != "" || lines[len(lines)-1] != "Stats: 0:00:01 elapsed" {
		t.Fatalf("streaming writer = %q, overflowed %v, lines %q", writer.String(), writer.overflowed(), lines)
	}
}

func TestScannerFilesStayInItsTemporaryDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := filepath.Join(dir, "data", "tmp", "scanner")
	nmapPaths, naabuPaths := filepath.Join(dir, "nmap-paths"), filepath.Join(dir, "naabu-paths")
	nmap, naabu := filepath.Join(dir, "nmap"), filepath.Join(dir, "naabu")
	writeScript(t, nmap, xmlOutputScript+"printf '%s\\n' \"$out\" >> '"+nmapPaths+"'\nprintf '%s' '"+sampleXML+"' > \"$out\"\n")
	writeScript(t, naabu, "#!/bin/sh\nprintf '%s\\n' \"$2\" >> '"+naabuPaths+"'\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n")
	n := NewWithNaabu(nmap, naabu)
	if err := n.SetTemporaryDirectory(base); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(base)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("scanner temporary directory = %v, %v; want mode 0700", info, err)
	}
	if filepath.Dir(n.workDir) != base || !strings.HasPrefix(filepath.Base(n.workDir), scanRunPrefix) {
		t.Fatalf("scan files go to %q, want a directory of this process below %q", n.workDir, base)
	}
	job := config.NormalizeJob(config.Job{Name: "files", Targets: []string{"192.0.2.1"}, MaxExpandedHosts: 1, TCP: &config.Protocol{Ports: "22", Mode: "connect"}, Timing: "balanced"})
	if _, err := n.Scan(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.runNaabu(context.Background(), testNaabuOptions(), nil, []string{"192.0.2.1"}, true); err != nil {
		t.Fatal(err)
	}
	for _, record := range []string{nmapPaths, naabuPaths} {
		raw, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range strings.Fields(string(raw)) {
			if filepath.Dir(path) != n.workDir {
				t.Fatalf("a scan file was created at %s, outside %s", path, n.workDir)
			}
		}
	}
	// The scans removed their files.
	if entries, err := os.ReadDir(n.workDir); err != nil || len(entries) != 0 {
		t.Fatalf("files left behind = %v, %v", entries, err)
	}
}

func TestSetTemporaryDirectoryRemovesOnlyAbandonedRuns(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleRunAge)
	makeRun := func(name string, modified time.Time) string {
		path := filepath.Join(base, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "edgewatch-nmap-1.xml"), []byte("<nmaprun>"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
		return path
	}
	abandoned := makeRun(scanRunPrefix+"abandoned", old)
	starting := makeRun(scanRunPrefix+"starting", time.Now())
	running := makeRun(scanRunPrefix+"running", old)
	other := makeRun("other", old)
	lock, err := lockDirectory(running)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	n := New("/bin/true")
	if err := n.SetTemporaryDirectory(base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the abandoned run was kept: %v", err)
	}
	for _, kept := range []string{starting, running, other} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s was removed: %v", kept, err)
		}
	}
	if info, err := os.Stat(base); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("scanner temporary directory = %v, %v; want it restricted to 0700", info, err)
	}
	if locked, err := directoryLocked(n.workDir); err != nil || !locked {
		t.Fatalf("this process's run is not locked: %v, %v", locked, err)
	}
	// A second call replaces the run and releases the first one's lock. A
	// process that a parallel test forks holds the lock until it executes
	// its program, so the release can take a moment to show.
	first := n.workDir
	if err := n.SetTemporaryDirectory(base); err != nil {
		t.Fatal(err)
	}
	locked, err := directoryLocked(first)
	for deadline := time.Now().Add(5 * time.Second); err == nil && locked && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		locked, err = directoryLocked(first)
	}
	if err != nil || locked || n.workDir == first {
		t.Fatalf("the replaced run = %v, %v", locked, err)
	}
}

func TestSetTemporaryDirectoryRefusesWhatIsNotAPrivateDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	n := New("/bin/true")
	for path, want := range map[string]string{
		file:                         "create the scanner temporary directory",
		filepath.Join(file, "below"): "create the scanner temporary directory",
		link:                         "is not a directory",
	} {
		if err := n.SetTemporaryDirectory(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	if n.workDir != "" {
		t.Fatalf("a refused directory was used: %q", n.workDir)
	}
}
