//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/crypt0rr/edgewatch/internal/store"
)

const perimeterStdinHelperEnv = "EDGEWATCH_TEST_PERIMETER_BLOCKING_STDIN"

func TestPerimeterDeclareCancellationInterruptsInheritedStdin(t *testing.T) {
	if os.Getenv(perimeterStdinHelperEnv) == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		startedCtx := &perimeterReadWaitContext{Context: ctx}
		_, _, err := parsePerimeterDeclarationContext(startedCtx, os.Stdin, store.PerimeterKindPrefix)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled inherited-stdin parser error = %v, want context.Canceled", err)
		}
		_, _ = os.Stdout.Write([]byte("PERIMETER_PARSE_RETURNED\n"))
		return
	}

	// Use a blocking kernel pipe, not os.Pipe's runtime-pollable files. The
	// child receives the reader as fd 0, matching inherited stdin. Keep the
	// writer open through child exit so cancellation cannot rely on EOF.
	fds := []int{-1, -1}
	if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
		t.Fatalf("create blocking stdin pipe: %v", err)
	}
	stdin := os.NewFile(uintptr(fds[0]), "blocking-stdin-reader")
	writer := os.NewFile(uintptr(fds[1]), "blocking-stdin-writer")
	if stdin == nil || writer == nil {
		if stdin != nil {
			_ = stdin.Close()
		}
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatal("wrap blocking stdin pipe descriptors")
	}
	defer writer.Close()

	executable, err := os.Executable()
	if err != nil {
		stdin.Close()
		t.Fatalf("locate test executable: %v", err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPerimeterDeclareCancellationInterruptsInheritedStdin$")
	cmd.Stdin = stdin
	cmd.Env = perimeterStdinHelperEnvironment()
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		t.Fatalf("open helper stdout: %v", err)
	}
	defer stdout.Close()
	stdoutFile, ok := stdout.(*os.File)
	if !ok {
		stdin.Close()
		t.Fatalf("helper stdout has type %T, want *os.File", stdout)
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		t.Fatalf("start inherited-stdin helper: %v", err)
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("close parent's stdin reader: %v", err)
	}

	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	finished := false
	defer func() {
		if finished {
			return
		}
		// The only helper goroutine is Cmd.Wait; killing and joining the child
		// bounds its lifetime on every failing path.
		killErr := cmd.Process.Kill()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			t.Errorf("kill inherited-stdin helper during cleanup: %v", killErr)
		}
		select {
		case waitErr := <-wait:
			if waitErr != nil && (killErr != nil || !perimeterHelperWasKilled(waitErr)) {
				t.Errorf("wait for inherited-stdin helper during cleanup: %v", waitErr)
			}
		case <-time.After(time.Second):
			t.Error("killed inherited-stdin helper did not exit within one second")
		}
	}()

	if err := waitForPerimeterReadWaitMarker(stdoutFile, 3*time.Second); err != nil {
		t.Fatalf("parser did not reach its blocking stdin wait: %v", err)
	}
	started := time.Now()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("cancel inherited-stdin helper: %v", err)
	}
	if err := waitForPerimeterMarker(stdoutFile, "PERIMETER_PARSE_RETURNED\n", time.Second); err != nil {
		t.Fatalf("canceled inherited-stdin parser did not return while its writer remained open: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled inherited-stdin parser returned after %s, want within one second", elapsed)
	}
	killErr := cmd.Process.Kill()
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		t.Fatalf("stop inherited-stdin helper after parser return: %v", killErr)
	}
	select {
	case waitErr := <-wait:
		finished = true
		if waitErr != nil && (killErr != nil || !perimeterHelperWasKilled(waitErr)) {
			t.Fatalf("wait for inherited-stdin helper after parser return: %v", waitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("inherited-stdin helper did not exit after cleanup")
	}
}

func perimeterHelperWasKilled(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

// perimeterReadWaitContext signals after the parser's initial context check
// and one full poll timeout. That proves the child reached the no-data stdin
// wait before the parent sends SIGINT.
type perimeterReadWaitContext struct {
	context.Context
	checks          int
	readWaitStarted time.Time
}

func (c *perimeterReadWaitContext) Err() error {
	c.checks++
	switch c.checks {
	case 2:
		c.readWaitStarted = time.Now()
	case 3:
		if time.Since(c.readWaitStarted) >= time.Duration(perimeterInputPollTimeoutMillis-20)*time.Millisecond {
			_, _ = os.Stdout.Write([]byte("PERIMETER_READ_WAIT\n"))
		}
	}
	return c.Context.Err()
}

func perimeterStdinHelperEnvironment() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, perimeterStdinHelperEnv+"=") {
			env = append(env, item)
		}
	}
	return append(env, fmt.Sprintf("%s=1", perimeterStdinHelperEnv))
}

func waitForPerimeterReadWaitMarker(stdout *os.File, timeout time.Duration) error {
	return waitForPerimeterMarker(stdout, "PERIMETER_READ_WAIT\n", timeout)
}

func waitForPerimeterMarker(stdout *os.File, markerText string, timeout time.Duration) error {
	fd := int(stdout.Fd())
	deadline := time.Now().Add(timeout)
	output := make([]byte, 0, len(markerText))
	marker := []byte(markerText)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("timed out waiting for parser read marker")
		}
		millis := int(remaining / time.Millisecond)
		if millis < 1 {
			millis = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, millis)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll helper stdout: %w", err)
		}
		if ready == 0 {
			return errors.New("timed out waiting for parser read marker")
		}
		var buffer [64]byte
		n, err := unix.Read(fd, buffer[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read helper stdout: %w", err)
		}
		if n == 0 {
			return errors.New("helper exited before parser read marker")
		}
		output = append(output, buffer[:n]...)
		if bytes.Contains(output, marker) {
			return nil
		}
	}
}
