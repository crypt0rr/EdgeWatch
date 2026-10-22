//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const perimeterInputPollTimeoutMillis = 100

// perimeterInputWithCancellation uses poll for OS files so cancellation does
// not depend on closing a descriptor interrupting a read already in progress.
// Other reader types retain the close-on-cancel behavior used by the parser.
func perimeterInputWithCancellation(ctx context.Context, input io.Reader) (io.Reader, func() bool) {
	if file, ok := input.(*os.File); ok {
		return perimeterPollFileReader{ctx: ctx, file: file}, nil
	}
	if closer, ok := input.(io.Closer); ok {
		return input, context.AfterFunc(ctx, func() { _ = closer.Close() })
	}
	return input, nil
}

// perimeterPollFileReader waits for descriptor readability in bounded poll
// intervals, checking ctx between waits. It starts no worker goroutine and
// never closes the file. Reads use a temporarily nonblocking descriptor so a
// readiness race cannot strand the parser inside the read syscall.
type perimeterPollFileReader struct {
	ctx  context.Context
	file *os.File
}

func (r perimeterPollFileReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	fd := int(r.file.Fd())
	if fd < 0 {
		return 0, os.ErrClosed
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return 0, err
	}
	restoreBlocking := flags&unix.O_NONBLOCK == 0
	if restoreBlocking {
		if err := unix.SetNonblock(fd, true); err != nil {
			return 0, err
		}
		defer func() { _ = unix.SetNonblock(fd, false) }()
	}

	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, perimeterInputPollTimeoutMillis)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if ready == 0 {
			continue
		}
		revents := fds[0].Revents
		if revents&unix.POLLNVAL != 0 {
			return 0, os.ErrClosed
		}
		if revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) == 0 {
			continue
		}
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}

		n, err := unix.Read(fd, p)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return n, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}
