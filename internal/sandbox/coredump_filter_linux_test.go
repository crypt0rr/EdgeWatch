//go:build linux

package sandbox

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestSetAndVerifyZeroCoredumpFilterWithFileBackedIO(t *testing.T) {
	t.Parallel()

	openFailure := errors.New("open denied")
	writeFailure := errors.New("write denied")
	closeFailure := errors.New("close failed")
	readFailure := errors.New("read denied")
	tests := []struct {
		name         string
		initial      string
		openErr      error
		writeErr     error
		shortWrite   bool
		closeErr     error
		readErr      error
		readback     string
		setReadback  bool
		wantError    string
		wantContents string
	}{
		{
			name:         "write zero and verify persisted value",
			initial:      "33\n",
			wantContents: "0",
		},
		{
			name:         "accept denied write when inherited value is zero",
			initial:      "00000000\n",
			openErr:      openFailure,
			wantContents: "00000000\n",
		},
		{
			name:         "refuse denied open when inherited value is nonzero",
			initial:      "1\n",
			openErr:      openFailure,
			wantError:    "current filter is 0x1",
			wantContents: "1\n",
		},
		{
			name:         "refuse denied open when inherited value cannot be read",
			initial:      "0\n",
			openErr:      openFailure,
			readErr:      readFailure,
			wantError:    "read back /proc/self/coredump_filter after setting it failed",
			wantContents: "0\n",
		},
		{
			name:         "accept denied write when readback is zero",
			initial:      "0\n",
			writeErr:     writeFailure,
			wantContents: "0\n",
		},
		{
			name:         "refuse denied write when readback is nonzero",
			initial:      "3\n",
			writeErr:     writeFailure,
			wantError:    "current filter is 0x3",
			wantContents: "3\n",
		},
		{
			name:         "refuse short write when readback is nonzero",
			initial:      "4\n",
			shortWrite:   true,
			wantError:    "wrote 0 of 1 byte; current filter is 0x4",
			wantContents: "4\n",
		},
		{
			name:         "accept close error only after zero readback",
			initial:      "5\n",
			closeErr:     closeFailure,
			wantContents: "0",
		},
		{
			name:         "fail closed when successful write cannot be read back",
			initial:      "6\n",
			readErr:      readFailure,
			wantError:    "read back /proc/self/coredump_filter: read denied",
			wantContents: "0",
		},
		{
			name:         "fail closed when readback remains nonzero",
			initial:      "7\n",
			readback:     "8\n",
			setReadback:  true,
			wantError:    "value is 0x8, want zero",
			wantContents: "8\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			filterIO := newFileBackedCoredumpFilterIO(t, tt.initial)
			filterIO.openErr = tt.openErr
			filterIO.writeErr = tt.writeErr
			filterIO.shortWrite = tt.shortWrite
			filterIO.closeErr = tt.closeErr
			filterIO.readErr = tt.readErr
			filterIO.readback = tt.readback
			filterIO.setReadback = tt.setReadback

			err := setAndVerifyZeroCoredumpFilterWith(filterIO)
			if tt.wantError == "" && err != nil {
				t.Fatalf("setAndVerifyZeroCoredumpFilterWith() error = %v", err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("setAndVerifyZeroCoredumpFilterWith() error = %v, want text %q", err, tt.wantError)
			}
			contents, readErr := os.ReadFile(filterIO.path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(contents) != tt.wantContents {
				t.Fatalf("persisted filter = %q, want %q", contents, tt.wantContents)
			}
		})
	}
}

func TestReadCoredumpFilterRejectsMalformedFileBackedValue(t *testing.T) {
	t.Parallel()
	filterIO := newFileBackedCoredumpFilterIO(t, "not-hex\n")
	if value, err := readCoredumpFilterWith(filterIO); err == nil {
		t.Fatalf("readCoredumpFilterWith() = %#x, nil; want parse error", value)
	}
}

func TestReadCoredumpFilterReadsFixedProcControlFile(t *testing.T) {
	t.Parallel()
	if _, err := readCoredumpFilter(); err != nil {
		t.Fatalf("readCoredumpFilter() error = %v", err)
	}
}

type fileBackedCoredumpFilterIO struct {
	path        string
	openErr     error
	writeErr    error
	shortWrite  bool
	closeErr    error
	readErr     error
	readback    string
	setReadback bool
}

func newFileBackedCoredumpFilterIO(t *testing.T, initial string) *fileBackedCoredumpFilterIO {
	t.Helper()
	path := t.TempDir() + "/coredump_filter"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fileBackedCoredumpFilterIO{path: path}
}

func (filterIO *fileBackedCoredumpFilterIO) openForWrite() (io.WriteCloser, error) {
	if filterIO.openErr != nil {
		return nil, filterIO.openErr
	}
	file, err := os.OpenFile(filterIO.path, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	return &fileBackedCoredumpFilterWriter{filterIO: filterIO, file: file}, nil
}

func (filterIO *fileBackedCoredumpFilterIO) read() ([]byte, error) {
	if filterIO.readErr != nil {
		return nil, filterIO.readErr
	}
	return os.ReadFile(filterIO.path)
}

type fileBackedCoredumpFilterWriter struct {
	filterIO *fileBackedCoredumpFilterIO
	file     *os.File
}

func (writer *fileBackedCoredumpFilterWriter) Write(contents []byte) (int, error) {
	if writer.filterIO.writeErr != nil {
		return 0, writer.filterIO.writeErr
	}
	if writer.filterIO.shortWrite {
		return 0, nil
	}
	written, err := writer.file.Write(contents)
	if err != nil {
		return written, err
	}
	if writer.filterIO.setReadback {
		if err := os.WriteFile(writer.filterIO.path, []byte(writer.filterIO.readback), 0o600); err != nil {
			return written, err
		}
	} else if err := writer.file.Truncate(int64(written)); err != nil {
		return written, err
	}
	return written, nil
}

func (writer *fileBackedCoredumpFilterWriter) Close() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	return writer.filterIO.closeErr
}
