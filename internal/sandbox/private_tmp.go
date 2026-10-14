package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// PrivateTemporaryDirectory owns the temporary path used by one Naabu
// invocation. Linux policies use the descriptor-pinned helper; other
// platforms use a unique directory without adding an OS sandbox.
type PrivateTemporaryDirectory struct {
	implementation privateTemporaryDirectoryImplementation
}

type privateTemporaryDirectoryImplementation interface {
	Started() error
	WaitReady(context.Context) error
	Cleanup(context.Context) error
	Close() error
}

type privateTemporaryDirectoryPreparer interface {
	preparePrivateTemporaryDirectory(context.Context, *exec.Cmd) (*PrivateTemporaryDirectory, error)
}

// PreparePrivateTemporaryDirectory gives Naabu a unique temporary directory.
// A platform policy may provide a stronger implementation for its runtime.
func PreparePrivateTemporaryDirectory(ctx context.Context, cmd *exec.Cmd, policy *Policy) (*PrivateTemporaryDirectory, error) {
	return preparePrivateTemporaryDirectory(ctx, cmd, any(policy))
}

func preparePrivateTemporaryDirectory(ctx context.Context, cmd *exec.Cmd, candidate any) (*PrivateTemporaryDirectory, error) {
	if preparer, ok := candidate.(privateTemporaryDirectoryPreparer); ok {
		return preparer.preparePrivateTemporaryDirectory(ctx, cmd)
	}
	return preparePortablePrivateTemporaryDirectory(ctx, cmd)
}

func preparePortablePrivateTemporaryDirectory(ctx context.Context, cmd *exec.Cmd) (*PrivateTemporaryDirectory, error) {
	if ctx == nil {
		return nil, errors.New("prepare Naabu temporary directory: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cmd == nil || cmd.Path == "" || len(cmd.Args) == 0 {
		return nil, errors.New("prepare Naabu temporary directory: invalid command")
	}
	path, err := os.MkdirTemp("", "edgewatch-naabu-")
	if err != nil {
		return nil, errors.New("prepare Naabu temporary directory: create directory failed")
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		if err := setEnvironment(cmd, name, path); err != nil {
			_ = os.RemoveAll(path)
			return nil, errors.New("prepare Naabu temporary directory: set environment failed")
		}
	}
	return &PrivateTemporaryDirectory{implementation: &portablePrivateTemporaryDirectory{path: path}}, nil
}

type portablePrivateTemporaryDirectory struct {
	path    string
	cleaned bool
}

func (temporary *portablePrivateTemporaryDirectory) Started() error { return nil }

func (temporary *portablePrivateTemporaryDirectory) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return errors.New("prepare Naabu temporary directory: context is nil")
	}
	return ctx.Err()
}

func (temporary *portablePrivateTemporaryDirectory) Cleanup(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cleanup Naabu temporary directory: context is nil")
	}
	if temporary == nil || temporary.cleaned || temporary.path == "" {
		return nil
	}
	if err := os.RemoveAll(temporary.path); err != nil {
		return errors.New("cleanup Naabu temporary directory failed")
	}
	temporary.cleaned = true
	return nil
}

func (*portablePrivateTemporaryDirectory) Close() error { return nil }

func (temporary *PrivateTemporaryDirectory) Started() error {
	if temporary == nil || temporary.implementation == nil {
		return nil
	}
	return temporary.implementation.Started()
}

func (temporary *PrivateTemporaryDirectory) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return errors.New("prepare Naabu temporary directory: context is nil")
	}
	if temporary == nil || temporary.implementation == nil {
		return nil
	}
	return temporary.implementation.WaitReady(ctx)
}

func (temporary *PrivateTemporaryDirectory) Cleanup(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cleanup Naabu temporary directory: context is nil")
	}
	if temporary == nil || temporary.implementation == nil {
		return nil
	}
	return temporary.implementation.Cleanup(ctx)
}

func (temporary *PrivateTemporaryDirectory) Close() error {
	if temporary == nil || temporary.implementation == nil {
		return nil
	}
	return temporary.implementation.Close()
}

func setEnvironment(cmd *exec.Cmd, key, value string) error {
	if cmd == nil || key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
		return errors.New("invalid environment value")
	}
	var environment []string
	found := false
	for _, item := range cmd.Env {
		name, _, ok := strings.Cut(item, "=")
		if ok && name == key {
			if !found {
				environment = append(environment, key+"="+value)
				found = true
			}
			continue
		}
		environment = append(environment, item)
	}
	if !found {
		environment = append(environment, key+"="+value)
	}
	cmd.Env = environment
	return nil
}

func privateTemporaryExecutionEnvironment(environment []string, path string) ([]string, error) {
	command := &exec.Cmd{Env: append([]string(nil), environment...)}
	if err := setEnvironment(command, "TMPDIR", path); err != nil {
		return nil, err
	}
	return command.Env, nil
}
