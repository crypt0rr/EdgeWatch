package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ErrConfiguration marks a scanner error that cannot be repaired by rerunning
// the same persisted work unit. The application uses this marker to surface
// invalid profiles, unsupported work-unit shapes, and missing capabilities
// immediately instead of scheduling retries that cannot succeed.
var ErrConfiguration = errors.New("scanner configuration error")

// ConfigurationError annotates an underlying validation/deployment error as
// permanent for resumable-cycle retry decisions while preserving the original
// text for the operator.
func ConfigurationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrConfiguration, err)
}

// IsConfigurationError reports whether err (including a wrapped error) is a
// permanent scanner configuration/deployment failure.
func IsConfigurationError(err error) bool {
	return errors.Is(err, ErrConfiguration)
}

// ExecutableStartError marks an executable that cannot be found or launched
// due to permissions as a deployment configuration error. Other process-start
// errors (for example temporary resource exhaustion) remain retryable.
func ExecutableStartError(path string, err error) error {
	if err == nil {
		return nil
	}
	var commandErr *exec.Error
	var pathErr *os.PathError
	commandPathFailure := errors.As(err, &commandErr) && filepath.Clean(commandErr.Name) == filepath.Clean(path)
	commandPathFailure = commandPathFailure || (errors.As(err, &pathErr) && filepath.Clean(pathErr.Path) == filepath.Clean(path))
	if commandPathFailure && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)) {
		return ConfigurationError(fmt.Errorf("start scanner executable %q: %w", path, err))
	}
	return err
}
