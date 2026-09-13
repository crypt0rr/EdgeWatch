package scanner

import (
	"errors"
	"fmt"
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
