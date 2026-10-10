package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WebMetrics configures the opt-in Prometheus endpoint, GET /metrics on the
// console's listener. It is off unless Enabled is true, and then requires a
// bearer token that TokenFile holds. The endpoint reports deployment
// aggregates only, never a business unit's name, slug, job, or target.
type WebMetrics struct {
	Enabled bool `yaml:"enabled"`
	// TokenFile is the absolute path of the file that holds the bearer
	// token a scraper sends; see ReadMetricsToken.
	TokenFile string `yaml:"token_file"`
}

// The bounds of the metrics bearer token, in bytes.
const (
	MinMetricsTokenBytes = 32
	MaxMetricsTokenBytes = 1024
)

// validate checks the metrics settings without reading the token file,
// which ReadMetricsToken checks when the daemon starts.
func (m WebMetrics) validate() error {
	tokenFile := strings.TrimSpace(m.TokenFile)
	if !m.Enabled {
		if tokenFile != "" {
			return errors.New("web.metrics.token_file requires web.metrics.enabled: true")
		}
		return nil
	}
	if tokenFile == "" {
		return errors.New("web.metrics.enabled requires web.metrics.token_file")
	}
	if !filepath.IsAbs(tokenFile) {
		return fmt.Errorf("web.metrics.token_file must be an absolute path: %q", m.TokenFile)
	}
	return nil
}

// ErrMetricsTokenInvalid reports a metrics token file that cannot be used.
// Its messages never contain the token.
var ErrMetricsTokenInvalid = errors.New("metrics token file is invalid")

// ReadMetricsToken reads the bearer token of the metrics endpoint. The file
// must be a regular file that only its owner can read or write, such as
// mode 0400 or 0600, and hold one token of MinMetricsTokenBytes to
// MaxMetricsTokenBytes printable ASCII characters without spaces, with an
// optional trailing line break.
func ReadMetricsToken(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%w: no file is configured", ErrMetricsTokenInvalid)
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: the file does not exist", ErrMetricsTokenInvalid)
		}
		return "", fmt.Errorf("%w: %v", ErrMetricsTokenInvalid, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: it is not a regular file", ErrMetricsTokenInvalid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: group and other users must have no access (use mode 0400 or 0600)", ErrMetricsTokenInvalid)
	}
	if info.Size() > MaxMetricsTokenBytes+2 {
		return "", fmt.Errorf("%w: the token must be at most %d bytes", ErrMetricsTokenInvalid, MaxMetricsTokenBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMetricsTokenInvalid, err)
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(token) < MinMetricsTokenBytes || len(token) > MaxMetricsTokenBytes {
		return "", fmt.Errorf("%w: the token must be %d to %d bytes", ErrMetricsTokenInvalid, MinMetricsTokenBytes, MaxMetricsTokenBytes)
	}
	for _, r := range token {
		if r <= ' ' || r > '~' {
			return "", fmt.Errorf("%w: the token must be printable ASCII without spaces", ErrMetricsTokenInvalid)
		}
	}
	return token, nil
}
