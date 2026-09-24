package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// notificationProcessRequest is deliberately exchanged over stdin rather
// than command-line arguments or environment variables. Shoutrrr URLs may
// contain credentials, so neither the parent process argument list nor its
// environment should expose them to process inspection tools.
type notificationProcessRequest struct {
	URL     string `json:"url"`
	Message string `json:"message"`
}

// These indirections keep the process boundary deterministic in unit tests
// without ever starting the test binary recursively.
var notificationExecutable = os.Executable
var notificationCommandContext = exec.CommandContext

var notificationChildEnvironmentAllowlist = []string{
	"ALL_PROXY", "all_proxy",
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
	"SSL_CERT_DIR", "SSL_CERT_FILE",
	"TZ", "LANG", "LC_ALL",
}

const notificationChildPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// runNotificationProcess executes provider code in a short-lived child. A
// provider panic can therefore terminate only this child instead of the
// daemon's notification worker or process. The caller supplies the hard
// timeout/cancellation context; CommandContext kills and reaps the child
// before returning, and ordinary failures are converted into a redacted
// delivery error.
//
//nolint:contextcheck // this low-level process boundary intentionally accepts the caller's lifecycle context.
func runNotificationProcess(ctx context.Context, rawURL, message string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	executable, err := notificationExecutable()
	if err != nil {
		return errors.Join(store.ErrDeliveryProvider, err)
	}
	payload, err := json.Marshal(notificationProcessRequest{URL: rawURL, Message: message})
	if err != nil {
		return errors.Join(store.ErrDeliveryProvider, err)
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := notificationCommandContext(childCtx, executable, "notify-send")
	command.Env = notificationChildEnvironment()
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if childCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrNotificationSendIndeterminate, err)
		}
		return errors.Join(store.ErrDeliveryProvider, errors.New("isolated notification provider failed"))
	}
	return nil
}

func notificationChildEnvironment() []string {
	environment := []string{"PATH=" + notificationChildPath}
	for _, key := range notificationChildEnvironmentAllowlist {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	sort.Strings(environment)
	return environment
}

// RunSendChild is the hidden command entry point used by the daemon's
// notification subprocess. It is intentionally small and does not load the
// EdgeWatch configuration or open SQLite; only the fixed Shoutrrr provider
// implementation is invoked.
func RunSendChild(input io.Reader) error {
	if input == nil {
		return errors.New("notification child input is required")
	}
	var request notificationProcessRequest
	decoder := json.NewDecoder(input)
	if err := decoder.Decode(&request); err != nil {
		return errors.New("invalid notification child request")
	}
	if strings.TrimSpace(request.URL) == "" {
		return errors.New("notification child URL is required")
	}
	return sendInProcess(request.URL, request.Message)
}

func isTestBinary() bool {
	name := filepath.Base(os.Args[0])
	return strings.HasSuffix(name, ".test")
}
