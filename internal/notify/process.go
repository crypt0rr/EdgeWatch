package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/crypt0rr/edgewatch/internal/sandbox"
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

// childSandbox confines the notification child. Nil, the default, starts it
// unconfined.
var childSandbox atomic.Pointer[sandbox.Policy]

// SetSandbox installs the policy that confines the notification child of
// this process. Nil starts it unconfined.
func SetSandbox(policy *sandbox.Policy) {
	childSandbox.Store(policy)
}

// ChildEnvironment is the environment of the notification child: a fixed
// PATH and the daemon's proxy, certificate authority, time zone, and locale
// variables.
func ChildEnvironment() []string {
	return notificationChildEnvironment()
}

// The notification child's exit status reports the class of a failed send,
// so the daemon learns it without reading provider text. Any other status,
// including that of a child that could not start, is a provider failure.
const (
	childExitDNS     = 10
	childExitConnect = 11
	childExitTLS     = 12
	// childExitTimeout reports a provider that did not answer within the
	// provider timeout. The provider may have accepted the message.
	childExitTimeout = 13
)

// ChildExitError is the error of a failed send in the notification child.
// ExitCode is the exit status that reports its class to the daemon.
type ChildExitError struct {
	code int
	err  error
}

func (e *ChildExitError) Error() string { return e.err.Error() }

func (e *ChildExitError) Unwrap() error { return e.err }

// ExitCode is the exit status of the notification child for the failure.
func (e *ChildExitError) ExitCode() int { return e.code }

// childExitCode is the exit status that reports a failure class.
func childExitCode(class string) int {
	switch class {
	case store.DeliveryClassDNS:
		return childExitDNS
	case store.DeliveryClassConnect:
		return childExitConnect
	case store.DeliveryClassTLS:
		return childExitTLS
	case store.DeliveryClassTimeout:
		return childExitTimeout
	}
	return 1
}

// childFailure is the redacted failure that a child's exit status reports.
func childFailure(code int) error {
	switch code {
	case childExitDNS:
		return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassDNS}
	case childExitConnect:
		return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassConnect}
	case childExitTLS:
		return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassTLS}
	case childExitTimeout:
		return providerTimeoutFailure()
	}
	return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: store.DeliveryClassProvider}
}

// runNotificationProcess executes provider code in a short-lived child. A
// provider panic can therefore terminate only this child instead of the
// daemon's notification worker or process. The caller supplies the hard
// timeout/cancellation context; CommandContext kills and reaps the child
// before returning, and ordinary failures are converted into a redacted
// delivery error of the class that the child's exit status reports.
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
	childSandbox.Load().Confine(command)
	if err := command.Run(); err != nil {
		if childCtx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrNotificationSendIndeterminate, err)
		}
		code := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		return childFailure(code)
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
// implementation is invoked. A failed send is a ChildExitError, whose exit
// status reports the class of the failure.
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
	if err := sendInProcess(request.URL, request.Message); err != nil {
		return &ChildExitError{code: childExitCode(failureClass(err)), err: err}
	}
	return nil
}

// failureClass names the class of a provider error: a name that could not be
// resolved, a connection that could not be made, a failed certificate check
// or TLS handshake, a provider that did not answer in time, or any other
// failure. It reads the type of the error and, for a provider that formats
// the error of its client into its own instead of wrapping it, the error
// text, which never leaves the process: only the class does.
func failureClass(err error) string {
	var dnsErr *net.DNSError
	var verifyErr *tls.CertificateVerificationError
	var authorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var opErr *net.OpError
	switch {
	case errors.Is(err, errProviderTimeout):
		return store.DeliveryClassTimeout
	case errors.As(err, &dnsErr):
		return store.DeliveryClassDNS
	case errors.As(err, &verifyErr), errors.As(err, &authorityErr), errors.As(err, &hostnameErr), errors.As(err, &invalidErr), errors.As(err, &recordErr), errors.As(err, &alertErr):
		return store.DeliveryClassTLS
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return store.DeliveryClassConnect
	}
	return failureClassFromText(err.Error())
}

// failureClassFromText classifies the text of a Go network or TLS error that
// a provider formatted into its own error.
func failureClassFromText(text string) string {
	text = strings.ToLower(text)
	containsAny := func(parts ...string) bool {
		for _, part := range parts {
			if strings.Contains(text, part) {
				return true
			}
		}
		return false
	}
	switch {
	case strings.Contains(text, "lookup ") && containsAny("no such host", "server misbehaving", "name resolution", "i/o timeout"):
		return store.DeliveryClassDNS
	case containsAny("x509: ", "tls: ", "remote error: tls", "certificate"):
		return store.DeliveryClassTLS
	case containsAny("dial tcp", "dial udp", "connection refused", "no route to host", "network is unreachable"):
		return store.DeliveryClassConnect
	}
	return store.DeliveryClassProvider
}

// CheckChildTrust is the hidden command with which the daemon confirms that a
// confined notification child trusts the same certificate authorities as an
// unconfined one. It reads the files that SSL_CERT_FILE and SSL_CERT_DIR name,
// which a child that runs as another identity, or is restricted with
// Landlock, might not be allowed to open, and loads the system roots. Go
// skips missing files and directories, so they fail no check.
func CheckChildTrust() error {
	readable := func(variable, path string) error {
		if _, err := os.ReadFile(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read %s: %w", variable, err)
		}
		return nil
	}
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		if err := readable("SSL_CERT_FILE", file); err != nil {
			return err
		}
	}
	for _, directory := range filepath.SplitList(os.Getenv("SSL_CERT_DIR")) {
		if directory == "" {
			continue
		}
		entries, err := os.ReadDir(directory)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read SSL_CERT_DIR: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if err := readable("SSL_CERT_DIR", filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
	}
	if _, err := x509.SystemCertPool(); err != nil {
		return fmt.Errorf("load the system certificate authorities: %w", err)
	}
	return nil
}

func isTestBinary() bool {
	name := filepath.Base(os.Args[0])
	return strings.HasSuffix(name, ".test")
}
