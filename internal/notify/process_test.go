package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// runSendChildInProcess keeps guarded globals scoped to direct unit tests.
// Production RunSendChild is exercised in a subprocess because it deliberately
// retains its guards until that one-request process exits.
func runSendChildInProcess(input io.Reader) error {
	return runSendChild(input, sendInProcessWithPolicy)
}

func TestRunSendChildOwnsDestinationGuardsUntilProcessExit(t *testing.T) {
	const modeEnv = "EDGEWATCH_NOTIFY_CHILD_GUARD_TEST_MODE"
	mode := os.Getenv(modeEnv)
	if mode == "" {
		for _, childMode := range []string{"blocked", "allowed", "timeout"} {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRunSendChildOwnsDestinationGuardsUntilProcessExit$")
			cmd.Env = append(environmentWithout(modeEnv), modeEnv+"="+childMode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child mode %q: %v\n%s", childMode, err, output)
			}
		}
		return
	}

	originalResolver := net.DefaultResolver
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not an HTTP transport")
	}
	var rawURL string
	var exclusions []string
	var providerStarted <-chan struct{}
	switch mode {
	case "blocked":
		rawURL = "generic+http://127.0.0.1:1/hook?template=json"
		exclusions = []string{"127.0.0.0/8"}
	case "allowed", "timeout":
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			started <- struct{}{}
			if mode == "timeout" {
				<-release
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		defer close(release)
		providerStarted = started
		parsed, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, port, err := net.SplitHostPort(parsed.Host)
		if err != nil {
			t.Fatal(err)
		}
		rawURL = "generic+http://safe.example:" + port + "/hook?template=json"
		exclusions = []string{"198.51.100.0/24"}
		defaultTransport.Proxy = nil
		serverAddress := server.Listener.Addr().String()
		destinationLookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		}
		destinationTargetDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialDestinationTestAddress(ctx, network, serverAddress)
		}
		if mode == "timeout" {
			notificationProviderTimeout = 150 * time.Millisecond
		}
	default:
		t.Fatalf("unknown child test mode %q", mode)
	}
	payload, err := json.Marshal(notificationProcessRequest{URL: rawURL, Message: "guard lifecycle", TargetExclusions: exclusions})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "timeout" {
		sendResult := make(chan error, 1)
		go func() { sendResult <- RunSendChild(strings.NewReader(string(payload))) }()
		select {
		case <-providerStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("provider did not reach the controlled listener")
		}
		select {
		case err = <-sendResult:
		case <-time.After(2 * time.Second):
			t.Fatal("notification child did not return after its provider timeout")
		}
		var childErr *ChildExitError
		if !errors.As(err, &childErr) || childErr.ExitCode() != childExitTimeout {
			t.Fatalf("timed-out child send error = %v, want timeout child error", err)
		}
	} else {
		err = RunSendChild(strings.NewReader(string(payload)))
	}
	switch mode {
	case "blocked":
		if !errors.Is(err, ErrDestinationExcluded) {
			t.Fatalf("blocked child send error = %v, want destination exclusion", err)
		}
	case "allowed":
		if err != nil {
			t.Fatalf("allowed child send error = %v", err)
		}
	}
	if net.DefaultResolver == originalResolver {
		t.Fatal("child restored DefaultResolver before process exit")
	}
	if http.DefaultClient.Transport != defaultTransport || http.DefaultClient.CheckRedirect == nil || defaultTransport.DialContext == nil {
		t.Fatal("child restored HTTP guards before process exit")
	}
}

func environmentWithout(key string) []string {
	prefix := key + "="
	environment := os.Environ()
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func TestRunSendChildRejectsMalformedRequest(t *testing.T) {
	t.Parallel()
	if err := RunSendChild(nil); err == nil {
		t.Fatal("nil child input was accepted")
	}
	if err := RunSendChild(strings.NewReader("{")); err == nil {
		t.Fatal("malformed child request was accepted")
	}
	if err := RunSendChild(strings.NewReader(`{"message":"missing URL"}`)); err == nil {
		t.Fatal("child request without a URL was accepted")
	}
}

func TestNotificationProcessFailureIsRedactedAndSendUsesIsolation(t *testing.T) {
	originalIsTestBinary := notificationIsTestBinary
	originalCommand := notificationCommandContext
	defer func() {
		notificationIsTestBinary = originalIsTestBinary
		notificationCommandContext = originalCommand
	}()
	notificationIsTestBinary = func() bool { return false }
	notificationCommandContext = func(_ context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.Command("/bin/false")
	}
	if err := runNotificationProcess(context.Background(), "generic://127.0.0.1/no-listener", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("isolated process error = %v, want provider error", err)
	}
	if err := send(context.Background(), "generic://127.0.0.1/no-listener", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("isolated send error = %v, want provider error", err)
	}
}

func TestNotificationProcessUsesSafeExecutableAndCommand(t *testing.T) {
	originalExecutable := notificationExecutable
	originalCommand := notificationCommandContext
	defer func() {
		notificationExecutable = originalExecutable
		notificationCommandContext = originalCommand
	}()
	notificationExecutable = func() (string, error) { return "", errors.New("executable unavailable") }
	if err := runNotificationProcess(context.Background(), "generic://example.invalid", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("executable lookup error = %v, want provider error", err)
	}
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	notificationCommandContext = func(_ context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.Command("/bin/true")
	}
	if err := runNotificationProcess(context.Background(), "generic://example.invalid", "test"); err != nil {
		t.Fatalf("successful isolated process = %v", err)
	}
}

func TestNotificationProcessPassesOnlyRequiredProviderEnvironment(t *testing.T) {
	t.Setenv("EDGEWATCH_TEST_SECRET", "must-not-reach-provider")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "also-must-not-reach-provider")
	t.Setenv("PATH", "/tmp/untrusted-bin")
	t.Setenv("HOME", "/tmp/private-home")
	t.Setenv("HTTPS_PROXY", "https://proxy-user:proxy-password@proxy.example:8443")
	t.Setenv("NO_PROXY", "localhost,127.0.0.1")
	t.Setenv("SSL_CERT_FILE", "/etc/edgewatch/test-ca.pem")
	t.Setenv("TZ", "Europe/Amsterdam")

	originalExecutable := notificationExecutable
	originalCommand := notificationCommandContext
	defer func() {
		notificationExecutable = originalExecutable
		notificationCommandContext = originalCommand
	}()
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	var child *exec.Cmd
	notificationCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		child = exec.CommandContext(ctx, "/usr/bin/env")
		return child
	}
	if err := runNotificationProcess(context.Background(), "generic://example.invalid", "test"); err != nil {
		t.Fatalf("run isolated child: %v", err)
	}
	if child == nil {
		t.Fatal("notification child command was not created")
	}
	environment := make(map[string]string, len(child.Env))
	for _, entry := range child.Env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			environment[key] = value
		}
	}
	if environment["PATH"] != notificationChildPath {
		t.Errorf("child PATH did not use the fixed provider path")
	}
	for _, key := range []string{"EDGEWATCH_TEST_SECRET", "AWS_SECRET_ACCESS_KEY", "HOME"} {
		if _, ok := environment[key]; ok {
			t.Errorf("unrelated parent variable %q reached the provider child", key)
		}
	}
	for key, want := range map[string]string{
		"HTTPS_PROXY":   "https://proxy-user:proxy-password@proxy.example:8443",
		"NO_PROXY":      "localhost,127.0.0.1",
		"SSL_CERT_FILE": "/etc/edgewatch/test-ca.pem",
		"TZ":            "Europe/Amsterdam",
	} {
		if environment[key] != want {
			t.Errorf("provider environment did not preserve %s", key)
		}
	}
}

func TestNotificationProcessTimeoutTerminatesAndReapsChild(t *testing.T) {
	originalExecutable := notificationExecutable
	originalCommand := notificationCommandContext
	defer func() {
		notificationExecutable = originalExecutable
		notificationCommandContext = originalCommand
	}()
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	notificationCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exec sleep 30")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runNotificationProcess(ctx, "generic://example.invalid", "test")
	if !errors.Is(err, ErrNotificationSendIndeterminate) {
		t.Fatalf("timed-out process error = %v, want indeterminate", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timed-out process took %s; child was not reaped promptly", elapsed)
	}
}

func TestRunSendChildDeliversWithoutPuttingCredentialsInArguments(t *testing.T) {
	t.Parallel()
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode webhook body: %v", err)
			return
		}
		received <- body.Message
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := "generic://user:secret@" + parsed.Host + "/alerts?disabletls=yes&template=json"
	payload, err := json.Marshal(notificationProcessRequest{URL: destination, Message: "EdgeWatch test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunSendChild(strings.NewReader(string(payload))); err != nil {
		t.Fatalf("run child: %v", err)
	}
	select {
	case message := <-received:
		if message != "EdgeWatch test" {
			t.Fatalf("message = %q, want EdgeWatch test", message)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook was not delivered")
	}
}
