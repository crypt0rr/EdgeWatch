package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestRunSendChildRejectsMalformedRequest(t *testing.T) {
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
