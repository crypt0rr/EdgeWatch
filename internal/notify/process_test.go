package notify

import (
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
	originalCommand := notificationCommand
	defer func() {
		notificationIsTestBinary = originalIsTestBinary
		notificationCommand = originalCommand
	}()
	notificationIsTestBinary = func() bool { return false }
	notificationCommand = func(_ string, _ ...string) *exec.Cmd {
		return exec.Command("/bin/false")
	}
	if err := runNotificationProcess("generic://127.0.0.1/no-listener", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("isolated process error = %v, want provider error", err)
	}
	if err := send("generic://127.0.0.1/no-listener", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("isolated send error = %v, want provider error", err)
	}
}

func TestNotificationProcessUsesSafeExecutableAndCommand(t *testing.T) {
	originalExecutable := notificationExecutable
	originalCommand := notificationCommand
	defer func() {
		notificationExecutable = originalExecutable
		notificationCommand = originalCommand
	}()
	notificationExecutable = func() (string, error) { return "", errors.New("executable unavailable") }
	if err := runNotificationProcess("generic://example.invalid", "test"); !errors.Is(err, store.ErrDeliveryProvider) {
		t.Fatalf("executable lookup error = %v, want provider error", err)
	}
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	notificationCommand = func(_ string, _ ...string) *exec.Cmd {
		return exec.Command("/bin/true")
	}
	if err := runNotificationProcess("generic://example.invalid", "test"); err != nil {
		t.Fatalf("successful isolated process = %v", err)
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
