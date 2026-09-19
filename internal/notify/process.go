package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
var notificationCommand = exec.Command

// runNotificationProcess executes provider code in a short-lived child. A
// provider panic can therefore terminate only this child instead of the
// daemon's notification worker or process. The caller already bounds the
// operation and converts child failures into a redacted delivery error.
func runNotificationProcess(rawURL, message string) error {
	executable, err := notificationExecutable()
	if err != nil {
		return errors.Join(store.ErrDeliveryProvider, err)
	}
	payload, err := json.Marshal(notificationProcessRequest{URL: rawURL, Message: message})
	if err != nil {
		return errors.Join(store.ErrDeliveryProvider, err)
	}
	command := notificationCommand(executable, "notify-send")
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.Join(store.ErrDeliveryProvider, errors.New("isolated notification provider failed"))
	}
	return nil
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
