package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRunSendChildRejectsMalformedRequest(t *testing.T) {
	if err := RunSendChild(strings.NewReader("{")); err == nil {
		t.Fatal("malformed child request was accepted")
	}
	if err := RunSendChild(strings.NewReader(`{"message":"missing URL"}`)); err == nil {
		t.Fatal("child request without a URL was accepted")
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
