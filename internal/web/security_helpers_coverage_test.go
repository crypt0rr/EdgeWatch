package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestWriteSecurityMutationErrorUsesStableContracts(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		status      int
		code        string
		message     string
		fallback    string
		fallbackMsg string
	}{
		{name: "totp locked", err: store.ErrTOTPSecretLocked, status: http.StatusServiceUnavailable, code: "totp_locked"},
		{name: "conflict", err: store.ErrConflict, status: http.StatusConflict, code: "conflict"},
		{name: "last administrator", err: store.ErrLastAdministrator, status: http.StatusBadRequest, code: "last_admin"},
		{name: "missing", err: store.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "fallback defaults", err: errors.New("sqlite leaked details"), status: http.StatusInternalServerError, code: "save_failed"},
		{name: "fallback custom", err: errors.New("unexpected"), status: http.StatusInternalServerError, code: "custom", fallback: "custom", fallbackMsg: "safe message"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeSecurityMutationError(recorder, tt.err, tt.fallback, tt.fallbackMsg)
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.status)
			}
			var payload struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error.Code != tt.code {
				t.Fatalf("error code = %q, want %q", payload.Error.Code, tt.code)
			}
			if strings.Contains(recorder.Body.String(), "sqlite leaked") || strings.Contains(recorder.Body.String(), "unexpected") {
				t.Fatalf("storage detail leaked in response: %s", recorder.Body.String())
			}
			if tt.fallback != "" && payload.Error.Message != tt.fallbackMsg {
				t.Fatalf("custom fallback message = %q, want %q", payload.Error.Message, tt.fallbackMsg)
			}
		})
	}
}

func TestSecurityScopeSummaryHelpersCoverScannerAndProtocolChanges(t *testing.T) {
	if !sameStringMap(map[string]string{"a": "1"}, map[string]string{"a": "1"}) {
		t.Fatal("equal string maps were not recognized")
	}
	if sameStringMap(map[string]string{"a": "1"}, map[string]string{"a": "2"}) || sameStringMap(map[string]string{"a": "1"}, nil) {
		t.Fatal("different string maps were treated as equal")
	}
	if nseSummary(nil) != "disabled" || nseSummary(&config.Protocol{NSEProfile: "  "}) != "disabled" || nseSummary(&config.Protocol{NSEProfile: "banner"}) != "banner" {
		t.Fatal("NSE summary did not normalize empty and enabled profiles")
	}
	if naabuSecuritySummary(nil) != "disabled" || naabuSecuritySummary(&config.Protocol{}) != "disabled" || naabuSecuritySummary(&config.Protocol{Naabu: &config.NaabuOptions{ScanType: "connect", Verify: true}}) != "connect (verify=true)" {
		t.Fatal("Naabu summary did not cover disabled and enabled states")
	}

	old := config.Job{
		Targets: []string{"198.51.100.10"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "connect", ServiceDetection: false, NSEProfile: "banner", Naabu: &config.NaabuOptions{ScanType: "connect", Verify: false, VerifySet: true}},
		UDP:     &config.Protocol{Ports: "53", ServiceDetection: false},
	}
	next := config.Job{
		Targets: []string{"198.51.100.11"},
		TCP:     &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Mode: "syn", ServiceDetection: true, NSEProfile: "http-title", Naabu: &config.NaabuOptions{ScanType: "syn", Verify: true}},
		UDP:     &config.Protocol{Ports: "53,123", ServiceDetection: true},
	}
	changes := securityScopeChanges(old, next)
	for _, want := range []string{"targets:", "TCP mode:", "TCP service detection:", "TCP NSE:", "TCP discovery mode:", "TCP discovery verification:", "UDP ports:", "UDP service detection:"} {
		found := false
		for _, change := range changes {
			if strings.Contains(change, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("scope changes missing %q: %#v", want, changes)
		}
	}
}
