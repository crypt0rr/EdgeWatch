package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/notify"
)

func TestNotificationProviderConfigUsesEncryptedWriteOnlyDestination(t *testing.T) {
	t.Parallel()
	server, _, admin := newUsersTestServer(t)
	createBody := `{"name":"Push alerts","config":{"provider":"ntfy","fields":{"topic":"edgewatch-alerts","username":"operator","password":"provider-secret"}},"password":"administrator password"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/destinations", strings.NewReader(createBody))
	request.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	server.createNotificationDestination(created, request, admin, defaultTenantStore(server))
	expectResponse(t, created, http.StatusCreated, "create provider destination", nil)
	expectNoMarkers(t, created.Body.String(), "create response", "provider-secret", "edgewatch-alerts", "url", "password")
	if !strings.Contains(created.Body.String(), `"provider":"ntfy"`) {
		t.Fatalf("create response omitted provider metadata: %s", created.Body.String())
	}

	var view struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil || view.ID == "" || view.Revision != 1 {
		t.Fatalf("created destination = %s (%v)", created.Body.String(), err)
	}
	record, err := defaultTenantStore(server).GetManagedNotification(context.Background(), view.ID)
	if err != nil {
		t.Fatal("load encrypted destination:", err)
	}
	if strings.Contains(string(record.Ciphertext), "provider-secret") || strings.Contains(string(record.Ciphertext), "edgewatch-alerts") {
		t.Fatal("provider credentials were stored in plaintext")
	}

	updateBody := `{"name":"Push alerts","revision":1,"config":{"provider":"ntfy","fields":{"topic":"new-alerts","username":"operator","password":"replacement-secret"}},"password":"administrator password"}`
	updateRequest := httptest.NewRequest(http.MethodPut, "/api/v1/notifications/destinations/"+view.ID, strings.NewReader(updateBody))
	updateRequest.Header.Set("Content-Type", "application/json")
	updated := httptest.NewRecorder()
	server.updateNotificationDestination(updated, updateRequest, admin, defaultTenantStore(server), view.ID)
	expectResponse(t, updated, http.StatusOK, "replace provider credentials", nil)
	expectNoMarkers(t, updated.Body.String(), "update response", "replacement-secret", "new-alerts", "url", "password")
	if !strings.Contains(updated.Body.String(), `"revision":2`) || !strings.Contains(updated.Body.String(), `"provider":"ntfy"`) {
		t.Fatalf("updated destination metadata = %s", updated.Body.String())
	}
}

func TestNotificationDestinationURLRejectsConflictingCredentialInputs(t *testing.T) {
	t.Parallel()
	rawURL := "generic://example.test/alerts?disabletls=yes"
	config := &notify.ProviderConfig{Provider: "ntfy", Fields: map[string]string{"topic": "alerts"}}
	_, err := notificationDestinationURL(&rawURL, config, true)
	if err == nil || err.Error() != "notification provider configuration is invalid" {
		t.Fatalf("conflicting credential inputs error = %v", err)
	}
	if _, err := notificationDestinationURL(nil, nil, true); err == nil || err.Error() != "notification URL is required" {
		t.Fatalf("missing credential input error = %v", err)
	}
	if value, err := notificationDestinationURL(nil, nil, false); err != nil || value != nil {
		t.Fatalf("omitted update credentials = %v, %v; want preserve existing", value, err)
	}
}

func TestPlatformNotificationProviderConfigUsesEncryptedWriteOnlyDestination(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	body := confirmBody(`"name":"Platform push","config":{"provider":"ntfy","fields":{"topic":"platform-alerts","password":"platform-provider-secret"}}`)
	created := f.call(t, actorPlatform, http.MethodPost, "/platform/notifications", body)
	expectResponse(t, created, http.StatusCreated, "create platform provider destination", nil)
	expectNoMarkers(t, created.Body.String(), "platform create response", "platform-provider-secret", "platform-alerts")
	if !strings.Contains(created.Body.String(), `"provider":"ntfy"`) {
		t.Fatalf("platform create response omitted provider metadata: %s", created.Body.String())
	}
	var view struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &view); err != nil || view.ID == "" {
		t.Fatalf("created platform destination = %s (%v)", created.Body.String(), err)
	}
	record, err := f.db.System().GetManagedNotification(context.Background(), view.ID)
	if err != nil {
		t.Fatal("load encrypted platform destination:", err)
	}
	if strings.Contains(string(record.Ciphertext), "platform-provider-secret") || strings.Contains(string(record.Ciphertext), "platform-alerts") {
		t.Fatal("platform provider credentials were stored in plaintext")
	}
	updateBody := confirmBody(`"revision":1,"name":"Platform push","config":{"provider":"ntfy","fields":{"topic":"platform-replacement-alerts","password":"platform-replacement-secret"}}`)
	updated := f.call(t, actorPlatform, http.MethodPatch, "/platform/notifications/"+view.ID, updateBody)
	expectResponse(t, updated, http.StatusOK, "replace platform provider configuration", nil)
	expectNoMarkers(t, updated.Body.String(), "platform update response", "platform-replacement-secret", "platform-replacement-alerts")
	record, err = f.db.System().GetManagedNotification(context.Background(), view.ID)
	if err != nil {
		t.Fatal("load updated encrypted platform destination:", err)
	}
	if strings.Contains(string(record.Ciphertext), "platform-replacement-secret") || strings.Contains(string(record.Ciphertext), "platform-replacement-alerts") {
		t.Fatal("updated platform provider credentials were stored in plaintext")
	}
}
