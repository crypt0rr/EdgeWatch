package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestNaabuOptionHelpersRoundTripEveryField(t *testing.T) {
	values := config.NaabuOptions{Rate: 10, Workers: 11, Retries: 2, TimeoutMS: 500, WarmUpSeconds: 3, AddressBatchSize: 4}
	for _, tc := range []struct {
		field string
		value int
	}{
		{"rate", 101}, {"workers", 102}, {"retries", 5}, {"timeout_ms", 600}, {"warm_up_seconds", 7}, {"address_batch_size", 8}} {
		setNaabuOptionValue(&values, tc.field, tc.value)
		if got := naabuOptionValue(values, tc.field); got != tc.value || !naabuOptionSet(values, tc.field) {
			t.Errorf("%s helper round trip = %d/%t", tc.field, got, naabuOptionSet(values, tc.field))
		}
	}
	if naabuOptionValue(values, "scan_type") != 0 || naabuOptionSet(values, "scan_type") {
		t.Fatal("unknown option unexpectedly has a value")
	}
	setNaabuOptionValue(nil, "rate", 1)
	zero := config.NaabuOptions{RetriesSet: true, VerifySet: true}
	if !naabuOptionSet(zero, "retries") || naabuOptionSet(zero, "rate") || naabuOptionSet(zero, "unknown") {
		t.Fatalf("presence markers were not respected: %#v", zero)
	}
}

func TestScannerProfileJSONShapesAndCapabilities(t *testing.T) {
	profile := store.ScannerProfileRecord{ID: "profile-1", Name: "Ops", Description: "desc", BuiltIn: true, Revision: 2, Definition: config.BuiltinNmapProfile()}
	without := scannerProfileJSON(profile, false)
	if _, ok := without["definition"]; ok {
		t.Fatal("definition included in summary response")
	}
	with := scannerProfileJSON(profile, true)
	if _, ok := with["definition"]; !ok || with["id"] != "profile-1" || with["revision"] != int64(2) {
		t.Fatalf("profile JSON = %#v", with)
	}
	definition := scannerProfileDefinitionJSON(config.ScannerProfile{Engine: config.EngineNmap, NaabuArgs: []string{"-v"}})
	if definition["engine"] != config.EngineNmap || !reflect.DeepEqual(definition["naabu_args"], []string{"-v"}) {
		t.Fatalf("definition JSON = %#v", definition)
	}

	server, _, admin := newUsersTestServer(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scanner-capabilities", nil)
	server.scannerCapabilities(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", recorder.Code)
	}
	var capabilities map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if _, ok := capabilities["engines"]; !ok {
		t.Fatalf("capabilities response = %#v", capabilities)
	}
	// The route accepts the session argument for symmetry with other scanner
	// profile handlers; ensure a real profile listing can be serialized too.
	list := httptest.NewRecorder()
	server.scannerProfilesRoute(list, httptest.NewRequest(http.MethodGet, "/api/v1/scanner-profiles/", nil), admin, "")
	if list.Code != http.StatusOK {
		t.Fatalf("profile list status = %d: %s", list.Code, list.Body.String())
	}
}
