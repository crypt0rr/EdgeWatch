package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// perimeterCall sends a request with the content type and body through the
// API router as the actor, with its session and CSRF token.
func perimeterCall(t *testing.T, f *platformFixture, actor, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	account := f.sessions[actor]
	request := httptest.NewRequest(method, consoleAPIBase+path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: account.raw})
	request.Header.Set("X-CSRF-Token", account.session.CSRFToken)
	recorder := httptest.NewRecorder()
	f.server.api(recorder, request)
	return recorder
}

// perimeterDeclareBody returns the body of a declaration of the entries.
func perimeterDeclareBody(t *testing.T, entries ...store.PerimeterEntry) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"entries": entries})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// perimeterValues returns the kind and value of each of a unit's ranges.
func perimeterValues(t *testing.T, ts *store.TenantStore) []string {
	t.Helper()
	seeds, err := ts.ListPerimeterSeeds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	values := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		values = append(values, seed.Kind+" "+seed.Value)
	}
	return values
}

// Each perimeter route refuses a request without a session, and a change
// without the CSRF token, at the gate. Administrators read and change their
// own unit's perimeter, operators only read it, and viewers and platform
// administrators reach none of it. Unit B's administrator gets 404 for unit
// A's range, like an unknown one.
func TestPerimeterRoutesAnswerEachRole(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	declare := perimeterDeclareBody(t, store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.0/25", Label: "edge"})
	seedPath := "/perimeter/seeds/" + f.seedA
	for _, route := range []struct {
		method, path, body, permission string
		want                           map[string]int
	}{
		{http.MethodGet, "/perimeter", "", auth.PermissionPerimeterRead, map[string]int{actorAdminA: http.StatusOK, actorOperatorA: http.StatusOK, actorAdminB: http.StatusOK}},
		{http.MethodGet, seedPath, "", auth.PermissionPerimeterRead, map[string]int{actorAdminA: http.StatusOK, actorOperatorA: http.StatusOK, actorAdminB: http.StatusNotFound}},
		{http.MethodPost, "/perimeter/seeds", declare, auth.PermissionPerimeterManage, map[string]int{actorAdminA: http.StatusOK, actorAdminB: http.StatusOK}},
		{http.MethodDelete, seedPath, "", auth.PermissionPerimeterManage, map[string]int{actorAdminB: http.StatusNotFound, actorAdminA: http.StatusNoContent}},
	} {
		name := route.method + " " + route.path
		if response := serveRouteMatrixRequest(t, f.server.api, route.method, consoleAPIBase+route.path, nil, false, ""); response.status != http.StatusUnauthorized || response.code != "unauthorized" {
			t.Errorf("%s without a session = %d %s, want 401 unauthorized", name, response.status, response.body)
		}
		// Unit B's administrator asks for unit A's range before unit A's
		// administrator removes it.
		actors := []string{actorOperatorA, actorViewerA, actorAdminB, actorAdminA, actorPlatform}
		for _, actor := range actors {
			account := f.sessions[actor]
			if route.method != http.MethodGet {
				if response := serveRouteMatrixRequest(t, f.server.api, route.method, consoleAPIBase+route.path, &account, false, ""); response.status != http.StatusForbidden || response.code != "csrf" {
					t.Errorf("%s as %s without CSRF = %d %s, want 403 csrf", name, actor, response.status, response.body)
				}
			}
			response := f.call(t, actor, route.method, route.path, route.body)
			want, allowed := route.want[actor]
			if allowed != auth.HasPermission(account.session, route.permission) {
				t.Fatalf("%s: the test expects %s to hold %s = %t", name, actor, route.permission, allowed)
			}
			if !allowed {
				if details := expectError(t, response, http.StatusForbidden, "forbidden", name+" as "+actor); details["permission"] != route.permission {
					t.Errorf("%s as %s refused for %v, want %s", name, actor, details["permission"], route.permission)
				}
				continue
			}
			if response.Code != want {
				t.Errorf("%s as %s = %d %s, want %d", name, actor, response.Code, response.Body.String(), want)
			}
		}
	}
	if got := perimeterValues(t, f.a); !reflect.DeepEqual(got, []string{"prefix 203.0.113.0/25"}) {
		t.Fatalf("unit A's perimeter = %v", got)
	}
	if got := perimeterValues(t, f.b); !reflect.DeepEqual(got, []string{"prefix 198.51.100.0/24", "prefix 203.0.113.0/25"}) {
		t.Fatalf("unit B's perimeter = %v", got)
	}
}

// The report, a range's detail, a declaration and a removal answer with
// their documented bodies; an empty perimeter lists empty arrays, never
// null; a declaration and a removal are recorded in the unit's audit with
// their actor, who is also each new range's creator.
func TestPerimeterRoutesServeTheReport(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)

	response := f.call(t, actorAdminA, http.MethodGet, "/perimeter", "")
	var report app.PerimeterReport
	expectResponse(t, response, http.StatusOK, "report", &report)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("report Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	if len(report.Ranges) != 1 || report.Ranges[0].ID != f.seedA || report.Ranges[0].Value != "192.0.2.0/24" || report.Ranges[0].Label != "alpha-perimeter" || report.Ranges[0].CreatedBy != "alpha-admin" || report.Totals.Ranges != 1 {
		t.Fatalf("report ranges = %+v, totals %+v", report.Ranges, report.Totals)
	}
	if len(report.Monitors) != 1 || report.Monitors[0].JobID != f.jobA || report.Monitors[0].State != "covering" || !slices.Equal(report.Ranges[0].MonitorIDs, []string{f.jobA}) {
		t.Fatalf("report monitors = %+v", report.Monitors)
	}
	if report.Limits.MaxRanges != store.MaxPerimeterRanges || report.Limits.MaxEntriesPerRequest != store.MaxPerimeterEntriesPerRequest {
		t.Fatalf("report limits = %+v", report.Limits)
	}

	var detail app.PerimeterRangeDetail
	expectResponse(t, f.call(t, actorOperatorA, http.MethodGet, "/perimeter/seeds/"+f.seedA, ""), http.StatusOK, "range detail", &detail)
	if detail.Range.ID != f.seedA || len(detail.Monitors) != 1 || detail.Monitors[0].JobID != f.jobA || detail.AddressesPerMonitor.FullTCP == 0 || len(detail.Suggestions) == 0 {
		t.Fatalf("range detail = %+v", detail)
	}

	declared := f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t,
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.7/24", Label: "DC1 edge"},
		store.PerimeterEntry{Kind: store.PerimeterKindAuthorized, Value: "2001:db8::1"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "192.0.2.0/24"},
	))
	if declared.Code != http.StatusOK || declared.Body.String() != `{"created":2,"skipped":1}`+"\n" {
		t.Fatalf("declaration = %d %s", declared.Code, declared.Body.String())
	}
	if got := perimeterValues(t, f.a); !reflect.DeepEqual(got, []string{"prefix 192.0.2.0/24", "prefix 203.0.113.0/24", "authorized 2001:db8::1/128"}) {
		t.Fatalf("unit A's perimeter = %v", got)
	}
	// The declaration names the session's account in the audit and on each
	// range it created. The fixture's own declaration wrote an earlier
	// record for the same account.
	added := queryRows(t, f.db, `SELECT actor_username||'|'||actor_user_id FROM security_audit WHERE tenant_id='`+store.DefaultTenantID+`' AND action='perimeter.seeds_added' ORDER BY id DESC LIMIT 1`)
	if want := []string{"alpha-admin|" + f.users[actorAdminA].ID}; !reflect.DeepEqual(added, want) {
		t.Fatalf("declaration audit actor = %v, want %v", added, want)
	}

	seeds, err := f.a.ListPerimeterSeeds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range seeds {
		if (seed.Value == "203.0.113.0/24" || seed.Value == "2001:db8::1/128") && seed.CreatedBy != "alpha-admin" {
			t.Fatalf("%s created by %q, want alpha-admin", seed.Value, seed.CreatedBy)
		}
	}
	for _, seed := range seeds {
		removed := f.call(t, actorAdminA, http.MethodDelete, "/perimeter/seeds/"+seed.ID, "")
		if removed.Code != http.StatusNoContent || removed.Body.Len() != 0 {
			t.Fatalf("removal of %s = %d %q", seed.Value, removed.Code, removed.Body.String())
		}
	}
	actors := queryRows(t, f.db, `SELECT actor_username FROM security_audit WHERE tenant_id='`+store.DefaultTenantID+`' AND action='perimeter.seed_removed' ORDER BY id`)
	if !reflect.DeepEqual(actors, []string{"alpha-admin", "alpha-admin", "alpha-admin"}) {
		t.Fatalf("removal audit actors = %v", actors)
	}

	empty := f.call(t, actorAdminA, http.MethodGet, "/perimeter", "")
	expectResponse(t, empty, http.StatusOK, "empty report", nil)
	for _, list := range []string{`"ranges":[]`, `"outside":[]`, `"monitors":[]`} {
		if !strings.Contains(empty.Body.String(), list) {
			t.Errorf("empty report lacks %s: %s", list, empty.Body.String())
		}
	}
}

// Every refusal of a declaration answers with the documented envelope and
// writes nothing: the body errors of decodeJSON, unknown fields included,
// the entry count, the refused entries in details.entries, and the range
// limit. None of them sends a live update.
func TestDeclarePerimeterSeedsRefusals(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	updates, _ := registerSSEChannel(f.server, sseSubscriber{tenantID: store.DefaultTenantID})
	unchanged := func(step string, want ...string) {
		t.Helper()
		if got := perimeterValues(t, f.a); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: unit A's perimeter = %v, want %v", step, got, want)
		}
		if got := drainSSEChannel(updates); len(got) != 0 {
			t.Fatalf("%s sent live updates %q", step, got)
		}
	}
	valid := `{"entries":[{"kind":"prefix","value":"203.0.113.0/24"}]}`
	for _, test := range []struct {
		name, contentType, body string
		status                  int
		code, reason            string
	}{
		{"another content type", "text/plain", valid, http.StatusUnsupportedMediaType, "unsupported_media_type", ""},
		{"no content type", "", valid, http.StatusUnsupportedMediaType, "unsupported_media_type", ""},
		{"not JSON", "application/json", "entries=203.0.113.0/24", http.StatusBadRequest, "invalid_json", "malformed or unsupported JSON"},
		{"an empty body", "application/json", "", http.StatusBadRequest, "invalid_json", "request body is empty"},
		{"an unknown field", "application/json", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24"}],"confirm":true}`, http.StatusBadRequest, "invalid_json", "malformed or unsupported JSON"},
		{"an unknown entry field", "application/json", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24","source":"adopted"}]}`, http.StatusBadRequest, "invalid_json", "malformed or unsupported JSON"},
		{"trailing data", "application/json", valid + `{}`, http.StatusBadRequest, "invalid_json", "malformed or unsupported JSON"},
		{"a body over the limit", "application/json", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24","label":"` + strings.Repeat("a", 1<<20) + `"}]}`, http.StatusBadRequest, "invalid_json", "request body is too large"},
	} {
		response := perimeterCall(t, f, actorAdminA, http.MethodPost, "/perimeter/seeds", test.contentType, test.body)
		details := expectError(t, response, test.status, test.code, test.name)
		if test.reason != "" && details["reason"] != test.reason {
			t.Errorf("%s: reason = %v, want %q", test.name, details["reason"], test.reason)
		}
		unchanged(test.name, "prefix 192.0.2.0/24")
	}

	// The entry count.
	tooMany := make([]store.PerimeterEntry, store.MaxPerimeterEntriesPerRequest+1)
	for i := range tooMany {
		tooMany[i] = store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: fmt.Sprintf("10.9.%d.%d", i/256, i%256)}
	}
	const countRefusal = `{"error":{"code":"validation_failed","details":{"limit":256},"message":"Declare between 1 and 256 entries."}}` + "\n"
	for name, body := range map[string]string{"no entries key": `{}`, "null entries": `{"entries":null}`, "no entries": `{"entries":[]}`, "257 entries": perimeterDeclareBody(t, tooMany...)} {
		response := f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", body)
		if response.Code != http.StatusBadRequest || response.Body.String() != countRefusal {
			t.Errorf("%s = %d %s, want %s", name, response.Code, response.Body.String(), countRefusal)
		}
		unchanged(name, "prefix 192.0.2.0/24")
	}

	// Refused entries: every one is listed, in request order, and the valid
	// entry among them is not written either.
	long := strings.Repeat("x", 100)
	response := f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t,
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.0/24", Label: "valid"},
		store.PerimeterEntry{Kind: store.PerimeterKindASN, Value: "AS64500"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "edge.example.com"},
		store.PerimeterEntry{Kind: store.PerimeterKindAuthorized, Value: "192.0.2.0/24"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "fe80::1%eth0"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "10.0.0.0/7"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "::ffff:192.0.2.1"},
		store.PerimeterEntry{Kind: store.PerimeterKindAuthorized, Value: "203.0.113.9/24"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: long},
	))
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details struct {
				Entries []store.PerimeterLineError `json:"entries"`
			} `json:"details"`
		} `json:"error"`
	}
	expectResponse(t, response, http.StatusBadRequest, "refused entries", &envelope)
	want := []store.PerimeterLineError{
		{Index: 1, Value: "AS64500", Reason: "ASN declarations are not supported; declare the prefixes the ASN announces"},
		{Index: 2, Value: "edge.example.com", Reason: "not an IP address or CIDR prefix"},
		{Index: 3, Value: "192.0.2.0/24", Reason: "already declared as owned"},
		{Index: 4, Value: "fe80::1%eth0", Reason: "zones are not allowed"},
		{Index: 5, Value: "10.0.0.0/7", Reason: "IPv4 prefixes must be /8 or longer"},
		{Index: 6, Value: "::ffff:192.0.2.1", Reason: "write the IPv4 form"},
		{Index: 7, Value: "203.0.113.9/24", Reason: "already declared as owned"},
		{Index: 8, Value: long[:64], Reason: "not an IP address or CIDR prefix"},
	}
	if envelope.Error.Code != "validation_failed" || envelope.Error.Message == "" || !reflect.DeepEqual(envelope.Error.Details.Entries, want) {
		t.Fatalf("refused entries = %s", response.Body.String())
	}
	// The details hold only the entries, never the job form's field.
	var raw struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Error.Details["entries"]; !ok || len(raw.Error.Details) != 1 {
		t.Fatalf("refusal details = %v, want only entries", raw.Error.Details)
	}
	unchanged("refused entries", "prefix 192.0.2.0/24")

	// The range limit: the unit holds 1,024 ranges, so two new ones are
	// refused with the counts, and a declaration that only repeats a range
	// is accepted without a live update.
	for batch := range 4 {
		size := store.MaxPerimeterEntriesPerRequest
		if batch == 3 {
			size--
		}
		entries := make([]store.PerimeterEntry, size)
		for i := range entries {
			value := fmt.Sprintf("10.%d.%d.0/24", batch, i)
			entries[i] = store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: value}
		}
		response := f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t, entries...))
		if want := fmt.Sprintf(`{"created":%d,"skipped":0}`+"\n", size); response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("batch %d = %d %s, want %s", batch, response.Code, response.Body.String(), want)
		}
		if got := drainSSEChannel(updates); !slices.Equal(got, []string{`{"type":"perimeter.updated"}`}) {
			t.Fatalf("batch %d sent %q", batch, got)
		}
	}
	held := perimeterValues(t, f.a)
	if len(held) != store.MaxPerimeterRanges {
		t.Fatalf("unit A holds %d ranges, want %d", len(held), store.MaxPerimeterRanges)
	}
	response = f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t,
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.0/24"},
		store.PerimeterEntry{Kind: store.PerimeterKindAuthorized, Value: "2001:db8::/48"},
		store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "192.0.2.0/24"},
	))
	const limitRefusal = `{"error":{"code":"perimeter_limit","details":{"held":1024,"limit":1024,"new":2},"message":"A business unit holds at most 1024 perimeter ranges; nothing was saved."}}` + "\n"
	if response.Code != http.StatusBadRequest || response.Body.String() != limitRefusal {
		t.Fatalf("declaration over the limit = %d %s, want %s", response.Code, response.Body.String(), limitRefusal)
	}
	unchanged("declaration over the limit", held...)
	repeat := f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t, store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "192.0.2.7/24"}))
	if repeat.Code != http.StatusOK || repeat.Body.String() != `{"created":0,"skipped":1}`+"\n" {
		t.Fatalf("repeated range at the limit = %d %s", repeat.Code, repeat.Body.String())
	}
	unchanged("repeated range at the limit", held...)
}

// A declaration or removal whose audit record cannot be written answers 503
// audit_unavailable, like the job routes, keeps the store's message out of
// the response, stores nothing and sends no live update.
func TestPerimeterChangesFailWithoutTheirAuditRecord(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	updates, _ := registerSSEChannel(f.server, sseSubscriber{tenantID: store.DefaultTenantID})
	if _, err := f.db.DB.Exec(`CREATE TRIGGER fail_perimeter_audit BEFORE INSERT ON security_audit BEGIN SELECT RAISE(ABORT, 'sqlite audit detail'); END`); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path, body string }{
		{http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t, store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.0/24"})},
		{http.MethodDelete, "/perimeter/seeds/" + f.seedA, ""},
	} {
		name := request.method + " " + request.path
		response := f.call(t, actorAdminA, request.method, request.path, request.body)
		const want = `{"error":{"code":"audit_unavailable","details":null,"message":"the action was not committed because the security audit could not be recorded"}}` + "\n"
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != want {
			t.Errorf("%s = %d %s, want 503 %s", name, response.Code, response.Body.String(), want)
		}
		if strings.Contains(response.Body.String(), "sqlite") || strings.Contains(response.Body.String(), "203.0.113") {
			t.Errorf("%s response leaks the failure: %s", name, response.Body.String())
		}
	}
	if got := perimeterValues(t, f.a); !reflect.DeepEqual(got, []string{"prefix 192.0.2.0/24"}) {
		t.Fatalf("unit A's perimeter after the failed changes = %v", got)
	}
	if got := drainSSEChannel(updates); len(got) != 0 {
		t.Fatalf("failed changes sent live updates %q", got)
	}
}

// A range of another unit, an unknown range, and a range already removed
// get the same 404, byte for byte, which does not name the ID; a removal
// with another unit's ID removes nothing.
func TestPerimeterRangeNotFoundIsIdentical(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	removed, err := f.a.ListPerimeterSeeds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectResponse(t, f.call(t, actorAdminA, http.MethodPost, "/perimeter/seeds", perimeterDeclareBody(t, store.PerimeterEntry{Kind: store.PerimeterKindPrefix, Value: "203.0.113.0/24"})), http.StatusOK, "declaration", nil)
	declared := perimeterValues(t, f.a)
	expectResponse(t, f.call(t, actorAdminA, http.MethodDelete, "/perimeter/seeds/"+removed[0].ID, ""), http.StatusNoContent, "removal", nil)
	const want = `{"error":{"code":"not_found","details":null,"message":"perimeter range not found"}}` + "\n"
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		for _, id := range []string{f.seedB, unknownIsolationIDs.seed, removed[0].ID, "seed-1"} {
			for _, actor := range []string{actorAdminA, actorOperatorA} {
				if method == http.MethodDelete && actor == actorOperatorA {
					continue
				}
				response := f.call(t, actor, method, "/perimeter/seeds/"+id, "")
				if response.Code != http.StatusNotFound || response.Body.String() != want {
					t.Errorf("%s %s as %s = %d %s, want %s", method, id, actor, response.Code, response.Body.String(), want)
				}
			}
		}
	}
	if got := perimeterValues(t, f.b); !reflect.DeepEqual(got, []string{"prefix 198.51.100.0/24"}) {
		t.Fatalf("unit B's perimeter = %v", got)
	}
	if got := perimeterValues(t, f.a); !reflect.DeepEqual(got, declared[1:]) {
		t.Fatalf("unit A's perimeter = %v, want %v", got, declared[1:])
	}
}

// A declaration that created a range and a removal tell the unit's own
// streams, with a message that names no range. A declaration whose entries
// were all skipped, a refused one, and a removal that found nothing send
// nothing, and no other unit or the platform ever receives the message.
func TestPerimeterUpdatesReachOnlyTheUnit(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	streams := map[string]chan sseMessage{}
	for name, subscriber := range map[string]sseSubscriber{"unit A": {tenantID: store.DefaultTenantID}, "unit B": {tenantID: f.unitB}, "platform": {platform: true}} {
		streams[name], _ = registerSSEChannel(f.server, subscriber)
	}
	const update = `{"type":"perimeter.updated"}`
	for _, step := range []struct {
		name, actor, method, path, body string
		status                          int
		stream                          string
	}{
		{"new range", actorAdminA, http.MethodPost, "/perimeter/seeds", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24"}]}`, http.StatusOK, "unit A"},
		{"repeated range", actorAdminA, http.MethodPost, "/perimeter/seeds", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24"},{"kind":"prefix","value":"192.0.2.0/24"}]}`, http.StatusOK, ""},
		{"refused range", actorAdminA, http.MethodPost, "/perimeter/seeds", `{"entries":[{"kind":"authorized","value":"203.0.113.0/24"}]}`, http.StatusBadRequest, ""},
		{"removal of another unit's range", actorAdminA, http.MethodDelete, "/perimeter/seeds/" + f.seedB, "", http.StatusNotFound, ""},
		{"removal of an unknown range", actorAdminA, http.MethodDelete, "/perimeter/seeds/" + unknownIsolationIDs.seed, "", http.StatusNotFound, ""},
		{"removal", actorAdminA, http.MethodDelete, "/perimeter/seeds/" + f.seedA, "", http.StatusNoContent, "unit A"},
		{"unit B's new range", actorAdminB, http.MethodPost, "/perimeter/seeds", `{"entries":[{"kind":"authorized","value":"203.0.113.0/24"}]}`, http.StatusOK, "unit B"},
		{"unit B's removal", actorAdminB, http.MethodDelete, "/perimeter/seeds/" + f.seedB, "", http.StatusNoContent, "unit B"},
	} {
		expectResponse(t, f.call(t, step.actor, step.method, step.path, step.body), step.status, step.name, nil)
		for name, stream := range streams {
			var want []string
			if name == step.stream {
				want = []string{update}
			}
			if got := drainSSEChannel(stream); !slices.Equal(got, want) {
				t.Errorf("%s: %s's stream received %q, want %q", step.name, name, got, want)
			}
		}
	}
}

// A request whose probe budget or data cannot be read fails with the
// internal error and no partial report; so does a change that the store
// cannot make.
func TestPerimeterRoutesFailClosedOnStoreErrors(t *testing.T) {
	t.Parallel()
	f := newPlatformFixture(t)
	check := func(step string, recorder *httptest.ResponseRecorder, markers ...string) {
		t.Helper()
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		expectResponse(t, recorder, http.StatusInternalServerError, step, &envelope)
		if envelope.Error.Code != "store" || envelope.Error.Message != "internal server error" {
			t.Errorf("%s = %s", step, recorder.Body.String())
		}
		expectNoMarkers(t, recorder.Body.String(), step, append(markers, "perimeter_seeds", "sqlite")...)
	}

	// A unit whose capacity cannot be read has no probe budget. The gate
	// refuses the sessions of a deleted unit, so the handlers are called
	// directly.
	if _, err := f.db.DB.Exec(`UPDATE tenants SET state=? WHERE id=?`, store.TenantStateDeleted, f.unitB); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	f.server.perimeterOverview(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/perimeter", nil), f.b)
	check("report without a probe budget", recorder, "bravo", "198.51.100", f.seedB, f.jobB)
	recorder = httptest.NewRecorder()
	f.server.perimeterRangeDetail(recorder, httptest.NewRequest(http.MethodGet, consoleAPIBase+"/perimeter/seeds/"+f.seedB, nil), f.b, f.seedB)
	check("detail without a probe budget", recorder, "bravo", "198.51.100", f.seedB, f.jobB)

	// Without its table, every route fails, and none answers as if the
	// range did not exist.
	if _, err := f.db.DB.Exec(`DROP TABLE perimeter_seeds`); err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, path, body string }{
		{http.MethodGet, "/perimeter", ""},
		{http.MethodGet, "/perimeter/seeds/" + f.seedA, ""},
		{http.MethodPost, "/perimeter/seeds", `{"entries":[{"kind":"prefix","value":"203.0.113.0/24"}]}`},
		{http.MethodDelete, "/perimeter/seeds/" + f.seedA, ""},
	} {
		check(request.method+" "+request.path+" without the table", f.call(t, actorAdminA, request.method, request.path, request.body), "alpha", "192.0.2", f.jobA)
	}
}

// The public status pages publish no perimeter data, although both units
// declare the ranges that hold their published hosts.
func TestPublicStatusCarriesNoPerimeterData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newPublicTenantFixture(t)
	var ids []string
	for _, ts := range []*store.TenantStore{defaultTenantStore(f.server), f.db.Tenant(f.scopeB)} {
		entries := []store.PerimeterEntry{{Kind: store.PerimeterKindPrefix, Value: "198.51.100.0/24", Label: "perimeter-label"}, {Kind: store.PerimeterKindAuthorized, Value: "8.8.8.0/24", Label: "perimeter-label"}}
		if _, err := ts.DeclarePerimeterSeeds(ctx, entries, store.AuditEntry{ActorUsername: "perimeter-actor"}); err != nil {
			t.Fatal(err)
		}
		seeds, err := ts.ListPerimeterSeeds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, seed := range seeds {
			ids = append(ids, seed.ID)
		}
	}
	scopeB, err := f.db.PublicScopeBySlug(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	pageA := f.getPublicPage(store.DefaultPublicScope(), "198.51.100.70:1000")
	if pageA.Code != http.StatusOK || pageA.Body.String() != publicTenantAPage {
		t.Fatalf("default page = %d:\n%s\nwant\n%s", pageA.Code, pageA.Body.String(), publicTenantAPage)
	}
	pageB := f.getPublicPage(scopeB, "198.51.100.71:1000")
	wantB := strings.NewReplacer("Tenant A status", "Tenant B status", `"introduction":"A"`, `"introduction":"B"`, `"port":443,"service":"https"`, `"port":22,"service":"ssh"`, `"port":443`, `"port":22`).Replace(publicTenantAPage)
	if pageB.Code != http.StatusOK || pageB.Body.String() != wantB {
		t.Fatalf("tenant B's page = %d:\n%s\nwant\n%s", pageB.Code, pageB.Body.String(), wantB)
	}
	expectNoMarkers(t, pageA.Body.String()+pageB.Body.String(), "public pages", append(ids, "perimeter", "198.51.100.0/24", "8.8.8.0/24")...)
}
