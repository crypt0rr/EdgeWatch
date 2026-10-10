package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// A unit's stream receives its own unit's messages and those for everyone;
// a platform stream the platform's and those for everyone. A platform
// stream never receives a unit's message, a unit's stream never another
// unit's or the platform's, and no stream a message without an audience.
func TestSSEAudiencesSeparateUnitsAndThePlatform(t *testing.T) {
	t.Parallel()
	const unitA, unitB = store.DefaultTenantID, tenantAccountsOtherID
	subscribers := map[string]sseSubscriber{
		"unit A":   {tenantID: unitA},
		"unit B":   {tenantID: unitB},
		"platform": {platform: true},
		"none":     {},
	}
	audiences := map[string]sseAudience{
		"everyone": audienceEveryone(),
		"unit A":   audienceUnit(unitA),
		"unit B":   audienceUnit(" " + unitB + " "),
		"platform": audiencePlatform(),
		"empty":    {},
		"blank":    audienceUnit("  "),
		"no store": audienceTenant(nil),
	}
	want := map[string][]string{
		"unit A":   {"everyone", "unit A"},
		"unit B":   {"everyone", "unit B"},
		"platform": {"everyone", "platform"},
		"none":     {"everyone"},
	}
	for subscriberName, subscriber := range subscribers {
		for audienceName, audience := range audiences {
			if got, expected := subscriber.matches(audience), slices.Contains(want[subscriberName], audienceName); got != expected {
				t.Errorf("%s stream matches the %s audience = %t, want %t", subscriberName, audienceName, got, expected)
			}
		}
	}
	for name, audience := range audiences {
		if valid := !slices.Contains([]string{"empty", "blank", "no store"}, name); audience.valid() != valid {
			t.Errorf("%s audience valid = %t, want %t", name, audience.valid(), valid)
		}
	}
	// Resolving a store's audience reads only its scope, not the database.
	db := new(store.Store)
	if got := audienceTenant(defaultTenant(db)); got != audienceUnit(unitA) {
		t.Fatalf("default tenant store audience = %+v", got)
	}
	if got := audienceTenant(db.Tenant(store.TenantScope{})); got.valid() {
		t.Fatalf("a store without a tenant addresses %+v", got)
	}
}

// An application event that names a unit goes to that unit; a job's event
// without a unit is dropped; the update status goes to everyone; any other
// event without a job or a unit, such as the platform's copy of an update
// alert, goes to the platform.
func TestAppEventAudience(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		event model.Event
		want  sseAudience
	}{
		{"unit job event", model.Event{Type: "scan.completed", JobID: "job", TenantID: tenantAccountsOtherID}, audienceUnit(tenantAccountsOtherID)},
		{"job event without a unit", model.Event{Type: "scan.completed", JobID: "job"}, sseAudience{}},
		{"unit copy of an update alert", model.Event{Type: "application-update-available", TenantID: store.DefaultTenantID}, audienceUnit(store.DefaultTenantID)},
		{"platform copy of an update alert", model.Event{Type: "application-update-available"}, audiencePlatform()},
		{"update status", model.Event{Type: "application.update_status"}, audienceEveryone()},
		{"unknown event without a job or unit", model.Event{Type: "future"}, audiencePlatform()},
	} {
		if got := appEventAudience(test.event); got != test.want {
			t.Errorf("%s: audience = %+v, want %+v", test.name, got, test.want)
		}
	}
}

// drainSSEChannel returns the messages queued on a subscriber channel.
func drainSSEChannel(ch chan sseMessage) []string {
	var payloads []string
	for {
		select {
		case message := <-ch:
			payloads = append(payloads, string(message.payload))
		default:
			return payloads
		}
	}
}

// registerSSEChannel registers a bare subscriber channel with an identity,
// as a stream does, and returns it with the number of times its stream was
// cancelled.
func registerSSEChannel(server *Server, subscriber sseSubscriber) (chan sseMessage, *int) {
	ch := make(chan sseMessage, 64)
	cancelled := new(int)
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.sseIdentity == nil {
		server.sseIdentity = map[chan sseMessage]sseSubscriber{}
	}
	server.subscribers[ch] = struct{}{}
	server.sseIdentity[ch] = subscriber
	server.sseCancels[ch] = func() { *cancelled++ }
	return ch, cancelled
}

// Each unit's stream receives its own copy of an update alert, and the
// platform's stream the platform's copy; the update status reaches all of
// them. A job's event that names no unit reaches none of them.
func TestUpdateAlertCopiesReachOnlyTheirOwners(t *testing.T) {
	t.Parallel()
	f := newTenantAccountsFixture(t)
	var logs bytes.Buffer
	f.server.Log = slog.New(slog.NewTextHandler(&logs, nil))
	streamA := f.openLiveStream(t, "own", 0)
	streamB := f.openLiveStream(t, "other", 0)
	platform, _ := registerSSEChannel(f.server, sseSubscriber{platform: true})
	alert := func(message, tenantID string) model.Event {
		return model.Event{Type: "application-update-available", Message: message, PreviousVersion: "v1.0.0", CurrentVersion: "v1.1.0", LatestVersion: "v9.9.9", ReleaseURL: "https://example.invalid/v9.9.9", TenantID: tenantID}
	}
	// The application publishes the copies in this order; see
	// App.emitUpdateAlert.
	f.server.publishAppEvent(alert("platform copy", ""))
	f.server.publishAppEvent(alert("copy of unit A", store.DefaultTenantID))
	f.server.publishAppEvent(alert("copy of unit B", tenantAccountsOtherID))
	f.server.publishAppEvent(model.Event{Type: "scan.completed", JobID: "job-without-unit", Message: "no unit"})
	f.server.publishAppEvent(model.Event{Type: "application.update_status", Message: "Application update status changed"})
	for name, test := range map[string]struct {
		stream *liveStream
		copy   string
	}{"unit A": {streamA, "copy of unit A"}, "unit B": {streamB, "copy of unit B"}} {
		waitForSSEBody(t, test.stream.writer, "application.update_status")
		events := test.stream.events(t)
		if len(events) != 2 || events[1]["type"] != "application.update_status" {
			t.Errorf("%s's stream received %v, want its own copy and the update status: %s", name, test.stream.eventTypes(t), test.stream.body())
			continue
		}
		// The payload is the one every stream received before audiences.
		want := map[string]any{"type": "application-update-available", "job_id": "", "job": "", "scan_id": "", "message": test.copy, "previous_version": "v1.0.0", "current_version": "v1.1.0", "latest_version": "v9.9.9", "release_url": "https://example.invalid/v9.9.9"}
		if !reflect.DeepEqual(events[0], want) {
			t.Errorf("%s's copy = %v, want %v", name, events[0], want)
		}
	}
	got := drainSSEChannel(platform)
	if len(got) != 2 || !strings.Contains(got[0], "platform copy") || !strings.Contains(got[1], "application.update_status") {
		t.Fatalf("platform stream received %q, want the platform's copy and the update status", got)
	}
	if !strings.Contains(logs.String(), "live update dropped because it has no audience") || strings.Contains(logs.String(), "job-without-unit") {
		t.Fatalf("the job event without a unit was not dropped as such: %s", logs.String())
	}
}

// A platform administrator holds no stream permission, so the console
// offers it no live updates and the API router refuses its /stream request
// (see TestRouteInventoryDeniesPlatformAdministratorsUnitData). Were its
// session to reach the handler, the stream would register as the
// platform's, receive none of a unit's messages, and end at the first
// platform message without writing it. A session with neither a unit nor
// the platform role is refused before it registers.
func TestPlatformAdministratorsStayOffTheLiveUpdateStream(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	if auth.HasPermission(store.Session{Role: store.RolePlatformAdmin}, auth.PermissionStreamRead) {
		t.Fatal("platform administrators hold the stream permission")
	}
	if subscriber, ok := streamSubscriber(store.Session{Role: store.RolePlatformAdmin}, nil); !ok || subscriber != (sseSubscriber{platform: true}) {
		t.Fatalf("platform subscriber = %+v, %t", subscriber, ok)
	}
	if _, ok := streamSubscriber(store.Session{Role: store.RolePlatformAdmin}, defaultTenantStore(server)); ok {
		t.Fatal("a platform administrator's stream took a unit's store")
	}
	if subscriber, ok := streamSubscriber(store.Session{Role: store.RoleViewer}, defaultTenantStore(server)); !ok || subscriber != (sseSubscriber{tenantID: store.DefaultTenantID}) {
		t.Fatalf("unit subscriber = %+v, %t", subscriber, ok)
	}

	refused := httptest.NewRecorder()
	server.stream(refused, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil), store.Session{IDHash: "unitless", UserID: "unitless", Role: store.RoleViewer}, nil)
	if refused.Code != http.StatusForbidden || !strings.Contains(refused.Body.String(), `"forbidden"`) || refused.Header().Get("Content-Type") == "text/event-stream" {
		t.Fatalf("stream without a unit = %d %q: %s", refused.Code, refused.Header().Get("Content-Type"), refused.Body.String())
	}
	waitForSSESubscribers(t, server, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &deadlineTrackingWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.stream(writer, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(ctx), store.Session{IDHash: "platform-session", UserID: "platform", Role: store.RolePlatformAdmin}, nil)
	}()
	waitForSSEBody(t, writer, ": connected")
	server.mu.Lock()
	identities := make([]sseSubscriber, 0, len(server.sseIdentity))
	for _, identity := range server.sseIdentity {
		identities = append(identities, identity)
	}
	server.mu.Unlock()
	if len(identities) != 1 || identities[0] != (sseSubscriber{platform: true}) {
		t.Fatalf("stream identities = %+v, want one platform stream", identities)
	}
	server.broadcastTo(ctx, audienceUnit(store.DefaultTenantID), map[string]any{"type": "job.created", "job_id": "unit-job"})
	server.broadcastTo(ctx, audiencePlatform(), map[string]any{"type": "platform.notice", "token": "platform-only"})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the platform stream stayed open without a stream permission")
	}
	writer.mu.Lock()
	body := writer.body.String()
	writer.mu.Unlock()
	if strings.Contains(body, "unit-job") || strings.Contains(body, "platform-only") {
		t.Fatalf("platform stream wrote %s", body)
	}
}

// Once more than one unit exists, each unit has its own share of the live
// streams. Unit B reaching its share is refused in band, with the stream
// limit backoff, while unit A still opens streams up to its own share. A
// closed stream frees its place in the share.
func TestEachBusinessUnitHasItsOwnLiveStreamLimit(t *testing.T) {
	t.Parallel()
	f := newTenantAccountsFixture(t)
	f.server.sseMaxSubscribersPerUnit = 2
	f.server.sseMaxSubscribersPerUser = 10
	first := f.openLiveStream(t, "other", 0)
	f.openLiveStream(t, "other", 0)
	refusedB := f.startLiveStream(t, "other", 0)
	if !refusedB.ended(2*time.Second) || !strings.Contains(refusedB.body(), `"type":"stream_limit","reason":"too many live streams for this business unit"`) || refusedB.writer.header.Get("Retry-After") != "5" {
		t.Fatalf("unit B's stream over its share = %q, Retry-After %q", refusedB.body(), refusedB.writer.header.Get("Retry-After"))
	}
	streamA := f.openLiveStream(t, "own", 0)
	operatorA := f.openLiveStream(t, "operator", 0)
	refusedA := f.startLiveStream(t, "operator", 0)
	if !refusedA.ended(2*time.Second) || !strings.Contains(refusedA.body(), "too many live streams for this business unit") {
		t.Fatalf("unit A's stream over its share = %q", refusedA.body())
	}
	waitForSSESubscribers(t, f.server, 4)
	jobA := createdID(t, "unit A's job", f.call("own", http.MethodPost, "/api/v1/jobs", unitJobBody))
	waitForSSEBody(t, streamA.writer, jobA)
	waitForSSEBody(t, operatorA.writer, jobA)

	first.close(t)
	waitForSSESubscribers(t, f.server, 3)
	f.openLiveStream(t, "other", 0)
	waitForSSESubscribers(t, f.server, 4)
}

// With a single unit, only the deployment-wide stream limit applies, as
// before business units existed. The unit share applies whenever the units
// cannot be counted.
func TestASingleUnitHasNoLiveStreamShareOfItsOwn(t *testing.T) {
	t.Parallel()
	server, db, _ := newUsersTestServer(t)
	server.sseMaxSubscribersPerUnit = 1
	server.sseMaxSubscribersPerUser = 10
	server.sseMaxSubscribers = 3
	for _, user := range []string{"user-a", "user-b", "user-c"} {
		cancel, done := startTestSSEStream(server, store.Session{IDHash: "session-" + user, UserID: user})
		t.Cleanup(func() {
			cancel()
			<-done
		})
	}
	waitForSSESubscribers(t, server, 3)
	limited := &deadlineTrackingWriter{header: make(http.Header)}
	server.stream(limited, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil), store.Session{IDHash: "session-d", UserID: "user-d"}, defaultTenantStore(server))
	if !strings.Contains(limited.body.String(), `"reason":"too many live streams"`) {
		t.Fatalf("a single unit's stream over the deployment-wide limit = %q", limited.body.String())
	}

	ctx := context.Background()
	if got := server.sseUnitStreamLimit(ctx); got != 0 {
		t.Fatalf("single unit share = %d, want none", got)
	}
	server.sseMaxSubscribersPerUnit = 0
	if got := (&Server{}).sseUnitStreamLimit(ctx); got != defaultMaxSSESubscribersPerUnit {
		t.Fatalf("share without a store = %d, want %d", got, defaultMaxSSESubscribersPerUnit)
	}
	_ = db.Close()
	if got := server.sseUnitStreamLimit(ctx); got != defaultMaxSSESubscribersPerUnit {
		t.Fatalf("share when the units cannot be counted = %d, want %d", got, defaultMaxSSESubscribersPerUnit)
	}
}

// revokeSSETenant cancels exactly the named unit's streams and drops the
// cached authorization of its sessions. The other unit's streams, the
// platform's, and their cached authorization are kept; an empty unit
// revokes nothing.
func TestRevokeSSETenantCancelsOnlyThatUnitsStreams(t *testing.T) {
	t.Parallel()
	server, _, _ := newUsersTestServer(t)
	_, cancelledA := registerSSEChannel(server, sseSubscriber{tenantID: store.DefaultTenantID})
	_, cancelledB := registerSSEChannel(server, sseSubscriber{tenantID: tenantAccountsOtherID})
	_, cancelledB2 := registerSSEChannel(server, sseSubscriber{tenantID: tenantAccountsOtherID})
	_, cancelledPlatform := registerSSEChannel(server, sseSubscriber{platform: true})
	server.sseAuthCache = map[string]sseAuthCacheEntry{
		"session:a":        {session: store.Session{IDHash: "a", TenantID: store.DefaultTenantID}},
		"session:b":        {session: store.Session{IDHash: "b", TenantID: tenantAccountsOtherID}},
		"session:platform": {session: store.Session{IDHash: "platform", Role: store.RolePlatformAdmin}},
	}
	server.revokeSSETenant("  ")
	if *cancelledA+*cancelledB+*cancelledB2+*cancelledPlatform != 0 || len(server.sseAuthCache) != 3 {
		t.Fatal("an empty unit revoked streams")
	}
	server.revokeSSETenant(tenantAccountsOtherID)
	if *cancelledA != 0 || *cancelledB != 1 || *cancelledB2 != 1 || *cancelledPlatform != 0 {
		t.Fatalf("cancelled streams: A %d, B %d and %d, platform %d", *cancelledA, *cancelledB, *cancelledB2, *cancelledPlatform)
	}
	if _, ok := server.sseAuthCache["session:b"]; ok || len(server.sseAuthCache) != 2 {
		t.Fatalf("cached authorization after the revocation = %+v", server.sseAuthCache)
	}
}

// With a single unit, every live update still reaches the unit's streams:
// its writes, the application's scan events, the unit's copy of an update
// alert (the platform's copy goes to the platform), and the update status.
func TestASingleUnitsStreamReceivesEveryLiveUpdate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, _, _ := newUsersTestServer(t)
	raw, _, err := server.Auth.LoginAs(ctx, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "admin", "administrator password", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f := tenantAccountsFixture{server: server, db: server.Store, cookies: map[string]string{"admin": raw}}
	stream := f.openLiveStream(t, "admin", 0)
	account := routeMatrixSession{raw: raw}
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: raw})
	if account.session, _ = server.Auth.AuthenticateReadOnly(ctx, probe); account.session.CSRFToken == "" {
		t.Fatal("session was not authenticated")
	}
	jobID := createdID(t, "job", callAPI(t, server, account, http.MethodPost, "/jobs", unitJobBody))
	server.App.Scanner = &sequenceScanner{snapshots: []model.Snapshot{{Scopes: []model.Scope{{Target: "127.0.0.1", Protocol: "tcp", Ports: "1-2"}}, Units: []model.Unit{{Target: "127.0.0.1", Protocol: "tcp", Ports: []model.PortState{{Port: 1, State: "open"}}}}}}}
	record, err := defaultTenantStore(server).GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if scan, _, err := server.App.RunJobRecord(ctx, record); err != nil || scan.Status != "success" {
		t.Fatalf("scan = %+v, %v", scan, err)
	}
	server.publishAppEvent(model.Event{Type: "application-update-available", Message: "platform copy"})
	server.publishAppEvent(model.Event{Type: "application-update-available", Message: "unit copy", TenantID: store.DefaultTenantID})
	server.publishAppEvent(model.Event{Type: "application.update_status"})
	waitForSSEBody(t, stream.writer, "application.update_status")
	want := []string{"job.created", "scan.started", "baseline-complete", "scan.completed", "application-update-available", "application.update_status"}
	if got := stream.eventTypes(t); !slices.Equal(got, want) {
		t.Fatalf("single unit stream received %v, want %v", got, want)
	}
	if strings.Contains(stream.body(), "platform copy") || !strings.Contains(stream.body(), "unit copy") {
		t.Fatalf("single unit stream received the wrong update alert copy: %s", stream.body())
	}
}

// With six active units, each unit's share is a sixth of the deployment's
// streams. Four units holding their whole share leave units 5 and 6 room for
// theirs, the deployment-wide limit still holds, and a unit over its share
// is refused in band. When units are added, the smaller share applies to new
// streams; the streams already open are kept.
func TestLiveStreamSharesFitTheActiveUnits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server, db, _ := newUsersTestServer(t)
	server.sseMaxSubscribers = 24
	server.sseMaxSubscribersPerUser = 2
	server.sseMaxSubscribersPerUnit = 10
	units := []*store.TenantStore{defaultTenantStore(server)}
	for index := 2; index <= 6; index++ {
		record, err := db.Platform().CreateTenant(ctx, fmt.Sprintf("Unit %d", index), fmt.Sprintf("unit-%d", index), store.AuditEntry{ActorKind: store.AuditActorHost})
		if err != nil {
			t.Fatal(err)
		}
		scope, err := db.TenantScopeByID(ctx, record.ID)
		if err != nil {
			t.Fatal(err)
		}
		units = append(units, db.Tenant(scope))
	}
	if got := server.sseUnitStreamLimit(ctx); got != 4 {
		t.Fatalf("share of six units in 24 streams = %d, want 4", got)
	}
	opened := 0
	var closers [][]func()
	open := func(unit int, wantLimit string) {
		t.Helper()
		user := fmt.Sprintf("unit-%d-user-%d", unit, opened)
		streamCtx, cancel := context.WithCancel(ctx)
		writer := &deadlineTrackingWriter{header: make(http.Header)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			server.stream(writer, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil).WithContext(streamCtx), store.Session{IDHash: "session-" + user, UserID: user, Role: store.RoleViewer}, units[unit-1])
		}()
		closeStream := func() {
			cancel()
			<-done
		}
		t.Cleanup(closeStream)
		if wantLimit != "" {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("unit %d's stream over the limit stayed open", unit)
			}
			writer.mu.Lock()
			body := writer.body.String()
			writer.mu.Unlock()
			if !strings.Contains(body, `"reason":"`+wantLimit+`"`) {
				t.Fatalf("unit %d's refused stream = %q, want %q", unit, body, wantLimit)
			}
			return
		}
		opened++
		waitForSSESubscribers(t, server, opened)
		for len(closers) < unit {
			closers = append(closers, nil)
		}
		closers[unit-1] = append(closers[unit-1], closeStream)
	}
	for unit := 1; unit <= 4; unit++ {
		for range 4 {
			open(unit, "")
		}
		open(unit, "too many live streams for this business unit")
	}
	for _, unit := range []int{5, 6} {
		for range 4 {
			open(unit, "")
		}
	}
	if opened != 24 {
		t.Fatalf("%d streams open, want 24", opened)
	}
	open(5, "too many live streams")

	// Two more units shrink the share to three. The four streams each unit
	// holds stay open, and a unit cannot open another, even below the
	// deployment-wide limit, until it is back under its new share.
	for index := 7; index <= 8; index++ {
		if _, err := db.Platform().CreateTenant(ctx, fmt.Sprintf("Unit %d", index), fmt.Sprintf("unit-%d", index), store.AuditEntry{ActorKind: store.AuditActorHost}); err != nil {
			t.Fatal(err)
		}
	}
	if got := server.sseUnitStreamLimit(ctx); got != 3 {
		t.Fatalf("share of eight units in 24 streams = %d, want 3", got)
	}
	for _, closeStream := range closers[5][:2] {
		closeStream()
	}
	opened -= 2
	waitForSSESubscribers(t, server, opened)
	open(1, "too many live streams for this business unit")
	open(6, "")
	open(6, "too many live streams for this business unit")
}

func TestLiveStreamShareBounds(t *testing.T) {
	t.Parallel()
	for _, check := range []struct {
		total, perUser, perUnit, units, want int
	}{
		{256, 4, 64, 2, 64},
		{256, 4, 64, 4, 64},
		{256, 4, 64, 5, 51},
		{256, 4, 64, 6, 42},
		{256, 4, 64, 64, 4},
		{256, 4, 64, 100, 4},
		{256, 4, 2, 100, 2},
	} {
		if got := sseUnitStreamShare(check.total, check.perUser, check.perUnit, check.units); got != check.want {
			t.Errorf("share of %d units in %d streams = %d, want %d", check.units, check.total, got, check.want)
		}
	}
}

// NewServer takes the stream limits from web.max_live_streams and
// web.max_live_streams_per_unit, and the defaults without a configuration.
func TestNewServerTakesTheConfiguredStreamLimits(t *testing.T) {
	t.Parallel()
	total, perUnit := 512, 32
	server := NewServer(&app.App{Config: &config.Config{Web: config.Web{MaxLiveStreams: &total, MaxLiveStreamsPerUnit: &perUnit}}}, nil, nil)
	if server.maxSSESubscribers() != 512 || server.sseMaxSubscribersPerUnit != 32 {
		t.Fatalf("configured limits = %d/%d", server.maxSSESubscribers(), server.sseMaxSubscribersPerUnit)
	}
	server = NewServer(nil, nil, nil)
	if server.maxSSESubscribers() != config.DefaultMaxLiveStreams || server.maxSSESubscribersPerUser() != defaultMaxSSESubscribersPerUser || server.sseUnitStreamLimit(context.Background()) != config.DefaultMaxLiveStreamsPerUnit {
		t.Fatalf("default limits = %d/%d/%d", server.maxSSESubscribers(), server.maxSSESubscribersPerUser(), server.sseUnitStreamLimit(context.Background()))
	}
}
