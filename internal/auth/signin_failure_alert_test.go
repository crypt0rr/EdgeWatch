package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func TestKnownAccountWrongPasswordsAggregateAcrossClientsAndSurviveSuccess(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	destination := configureUnitSecurityAlerts(t, s, store.DefaultTenantScope(), "unit-ops")
	m := NewManager(s)
	now := time.Now().UTC().Truncate(time.Microsecond)
	m.Now = func() time.Time { return now }

	for index, address := range []string{"198.51.100.11", "198.51.100.12", "198.51.100.13", "198.51.100.14"} {
		wrongAccountPassword(t, m, store.WithAuditContext(ctx, fmt.Sprintf("request-%d", index), address), admin.Username, address, "wrong-secret-never-in-alert")
	}
	request := loginRequest("198.51.100.50")
	if _, _, err := m.LoginAs(ctx, request, admin.Username, "unit administrator password", "", ""); err != nil {
		t.Fatalf("valid login between failures = %v", err)
	}
	wrongAccountPassword(t, m, store.WithAuditContext(ctx, "request-5", "198.51.100.15"), admin.Username, "198.51.100.15", "wrong-secret-never-in-alert")
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}

	entries := aggregateAuditRows(t, s)
	if len(entries) != 1 {
		t.Fatalf("aggregate audit entries = %+v, want one after five wrong passwords and a successful intervening login", entries)
	}
	entry := entries[0]
	if !entry.tenant.Valid || entry.tenant.String != store.DefaultTenantID || entry.actorID != admin.ID || entry.actorName != admin.Username || entry.actorKind != store.AuditActorUnit || entry.category != "account" {
		t.Errorf("aggregate audit attribution = %+v", entry)
	}
	if entry.source.Valid && entry.source.String != "" || entry.requestID.Valid && entry.requestID.String != "" {
		t.Errorf("aggregate audit retained request attribution: source=%+v request=%+v", entry.source, entry.requestID)
	}
	if !strings.Contains(entry.detail, fmt.Sprint(model.SecurityAlertAccountSignInFailureCount)) || strings.Contains(entry.detail, "wrong-secret") {
		t.Errorf("aggregate audit detail = %q", entry.detail)
	}

	alerts := securityAlertRows(t, s)
	if len(alerts) != 1 {
		t.Fatalf("security alerts = %+v, want one", alerts)
	}
	alert := alerts[0]
	if alert.tenant != store.DefaultTenantID || alert.destination != fmt.Sprintf("managed:%s:1", destination) {
		t.Errorf("aggregate alert route = tenant %q destination %q", alert.tenant, alert.destination)
	}
	var event model.Event
	if err := json.Unmarshal([]byte(alert.payload), &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != model.EventSecurityAlert || event.Alert == nil || event.Alert.Kind != model.SecurityAlertAccountSignInFailures || event.Alert.Account != admin.Username || event.Alert.Count != model.SecurityAlertAccountSignInFailureCount {
		t.Errorf("aggregate alert = %+v", event)
	}
	for _, secret := range []string{"wrong-secret-never-in-alert", "198.51.100.", "request-5"} {
		if strings.Contains(alert.payload, secret) {
			t.Errorf("aggregate alert payload contains %q: %s", secret, alert.payload)
		}
	}
}

func TestAccountSignInFailureAlertsStayInTheirUnitOrPlatformScope(t *testing.T) {
	ctx := context.Background()
	s, defaultAdmin, _ := platformTestStore(t)
	m := NewManager(s)
	platformAdmin := createPlatformAdmin(t, m, "platform-root", "platform administrator password")
	addSecondUnit(t, s)
	unitB, err := s.TenantScopeByID(ctx, platformTestTenantID)
	if err != nil {
		t.Fatal(err)
	}
	adminB, err := storetest.CreateUser(ctx, s, unitB, store.User{Username: "bravo-admin", Role: store.RoleAdministrator, PasswordHash: cheapHash("unit B administrator password"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := storetest.CreateUser(ctx, s, unitB, store.User{Username: "disabled-bravo", Role: store.RoleOperator, PasswordHash: cheapHash("disabled account password"), Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	unitADestination := configureUnitSecurityAlerts(t, s, store.DefaultTenantScope(), "unit-a-ops")
	unitBDestination := configureUnitSecurityAlerts(t, s, unitB, "unit-b-ops")
	platformDestination, err := s.Platform().CreatePlatformNotificationWithAudit(ctx, "", "platform-ops", "generic", []byte("sealed platform"), []byte("nonce platform"), true, store.AuditEntry{ActorUserID: platformAdmin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Platform().SetPlatformSecurityAlertDestinations(ctx, []string{platformDestination.ID}, store.AuditEntry{ActorUserID: platformAdmin.ID}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		user       store.User
		startOctet int
	}{
		{defaultAdmin, 1},
		{adminB, 11},
		{platformAdmin, 21},
	} {
		for index := 0; index < model.SecurityAlertAccountSignInFailureCount; index++ {
			address := fmt.Sprintf("203.0.113.%d", test.startOctet+index)
			wrongAccountPassword(t, m, ctx, test.user.Username, address, "bad-pass-not-retained")
		}
	}
	wrongAccountPassword(t, m, ctx, "unknown-name", "203.0.113.31", "not-a-known-account")
	wrongAccountPassword(t, m, ctx, disabled.Username, "203.0.113.32", "not-an-enabled-account")
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}

	entries := aggregateAuditRows(t, s)
	if len(entries) != 3 {
		t.Fatalf("aggregate audit entries = %d, want only the three enabled known accounts: %+v", len(entries), entries)
	}
	byTenant := map[string]aggregateAudit{}
	for _, entry := range entries {
		key := ""
		if entry.tenant.Valid {
			key = entry.tenant.String
			if entry.actorKind != store.AuditActorUnit {
				t.Errorf("tenant aggregate actor kind = %q", entry.actorKind)
			}
		} else if entry.actorKind != store.AuditActorPlatform {
			t.Errorf("platform aggregate actor kind = %q", entry.actorKind)
		}
		if entry.source.Valid && entry.source.String != "" {
			t.Errorf("aggregate entry retained source %q", entry.source.String)
		}
		byTenant[key] = entry
	}
	if byTenant[store.DefaultTenantID].actorID != defaultAdmin.ID || byTenant[platformTestTenantID].actorID != adminB.ID || byTenant[""].actorID != platformAdmin.ID {
		t.Errorf("aggregate audit scopes = %+v", byTenant)
	}
	if len(m.accountSignInFailures) != 3 {
		t.Errorf("tracked aggregate accounts = %d, want only enabled known accounts", len(m.accountSignInFailures))
	}

	alerts := securityAlertRows(t, s)
	if len(alerts) != 3 {
		t.Fatalf("security alerts = %+v, want one per routed owner", alerts)
	}
	wantRoutes := map[string]string{
		store.DefaultTenantID: fmt.Sprintf("managed:%s:1", unitADestination),
		platformTestTenantID:  fmt.Sprintf("managed:%s:1", unitBDestination),
		"":                    fmt.Sprintf("managed:%s:1", platformDestination.ID),
	}
	seen := make(map[string]bool)
	for _, alert := range alerts {
		if want := wantRoutes[alert.tenant]; alert.destination != want || want == "" {
			t.Errorf("alert routed to %q/%q, want %q", alert.tenant, alert.destination, want)
		}
		seen[alert.tenant] = true
		var event model.Event
		if err := json.Unmarshal([]byte(alert.payload), &event); err != nil {
			t.Fatal(err)
		}
		if event.Alert == nil || event.Alert.Kind != model.SecurityAlertAccountSignInFailures || event.Alert.Count != model.SecurityAlertAccountSignInFailureCount {
			t.Errorf("alert detail = %+v", event.Alert)
		}
		for _, secret := range []string{"bad-pass-not-retained", "203.0.113.", "unknown-name", "disabled-bravo"} {
			if strings.Contains(alert.payload, secret) {
				t.Errorf("alert payload leaked %q: %s", secret, alert.payload)
			}
		}
	}
	for scope := range wantRoutes {
		if !seen[scope] {
			t.Errorf("no alert was routed to owner %q", scope)
		}
	}
}

func TestAccountSignInFailureQueueFullAndWriteFailureReleaseClaims(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	m := NewManager(s)
	now := time.Now().UTC()
	m.Now = func() time.Time { return now }
	key := accountSignInFailureKey(admin, false)

	for range model.SecurityAlertAccountSignInFailureCount - 1 {
		m.recordAccountPasswordFailure(ctx, admin)
	}
	for range rateLimitRecordsPending {
		m.rateRecordSlots <- struct{}{}
	}
	m.recordAccountPasswordFailure(store.WithAuditContext(ctx, "private-request", "198.51.100.76"), admin)
	state := m.accountSignInFailures[key]
	if state == nil || state.pendingAudit || !state.lastAlertAt.IsZero() {
		t.Fatalf("queue-full claim state = %+v, want unclaimed retryable state", state)
	}
	for range rateLimitRecordsPending {
		<-m.rateRecordSlots
	}
	if got := countAccountSignInFailureAudits(t, s); got != 0 {
		t.Fatalf("audit rows after full queue = %d, want none", got)
	}
	m.recordAccountPasswordFailure(store.WithAuditContext(ctx, "private-request", "198.51.100.76"), admin)
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if state.pendingAudit || state.lastAlertAt.IsZero() {
		t.Fatalf("successful audit did not release pending claim while retaining cooldown: %+v", state)
	}
	if got := countAccountSignInFailureAudits(t, s); got != 1 {
		t.Fatalf("audits after retry from full queue = %d, want one", got)
	}

	key2 := accountSignInFailureKey(store.User{ID: "retry-user", Username: "retry-user", TenantID: admin.TenantID, Enabled: true}, false)
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_account_sign_in_audit BEFORE INSERT ON security_audit WHEN NEW.action='auth.sign_in_failures' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	retryUser := store.User{ID: "retry-user", Username: "retry-user", TenantID: admin.TenantID, Role: store.RoleAdministrator, Enabled: true}
	for range model.SecurityAlertAccountSignInFailureCount {
		m.recordAccountPasswordFailure(store.WithAuditContext(ctx, "private-request", "198.51.100.77"), retryUser)
	}
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	failedState := m.accountSignInFailures[key2]
	if failedState == nil || failedState.pendingAudit || !failedState.lastAlertAt.IsZero() {
		t.Fatalf("failed write claim state = %+v, want retryable", failedState)
	}
	if got := countAccountSignInFailureAudits(t, s); got != 1 {
		t.Fatalf("audits after forced writer failure = %d, want the earlier successful row only", got)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER fail_account_sign_in_audit`); err != nil {
		t.Fatal(err)
	}
	m.recordAccountPasswordFailure(store.WithAuditContext(ctx, "private-request", "198.51.100.77"), retryUser)
	if err := m.WaitForRateLimitRecords(ctx); err != nil {
		t.Fatal(err)
	}
	if got := countAccountSignInFailureAudits(t, s); got != 2 {
		t.Fatalf("audits after writer retry = %d, want two", got)
	}
}

func TestAccountSignInFailureCooldownAndWindowExpiry(t *testing.T) {
	ctx := context.Background()
	s, admin, _ := platformTestStore(t)
	m := NewManager(s)
	start := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	now := start
	m.Now = func() time.Time { return now }

	for minute := 0; minute < model.SecurityAlertAccountSignInFailureCount; minute++ {
		now = start.Add(time.Duration(minute) * time.Minute)
		m.recordAccountPasswordFailure(ctx, admin)
		if minute == model.SecurityAlertAccountSignInFailureCount-1 {
			if err := m.WaitForRateLimitRecords(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := countAccountSignInFailureAudits(t, s); got != 1 {
		t.Fatalf("initial threshold audits = %d, want one", got)
	}

	// The first attempt ages out of the rolling window at minute five. The
	// remaining four plus this attempt cross the threshold again, but remain
	// inside the original detection cooldown and must not emit another alert.
	now = start.Add(authFailureWindow)
	m.recordAccountPasswordFailure(ctx, admin)
	if got := countAccountSignInFailureAudits(t, s); got != 1 {
		t.Fatalf("audit emitted again during cooldown = %d, want one", got)
	}

	// Once the cooldown and old attempt timestamps expire, a fresh five
	// failures form a new detection window and may emit one new record.
	for minute := 10; minute < 10+model.SecurityAlertAccountSignInFailureCount; minute++ {
		now = start.Add(time.Duration(minute) * time.Minute)
		m.recordAccountPasswordFailure(ctx, admin)
		if minute == 10+model.SecurityAlertAccountSignInFailureCount-1 {
			if err := m.WaitForRateLimitRecords(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := countAccountSignInFailureAudits(t, s); got != 2 {
		t.Fatalf("audit rows after new window = %d, want two", got)
	}
}

func TestAccountSignInFailureStateIsBoundedAndExpiryIsRolling(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	manager := &Manager{Now: func() time.Time { return now }, accountSignInFailures: make(map[string]*accountSignInFailureState, authLimiterMaxEntries)}
	for index := 0; index < authLimiterMaxEntries; index++ {
		key := fmt.Sprintf("tenant\x00tenant-%04d\x00account-%04d", index, index)
		manager.accountSignInFailures[key] = &accountSignInFailureState{lastAlertAt: now, lastTouched: now.Add(-time.Duration(index) * time.Second)}
	}
	activeKey := "tenant\x00tenant-0001\x00account-0001"
	manager.accountSignInFailures[activeKey] = &accountSignInFailureState{failures: []time.Time{now}, lastTouched: now.Add(-25 * time.Hour)}
	newAccount := store.User{ID: "new-id", TenantID: "new-tenant", Username: "new-account", Enabled: true}
	newKey := accountSignInFailureKey(newAccount, false)
	manager.recordAccountPasswordFailure(context.Background(), newAccount)
	if len(manager.accountSignInFailures) != authLimiterMaxEntries || manager.accountSignInFailures[newKey] != nil || manager.accountSignInFailures[activeKey] == nil {
		t.Fatalf("full active map grew or discarded cooldown state: size=%d new=%+v", len(manager.accountSignInFailures), manager.accountSignInFailures[newKey])
	}
	oldestKey := "tenant\x00tenant-0000\x00account-0000"
	manager.accountSignInFailures[oldestKey] = &accountSignInFailureState{lastAlertAt: now.Add(-authFailureWindow - time.Second), lastTouched: now.Add(-24 * time.Hour)}
	manager.recordAccountPasswordFailure(context.Background(), newAccount)
	if len(manager.accountSignInFailures) != authLimiterMaxEntries || manager.accountSignInFailures[newKey] == nil || manager.accountSignInFailures[oldestKey] != nil {
		t.Fatalf("expired state was not replaced within the cap: size=%d new=%+v old=%+v", len(manager.accountSignInFailures), manager.accountSignInFailures[newKey], manager.accountSignInFailures[oldestKey])
	}

	state := &accountSignInFailureState{failures: []time.Time{now.Add(-authFailureWindow), now.Add(-time.Minute)}}
	if got := state.recentFailures(now); got != 1 || len(state.failures) != 1 || !state.failures[0].Equal(now.Add(-time.Minute)) {
		t.Fatalf("rolling window retained %d failures at the exact cutoff: %v", got, state.failures)
	}
}

func TestAccountSignInFailureAuditCompletionIsClaimBound(t *testing.T) {
	key := "tenant\x00unit-a\x00account-a"
	now := time.Now().UTC()
	state := &accountSignInFailureState{claim: 12, pendingAudit: true, lastAlertAt: now}
	manager := &Manager{accountSignInFailures: map[string]*accountSignInFailureState{key: state}}
	manager.finishAccountSignInFailureAudit(key, 11, errors.New("stale writer error"), true)
	if !state.pendingAudit || state.claim != 12 || !state.lastAlertAt.Equal(now) {
		t.Fatalf("stale claim changed newer state: %+v", state)
	}
	manager.finishAccountSignInFailureAudit(key, 12, errors.New("writer failure"), true)
	if state.pendingAudit || !state.lastAlertAt.IsZero() {
		t.Fatalf("matching failed claim was not released for retry: %+v", state)
	}
	state.claim, state.pendingAudit, state.lastAlertAt = 14, true, now.Add(time.Minute)
	manager.finishAccountSignInFailureAudit(key, 13, nil, true)
	if !state.pendingAudit || !state.lastAlertAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("older success changed newer cooldown: %+v", state)
	}
	manager.finishAccountSignInFailureAudit(key, 14, nil, true)
	if state.pendingAudit || !state.lastAlertAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("successful matching claim did not retain cooldown: %+v", state)
	}
}

func TestCloseAndWaitForAuthAuditWritesSerializesEnqueueAndShutdown(t *testing.T) {
	ctx := context.Background()
	m := &Manager{}
	writeStarted := make(chan struct{})
	lateWriteStarted := make(chan struct{}, 1)
	allowWrite := make(chan struct{})
	finish := make(chan struct {
		err       error
		submitted bool
	}, 2)

	m.recordAuditInBackground(ctx, store.AuditEntry{Action: "first"}, func(context.Context, store.AuditEntry) error {
		close(writeStarted)
		<-allowWrite
		return nil
	}, func(err error, submitted bool) {
		finish <- struct {
			err       error
			submitted bool
		}{err: err, submitted: submitted}
	})
	select {
	case <-writeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted audit write did not start")
	}

	closed := make(chan error, 1)
	go func() {
		closed <- m.CloseAndWaitForAuthAuditWrites(ctx)
	}()
	deadline := time.NewTimer(3 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		m.mu.Lock()
		isClosed := m.authAuditQueueClosed
		m.mu.Unlock()
		if isClosed {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("shutdown did not close audit enqueue")
		}
	}
	select {
	case err := <-closed:
		t.Fatalf("shutdown returned before accepted write drained: %v", err)
	default:
	}

	lateFinish := make(chan struct {
		err       error
		submitted bool
	}, 1)
	m.recordAuditInBackground(ctx, store.AuditEntry{Action: "late"}, func(context.Context, store.AuditEntry) error {
		lateWriteStarted <- struct{}{}
		return nil
	}, func(err error, submitted bool) {
		lateFinish <- struct {
			err       error
			submitted bool
		}{err: err, submitted: submitted}
	})
	select {
	case result := <-lateFinish:
		if result.err == nil || result.submitted {
			t.Fatalf("post-shutdown enqueue result = %+v, want rejected", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("post-shutdown enqueue did not finish synchronously")
	}
	select {
	case <-lateWriteStarted:
		t.Fatal("post-shutdown write was started")
	default:
	}

	close(allowWrite)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("CloseAndWaitForAuthAuditWrites() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not finish after accepted write drained")
	}
	select {
	case result := <-finish:
		if result.err != nil || !result.submitted {
			t.Fatalf("accepted write completion = %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accepted write completion callback did not run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rateRecordsPending != 0 || len(m.rateRecordSlots) != 0 {
		t.Errorf("shutdown left audit work pending: pending=%d slots=%d", m.rateRecordsPending, len(m.rateRecordSlots))
	}
}

type aggregateAudit struct {
	tenant    sql.NullString
	source    sql.NullString
	requestID sql.NullString
	actorID   string
	actorName string
	actorKind string
	category  string
	detail    string
}

func aggregateAuditRows(t *testing.T, s *store.Store) []aggregateAudit {
	t.Helper()
	rows, err := s.DB.Query(`SELECT tenant_id,source_ip,request_id,COALESCE(actor_user_id,''),actor_username,actor_kind,category,detail FROM security_audit WHERE action='auth.sign_in_failures' ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var entries []aggregateAudit
	for rows.Next() {
		var entry aggregateAudit
		if err := rows.Scan(&entry.tenant, &entry.source, &entry.requestID, &entry.actorID, &entry.actorName, &entry.actorKind, &entry.category, &entry.detail); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}

func countAccountSignInFailureAudits(t *testing.T, s *store.Store) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM security_audit WHERE action='auth.sign_in_failures'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

type securityAlertRow struct {
	tenant      string
	destination string
	payload     string
}

func securityAlertRows(t *testing.T, s *store.Store) []securityAlertRow {
	t.Helper()
	rows, err := s.DB.Query(`SELECT COALESCE(tenant_id,''),destination,CAST(payload_json AS TEXT) FROM outbox WHERE json_extract(CAST(payload_json AS TEXT),'$.type')=? ORDER BY id`, model.EventSecurityAlert)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var alerts []securityAlertRow
	for rows.Next() {
		var alert securityAlertRow
		if err := rows.Scan(&alert.tenant, &alert.destination, &alert.payload); err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return alerts
}

func configureUnitSecurityAlerts(t *testing.T, s *store.Store, scope store.TenantScope, name string) string {
	t.Helper()
	ctx := context.Background()
	destination, err := s.Tenant(scope).CreateManagedNotification(ctx, "", name, "generic", []byte("sealed "+name), []byte("nonce "+name), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tenant(scope).SetSecurityAlertDestinations(ctx, []string{destination.ID}, store.AuditEntry{}); err != nil {
		t.Fatal(err)
	}
	return destination.ID
}

func wrongAccountPassword(t *testing.T, m *Manager, ctx context.Context, username, address, password string) {
	t.Helper()
	_, _, err := m.LoginAs(ctx, loginRequest(address), username, password, "", "")
	if err == nil || errors.Is(err, ErrRateLimited) {
		t.Fatalf("wrong-password login for %q from %s = %v; want generic invalid credentials", username, address, err)
	}
}

func loginRequest(address string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = net.JoinHostPort(address, "4000")
	return request
}
