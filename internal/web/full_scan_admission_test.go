package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

func acquireFullScanLease(t *testing.T, admission *fullScanAdmission, tenantID string) func() {
	t.Helper()
	release, result := admission.acquire(context.Background(), tenantID, 0)
	if result != fullScanAdmitted {
		t.Fatalf("acquire full-scan lease for %q = %v", tenantID, result)
	}
	return release
}

func waitForFullScanWaiters(t *testing.T, admission *fullScanAdmission, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		admission.mu.Lock()
		got := admission.waiting
		admission.mu.Unlock()
		if got == want {
			return
		}
		runtime.Gosched()
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	t.Fatalf("full-scan waiters = %d, want %d", admission.waiting, want)
}

func TestFullScanAdmissionDoesNotReserveGlobalCapacityForTenantWaiters(t *testing.T) {
	var admission fullScanAdmission
	releaseA := acquireFullScanLease(t, &admission, "tenant-a")
	defer releaseA()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type acquisition struct {
		release func()
		result  fullScanAdmissionResult
	}
	waiterDone := make(chan acquisition, 1)
	go func() {
		release, result := admission.acquire(ctx, "tenant-a", time.Second)
		waiterDone <- acquisition{release: release, result: result}
	}()
	waitForFullScanWaiters(t, &admission, 1)

	// This tenant is already active and has used its one waiter allowance.
	// It cannot add another waiter to crowd out other units.
	if _, result := admission.acquire(context.Background(), "tenant-a", time.Second); result != fullScanAdmissionBusy {
		t.Fatalf("second tenant-a request while one is active and one waits = %v, want busy", result)
	}

	// Tenant B takes the still-free deployment slot even though tenant A's
	// waiter is already queued. The waiter reserves neither kind of capacity.
	releaseB := acquireFullScanLease(t, &admission, "tenant-b")
	defer releaseB()
	admission.mu.Lock()
	active, waiting := admission.active, admission.waiting
	admission.mu.Unlock()
	if active != maxConcurrentFullScans || waiting != 1 {
		t.Fatalf("after tenant B admission: active=%d, waiting=%d", active, waiting)
	}

	releaseA()
	select {
	case got := <-waiterDone:
		if got.result != fullScanAdmitted {
			t.Fatalf("tenant A waiter after its active request ended = %v", got.result)
		}
		got.release()
	case <-time.After(time.Second):
		t.Fatal("tenant A waiter was not admitted after its active response ended")
	}

	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.active != 1 || admission.activeTenants["tenant-b"] != 1 || admission.waiting != 0 || len(admission.waitingTenants) != 0 {
		t.Fatalf("admission state after waiter completed: active=%d tenants=%v waiting=%d waiter-tenants=%v", admission.active, admission.activeTenants, admission.waiting, admission.waitingTenants)
	}
}

func TestFullScanAdmissionBoundsWaitersAndCleansCanceledOrExpiredEntries(t *testing.T) {
	var admission fullScanAdmission
	releaseA := acquireFullScanLease(t, &admission, "active-a")
	defer releaseA()
	releaseB := acquireFullScanLease(t, &admission, "active-b")
	defer releaseB()

	type waitingRequest struct {
		cancel context.CancelFunc
		done   chan fullScanAdmissionResult
	}
	waiters := make([]waitingRequest, 0, maxWaitingFullScans)
	t.Cleanup(func() {
		for _, request := range waiters {
			request.cancel()
		}
	})
	for i := range maxWaitingFullScans {
		ctx, cancel := context.WithCancel(context.Background())
		request := waitingRequest{cancel: cancel, done: make(chan fullScanAdmissionResult, 1)}
		waiters = append(waiters, request)
		go func(tenantID string, done chan<- fullScanAdmissionResult) {
			_, result := admission.acquire(ctx, tenantID, time.Second)
			done <- result
		}(string(rune('a'+i)), request.done)
		waitForFullScanWaiters(t, &admission, i+1)
	}
	if _, result := admission.acquire(context.Background(), "overflow", time.Second); result != fullScanAdmissionBusy {
		t.Fatalf("request beyond global waiter limit = %v, want busy", result)
	}
	for _, request := range waiters {
		request.cancel()
	}
	for _, request := range waiters {
		select {
		case result := <-request.done:
			if result != fullScanAdmissionCanceled {
				t.Errorf("canceled waiter result = %v, want canceled", result)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled admission waiter did not finish")
		}
	}

	admission.mu.Lock()
	if admission.waiting != 0 || len(admission.waitingTenants) != 0 {
		admission.mu.Unlock()
		t.Fatalf("canceled waiters remain: count=%d tenants=%v", admission.waiting, admission.waitingTenants)
	}
	admission.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, result := admission.acquire(ctx, "expired", 5*time.Millisecond)
	if result != fullScanAdmissionBusy {
		t.Fatalf("expired waiter result = %v, want busy", result)
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.waiting != 0 || len(admission.waitingTenants) != 0 {
		t.Fatalf("expired waiter remains: count=%d tenants=%v", admission.waiting, admission.waitingTenants)
	}
}

func TestFullScanAdmissionWaitBudgetUsesRequestStartAndContextDeadline(t *testing.T) {
	started := time.Unix(1_800_000_000, 0)
	writeTimeout := time.Second
	reserve := fullScanWriteReserve(writeTimeout)
	maxWait := 2 * time.Second

	wait, ok := fullScanAdmissionWaitBudget(context.Background(), started, started, writeTimeout, maxWait)
	if !ok || wait != writeTimeout-reserve {
		t.Fatalf("initial admission budget = %s, %v; want %s, true", wait, ok, writeTimeout-reserve)
	}
	now := started.Add(300 * time.Millisecond)
	wait, ok = fullScanAdmissionWaitBudget(context.Background(), now, started, writeTimeout, maxWait)
	if !ok || wait != writeTimeout-reserve-300*time.Millisecond {
		t.Fatalf("elapsed admission budget = %s, %v", wait, ok)
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(75*time.Millisecond))
	defer cancel()
	wait, ok = fullScanAdmissionWaitBudget(ctx, now, started, writeTimeout, maxWait)
	if !ok || wait != 75*time.Millisecond {
		t.Fatalf("context-clamped admission budget = %s, %v", wait, ok)
	}
	if wait, ok = fullScanAdmissionWaitBudget(context.Background(), started.Add(writeTimeout-reserve), started, writeTimeout, maxWait); ok || wait != 0 {
		t.Fatalf("budget at reserved write boundary = %s, %v; want 0, false", wait, ok)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if wait, ok = fullScanAdmissionWaitBudget(canceled, started, started, writeTimeout, maxWait); ok || wait != 0 {
		t.Fatalf("canceled context budget = %s, %v; want 0, false", wait, ok)
	}
}

func TestFullScanAdmissionDoesNotReadAfterResponseWriteBudgetExpires(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	server.writeTimeout = 200 * time.Millisecond
	db.ReadDB.SetMaxOpenConns(1)
	conn, err := db.ReadDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	readWaits := db.ReadDB.Stats().WaitCount
	started := time.Now().Add(-server.writeTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/no-scan", nil).WithContext(ctx)
	request = request.WithContext(context.WithValue(request.Context(), fullScanRequestStartContextKey{}, started))
	response := httptest.NewRecorder()
	server.getScan(response, request, defaultTenantStore(server), "no-scan")
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != fullScanRetryAfterSeconds || !strings.Contains(response.Body.String(), `"code":"scan_slots_busy"`) {
		t.Fatalf("late request = %d Retry-After %q body %q; want bounded 503 without a document read", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	if got := db.ReadDB.Stats().WaitCount; got != readWaits {
		t.Fatalf("late request waited for the document reader %d times; before=%d after=%d", got-readWaits, readWaits, got)
	}
}

func TestFullScanAdmissionCancellationDoesNotWriteBusyOrLeakPermit(t *testing.T) {
	server, _, _ := newUsersTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/no-scan", nil)
	request = request.WithContext(context.WithValue(ctx, fullScanRequestStartContextKey{}, time.Now()))
	response := httptest.NewRecorder()
	server.getScan(response, request, defaultTenantStore(server), "no-scan")
	if response.Body.Len() != 0 || response.Header().Get("Retry-After") != "" {
		t.Fatalf("canceled request wrote a response: status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	server.fullScanAdmission.mu.Lock()
	active, waiting := server.fullScanAdmission.active, server.fullScanAdmission.waiting
	server.fullScanAdmission.mu.Unlock()
	if active != 0 || waiting != 0 {
		t.Fatalf("canceled request left admission state active=%d waiting=%d", active, waiting)
	}
}

type admissionSignalContext struct {
	context.Context
	acquireChecked chan struct{}
	checks         atomic.Int32
}

func (c *admissionSignalContext) Err() error {
	if c.checks.Add(1) == 2 {
		close(c.acquireChecked)
	}
	return c.Context.Err()
}

func TestFullScanAdmissionRefusesAfterAdmissionWhenWriteBudgetExpires(t *testing.T) {
	server, db, _ := newUsersTestServer(t)
	server.writeTimeout = 400 * time.Millisecond
	db.ReadDB.SetMaxOpenConns(1)
	conn, err := db.ReadDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	readWaits := db.ReadDB.Stats().WaitCount

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	signalCtx := &admissionSignalContext{Context: ctx, acquireChecked: make(chan struct{})}
	started := time.Now()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans/no-scan", nil)
	request = request.WithContext(context.WithValue(signalCtx, fullScanRequestStartContextKey{}, started))

	server.fullScanAdmission.mu.Lock()
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.getScan(response, request, defaultTenantStore(server), "no-scan")
		close(done)
	}()
	select {
	case <-signalCtx.acquireChecked:
	case <-time.After(time.Second):
		server.fullScanAdmission.mu.Unlock()
		t.Fatal("request did not reach admission after its initial budget check")
	}
	cutoff := started.Add(server.httpWriteTimeout() - fullScanWriteReserve(server.httpWriteTimeout()))
	if delay := time.Until(cutoff.Add(5 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}
	server.fullScanAdmission.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request did not finish after admission mutex was released")
	}

	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != fullScanRetryAfterSeconds || !strings.Contains(response.Body.String(), `"code":"scan_slots_busy"`) {
		t.Fatalf("admitted late request = %d Retry-After %q body %q; want bounded 503", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	if got := db.ReadDB.Stats().WaitCount; got != readWaits {
		t.Fatalf("admitted late request waited for the document reader %d times; before=%d after=%d", got-readWaits, readWaits, got)
	}
	server.fullScanAdmission.mu.Lock()
	active := server.fullScanAdmission.active
	server.fullScanAdmission.mu.Unlock()
	if active != 0 {
		t.Fatalf("late admission retained %d full-scan permits after refusal", active)
	}
}

func TestFullScanAdmissionWaitIsClampedToRealListenerWriteTimeout(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	server.writeTimeout = time.Second
	server.fullScanAdmissionWait = 5 * time.Second
	if err := storetest.CreateSession(ctx, db, admin.UserID, digest("full-scan-budget-session"), "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	scope, err := defaultTenantStore(server).Scope()
	if err != nil {
		t.Fatal(err)
	}
	releaseDefault := acquireFullScanLease(t, &server.fullScanAdmission, scope.ID())
	defer releaseDefault()
	releaseOther := acquireFullScanLease(t, &server.fullScanAdmission, "write-budget-other")
	defer releaseOther()

	inner := server.Handler()
	const preHandlerDelay = 100 * time.Millisecond
	listenerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is the boundary net/http reaches immediately after setting the
		// request's WriteTimeout. Preserve that timestamp while a controlled
		// middleware-like delay consumes some of the same response budget.
		r = r.WithContext(context.WithValue(r.Context(), fullScanRequestStartContextKey{}, time.Now()))
		timer := time.NewTimer(preHandlerDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
			inner.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	})
	httpServer := httptest.NewUnstartedServer(listenerHandler)
	httpServer.Config.WriteTimeout = server.httpWriteTimeout()
	httpServer.Start()
	defer httpServer.Close()

	request, err := http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/scans/no-scan", nil)
	if err != nil {
		t.Fatal(err)
	}
	addTestSessionCookie(request, "full-scan-budget-session")
	started := time.Now()
	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatalf("request failed before the listener's write budget: %v (elapsed %s)", err, time.Since(started))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") != fullScanRetryAfterSeconds {
		t.Fatalf("full scan at capacity = %d Retry-After %q, want bounded 503: %s", response.StatusCode, response.Header.Get("Retry-After"), response.Status)
	}
	if elapsed := time.Since(started); elapsed >= server.httpWriteTimeout() {
		t.Fatalf("busy response took %s, beyond WriteTimeout %s", elapsed, server.httpWriteTimeout())
	}
}

func TestFullScanLateListenerRequestNeverReturnsSuccess(t *testing.T) {
	ctx := context.Background()
	server, db, admin := newUsersTestServer(t)
	server.writeTimeout = time.Second
	record := runtimeTestJob(t, db, "late-full-scan")
	scan := fullScanFixture(record, "late-full-scan", nil)
	if err := db.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if err := storetest.CreateSession(ctx, db, admin.UserID, digest("late-full-scan-session"), "csrf", time.Now().UTC(), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	inner := server.Handler()
	entered := make(chan struct{})
	completed := make(chan struct{})
	const handlerDelay = 970 * time.Millisecond
	listenerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ctx, cancel := context.WithDeadline(r.Context(), started.Add(handlerDelay+100*time.Millisecond))
		defer cancel()
		ctx = context.WithValue(ctx, fullScanRequestStartContextKey{}, started)
		r = r.WithContext(ctx)
		close(entered)
		timer := time.NewTimer(handlerDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
			inner.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
		close(completed)
	})
	httpServer := httptest.NewUnstartedServer(listenerHandler)
	httpServer.Config.WriteTimeout = server.httpWriteTimeout()
	httpServer.Start()
	defer httpServer.Close()

	request, err := http.NewRequest(http.MethodGet, httpServer.URL+"/api/v1/scans/"+scan.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	addTestSessionCookie(request, "late-full-scan-session")
	client := &http.Client{Timeout: 3 * time.Second}
	requestStarted := time.Now()
	response, requestErr := client.Do(request)
	select {
	case <-entered:
	default:
		t.Fatal("request never reached the listener handler")
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("listener handler did not finish the late request")
	}
	if requestErr != nil {
		// A response may be lost when the listener deadline expires under
		// scheduling pressure. It must never turn into a successful empty 200.
		if time.Since(requestStarted) < handlerDelay-100*time.Millisecond {
			t.Fatalf("late listener request failed before its controlled handler delay: %v", requestErr)
		}
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("late full-scan request returned %d instead of a bounded 503 refusal", response.StatusCode)
	}
	if response.Header.Get("Retry-After") != fullScanRetryAfterSeconds {
		t.Fatalf("late refusal Retry-After = %q, want %q", response.Header.Get("Retry-After"), fullScanRetryAfterSeconds)
	}
}
