package web

import (
	"context"
	"sync"
	"time"
)

const (
	maxConcurrentFullScans          = 2
	maxConcurrentFullScansPerTenant = 1
	maxWaitingFullScans             = 16
	maxWaitingFullScansPerTenant    = 1
	defaultFullScanAdmissionWait    = 2 * time.Second
	fullScanRetryAfterSeconds       = "1"
)

type fullScanRequestStartContextKey struct{}

func fullScanRequestStartedAt(ctx context.Context) (time.Time, bool) {
	started, ok := ctx.Value(fullScanRequestStartContextKey{}).(time.Time)
	return started, ok
}

// fullScanAdmissionWaitBudget keeps admission inside both the endpoint's
// short queue limit and the listener's existing write deadline. The reserve
// leaves time to write a refusal before net/http's absolute deadline expires;
// it is not a promise that a slow client can receive an arbitrarily large
// response before that deadline.
func fullScanAdmissionWaitBudget(ctx context.Context, now, started time.Time, writeTimeout, maxWait time.Duration) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	if writeTimeout <= 0 {
		writeTimeout = defaultHTTPWriteTimeout
	}
	if maxWait <= 0 {
		maxWait = defaultFullScanAdmissionWait
	}
	if started.IsZero() {
		started = now
	}
	remaining := started.Add(writeTimeout - fullScanWriteReserve(writeTimeout)).Sub(now)
	if deadline, ok := ctx.Deadline(); ok {
		if contextRemaining := deadline.Sub(now); contextRemaining < remaining {
			remaining = contextRemaining
		}
	}
	if remaining <= 0 {
		return 0, false
	}
	if remaining > maxWait {
		remaining = maxWait
	}
	return remaining, true
}

func fullScanWriteReserve(writeTimeout time.Duration) time.Duration {
	reserve := writeTimeout / 20
	if reserve < 25*time.Millisecond {
		reserve = 25 * time.Millisecond
	}
	if reserve > 250*time.Millisecond {
		reserve = 250 * time.Millisecond
	}
	return reserve
}

type fullScanAdmissionResult uint8

const (
	fullScanAdmitted fullScanAdmissionResult = iota
	fullScanAdmissionCanceled
	fullScanAdmissionBusy
)

// fullScanAdmission makes the global and per-tenant checks one atomic
// decision. A waiter never reserves either limit while it is waiting. Its
// tenant-keyed entry is held only while that request is in the bounded queue
// and is removed on admission, cancellation, or timeout.
type fullScanAdmission struct {
	mu             sync.Mutex
	active         int
	activeTenants  map[string]int
	waiting        int
	waitingTenants map[string]int
	changed        chan struct{}
}

func (a *fullScanAdmission) acquire(ctx context.Context, tenantID string, wait time.Duration) (func(), fullScanAdmissionResult) {
	if ctx.Err() != nil {
		return nil, fullScanAdmissionCanceled
	}
	if tenantID == "" {
		return nil, fullScanAdmissionBusy
	}

	a.mu.Lock()
	a.ensureLocked()
	if a.canAcquireLocked(tenantID) {
		a.addActiveLocked(tenantID)
		a.mu.Unlock()
		return a.releaseFor(tenantID), fullScanAdmitted
	}
	if wait <= 0 || a.waiting >= maxWaitingFullScans || a.waitingTenants[tenantID] >= maxWaitingFullScansPerTenant {
		a.mu.Unlock()
		return nil, fullScanAdmissionBusy
	}
	a.addWaiterLocked(tenantID)
	changed := a.changed
	a.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			a.mu.Lock()
			a.removeWaiterLocked(tenantID)
			a.mu.Unlock()
			return nil, fullScanAdmissionCanceled
		case <-timer.C:
			a.mu.Lock()
			a.removeWaiterLocked(tenantID)
			a.mu.Unlock()
			return nil, fullScanAdmissionBusy
		case <-changed:
			a.mu.Lock()
			if ctx.Err() != nil {
				a.removeWaiterLocked(tenantID)
				a.mu.Unlock()
				return nil, fullScanAdmissionCanceled
			}
			if a.canAcquireLocked(tenantID) {
				a.removeWaiterLocked(tenantID)
				a.addActiveLocked(tenantID)
				a.mu.Unlock()
				return a.releaseFor(tenantID), fullScanAdmitted
			}
			changed = a.changed
			a.mu.Unlock()
		}
	}
}

func (a *fullScanAdmission) ensureLocked() {
	if a.activeTenants == nil {
		a.activeTenants = make(map[string]int, maxConcurrentFullScans)
	}
	if a.waitingTenants == nil {
		a.waitingTenants = make(map[string]int)
	}
	if a.changed == nil {
		a.changed = make(chan struct{})
	}
}

func (a *fullScanAdmission) canAcquireLocked(tenantID string) bool {
	return a.active < maxConcurrentFullScans && a.activeTenants[tenantID] < maxConcurrentFullScansPerTenant
}

func (a *fullScanAdmission) addActiveLocked(tenantID string) {
	a.active++
	a.activeTenants[tenantID]++
}

func (a *fullScanAdmission) addWaiterLocked(tenantID string) {
	a.waiting++
	a.waitingTenants[tenantID]++
}

func (a *fullScanAdmission) removeWaiterLocked(tenantID string) {
	a.waiting--
	if count := a.waitingTenants[tenantID] - 1; count > 0 {
		a.waitingTenants[tenantID] = count
	} else {
		delete(a.waitingTenants, tenantID)
	}
}

func (a *fullScanAdmission) releaseFor(tenantID string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.active--
			if count := a.activeTenants[tenantID] - 1; count > 0 {
				a.activeTenants[tenantID] = count
			} else {
				delete(a.activeTenants, tenantID)
			}
			a.signalLocked()
		})
	}
}

func (a *fullScanAdmission) signalLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}
