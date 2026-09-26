package app

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type slotResult struct {
	release func()
	err     error
}

// startSlotAcquire calls Acquire in a goroutine and reports its result.
func startSlotAcquire(ctx context.Context, p *slotPool, key string) <-chan slotResult {
	result := make(chan slotResult, 1)
	go func() {
		release, err := p.Acquire(ctx, key)
		result <- slotResult{release, err}
	}()
	return result
}

func mustAcquireSlot(t *testing.T, p *slotPool, key string) func() {
	t.Helper()
	release, err := p.Acquire(context.Background(), key)
	if err != nil {
		t.Fatalf("acquire %s: %v", key, err)
	}
	return release
}

// waitForSlotWaiters blocks until key has n queued waiters.
func waitForSlotWaiters(t *testing.T, p *slotPool, key string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for p.CapacitySnapshot().Keys[key].Queued != n {
		if time.Now().After(deadline) {
			t.Fatalf("key %s never had %d queued waiters: %#v", key, n, p.CapacitySnapshot())
		}
		time.Sleep(time.Millisecond)
	}
}

func receiveSlot(t *testing.T, result <-chan slotResult) slotResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("waiter was never granted or failed")
		return slotResult{}
	}
}

func assertSlotWaiting(t *testing.T, result <-chan slotResult) {
	t.Helper()
	select {
	case got := <-result:
		t.Fatalf("waiter returned early: err=%v", got.err)
	default:
	}
}

func assertIdleSlotPool(t *testing.T, p *slotPool, capacity int) {
	t.Helper()
	got := p.CapacitySnapshot()
	want := slotSnapshot{Capacity: capacity, Keys: map[string]slotUsage{}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("idle snapshot = %#v, want %#v", got, want)
	}
}

// queueOrdered queues one waiter per label, each after the previous one is
// queued. Every waiter records its label once granted and releases at once,
// so with one slot the recorded order is the grant order.
func queueOrdered(t *testing.T, p *slotPool, labels, keys []string, order *[]string, mu *sync.Mutex, wg *sync.WaitGroup) {
	t.Helper()
	queued := map[string]int{}
	for i, label := range labels {
		key := keys[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := p.Acquire(context.Background(), key)
			if err != nil {
				t.Errorf("acquire %s: %v", label, err)
				return
			}
			mu.Lock()
			*order = append(*order, label)
			mu.Unlock()
			release()
		}()
		queued[key]++
		waitForSlotWaiters(t, p, key, queued[key])
	}
}

func TestSlotPoolSingleKeyIsFIFO(t *testing.T) {
	p := newSlotPool(1, nil)
	hold := mustAcquireSlot(t, p, defaultSlotKey)
	var order []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	labels := []string{"0", "1", "2", "3", "4", "5"}
	keys := make([]string, len(labels))
	for i := range keys {
		keys[i] = defaultSlotKey
	}
	queueOrdered(t, p, labels, keys, &order, &mu, &wg)
	hold()
	wg.Wait()
	if !reflect.DeepEqual(order, labels) {
		t.Fatalf("grant order = %v, want %v", order, labels)
	}
	assertIdleSlotPool(t, p, 1)
}

func TestSlotPoolSingleKeyUsesFullCapacity(t *testing.T) {
	p := newSlotPool(2, nil)
	first := mustAcquireSlot(t, p, "a")
	second := mustAcquireSlot(t, p, "a")
	third := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	assertSlotWaiting(t, third)
	if got := p.CapacitySnapshot(); got.InUse != 2 || got.Queued != 1 {
		t.Fatalf("full pool = %#v", got)
	}
	first()
	granted := receiveSlot(t, third)
	if granted.err != nil {
		t.Fatal(granted.err)
	}
	// A release function is safe to call twice: the second call is a no-op
	// and does not free a slot someone else holds.
	first()
	if got := p.CapacitySnapshot(); got.InUse != 2 || got.Queued != 0 {
		t.Fatalf("after handover = %#v", got)
	}
	second()
	granted.release()
	assertIdleSlotPool(t, p, 2)
}

func TestSlotPoolRoundRobinDoesNotStarveSmallKey(t *testing.T) {
	p := newSlotPool(2, nil)
	a1 := mustAcquireSlot(t, p, "a")
	a2 := mustAcquireSlot(t, p, "a")
	var waiting []<-chan slotResult
	for i := 3; i <= 5; i++ {
		waiting = append(waiting, startSlotAcquire(context.Background(), p, "a"))
		waitForSlotWaiters(t, p, "a", i-2)
	}
	b1 := startSlotAcquire(context.Background(), p, "b")
	waitForSlotWaiters(t, p, "b", 1)

	// B queued after A's three waiters, but A was granted most recently, so
	// B takes the first free slot.
	a1()
	gotB := receiveSlot(t, b1)
	if gotB.err != nil {
		t.Fatal(gotB.err)
	}
	for _, w := range waiting {
		assertSlotWaiting(t, w)
	}
	// With B served, A's queue continues in FIFO order.
	a2()
	a3 := receiveSlot(t, waiting[0])
	assertSlotWaiting(t, waiting[1])
	gotB.release()
	a4 := receiveSlot(t, waiting[1])
	assertSlotWaiting(t, waiting[2])
	a3.release()
	a5 := receiveSlot(t, waiting[2])
	a4.release()
	a5.release()
	assertIdleSlotPool(t, p, 2)
}

func TestSlotPoolKeysTakeTurns(t *testing.T) {
	p := newSlotPool(1, nil)
	hold := mustAcquireSlot(t, p, "hold")
	var order []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	labels := []string{"a1", "a2", "a3", "b1", "b2", "b3", "c1", "c2", "c3"}
	keys := []string{"a", "a", "a", "b", "b", "b", "c", "c", "c"}
	queueOrdered(t, p, labels, keys, &order, &mu, &wg)
	hold()
	wg.Wait()
	want := []string{"a1", "b1", "c1", "a2", "b2", "c2", "a3", "b3", "c3"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("grant order = %v, want %v", order, want)
	}
	assertIdleSlotPool(t, p, 1)
}

func TestSlotPoolRespectsPerKeyCaps(t *testing.T) {
	caps := map[string]int{"a": 1, "big": 10}
	p := newSlotPool(4, func(key string) int { return caps[key] })
	a1 := mustAcquireSlot(t, p, "a")
	a2 := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	// A is at its cap of one, so its waiter stays queued while slots are free.
	assertSlotWaiting(t, a2)
	b1 := mustAcquireSlot(t, p, "b")
	big1 := mustAcquireSlot(t, p, "big")
	want := slotSnapshot{Capacity: 4, InUse: 3, Queued: 1, Keys: map[string]slotUsage{
		"a":   {InUse: 1, Queued: 1, Limit: 1},
		"b":   {InUse: 1, Limit: 4},
		"big": {InUse: 1, Limit: 4},
	}}
	if got := p.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capped snapshot = %#v, want %#v", got, want)
	}
	// The free slot goes to B rather than to A, which is still at its cap.
	b2 := mustAcquireSlot(t, p, "b")
	assertSlotWaiting(t, a2)
	a1()
	gotA2 := receiveSlot(t, a2)
	if gotA2.err != nil {
		t.Fatal(gotA2.err)
	}
	gotA2.release()
	b1()
	b2()
	big1()
	assertIdleSlotPool(t, p, 4)
}

func TestSlotPoolCancelRemovesWaiter(t *testing.T) {
	p := newSlotPool(1, nil)
	hold := mustAcquireSlot(t, p, "a")
	ctx, cancel := context.WithCancel(context.Background())
	canceled := startSlotAcquire(ctx, p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	next := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 2)
	cancel()
	if got := receiveSlot(t, canceled); !errors.Is(got.err, context.Canceled) || got.release != nil {
		t.Fatalf("canceled waiter = %v, release set %t", got.err, got.release != nil)
	}
	waitForSlotWaiters(t, p, "a", 1)
	if got := p.CapacitySnapshot(); got.InUse != 1 || got.Queued != 1 {
		t.Fatalf("after cancel = %#v", got)
	}
	// The next waiter receives the slot; the canceled one is gone.
	hold()
	gotNext := receiveSlot(t, next)
	if gotNext.err != nil {
		t.Fatal(gotNext.err)
	}
	gotNext.release()
	assertIdleSlotPool(t, p, 1)

	// A context that has already ended never queues or takes a free slot.
	if release, err := p.Acquire(ctx, "a"); !errors.Is(err, context.Canceled) || release != nil {
		t.Fatalf("acquire with ended context = %v, release set %t", err, release != nil)
	}
	assertIdleSlotPool(t, p, 1)
}

// A release and a cancellation that race must leave the pool without a
// leaked slot, whichever of them wins.
func TestSlotPoolGrantRacingCancelDoesNotLeak(t *testing.T) {
	p := newSlotPool(1, nil)
	for i := 0; i < 2000; i++ {
		hold := mustAcquireSlot(t, p, "hold")
		ctx, cancel := context.WithCancel(context.Background())
		result := startSlotAcquire(ctx, p, "waiter")
		waitForSlotWaiters(t, p, "waiter", 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); hold() }()
		go func() { defer wg.Done(); cancel() }()
		wg.Wait()
		got := receiveSlot(t, result)
		switch {
		case got.err == nil:
			got.release()
		case !errors.Is(got.err, context.Canceled):
			t.Fatalf("iteration %d: waiter error = %v", i, got.err)
		}
		if snapshot := p.CapacitySnapshot(); snapshot.InUse != 0 || snapshot.Queued != 0 || len(snapshot.Keys) != 0 {
			t.Fatalf("iteration %d: leaked slot state %#v", i, snapshot)
		}
	}
	// The pool is still whole: its only slot can be taken.
	mustAcquireSlot(t, p, "after")()
}

// A waiter that is granted a slot after its context ended hands the slot on
// instead of keeping it. The test grants the slot while the waiter is blocked
// on the pool lock in its cancellation path.
func TestSlotPoolReleasesGrantThatLostToCancel(t *testing.T) {
	deadline := time.Now().Add(20 * time.Second)
	for hits := 0; hits < 3; {
		if time.Now().After(deadline) {
			t.Fatalf("a grant racing with cancellation was observed %d times", hits)
		}
		p := newSlotPool(1, nil)
		mustAcquireSlot(t, p, "hold")
		ctx, cancel := context.WithCancel(context.Background())
		result := startSlotAcquire(ctx, p, "waiter")
		waitForSlotWaiters(t, p, "waiter", 1)
		next := startSlotAcquire(context.Background(), p, "next")
		waitForSlotWaiters(t, p, "next", 1)
		p.mu.Lock()
		cancel()
		time.Sleep(time.Millisecond)
		// Frees the held slot; the waiter arrived first, so it is granted.
		p.releaseLocked("hold")
		p.mu.Unlock()
		got := receiveSlot(t, result)
		switch {
		case got.err == nil:
			// The waiter saw the grant before the cancellation.
			got.release()
		case errors.Is(got.err, context.Canceled):
			hits++
		default:
			t.Fatalf("waiter error = %v", got.err)
		}
		// Either way the slot reaches the next waiter.
		gotNext := receiveSlot(t, next)
		if gotNext.err != nil {
			t.Fatal(gotNext.err)
		}
		gotNext.release()
		assertIdleSlotPool(t, p, 1)
	}
}

func TestSlotPoolFailWaiters(t *testing.T) {
	p := newSlotPool(1, nil)
	held := mustAcquireSlot(t, p, "a")
	failA1 := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	failA2 := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 2)
	b := startSlotAcquire(context.Background(), p, "b")
	waitForSlotWaiters(t, p, "b", 1)

	unitDisabled := errors.New("unit disabled")
	p.FailWaiters("a", unitDisabled)
	for _, result := range []<-chan slotResult{failA1, failA2} {
		if got := receiveSlot(t, result); !errors.Is(got.err, unitDisabled) || got.release != nil {
			t.Fatalf("failed waiter = %v, release set %t", got.err, got.release != nil)
		}
	}
	// The slot A holds and B's waiter are untouched.
	want := slotSnapshot{Capacity: 1, InUse: 1, Queued: 1, Keys: map[string]slotUsage{
		"a": {InUse: 1, Limit: 1},
		"b": {Queued: 1, Limit: 1},
	}}
	if got := p.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after FailWaiters = %#v, want %#v", got, want)
	}
	held()
	gotB := receiveSlot(t, b)
	if gotB.err != nil {
		t.Fatal(gotB.err)
	}

	// Without a reason the waiters still fail, with a generic error.
	c := startSlotAcquire(context.Background(), p, "c")
	waitForSlotWaiters(t, p, "c", 1)
	p.FailWaiters("c", nil)
	if got := receiveSlot(t, c); !errors.Is(got.err, errSlotWaitFailed) {
		t.Fatalf("FailWaiters without a reason = %v", got.err)
	}
	// An unknown key is a no-op.
	p.FailWaiters("unknown", unitDisabled)
	gotB.release()
	assertIdleSlotPool(t, p, 1)
}

// A waiter that FailWaiters removes while its context ends returns either
// error and never holds a slot. The test cancels while holding the pool lock,
// so the waiter usually reaches its cancellation path after the failure.
func TestSlotPoolFailedWaiterWithEndedContext(t *testing.T) {
	unitDisabled := errors.New("unit disabled")
	deadline := time.Now().Add(20 * time.Second)
	for hits := 0; hits < 3; {
		if time.Now().After(deadline) {
			t.Fatalf("a failure racing with cancellation was observed %d times", hits)
		}
		p := newSlotPool(1, nil)
		held := mustAcquireSlot(t, p, "a")
		ctx, cancel := context.WithCancel(context.Background())
		result := startSlotAcquire(ctx, p, "a")
		waitForSlotWaiters(t, p, "a", 1)
		p.mu.Lock()
		cancel()
		time.Sleep(time.Millisecond)
		p.mu.Unlock()
		p.FailWaiters("a", unitDisabled)
		got := receiveSlot(t, result)
		switch {
		case errors.Is(got.err, unitDisabled):
			hits++
		case !errors.Is(got.err, context.Canceled):
			t.Fatalf("waiter error = %v", got.err)
		}
		if got.release != nil {
			t.Fatal("a failed or canceled waiter received a release function")
		}
		held()
		assertIdleSlotPool(t, p, 1)
	}
}

func TestSlotPoolResize(t *testing.T) {
	p := newSlotPool(1, nil)
	first := mustAcquireSlot(t, p, "a")
	second := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	third := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 2)

	// Growing the capacity grants queued waiters at once.
	p.SetCapacity(3, nil)
	gotSecond, gotThird := receiveSlot(t, second), receiveSlot(t, third)
	if gotSecond.err != nil || gotThird.err != nil {
		t.Fatalf("grow grants: %v, %v", gotSecond.err, gotThird.err)
	}
	if got := p.CapacitySnapshot(); got.Capacity != 3 || got.InUse != 3 || got.Queued != 0 {
		t.Fatalf("after grow = %#v", got)
	}

	// Shrinking never takes slots back; it only holds back new grants until
	// use drops below the new capacity.
	p.SetCapacity(1, nil)
	if got := p.CapacitySnapshot(); got.Capacity != 1 || got.InUse != 3 {
		t.Fatalf("after shrink = %#v", got)
	}
	fourth := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	first()
	assertSlotWaiting(t, fourth)
	gotSecond.release()
	assertSlotWaiting(t, fourth)
	gotThird.release()
	gotFourth := receiveSlot(t, fourth)
	if gotFourth.err != nil {
		t.Fatal(gotFourth.err)
	}
	if got := p.CapacitySnapshot(); got.InUse != 1 || got.Queued != 0 {
		t.Fatalf("after shrink drains = %#v", got)
	}

	// Raising a key's cap through a new cap source also wakes its waiters.
	p.SetCapacity(2, func(string) int { return 1 })
	fifth := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	assertSlotWaiting(t, fifth)
	p.SetCapacity(2, nil)
	gotFifth := receiveSlot(t, fifth)
	if gotFifth.err != nil {
		t.Fatal(gotFifth.err)
	}
	gotFourth.release()
	gotFifth.release()

	// A capacity below zero grants nothing, like a capacity of zero.
	p.SetCapacity(-1, nil)
	blocked := startSlotAcquire(context.Background(), p, "a")
	waitForSlotWaiters(t, p, "a", 1)
	if got := p.CapacitySnapshot(); got.Capacity != 0 || got.InUse != 0 {
		t.Fatalf("negative capacity = %#v", got)
	}
	p.SetCapacity(1, nil)
	gotBlocked := receiveSlot(t, blocked)
	if gotBlocked.err != nil {
		t.Fatal(gotBlocked.err)
	}
	gotBlocked.release()
	assertIdleSlotPool(t, p, 1)
}

func TestSlotPoolSnapshotCounts(t *testing.T) {
	p := newSlotPool(3, func(key string) int {
		if key == "capped" {
			return 1
		}
		return 0
	})
	assertIdleSlotPool(t, p, 3)
	capped := mustAcquireSlot(t, p, "capped")
	cappedWaiter := startSlotAcquire(context.Background(), p, "capped")
	waitForSlotWaiters(t, p, "capped", 1)
	open1 := mustAcquireSlot(t, p, "open")
	open2 := mustAcquireSlot(t, p, "open")
	openWaiter := startSlotAcquire(context.Background(), p, "open")
	waitForSlotWaiters(t, p, "open", 1)
	want := slotSnapshot{Capacity: 3, InUse: 3, Queued: 2, Keys: map[string]slotUsage{
		"capped": {InUse: 1, Queued: 1, Limit: 1},
		"open":   {InUse: 2, Queued: 1, Limit: 3},
	}}
	if got := p.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %#v, want %#v", got, want)
	}
	// The snapshot is a copy: changing it does not change the pool.
	snapshot := p.CapacitySnapshot()
	snapshot.Keys["open"] = slotUsage{}
	if got := p.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot after caller edit = %#v, want %#v", got, want)
	}
	capped()
	gotCapped := receiveSlot(t, cappedWaiter)
	open1()
	gotOpen := receiveSlot(t, openWaiter)
	want = slotSnapshot{Capacity: 3, InUse: 3, Keys: map[string]slotUsage{
		"capped": {InUse: 1, Limit: 1},
		"open":   {InUse: 2, Limit: 3},
	}}
	if got := p.CapacitySnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot after grants = %#v, want %#v", got, want)
	}
	gotCapped.release()
	gotOpen.release()
	open2()
	assertIdleSlotPool(t, p, 3)
}
