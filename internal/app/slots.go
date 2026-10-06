package app

import (
	"container/list"
	"context"
	"errors"
	"sync"
)

// errSlotWaitFailed is returned to waiters that FailWaiters removed without
// giving a reason.
var errSlotWaitFailed = errors.New("scan slot wait failed")

// slotPool hands out the deployment's scan slots. Capacity is the global
// number of slots, max_concurrent_scans. A key identifies a tenant: a run
// takes a slot under the ID of its job's tenant, and a config.yaml job under
// the default tenant's. capFor may limit a key to fewer slots than the global
// capacity, and 0 means no limit below it. The application builds capFor
// from each tenant's max_concurrent_scans; see tenantSlotCaps.
//
// Each key has a FIFO queue of waiters. When a slot is free, it goes to the
// head waiter of the eligible key that was granted a slot least recently, so
// keys with waiters take turns and a key with many queued scans cannot starve
// one with a single scan. The pool retains relevant grant ages for idle keys,
// so a key that queues again does not jump ahead of keys that have waited
// longer. A key is eligible while it has waiters and uses fewer slots than
// its cap. With one key the pool is a FIFO semaphore.
//
// A free slot and an eligible waiter never coexist once a call returns: every
// change that can free a slot or make a waiter eligible dispatches before it
// releases the lock.
type slotPool struct {
	mu       sync.Mutex
	capacity int
	// capFor is called with mu held and must not call back into the pool.
	capFor   func(key string) int
	inUse    int
	queued   int
	grants   uint64
	arrivals uint64
	keys     map[string]*slotKey
	// idleGrants keeps the last grant age of idle keys while that age affects
	// ordering against active keys. Older ages sort before every active key and
	// can be forgotten without changing which active key wins next.
	idleGrants map[string]uint64
}

// slotKey holds one key's state. It exists only while the key uses a slot or
// has waiters, so the keys map stays bounded by active keys.
type slotKey struct {
	inUse int
	// lastGrant orders keys for round-robin grants; 0 means the key has no
	// retained grant age, either because it has never been granted or because
	// its idle age was older than every active key.
	lastGrant uint64
	waiters   list.List
}

type slotWaiterState int

const (
	slotWaiting slotWaiterState = iota
	slotGranted
	slotFailed
)

// slotWaiter is one Acquire call in a key's queue. The pool sets state and
// err under mu and then closes ready, so a reader that received from ready
// may read them without the lock.
type slotWaiter struct {
	key     string
	arrival uint64
	elem    *list.Element
	ready   chan struct{}
	state   slotWaiterState
	err     error
}

// slotUsage reports one key's slot use. Limit is the most slots the key may
// hold under the current capacity and cap.
type slotUsage struct {
	InUse  int
	Queued int
	Limit  int
}

// slotSnapshot reports slot use as counts only.
type slotSnapshot struct {
	Capacity int
	InUse    int
	Queued   int
	Keys     map[string]slotUsage
}

func newSlotPool(capacity int, capFor func(key string) int) *slotPool {
	return &slotPool{
		capacity:   max(capacity, 0),
		capFor:     capFor,
		keys:       map[string]*slotKey{},
		idleGrants: map[string]uint64{},
	}
}

// Acquire waits for a slot for key. The returned release function gives the
// slot back and may be called more than once. Acquire returns ctx.Err() when
// ctx ends first, including when a grant races with the cancellation: that
// slot is released at once so it cannot leak. A waiter that FailWaiters
// removes returns the error passed to it.
func (p *slotPool) Acquire(ctx context.Context, key string) (func(), error) {
	return p.AcquireWithQueued(ctx, key, nil)
}

// AcquireWithQueued behaves like Acquire and calls onQueued only when the
// waiter remains queued after the initial dispatch. The callback runs under
// the pool lock and must not call back into the pool.
func (p *slotPool) AcquireWithQueued(ctx context.Context, key string, onQueued func()) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &slotWaiter{key: key, ready: make(chan struct{})}
	p.mu.Lock()
	k := p.keys[key]
	if k == nil {
		k = &slotKey{lastGrant: p.idleGrants[key]}
		delete(p.idleGrants, key)
		p.keys[key] = k
	}
	p.arrivals++
	w.arrival = p.arrivals
	w.elem = k.waiters.PushBack(w)
	p.queued++
	p.dispatchLocked()
	if w.state == slotWaiting && onQueued != nil {
		onQueued()
	}
	p.mu.Unlock()

	select {
	case <-w.ready:
	case <-ctx.Done():
		p.mu.Lock()
		switch w.state {
		case slotWaiting:
			p.removeWaiterLocked(w)
			p.mu.Unlock()
			return nil, ctx.Err()
		case slotGranted:
			p.releaseLocked(key)
			p.mu.Unlock()
			return nil, ctx.Err()
		}
		p.mu.Unlock()
	}
	if w.state == slotFailed {
		return nil, w.err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.releaseLocked(key)
			p.mu.Unlock()
		})
	}, nil
}

// FailWaiters makes every queued waiter for key return err. Slots the key
// already holds are unaffected.
func (p *slotPool) FailWaiters(key string, err error) {
	if err == nil {
		err = errSlotWaitFailed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := p.keys[key]
	if k == nil {
		return
	}
	for e := k.waiters.Front(); e != nil; e = k.waiters.Front() {
		w := k.waiters.Remove(e).(*slotWaiter)
		w.elem = nil
		p.queued--
		w.state, w.err = slotFailed, err
		close(w.ready)
	}
	p.forgetIdleLocked(key, k)
}

// SetCapacity replaces the global capacity and the per-key cap source. A
// larger capacity or cap grants queued waiters at once. A smaller one never
// stops running scans; it only holds back new grants until use drops below
// the new limit.
func (p *slotPool) SetCapacity(capacity int, capFor func(key string) int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.capacity = max(capacity, 0)
	p.capFor = capFor
	p.dispatchLocked()
}

// SetCaps replaces the per-key cap source and keeps the global capacity. Like
// SetCapacity, a larger cap grants queued waiters at once, and a smaller one
// only holds back new grants.
func (p *slotPool) SetCaps(capFor func(key string) int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.capFor = capFor
	p.dispatchLocked()
}

// CapacitySnapshot returns the global capacity and slot use, and the use of
// every key that holds a slot or has waiters.
func (p *slotPool) CapacitySnapshot() slotSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := slotSnapshot{Capacity: p.capacity, InUse: p.inUse, Queued: p.queued, Keys: make(map[string]slotUsage, len(p.keys))}
	for key, k := range p.keys {
		snapshot.Keys[key] = slotUsage{InUse: k.inUse, Queued: k.waiters.Len(), Limit: p.limitLocked(key)}
	}
	return snapshot
}

// limitLocked returns the most slots key may hold; see slotLimit.
func (p *slotPool) limitLocked(key string) int {
	if p.capFor == nil {
		return p.capacity
	}
	return slotLimit(p.capacity, p.capFor(key))
}

// slotLimit returns the most slots a key may hold under the global capacity
// and the key's cap: the cap when it is set (above 0) and below the
// capacity, otherwise the capacity.
func slotLimit(capacity, keyCap int) int {
	if keyCap > 0 && keyCap < capacity {
		return keyCap
	}
	return capacity
}

// dispatchLocked grants free slots, one at a time, to the head waiter of the
// eligible key that was granted least recently. Ties between keys that have
// not been granted go to the waiter that arrived first.
func (p *slotPool) dispatchLocked() {
	for p.inUse < p.capacity {
		var next *slotKey
		var nextHead *slotWaiter
		for key, k := range p.keys {
			front := k.waiters.Front()
			if front == nil || k.inUse >= p.limitLocked(key) {
				continue
			}
			head := front.Value.(*slotWaiter)
			if next == nil || k.lastGrant < next.lastGrant || (k.lastGrant == next.lastGrant && head.arrival < nextHead.arrival) {
				next, nextHead = k, head
			}
		}
		if next == nil {
			break
		}
		next.waiters.Remove(nextHead.elem)
		nextHead.elem = nil
		p.queued--
		next.inUse++
		p.inUse++
		p.grants++
		next.lastGrant = p.grants
		nextHead.state = slotGranted
		close(nextHead.ready)
	}
	p.pruneIdleGrantsLocked()
}

func (p *slotPool) releaseLocked(key string) {
	k := p.keys[key]
	k.inUse--
	p.inUse--
	p.forgetIdleLocked(key, k)
	p.dispatchLocked()
}

func (p *slotPool) removeWaiterLocked(w *slotWaiter) {
	k := p.keys[w.key]
	k.waiters.Remove(w.elem)
	w.elem = nil
	p.queued--
	p.forgetIdleLocked(w.key, k)
}

func (p *slotPool) forgetIdleLocked(key string, k *slotKey) {
	if k.inUse == 0 && k.waiters.Len() == 0 {
		delete(p.keys, key)
		if k.lastGrant != 0 {
			p.idleGrants[key] = k.lastGrant
		}
		p.pruneIdleGrantsLocked()
	}
}

// pruneIdleGrantsLocked drops idle grant ages that are older than every
// active key. Such keys already sort ahead of all active keys; treating their
// age as zero preserves that ordering. With no active keys there is no turn
// order to preserve until a key queues again.
func (p *slotPool) pruneIdleGrantsLocked() {
	if len(p.idleGrants) == 0 {
		return
	}
	if len(p.keys) == 0 {
		clear(p.idleGrants)
		return
	}

	oldestActive := ^uint64(0)
	for _, k := range p.keys {
		if k.lastGrant < oldestActive {
			oldestActive = k.lastGrant
		}
	}
	if oldestActive == 0 {
		// Grant ages are positive, so none can be older than zero.
		return
	}
	for key, lastGrant := range p.idleGrants {
		if lastGrant < oldestActive {
			delete(p.idleGrants, key)
		}
	}
}
