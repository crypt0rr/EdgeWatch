package app

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/crypt0rr/edgewatch/internal/store"
)

// defaultSlotKey is the scan-slot key every job uses. It is the default
// tenant, which owns every job for now, so a single key keeps the
// deployment's scheduling identical to one FIFO semaphore.
//
// TODO(#839): use the job's tenant ID once job records carry it.
const defaultSlotKey = store.DefaultTenantID

// errSlotWaitFailed is returned to waiters that FailWaiters removed without
// giving a reason.
var errSlotWaitFailed = errors.New("scan slot wait failed")

// slotPool hands out the deployment's scan slots. Capacity is the global
// number of slots, max_concurrent_scans. A key identifies a tenant; capFor
// may limit a key to fewer slots than the global capacity, and 0 means no
// limit below it.
//
// Each key has a FIFO queue of waiters. When a slot is free, it goes to the
// head waiter of the eligible key that was granted a slot least recently, so
// keys with waiters take turns and a key with many queued scans cannot starve
// one with a single scan. A key is eligible while it has waiters and uses
// fewer slots than its cap. With one key the pool is a FIFO semaphore.
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
}

// slotKey holds one key's state. It exists only while the key uses a slot or
// has waiters, so the map stays bounded by the keys that are active.
type slotKey struct {
	inUse int
	// lastGrant orders keys for round-robin grants; 0 means the key has not
	// been granted a slot since it last became idle.
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
	return &slotPool{capacity: max(capacity, 0), capFor: capFor, keys: map[string]*slotKey{}}
}

// Acquire waits for a slot for key. The returned release function gives the
// slot back and may be called more than once. Acquire returns ctx.Err() when
// ctx ends first, including when a grant races with the cancellation: that
// slot is released at once so it cannot leak. A waiter that FailWaiters
// removes returns the error passed to it.
func (p *slotPool) Acquire(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w := &slotWaiter{key: key, ready: make(chan struct{})}
	p.mu.Lock()
	k := p.keys[key]
	if k == nil {
		k = &slotKey{}
		p.keys[key] = k
	}
	p.arrivals++
	w.arrival = p.arrivals
	w.elem = k.waiters.PushBack(w)
	p.queued++
	p.dispatchLocked()
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

// limitLocked returns the most slots key may hold: its cap when that is set
// and below the global capacity, otherwise the global capacity.
func (p *slotPool) limitLocked(key string) int {
	limit := p.capacity
	if p.capFor != nil {
		if keyCap := p.capFor(key); keyCap > 0 && keyCap < limit {
			limit = keyCap
		}
	}
	return limit
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
			return
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
	}
}
