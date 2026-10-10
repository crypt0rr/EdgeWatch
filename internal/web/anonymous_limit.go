package web

import (
	"container/list"
	"time"
)

const (
	// anonymousRequestLimit is the number of requests that one client may
	// send in one anonymous rate-limit namespace, such as one public page,
	// in anonymousWindowSeconds.
	anonymousRequestLimit = 120
	// publicPagesRequestLimit is the number of requests that one client may
	// send for all public pages together in anonymousWindowSeconds. Every
	// well-formed slug has a namespace of its own, so without it a client
	// could rotate slugs for unlimited lookups. It allows several busy
	// pages, so it rarely couples the pages of clients that share one
	// address.
	publicPagesRequestLimit = 600
	// publicPagesRateLimit is the namespace of publicPagesRequestLimit.
	publicPagesRateLimit = "public-any"
	// anonymousWindowSeconds is the length of the anonymous rate-limit
	// window: a request counts in the second it arrives and the 59 after.
	anonymousWindowSeconds = 60
	// anonymousBucketLimit bounds the number of anonymous rate-limit
	// buckets. Beyond it the least recently used bucket is dropped.
	anonymousBucketLimit = 4096
)

// anonymousBudget is a limit on the requests that a client may send in a
// namespace in anonymousWindowSeconds.
type anonymousBudget struct {
	namespace string
	limit     int
}

// anonymousBucket counts the requests of one client in one namespace, per
// second of the window, in a ring indexed by the Unix second. Its size does
// not depend on the limit.
type anonymousBucket struct {
	key    string
	counts [anonymousWindowSeconds]uint16
	// second is the Unix second of the bucket's latest count, and total
	// the requests counted in the window that ends with it.
	second int64
	total  int
}

// advance moves the bucket's window to end at the second, dropping the
// counts of the seconds that left it. A second before the latest count,
// after the clock went back, keeps the window where it is.
func (b *anonymousBucket) advance(second int64) {
	if second <= b.second {
		return
	}
	if second-b.second >= anonymousWindowSeconds {
		b.counts, b.total = [anonymousWindowSeconds]uint16{}, 0
	} else {
		for passed := b.second + 1; passed <= second; passed++ {
			slot := passed % anonymousWindowSeconds
			b.total -= int(b.counts[slot])
			b.counts[slot] = 0
		}
	}
	b.second = second
}

// anonymousBuckets holds the anonymous rate-limit buckets by key, in the
// order of their last use, most recent first. A request reads and counts
// only its own buckets, and expiry and the bound drop buckets from the
// least recently used end, so neither scans the buckets.
type anonymousBuckets struct {
	entries map[string]*list.Element
	order   list.List
}

// len returns the number of buckets.
func (b *anonymousBuckets) len() int {
	return len(b.entries)
}

// get returns the bucket of the key, with its window ending at the second,
// and marks it most recently used, so a client that keeps sending requests
// keeps its bucket. It returns nil when the key has no bucket.
func (b *anonymousBuckets) get(key string, second int64) *anonymousBucket {
	element := b.entries[key]
	if element == nil {
		return nil
	}
	b.order.MoveToFront(element)
	bucket := element.Value.(*anonymousBucket)
	bucket.advance(second)
	return bucket
}

// count counts a request in the second in the bucket of the key, which it
// creates when the key has none, and then drops the least recently used
// buckets beyond anonymousBucketLimit. Dropping a bucket forgets its
// client's requests in the namespace, which only lets that client send
// more.
func (b *anonymousBuckets) count(key string, second int64) {
	bucket := b.get(key, second)
	if bucket == nil {
		if b.entries == nil {
			b.entries = map[string]*list.Element{}
		}
		bucket = &anonymousBucket{key: key, second: second}
		b.entries[key] = b.order.PushFront(bucket)
	}
	bucket.counts[second%anonymousWindowSeconds]++
	bucket.total++
	for len(b.entries) > anonymousBucketLimit {
		b.remove(b.order.Back())
	}
}

// expire drops the least recently used buckets that counted nothing in the
// window that ends at the second. It stops at the first bucket that still
// counts a request, so its cost is the buckets that it drops.
func (b *anonymousBuckets) expire(second int64) {
	for element := b.order.Back(); element != nil; element = b.order.Back() {
		if second-element.Value.(*anonymousBucket).second < anonymousWindowSeconds {
			return
		}
		b.remove(element)
	}
}

func (b *anonymousBuckets) remove(element *list.Element) {
	delete(b.entries, element.Value.(*anonymousBucket).key)
	b.order.Remove(element)
}

// allowAnonymous admits an anonymous request of the client when each of
// the budgets has room for it, and then counts it in each. A refused
// request counts in none, so a client that a page refuses can still use
// the rest of its budget for all pages, but it keeps the buckets that
// refused it in use.
func (s *Server) allowAnonymous(identity string, now time.Time, budgets ...anonymousBudget) bool {
	second := now.Unix()
	s.publicMu.Lock()
	defer s.publicMu.Unlock()
	s.publicHits.expire(second)
	allowed := true
	for _, budget := range budgets {
		if bucket := s.publicHits.get(budget.namespace+":"+identity, second); bucket != nil && bucket.total >= budget.limit {
			allowed = false
		}
	}
	if !allowed {
		return false
	}
	for _, budget := range budgets {
		s.publicHits.count(budget.namespace+":"+identity, second)
	}
	return true
}
