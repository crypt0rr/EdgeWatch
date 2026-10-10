package app

import (
	"errors"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// reservationOf returns the job's reservation token.
func (r *runRegistry) reservationOf(jobID string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.jobs[jobID]; e != nil && e.reservation != "" {
		return e.reservation, true
	}
	return "", false
}

// replaceReservation gives the job's reservation to token, as a newer run
// takes it once an earlier run released its reservation before returning.
func (r *runRegistry) replaceReservation(jobID, token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entry(jobID).reservation = token
}

// claimed reports whether a run of the job holds it.
func (r *runRegistry) claimed(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.jobs[jobID]
	return e != nil && e.claimed
}

// The registry's transitions refuse a second run of a job and keep an entry
// only while something holds it.
func TestRunRegistryTransitions(t *testing.T) {
	t.Parallel()
	var r runRegistry
	if err := r.reserve("job", "first"); err != nil {
		t.Fatal(err)
	}
	if err := r.reserve("job", "second"); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("second reservation = %v, want ErrBusy", err)
	}
	// A scheduled run waits for the reserved web-triggered run; the
	// reserved run itself claims the job.
	if err := r.claim("job", false); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("scheduled claim of a reserved job = %v, want ErrBusy", err)
	}
	if err := r.claim("job", true); err != nil {
		t.Fatal(err)
	}
	if err := r.claim("job", true); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("second claim = %v, want ErrBusy", err)
	}
	r.unreserve("job", "other")
	if token, ok := r.reservationOf("job"); !ok || token != "first" {
		t.Fatalf("reservation after another token's release = %q, %t", token, ok)
	}
	r.unreserve("job", "first")
	if err := r.reserve("job", "third"); !errors.Is(err, scanner.ErrBusy) {
		t.Fatalf("reservation of a claimed job = %v, want ErrBusy", err)
	}

	queued := &queuedRun{}
	r.enqueue("job", queued)
	if got, ok := r.queuedRun("job"); !ok || got != queued || len(r.queuedRuns()) != 1 {
		t.Fatalf("queued run = %p, %t", got, ok)
	}
	r.dequeue("job", &queuedRun{})
	if _, ok := r.queuedRun("job"); !ok {
		t.Fatal("another wait ended the job's wait")
	}
	// Starting the scan ends the wait in the same step.
	run := &activeRun{}
	r.start("job", "scan", run)
	if _, ok := r.queuedRun("job"); ok {
		t.Fatal("the job still waited after its scan started")
	}
	if got, ok := r.scan("scan"); !ok || got != run || len(r.activeRuns()) != 1 {
		t.Fatalf("running scan = %p, %t", got, ok)
	}
	r.finish("job", "scan")
	r.unclaim("job")
	if _, ok := r.scan("scan"); ok || r.size() != 0 {
		t.Fatalf("registry after the run ended has %d entries", r.size())
	}
	r.unclaim("missing")
	r.dequeue("missing", queued)
	r.finish("missing", "missing")
	if r.size() != 0 {
		t.Fatalf("releasing unknown runs created %d entries", r.size())
	}
}
