package app

import (
	"sync"

	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// runRegistry is this process's record of the runs of its jobs. A run is
// accepted when StartManagedRun reserves its job for a web-triggered run, or
// when runJob claims the job. It may then wait in a queue for a scan slot,
// and it runs once it holds the job's lease, until runJob returns. One mutex
// guards every job's entry, so each transition is atomic: in particular, a
// run leaves the queue in the same step that makes its scan visible to
// ActiveScans and CancelScan.
//
// The zero value is an empty registry.
type runRegistry struct {
	mu   sync.Mutex
	jobs map[string]*jobRun
	// scans holds the running scans by scan ID.
	scans map[string]*activeRun
}

// jobRun is the registry's entry of one job. It exists while any of its
// fields is set.
type jobRun struct {
	// reservation is the token of the web-triggered run that
	// StartManagedRun accepted, until that run's goroutine releases it.
	// Scheduled runs of the job are refused meanwhile, so the accepted run
	// gets the job.
	reservation string
	// claimed is set while runJob runs the job.
	claimed bool
	// queued is the run's wait for a scan slot, from the moment the slot
	// pool queues it until the run starts its scan or gives up.
	queued *queuedRun
	// scanID is the ID of the run's scan while it runs.
	scanID string
}

func (e *jobRun) empty() bool {
	return e.reservation == "" && !e.claimed && e.queued == nil && e.scanID == ""
}

// entry returns the job's entry, creating it. The caller holds mu.
func (r *runRegistry) entry(jobID string) *jobRun {
	if r.jobs == nil {
		r.jobs = map[string]*jobRun{}
	}
	e := r.jobs[jobID]
	if e == nil {
		e = &jobRun{}
		r.jobs[jobID] = e
	}
	return e
}

// tidy drops the job's entry once it is empty. The caller holds mu.
func (r *runRegistry) tidy(jobID string) {
	if e := r.jobs[jobID]; e != nil && e.empty() {
		delete(r.jobs, jobID)
	}
}

// reserve reserves the job for a web-triggered run with token. It returns
// scanner.ErrBusy when the job is reserved or a run of it is running.
func (r *runRegistry) reserve(jobID, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entry(jobID)
	if e.reservation != "" || e.claimed {
		r.tidy(jobID)
		return scanner.ErrBusy
	}
	e.reservation = token
	return nil
}

// unreserve ends the job's reservation if token still holds it, so a run
// can never release a newer run's reservation.
func (r *runRegistry) unreserve(jobID, token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.jobs[jobID]; e != nil && e.reservation == token {
		e.reservation = ""
		r.tidy(jobID)
	}
}

// claim claims the job for a run. It returns scanner.ErrBusy when a run of
// the job is running, and, for a scheduled run, also while the job is
// reserved for a web-triggered run.
func (r *runRegistry) claim(jobID string, manual bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entry(jobID)
	if e.claimed || (!manual && e.reservation != "") {
		r.tidy(jobID)
		return scanner.ErrBusy
	}
	e.claimed = true
	return nil
}

// unclaim ends the job's claim when its run returns.
func (r *runRegistry) unclaim(jobID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.jobs[jobID]; e != nil {
		e.claimed = false
		r.tidy(jobID)
	}
}

// enqueue records that the job's run waits for a scan slot.
func (r *runRegistry) enqueue(jobID string, queued *queuedRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entry(jobID).queued = queued
}

// dequeue ends the job's wait for a scan slot if it is still queued's.
func (r *runRegistry) dequeue(jobID string, queued *queuedRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.jobs[jobID]; e != nil && e.queued == queued {
		e.queued = nil
		r.tidy(jobID)
	}
}

// queuedRun returns the job's wait for a scan slot, if it waits.
func (r *runRegistry) queuedRun(jobID string) (*queuedRun, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.jobs[jobID]; e != nil && e.queued != nil {
		return e.queued, true
	}
	return nil, false
}

// queuedRuns returns every wait for a scan slot.
func (r *runRegistry) queuedRuns() []*queuedRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	var queued []*queuedRun
	for _, e := range r.jobs {
		if e.queued != nil {
			queued = append(queued, e.queued)
		}
	}
	return queued
}

// start makes the scan of the job's run visible to ActiveScans and
// CancelScan and, in the same step, ends the run's wait for a scan slot. A
// run without a job ID, as some tests register, only becomes visible.
func (r *runRegistry) start(jobID, scanID string, run *activeRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.scans == nil {
		r.scans = map[string]*activeRun{}
	}
	r.scans[scanID] = run
	if jobID == "" {
		return
	}
	e := r.entry(jobID)
	e.queued = nil
	e.scanID = scanID
}

// finish removes the scan of the job's run when the run ends.
func (r *runRegistry) finish(jobID, scanID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.scans, scanID)
	if e := r.jobs[jobID]; e != nil && e.scanID == scanID {
		e.scanID = ""
		r.tidy(jobID)
	}
}

// scan returns the running scan with the ID.
func (r *runRegistry) scan(scanID string) (*activeRun, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run, ok := r.scans[scanID]
	return run, ok
}

// activeRuns returns every running scan.
func (r *runRegistry) activeRuns() []*activeRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	runs := make([]*activeRun, 0, len(r.scans))
	for _, run := range r.scans {
		runs = append(runs, run)
	}
	return runs
}

// size counts the jobs with an entry and the running scans.
func (r *runRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.jobs) + len(r.scans)
}
