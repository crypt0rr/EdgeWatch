package store

// scanCyclesCompletedExecutionIndex lists each job's completed cycles by
// execution hash, newest first, with the attempt columns of a cycle's
// duration sample, so ListCompletedScanCycleDurations reads a job's newest
// samples without reading or sorting its cycle history and plans.
const scanCyclesCompletedExecutionIndex = "scan_cycles_completed_execution"

// migration79Statements adds the partial index of completed cycles that the
// scan-slot demand estimate reads. Building it reads each scan cycle once;
// no row changes.
func migration79Statements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS ` + scanCyclesCompletedExecutionIndex + ` ON scan_cycles(job_id,execution_hash,finished_at DESC,id DESC,attempt_count,started_at,attempt_started_at) WHERE status='completed'`,
	}
}
