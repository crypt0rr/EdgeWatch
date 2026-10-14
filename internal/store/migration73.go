package store

const (
	changeWindowsOpenLatestIndex    = "change_windows_open_latest"
	changeWindowsOpenScheduledIndex = "change_windows_open_scheduled"
	changeWindowsDueReviewIndex     = "change_windows_due_review"
	changeWindowsClosedHistoryIndex = "change_windows_closed_history"
)

// migration73Statements adds partial order indexes for the retained window
// groups that ListChangeWindows prioritizes. Each group contributes at most
// one page to its final ranked merge, so a large due-review history does not
// need to be sorted together with every other retained window.
func migration73Statements() []string {
	return []string{
		`CREATE INDEX IF NOT EXISTS ` + changeWindowsOpenLatestIndex + ` ON change_windows(job_id,start_at DESC,id DESC,end_at) WHERE closed_at=''`,
		`CREATE INDEX IF NOT EXISTS ` + changeWindowsOpenScheduledIndex + ` ON change_windows(job_id,start_at ASC,id DESC) WHERE closed_at=''`,
		`CREATE INDEX IF NOT EXISTS ` + changeWindowsDueReviewIndex + ` ON change_windows(job_id,start_at DESC,id DESC) WHERE closed_at<>'' AND review_state='due'`,
		`CREATE INDEX IF NOT EXISTS ` + changeWindowsClosedHistoryIndex + ` ON change_windows(job_id,start_at DESC,id DESC) WHERE closed_at<>'' AND review_state<>'due'`,
	}
}
