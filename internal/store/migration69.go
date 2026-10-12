package store

// migration69Statements adds durable, one-off planned change windows. Change
// references belong to the window rather than prunable event rows, so the
// close review remains complete for the configured history retention.
func migration69Statements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS change_windows (
 id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL,
 start_at TEXT NOT NULL,
 end_at TEXT NOT NULL,
 timezone TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 512),
 actor_user_id TEXT NOT NULL DEFAULT '',
 actor_label TEXT NOT NULL,
 created_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('scheduled','active','closed','cancelled')),
 end_reason TEXT NOT NULL DEFAULT '',
 closed_at TEXT NOT NULL DEFAULT '',
 effective_end TEXT NOT NULL DEFAULT '',
 new_count INTEGER NOT NULL DEFAULT 0 CHECK(new_count>=0),
 recovered_count INTEGER NOT NULL DEFAULT 0 CHECK(recovered_count>=0),
 still_open_count INTEGER NOT NULL DEFAULT 0 CHECK(still_open_count>=0),
	suppressed_event_count INTEGER NOT NULL DEFAULT 0 CHECK(suppressed_event_count>=0),
	in_flight_event_count INTEGER NOT NULL DEFAULT 0 CHECK(in_flight_event_count>=0),
	unknown_outcome_event_count INTEGER NOT NULL DEFAULT 0 CHECK(unknown_outcome_event_count>=0),
	incomplete_event_count INTEGER NOT NULL DEFAULT 0 CHECK(incomplete_event_count>=0),
 summary_json BLOB NOT NULL DEFAULT '',
 review_state TEXT NOT NULL DEFAULT 'none' CHECK(review_state IN ('none','due','reviewed')),
 reviewed_at TEXT NOT NULL DEFAULT '',
 reviewer_label TEXT NOT NULL DEFAULT '',
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);`,
		`CREATE INDEX IF NOT EXISTS change_windows_job_interval ON change_windows(job_id,start_at,end_at)`,
		`CREATE INDEX IF NOT EXISTS change_windows_job_latest ON change_windows(job_id,start_at DESC,id DESC)`,
		`CREATE INDEX IF NOT EXISTS change_windows_expiry ON change_windows(status,end_at,closed_at)`,
		`CREATE INDEX IF NOT EXISTS change_windows_retention ON change_windows(closed_at) WHERE closed_at<>''`,
		`CREATE TABLE IF NOT EXISTS change_window_events (
 window_id TEXT NOT NULL,
 event_key TEXT NOT NULL,
 event_type TEXT NOT NULL,
 scan_id TEXT NOT NULL DEFAULT '',
 event_at TEXT NOT NULL,
 disposition TEXT NOT NULL DEFAULT 'suppressed' CHECK(disposition IN ('suppressed','in_flight','unknown_outcome')),
 details_complete INTEGER NOT NULL CHECK(details_complete IN (0,1)),
 reported_count INTEGER NOT NULL DEFAULT 0 CHECK(reported_count>=0),
 PRIMARY KEY(window_id,event_key),
 FOREIGN KEY(window_id) REFERENCES change_windows(id) ON DELETE CASCADE
);`,
		`CREATE TABLE IF NOT EXISTS change_window_refs (
 window_id TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('new','recovered')),
 change_key TEXT NOT NULL,
 change_json BLOB NOT NULL,
 event_key TEXT NOT NULL,
 event_type TEXT NOT NULL,
 scan_id TEXT NOT NULL DEFAULT '',
 event_at TEXT NOT NULL,
 PRIMARY KEY(window_id,category,change_key),
 FOREIGN KEY(window_id) REFERENCES change_windows(id) ON DELETE CASCADE
);`,
		`CREATE INDEX IF NOT EXISTS change_window_refs_event ON change_window_refs(window_id,event_key)`,
		`ALTER TABLE outbox ADD COLUMN event_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE outbox ADD COLUMN event_job_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE outbox ADD COLUMN change_window_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE outbox ADD COLUMN attempt_started_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE outbox ADD COLUMN coalesce_after_attempt INTEGER NOT NULL DEFAULT 0 CHECK(coalesce_after_attempt IN (0,1))`,
		`ALTER TABLE outbox ADD COLUMN coalesced_at TEXT NOT NULL DEFAULT ''`,
		`UPDATE outbox SET event_type=COALESCE(json_extract(CAST(payload_json AS TEXT),'$.type'),''),event_job_id=COALESCE(json_extract(CAST(payload_json AS TEXT),'$.job_id'),'' ) WHERE json_valid(CAST(payload_json AS TEXT))`,
		`CREATE INDEX IF NOT EXISTS outbox_change_window_pending ON outbox(change_window_id,sent_at,terminal_at,coalesced_at,id)`,
		`CREATE INDEX IF NOT EXISTS outbox_job_change_pending ON outbox(event_job_id,event_type,sent_at,terminal_at,id)`,
	}
}
