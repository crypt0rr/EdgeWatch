package store

import (
	"context"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// jobTenantSQL is the tenant_id of a row that belongs to a job, derived from
// the job's row inside the write transaction. It takes one argument, the job
// ID. A job from config.yaml has no ID and belongs to the default tenant. An
// ID without a jobs row yields NULL, which the schema 53 guard triggers
// refuse.
const jobTenantSQL = `(SELECT CASE WHEN owner.id='' THEN '` + DefaultTenantID + `' ELSE (SELECT tenant_id FROM jobs WHERE jobs.id=owner.id) END FROM (SELECT COALESCE(?,'') AS id) AS owner)`

// eventTenantSQL returns the tenant_id of an event row, and of the outbox
// rows queued for the event, with its arguments. A job's event belongs to
// the job's tenant, as the job's scans do. An event without a job, such as
// an update alert, belongs to the platform and has no tenant.
func eventTenantSQL(event model.Event) (string, []any) {
	if event.JobID == "" && event.Job == "" {
		return "NULL", nil
	}
	return jobTenantSQL, []any{event.JobID}
}

// insertEventExec writes an event row with its payload, stored at
// createdAt, and the tenant that eventTenantSQL derives.
func insertEventExec(ctx context.Context, execer contextExecer, event model.Event, payload []byte, createdAt time.Time) error {
	tenantSQL, tenantArgs := eventTenantSQL(event)
	args := append([]any{event.Type, event.Job, event.JobID, event.ScanID, payload, sqliteTimestamp(createdAt)}, tenantArgs...)
	_, err := execer.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,?,`+tenantSQL+`)`, args...)
	return err
}
