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
// the job's tenant, as the job's scans do. An event without a job belongs to
// the tenant it names, as a tenant's copy of an update alert does, or else
// to the platform, with no tenant.
func eventTenantSQL(event model.Event) (string, []any) {
	switch {
	case platformEvent(event):
		return "NULL", nil
	case tenantEvent(event):
		return "?", []any{event.TenantID}
	default:
		return jobTenantSQL, []any{event.JobID}
	}
}

// platformEvent reports whether an event belongs to the platform: an event
// without a job or a tenant, such as the platform's copy of an update alert.
func platformEvent(event model.Event) bool {
	return jobless(event) && event.TenantID == ""
}

// tenantEvent reports whether an event without a job belongs to the tenant
// it names, such as a tenant's copy of an update alert.
func tenantEvent(event model.Event) bool {
	return jobless(event) && event.TenantID != ""
}

// jobless reports whether an event has no job, managed or from config.yaml.
func jobless(event model.Event) bool {
	return event.JobID == "" && event.Job == ""
}

// insertEventExec writes an event row with its payload, stored at
// createdAt, and the tenant that eventTenantSQL derives.
func insertEventExec(ctx context.Context, execer contextExecer, event model.Event, payload []byte, createdAt time.Time) error {
	tenantSQL, tenantArgs := eventTenantSQL(event)
	args := append([]any{event.Type, event.Job, event.JobID, event.ScanID, payload, sqliteTimestamp(createdAt)}, tenantArgs...)
	_, err := execer.ExecContext(ctx, `INSERT INTO events(type,job,job_id,scan_id,payload_json,created_at,tenant_id) VALUES(?,?,?,?,?,?,`+tenantSQL+`)`, args...)
	return err
}
