package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/crypt0rr/edgewatch/internal/model"
)

// The paged runtime reads below decode only the members of the runtime JSON
// that a page needs. encoding/json skips the other members, including the
// baseline host evidence and the candidate snapshot, without building them,
// so a page allocates its own items rather than a copy of the whole state.
// The SQLite JSON functions are no cheaper here: each call on the stored
// BLOB parses the whole document again.

// RuntimePendingChange is one unconfirmed change in the runtime state of a
// job, under its key in JobState.Pending.
type RuntimePendingChange struct {
	Key    string
	Change model.Change
	Count  int
}

// RuntimePendingChangesPage returns one page of the pending changes of one
// of the tenant's jobs, ordered by target, protocol, port, kind and key. It
// decodes the pending changes of the runtime state but not its baseline or
// candidate snapshots. An unknown job and a job of another tenant have none.
func (ts *TenantStore) RuntimePendingChangesPage(ctx context.Context, jobID string, limit, offset int) (Page[RuntimePendingChange], error) {
	if err := ts.ready(); err != nil {
		return Page[RuntimePendingChange]{}, err
	}
	limit, offset = normalizePage(limit, offset)
	var document struct {
		Pending map[string]model.Pending `json:"pending"`
	}
	if err := ts.decodeRuntimeStateJSON(ctx, jobID, &document); err != nil {
		return Page[RuntimePendingChange]{}, fmt.Errorf("read pending changes of job %s: %w", jobID, err)
	}
	items := make([]RuntimePendingChange, 0, len(document.Pending))
	for key, pending := range document.Pending {
		items = append(items, RuntimePendingChange{Key: key, Change: pending.Change, Count: pending.Count})
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Change.Target != b.Change.Target {
			return a.Change.Target < b.Change.Target
		}
		if a.Change.Protocol != b.Change.Protocol {
			return a.Change.Protocol < b.Change.Protocol
		}
		if a.Change.Port != b.Change.Port {
			return a.Change.Port < b.Change.Port
		}
		if a.Change.Kind != b.Change.Kind {
			return a.Change.Kind < b.Change.Kind
		}
		return a.Key < b.Key
	})
	page := Page[RuntimePendingChange]{Total: len(items)}
	if offset < len(items) {
		page.Items = items[offset:min(offset+limit, len(items))]
	}
	return page, nil
}

// RuntimeBaselinePage is one page of the logical units of a job's
// baseline, with the baseline's scopes, DNS answers and target coverage
// failures. Snapshot.Units holds only the units on the page, and is never
// nil; the host observations and host states of the baseline are left out,
// as they grow with every address in the scope. Present is false when the
// job has no baseline.
type RuntimeBaselinePage struct {
	Present  bool
	Snapshot model.Snapshot
	Total    int
}

// RuntimeBaselinePage returns one page of the baseline units of one of the
// tenant's jobs. It decodes the units on the page and the baseline's scope
// metadata, and only counts the other units; the host evidence and the
// candidate snapshot are never decoded. An unknown job and a job of another
// tenant have no baseline.
func (ts *TenantStore) RuntimeBaselinePage(ctx context.Context, jobID string, limit, offset int) (RuntimeBaselinePage, error) {
	if err := ts.ready(); err != nil {
		return RuntimeBaselinePage{}, err
	}
	limit, offset = normalizePage(limit, offset)
	document := struct {
		Baseline runtimeBaselinePageValue `json:"baseline"`
	}{Baseline: runtimeBaselinePageValue{offset: offset, limit: limit}}
	if err := ts.decodeRuntimeStateJSON(ctx, jobID, &document); err != nil {
		return RuntimeBaselinePage{}, fmt.Errorf("read baseline of job %s: %w", jobID, err)
	}
	return document.Baseline.page, nil
}

// decodeRuntimeStateJSON decodes the stored runtime JSON of one of the
// tenant's jobs into target, straight from the driver's copy of the value.
// A job without runtime state, an unknown job, and a job of another tenant
// leave target unchanged.
func (ts *TenantStore) decodeRuntimeStateJSON(ctx context.Context, jobID string, target any) error {
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT r.state_json FROM job_runtime r JOIN jobs j ON j.id=r.job_id AND j.tenant_id=? WHERE r.job_id=? AND NOT EXISTS (SELECT 1 FROM job_history_purges AS purge WHERE purge.tenant_id=j.tenant_id AND purge.job_id=j.id)`, ts.scope.id, jobID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		// RawBytes is valid until the next call on rows, which spares a
		// second copy of a value as large as the baseline and candidate
		// snapshots together.
		var raw sql.RawBytes
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return rows.Close()
}

// runtimeBaselinePageValue decodes the baseline member of a runtime state
// into one page. A missing or null baseline leaves the page absent.
type runtimeBaselinePageValue struct {
	offset, limit int
	page          RuntimeBaselinePage
}

func (v *runtimeBaselinePageValue) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	baseline := struct {
		Units          baselineUnitsPage             `json:"units"`
		Scopes         []model.Scope                 `json:"scopes"`
		DNS            map[string][]string           `json:"dns"`
		TargetFailures []model.TargetCoverageFailure `json:"target_failures"`
	}{Units: baselineUnitsPage{offset: v.offset, limit: v.limit}}
	if err := json.Unmarshal(data, &baseline); err != nil {
		return err
	}
	units := baseline.Units.units
	if units == nil {
		units = []model.Unit{}
	}
	v.page = RuntimeBaselinePage{Present: true, Total: baseline.Units.total, Snapshot: model.Snapshot{Units: units, Scopes: baseline.Scopes, DNS: baseline.DNS, TargetFailures: baseline.TargetFailures}}
	return nil
}

// baselineUnitsPage decodes the units from offset to offset+limit of a
// baseline's units array and counts every unit. Each unit off the page is
// checked as an object and skipped without being built.
type baselineUnitsPage struct {
	offset, limit int
	total         int
	units         []model.Unit
}

func (p *baselineUnitsPage) UnmarshalJSON(data []byte) error {
	p.total, p.units = 0, nil
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return errors.New("baseline units are not an array")
	}
	for decoder.More() {
		if p.total >= p.offset && len(p.units) < p.limit {
			var unit model.Unit
			if err := decoder.Decode(&unit); err != nil {
				return err
			}
			p.units = append(p.units, unit)
		} else {
			var skipped struct{}
			if err := decoder.Decode(&skipped); err != nil {
				return err
			}
		}
		p.total++
	}
	return nil
}
