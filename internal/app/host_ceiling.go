package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// HostCeilingJob is a job whose targets expand to more addresses than
// scanner.max_job_hosts lets one job scan.
type HostCeilingJob struct {
	ID    string
	Name  string
	Hosts int64
}

// JobsBeyondHostCeiling returns the jobs of every unit whose targets expand
// to more than ceiling addresses, counting a DNS name as one. Their scans fail
// with an error that names scanner.max_job_hosts until their targets are split
// into several jobs or the setting is raised. Archived jobs, which never scan,
// are left out.
func JobsBeyondHostCeiling(ctx context.Context, s *store.Store, ceiling int) ([]HostCeilingJob, error) {
	scopes, err := s.System().TenantScopes(ctx)
	if err != nil {
		return nil, err
	}
	var beyond []HostCeilingJob
	for _, scope := range scopes {
		jobs, err := s.Tenant(scope).ListJobs(ctx, false)
		if err != nil {
			return nil, err
		}
		for _, record := range jobs {
			estimate, err := config.EstimateJobWork(record.Job)
			if err == nil && estimate.Hosts > int64(ceiling) {
				beyond = append(beyond, HostCeilingJob{ID: record.ID, Name: record.Job.Name, Hosts: estimate.Hosts})
			}
		}
	}
	return beyond, nil
}

// HostCeilingWarning describes the jobs that JobsBeyondHostCeiling found, or
// is empty when there are none.
func HostCeilingWarning(jobs []HostCeilingJob, ceiling int) string {
	if len(jobs) == 0 {
		return ""
	}
	names := make([]string, 0, len(jobs))
	for _, job := range jobs {
		names = append(names, fmt.Sprintf("%s (%s, %d hosts)", job.Name, job.ID, job.Hosts))
	}
	return fmt.Sprintf("the targets of %d jobs expand to more than scanner.max_job_hosts=%d hosts, so their scans fail; split their targets into several jobs, or raise the setting together with the container's memory: %s", len(jobs), ceiling, strings.Join(names, ", "))
}

// reportJobsBeyondHostCeiling logs the jobs whose scans scanner.max_job_hosts
// refuses. A failed check is logged and never blocks startup.
func reportJobsBeyondHostCeiling(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger) {
	ceiling := cfg.Scanner.MaxJobHostsValue()
	jobs, err := JobsBeyondHostCeiling(ctx, s, ceiling)
	if err != nil {
		logger.Warn("the scan host ceiling check failed", "error", err)
		return
	}
	if len(jobs) == 0 {
		return
	}
	names, ids := make([]string, 0, len(jobs)), make([]string, 0, len(jobs))
	for _, job := range jobs {
		names, ids = append(names, job.Name), append(ids, job.ID)
	}
	logger.Warn("jobs have targets that expand to more hosts than scanner.max_job_hosts allows one job, so their scans fail; split their targets into several jobs, or raise the setting together with the container's memory", "max_job_hosts", ceiling, "jobs", names, "job_ids", ids)
}
