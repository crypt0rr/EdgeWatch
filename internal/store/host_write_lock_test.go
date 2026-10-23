package store

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/scanner"
)

// writerWaitUserID is the unit account of the host recovery cases.
const writerWaitUserID = "00000000-0000-0000-0000-00000000d001"

// writerWaitCycle creates a job whose single TCP unit covers ports 1 and 2,
// so that a test can split it, and a paused cycle of that job that expires
// at expires.
func writerWaitCycle(t *testing.T, ctx context.Context, s *Store, expires time.Time) (JobRecord, ScanCycleRecord) {
	t.Helper()
	job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{Name: "writer-wait-cycle", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"192.0.2.1"}, TCP: &config.Protocol{Ports: "1-2", Mode: "syn"}}))
	if err != nil {
		t.Fatal(err)
	}
	plan := scanner.WorkPlan{CreatedAt: time.Now().UTC(), Job: job.Job, Scopes: []model.Scope{{Target: "192.0.2.1", Protocol: "tcp", Ports: "1-2"}}, Units: []scanner.WorkUnit{{Sequence: 0, Protocol: "tcp", Family: 4, Addresses: []string{"192.0.2.1"}, Ports: "1-2", PortCount: 2, Probes: 2}}}
	cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	return job, cycle
}

// writerWaitClaimedUnit starts an attempt of the cycle and claims its first
// unit, as a scan does before it runs the unit.
func writerWaitClaimedUnit(t *testing.T, ctx context.Context, s *Store, cycleID string) ScanCycleUnit {
	t.Helper()
	if _, err := s.System().StartScanCycleAttempt(ctx, cycleID); err != nil {
		t.Fatal(err)
	}
	unit, err := s.System().NextScanCycleUnit(ctx, cycleID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.System().ClaimScanCycleUnit(ctx, cycleID, unit.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	return claimed
}

// writerWaitJobWithScan creates a job and saves a successful scan of its
// current scope, which a baseline approval accepts.
func writerWaitJobWithScan(t *testing.T, ctx context.Context, s *Store, name string) (JobRecord, model.Scan) {
	t.Helper()
	job, err := defaultTenant(s).CreateJob(ctx, testJob(name))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scan := model.Scan{ID: name + "-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "success", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}
	if err := s.System().SaveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	return job, scan
}

// writerWaitCycleStatus returns the status of the cycle.
func writerWaitCycleStatus(t *testing.T, s *Store, cycleID string) string {
	t.Helper()
	got := queryStrings(t, s.DB, `SELECT status FROM scan_cycles WHERE id=?`, cycleID)
	if len(got) != 1 {
		t.Fatalf("cycle %s rows = %v", cycleID, got)
	}
	return got[0]
}

// A write that a host command makes beside the running daemon, directly or
// through the scan it runs, reads the current state before it writes. Each
// such transaction takes the write lock first, so while another connection,
// such as the daemon, holds the lock for a second, the write waits for it
// within busy_timeout instead of failing at once with SQLITE_BUSY, as
// "edgewatch admin platform-setup-token" did beside the daemon.
func TestHostCommandWritesWaitForAConcurrentWriter(t *testing.T) {
	t.Parallel()
	hostAudit := func(action string) AuditEntry {
		return AuditEntry{Action: action, Detail: "writer wait", ActorUsername: "host-cli", ActorKind: AuditActorHost}
	}
	for _, test := range []struct {
		name string
		// prepare gives the write its state, before another connection takes
		// the write lock, and returns the write and the check that it did
		// its work.
		prepare func(t *testing.T, ctx context.Context, s *Store) (run func(context.Context) error, check func(t *testing.T))
	}{
		{
			name: "platform setup token",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				seedDefaultAdministrator(t, s)
				return func(ctx context.Context) error {
						now := time.Now().UTC()
						return s.Platform().IssuePlatformSetupToken(ctx, "writer-wait-platform", now.Add(15*time.Minute), now, false)
					}, func(t *testing.T) {
						if got := queryStrings(t, s.DB, `SELECT purpose FROM setup_tokens WHERE token_hash='writer-wait-platform'`); len(got) != 1 || got[0] != SetupTokenPurposePlatform {
							t.Fatalf("platform setup token purpose = %v, want %s", got, SetupTokenPurposePlatform)
						}
					}
			},
		},
		{
			name: "reissued setup token",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				return func(ctx context.Context) error {
						now := time.Now().UTC()
						return s.Platform().ReissueSetupToken(ctx, "writer-wait-initial", now.Add(15*time.Minute), now)
					}, func(t *testing.T) {
						if got := queryStrings(t, s.DB, `SELECT purpose FROM setup_tokens WHERE token_hash='writer-wait-initial'`); len(got) != 1 || got[0] != SetupTokenPurposeInitial {
							t.Fatalf("reissued setup token purpose = %v, want %s", got, SetupTokenPurposeInitial)
						}
					}
			},
		},
		{
			name: "original administrator recovery",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				seedDefaultAdministrator(t, s)
				admin, err := s.GetAdmin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				admin.PasswordHash = "writer-wait-hash"
				return func(ctx context.Context) error {
						return s.SaveAdminSecurityWithAudit(ctx, admin, nil, false, true, hostAudit("admin.password_reset"))
					}, func(t *testing.T) {
						if got := queryStrings(t, s.DB, `SELECT password_hash FROM users WHERE id=?`, LegacyAdminUserID); len(got) != 1 || got[0] != "writer-wait-hash" {
							t.Fatalf("administrator password hash = %v, want writer-wait-hash", got)
						}
					}
			},
		},
		{
			name: "unit account recovery",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				insertTenantUser(t, s, writerWaitUserID, DefaultTenantID, RoleOperator)
				user, err := defaultTenant(s).GetUser(ctx, writerWaitUserID)
				if err != nil {
					t.Fatal(err)
				}
				user.PasswordHash = "writer-wait-hash"
				return func(ctx context.Context) error {
						return defaultTenant(s).SaveUserSecurity(ctx, user, nil, false, true, hostAudit("user.password_reset"))
					}, func(t *testing.T) {
						if got := queryStrings(t, s.DB, `SELECT password_hash FROM users WHERE id=?`, writerWaitUserID); len(got) != 1 || got[0] != "writer-wait-hash" {
							t.Fatalf("unit account password hash = %v, want writer-wait-hash", got)
						}
					}
			},
		},
		{
			name: "platform administrator recovery",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				insertTenantUser(t, s, platformRoot, nil, RolePlatformAdmin)
				user, err := s.Platform().Account(platformRoot).GetUser(ctx, platformRoot)
				if err != nil {
					t.Fatal(err)
				}
				user.PasswordHash = "writer-wait-hash"
				return func(ctx context.Context) error {
						return s.Platform().Account(platformRoot).SaveUserSecurity(ctx, user, nil, false, true, hostAudit("user.password_reset"))
					}, func(t *testing.T) {
						if got := queryStrings(t, s.DB, `SELECT password_hash FROM users WHERE id=?`, platformRoot); len(got) != 1 || got[0] != "writer-wait-hash" {
							t.Fatalf("platform administrator password hash = %v, want writer-wait-hash", got)
						}
					}
			},
		},
		{
			name: "baseline approval",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				job, scan := writerWaitJobWithScan(t, ctx, s, "writer-wait-approve")
				return func(ctx context.Context) error {
						_, err := defaultTenant(s).ApproveRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, model.Scan{ID: scan.ID}, nil, hostAudit("baseline.approved"))
						return err
					}, func(t *testing.T) {
						summary, err := defaultTenant(s).RuntimeStateSummary(ctx, job.ID)
						if err != nil || summary.BaselineScanID != scan.ID {
							t.Fatalf("baseline after the approval = %+v, %v; want scan %s", summary, err, scan.ID)
						}
					}
			},
		},
		{
			name: "baseline reset",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				job, scan := writerWaitJobWithScan(t, ctx, s, "writer-wait-reset")
				if _, err := defaultTenant(s).ApproveRuntime(ctx, job.ID, job.Job.Name, model.Scan{ID: scan.ID}); err != nil {
					t.Fatal(err)
				}
				return func(ctx context.Context) error {
						_, err := defaultTenant(s).ResetRuntimeWithOutboxAndAudit(ctx, job.ID, job.Job.Name, nil, hostAudit("baseline.reset"))
						return err
					}, func(t *testing.T) {
						summary, err := defaultTenant(s).RuntimeStateSummary(ctx, job.ID)
						if err != nil || summary.HasBaseline || summary.BaselineScanID != "" {
							t.Fatalf("baseline after the reset = %+v, %v; want none", summary, err)
						}
					}
			},
		},
		{
			// "edgewatch perimeter declare" reads the unit and its stored
			// ranges before it inserts the new ones and their audit record.
			name: "perimeter declaration",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				entries := []PerimeterEntry{prefixEntry("192.0.2.0/24", "writer wait"), authorizedEntry("2001:db8::/32", "")}
				return func(ctx context.Context) error {
						result, err := defaultTenant(s).DeclarePerimeterSeeds(ctx, entries, hostAudit(auditPerimeterSeedsAdded))
						if err == nil && result != (PerimeterDeclareResult{Created: 2}) {
							t.Errorf("declaration result = %+v, want 2 created", result)
						}
						return err
					}, func(t *testing.T) {
						if got, want := perimeterRows(t, s, DefaultTenantID), []string{"authorized:2001:db8::/32:", "prefix:192.0.2.0/24:writer wait"}; !slices.Equal(got, want) {
							t.Fatalf("declared ranges = %q, want %q", got, want)
						}
						if got := queryStrings(t, s.DB, `SELECT actor_username FROM security_audit WHERE tenant_id=? AND action=?`, DefaultTenantID, auditPerimeterSeedsAdded); len(got) != 1 || got[0] != "host-cli" {
							t.Fatalf("declaration audit actors = %v, want host-cli", got)
						}
					}
			},
		},
		{
			name: "scan save",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				job, err := defaultTenant(s).CreateJob(ctx, testJob("writer-wait-save"))
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				scan := model.Scan{ID: "writer-wait-save-scan", JobID: job.ID, JobRevision: job.Revision, Job: job.Job.Name, StartedAt: now.Add(-time.Minute), FinishedAt: now, Status: "failed", ConfigHash: job.Job.SecurityHash(), Snapshot: model.Snapshot{}}
				return func(ctx context.Context) error {
						return s.System().SaveScan(ctx, scan)
					}, func(t *testing.T) {
						if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scans WHERE id=?`, scan.ID); got != 1 {
							t.Fatalf("saved scans = %d, want 1", got)
						}
					}
			},
		},
		{
			name: "scan cycle expiry",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Now().UTC().Add(time.Hour))
				return func(ctx context.Context) error {
						expired, err := s.System().ExpireScanCycles(ctx, time.Now().UTC().Add(2*time.Hour))
						if err == nil && expired != 1 {
							t.Errorf("expired cycles = %d, want 1", expired)
						}
						return err
					}, func(t *testing.T) {
						if got := writerWaitCycleStatus(t, s, cycle.ID); got != "expired" {
							t.Fatalf("cycle status = %s, want expired", got)
						}
					}
			},
		},
		{
			name: "scan cycle attempt start",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Time{})
				return func(ctx context.Context) error {
						_, err := s.System().StartScanCycleAttempt(ctx, cycle.ID)
						return err
					}, func(t *testing.T) {
						if got := countRows(t, s.DB, `SELECT attempt_count FROM scan_cycles WHERE id=? AND status='running'`, cycle.ID); got != 1 {
							t.Fatalf("attempts of the running cycle = %d, want 1", got)
						}
					}
			},
		},
		{
			name: "scan cycle unit completion",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Time{})
				unit := writerWaitClaimedUnit(t, ctx, s, cycle.ID)
				return func(ctx context.Context) error {
						return s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{})
					}, func(t *testing.T) {
						if got := countRows(t, s.DB, `SELECT completed_units FROM scan_cycles WHERE id=?`, cycle.ID); got != 1 {
							t.Fatalf("completed units = %d, want 1", got)
						}
					}
			},
		},
		{
			name: "scan cycle unit split",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Time{})
				unit := writerWaitClaimedUnit(t, ctx, s, cycle.ID)
				first, second := unit.Unit, unit.Unit
				first.Ports, first.PortCount, first.Probes = "1", 1, 1
				second.Ports, second.PortCount, second.Probes = "2", 1, 1
				return func(ctx context.Context) error {
						return s.System().SplitScanCycleUnit(ctx, cycle.ID, unit.Sequence, first, second, "split after timeout")
					}, func(t *testing.T) {
						if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=? AND status='pending'`, cycle.ID); got != 2 {
							t.Fatalf("pending units after the split = %d, want 2", got)
						}
					}
			},
		},
		{
			name: "scan cycle completion",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Time{})
				unit := writerWaitClaimedUnit(t, ctx, s, cycle.ID)
				if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, model.Snapshot{}); err != nil {
					t.Fatal(err)
				}
				return func(ctx context.Context) error {
						_, err := s.System().CompleteScanCycle(ctx, cycle.ID)
						return err
					}, func(t *testing.T) {
						if got := writerWaitCycleStatus(t, s, cycle.ID); got != "completed" {
							t.Fatalf("cycle status = %s, want completed", got)
						}
					}
			},
		},
		{
			name: "scan cycle discard",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				_, cycle := writerWaitCycle(t, ctx, s, time.Time{})
				return func(ctx context.Context) error {
						return defaultTenant(s).DiscardScanCycle(ctx, cycle.ID)
					}, func(t *testing.T) {
						if got := writerWaitCycleStatus(t, s, cycle.ID); got != "discarded" {
							t.Fatalf("cycle status = %s, want discarded", got)
						}
					}
			},
		},
		{
			name: "scan cycle enrichment",
			prepare: func(t *testing.T, ctx context.Context, s *Store) (func(context.Context) error, func(*testing.T)) {
				job, err := defaultTenant(s).CreateJob(ctx, config.NormalizeJob(config.Job{Name: "writer-wait-naabu", Schedule: "0 * * * *", Timezone: "UTC", Targets: []string{"edge.example"}, MaxExpandedHosts: 1, TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{AddressBatchSize: 1}}}))
				if err != nil {
					t.Fatal(err)
				}
				target := scanner.ResolvedTarget{Name: "edge.example", ConfiguredTarget: "edge.example", Addresses: []string{"192.0.2.1"}, Aggregate: true, Hostname: true}
				plan := scanner.WorkPlan{Job: job.Job, Targets: []scanner.ResolvedTarget{target}, DNS: map[string][]string{"edge.example": {"192.0.2.1"}}, Scopes: []model.Scope{{Target: "edge.example", Protocol: "tcp", Ports: "1-65535"}}, Units: []scanner.WorkUnit{{Sequence: 0, Engine: config.EngineNaabuNmap, Phase: "discovery", Protocol: "tcp", Family: 4, Targets: []scanner.ResolvedTarget{target}, Addresses: []string{"192.0.2.1"}, Ports: "1-65535", PortCount: 65535, Probes: 65535}}}
				cycle, err := s.System().CreateScanCycle(ctx, ScanCycleRecord{JobID: job.ID, Job: job.Job.Name, JobRevision: job.Revision, ConfigHash: job.Job.SecurityHash(), ExecutionHash: job.Job.ExecutionHash(), Plan: plan})
				if err != nil {
					t.Fatal(err)
				}
				unit := writerWaitClaimedUnit(t, ctx, s, cycle.ID)
				fragment := model.Snapshot{Hosts: []model.HostObservation{{Address: "192.0.2.1", Protocols: []model.ProtocolObservation{{Protocol: "tcp", DiscoveryEngine: "naabu", DiscoveredPorts: []model.PortObservation{{Port: 443, State: "open", Verification: "discovered"}}}}}}}
				if err := s.System().CompleteScanCycleUnit(ctx, cycle.ID, unit.Sequence, fragment); err != nil {
					t.Fatal(err)
				}
				return func(ctx context.Context) error {
						return s.System().ReconcileScanCycleEnrichment(ctx, cycle.ID)
					}, func(t *testing.T) {
						if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_cycle_units WHERE cycle_id=? AND phase='enrichment'`, cycle.ID); got != 1 {
							t.Fatalf("enrichment units = %d, want 1", got)
						}
						if got := countRows(t, s.DB, `SELECT COUNT(*) FROM scan_cycle_discovery_checkpoints WHERE cycle_id=?`, cycle.ID); got != 1 {
							t.Fatalf("discovery checkpoints = %d, want 1", got)
						}
					}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := openTestStore(t)
			run, check := test.prepare(t, ctx, s)
			release := holdWriteLock(t, s.FilePath())
			var releaseOnce sync.Once
			releaseLock := func() { releaseOnce.Do(release) }
			timer := time.AfterFunc(startupWriteLockHold, releaseLock)
			// A write that fails at once must not leave the lock held while
			// the store closes.
			defer func() {
				timer.Stop()
				releaseLock()
			}()
			started := time.Now()
			if err := run(ctx); err != nil {
				t.Fatalf("%s while another connection writes: %v", test.name, err)
			}
			if waited := time.Since(started); waited < startupWriteLockHold/2 {
				t.Fatalf("%s finished after %v without waiting for the writer", test.name, waited)
			}
			check(t)
		})
	}
}
