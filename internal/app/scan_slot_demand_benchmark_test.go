package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/crypt0rr/edgewatch/internal/store/storetest"
)

// BenchmarkScanSlotDemand measures the estimate of a large unit: 300 enabled
// hourly jobs in Europe/Amsterdam with 2,000 current scans each. Half are
// single-address Nmap jobs whose scans have no cycle; the other half are
// Naabu jobs whose every scan is the one attempt of a completed cycle.
// "current" estimates every job from its history. "after-edits" then edits
// every job so that none of its history matches its settings: the ports of
// the jobs without cycles and the timeout of the cycle jobs, which is the
// most a request reads before a job has new samples. CI runs no
// benchmarks; run it with
//
//	go test -run '^$' -bench BenchmarkScanSlotDemand -benchtime 20x ./internal/app
func BenchmarkScanSlotDemand(b *testing.B) {
	const (
		jobs        = 300
		scansPerJob = 2000
	)
	ctx := context.Background()
	db := storetest.OpenFresh(b)
	ts := defaultTenant(db)
	seedScanSlotDemandBenchmark(b, db, jobs, scansPerJob)
	app := &App{Store: db, Config: &config.Config{Scheduler: config.Scheduler{MaxConcurrent: 4}}}
	run := func(b *testing.B, check func(ScanSlotDemand) bool) {
		demand, err := app.ScanSlotDemand(ctx, ts)
		if err != nil {
			b.Fatal(err)
		}
		if demand.EnabledJobs != jobs || !check(demand) {
			b.Fatalf("demand = %+v", demand)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := app.ScanSlotDemand(ctx, ts); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("current", func(b *testing.B) {
		run(b, func(demand ScanSlotDemand) bool { return demand.HistoryJobs == jobs })
	})
	records, err := ts.ListJobs(ctx, false)
	if err != nil {
		b.Fatal(err)
	}
	for _, record := range records {
		job := record.Job
		if job.TCP.Engine == config.EngineNmap {
			tcp := *job.TCP
			tcp.Ports = "443,8443"
			job.TCP = &tcp
		} else {
			job.Timeout = config.Duration(2 * time.Hour)
		}
		if _, _, err := ts.UpdateJob(ctx, record.ID, record.Revision, job, true, false, true); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("after-edits", func(b *testing.B) {
		run(b, func(demand ScanSlotDemand) bool { return demand.HistoryJobs == 0 })
	})
}

// seedScanSlotDemandBenchmark gives the default tenant the jobs and scans of
// BenchmarkScanSlotDemand.
func seedScanSlotDemandBenchmark(b testing.TB, db *store.Store, jobs, scansPerJob int) {
	b.Helper()
	ctx := context.Background()
	ts := defaultTenant(db)
	for i := range jobs {
		job := config.Job{
			Name: fmt.Sprintf("demand-%03d", i), Schedule: "0 * * * *", Timezone: "Europe/Amsterdam",
			Targets: []string{fmt.Sprintf("10.%d.%d.1", i/256, i%256)},
			TCP:     &config.Protocol{Engine: config.EngineNmap, Ports: "443", Mode: "connect"},
		}
		if i%2 == 1 {
			job.Targets = []string{fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)}
			job.TCP = &config.Protocol{Engine: config.EngineNaabuNmap, Ports: "1-65535", Naabu: &config.NaabuOptions{Rate: 1000}}
		}
		record, err := ts.CreateJobWithEnabled(ctx, config.NormalizeJob(job), true)
		if err != nil {
			b.Fatal(err)
		}
		key := store.NewScanDurationKey(record)
		payload := strings.Repeat("x", 512)
		// Each scan finished on the hour, newest first, and ran 20 minutes.
		const runs = `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i+1<?)
SELECT i,strftime('%Y-%m-%dT%H:%M:%S','2026-10-01T00:00:00','-'||i||' hours')||'.000000000Z' AS finished,
	strftime('%Y-%m-%dT%H:%M:%S','2026-10-01T00:00:00','-'||i||' hours','-20 minutes')||'.000000000Z' AS started FROM n`
		if i%2 == 0 {
			_, err = db.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json,job_id,job_revision,scanner_engine,scanner_profile_id,scanner_profile_revision,tenant_id)
SELECT printf('scan-%03d-%05d',?,i),?,started,finished,CASE WHEN i%10=9 THEN 'failed' ELSE 'success' END,?,?,?,?,'nmap',?,?,? FROM (`+runs+`)`,
				i, record.Job.Name, key.ConfigHash, payload, record.ID, record.Revision, key.ScannerProfileID, key.ScannerProfileRevision, store.DefaultTenantID, scansPerJob)
		} else {
			_, err = db.DB.ExecContext(ctx, `INSERT INTO scan_cycles(id,job_id,job,job_revision,config_hash,execution_hash,plan_json,status,attempt_count,total_units,completed_units,total_probes,completed_probes,started_at,attempt_started_at,updated_at,expires_at,finished_at)
SELECT printf('cycle-%03d-%05d',?,i),?,?,?,?,?,?,'completed',1,1,1,65535,65535,started,started,finished,finished,finished FROM (`+runs+`)`,
				i, record.ID, record.Job.Name, record.Revision, key.ConfigHash, key.ExecutionHash, payload, scansPerJob)
			if err == nil {
				_, err = db.DB.ExecContext(ctx, `INSERT INTO scans(id,job,started_at,finished_at,status,config_hash,snapshot_json,job_id,job_revision,cycle_id,cycle_attempt,cycle_status,resumable,scanner_engine,tenant_id)
SELECT printf('scan-%03d-%05d',?,i),?,started,finished,'success',?,?,?,?,printf('cycle-%03d-%05d',?,i),1,'completed',1,'naabu-nmap',? FROM (`+runs+`)`,
					i, record.Job.Name, key.ConfigHash, payload, record.ID, record.Revision, i, store.DefaultTenantID, scansPerJob)
			}
		}
		if err != nil {
			b.Fatal(err)
		}
	}
	if _, err := db.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		b.Fatal(err)
	}
}
