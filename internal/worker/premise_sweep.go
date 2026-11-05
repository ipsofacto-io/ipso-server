package worker

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

const (
	premiseSweepKind  = "premise_sweep"
	premiseSweepQueue = "premise_sweep"
	// The sweep reads what is due from the database clock, so an hour is enough for intervals counted in
	// days, and a skipped tick only delays the next one (ADR-0096).
	premiseSweepEvery    = time.Hour
	premiseSweepTimeout  = time.Minute
	premiseSweepAttempts = 3
	// probeInsertBatch bounds one InsertMany, so a tenant whose premises are all due at once is queued in
	// several statements and not in one.
	probeInsertBatch = 500
)

// dueFunc is registry.DuePremises. Tests replace it.
type dueFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]registry.PremiseRef, int, error)

// insertProbesFunc queues the probe jobs and returns how many were new. Tests replace it.
type insertProbesFunc func(ctx context.Context, jobs []PremiseProbeArgs) (int, error)

// PremiseSweepArgs is what the job carries: the tenant id and nothing else (ADR-0096).
type PremiseSweepArgs struct {
	Tenant uuid.UUID `json:"tenant"`
}

// Kind is the kind of the job.
func (PremiseSweepArgs) Kind() string { return premiseSweepKind }

// InsertOpts puts the job in its own queue and makes it unique for its kind and tenant while it waits,
// runs, or is due a retry.
func (PremiseSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: premiseSweepAttempts,
		Queue:       premiseSweepQueue,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeStates()},
	}
}

// premiseSweepPeriodic inserts the job every hour, and once when a client starts. Every worker that
// could lead has to run it, because River elects one leader for each database.
func premiseSweepPeriodic(tenant uuid.UUID) *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(premiseSweepEvery),
		func() (river.JobArgs, *river.InsertOpts) { return PremiseSweepArgs{Tenant: tenant}, nil },
		&river.PeriodicJobOpts{ID: premiseSweepKind, RunOnStart: true},
	)
}

// premiseSweep queues one probe job for each premise of the tenant that is due.
type premiseSweep struct {
	river.WorkerDefaults[PremiseSweepArgs]
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger
	due    dueFunc
	insert insertProbesFunc
}

func (*premiseSweep) Timeout(*river.Job[PremiseSweepArgs]) time.Duration {
	return premiseSweepTimeout
}

// Work refuses a job for another tenant before it touches the database, as waiver_notices does. A
// failure is stored as an operation and a cause class only. The log line holds counts and the tenant id,
// never a premise id or a URL.
func (w *premiseSweep) Work(ctx context.Context, job *river.Job[PremiseSweepArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.Warn("a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	refs, skipped, err := w.due(ctx, w.db, w.tenant)
	if err != nil {
		return reduce("read due premises", err)
	}
	jobs := make([]PremiseProbeArgs, len(refs))
	for i, ref := range refs {
		jobs[i] = PremiseProbeArgs{Tenant: w.tenant, Decision: ref.Decision, Premise: ref.ID}
	}
	queued, err := w.insert(ctx, jobs)
	if err != nil {
		return reduce("queue premise probes", err)
	}
	level := slog.LevelInfo
	if skipped > 0 {
		// A premise the table cannot store is never probed, and this line is the only sign of it.
		level = slog.LevelWarn
	}
	w.log.Log(ctx, level, "premise sweep", "job", job.ID, "tenant", w.tenant, "due", len(refs), "queued", queued, "skipped", skipped)
	return nil
}

// insertProbes queues the jobs through the client that runs this one, a batch at a time. A job already
// waiting or running for the same premise is skipped by its unique options and is not counted.
func insertProbes(ctx context.Context, jobs []PremiseProbeArgs) (int, error) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return 0, fmt.Errorf("find the job client: %w", err)
	}
	queued := 0
	for start := 0; start < len(jobs); start += probeInsertBatch {
		batch := jobs[start:min(start+probeInsertBatch, len(jobs))]
		params := make([]river.InsertManyParams, len(batch))
		for i := range batch {
			params[i] = river.InsertManyParams{Args: batch[i]}
		}
		results, err := client.InsertMany(ctx, params)
		if err != nil {
			return queued, fmt.Errorf("insert probe jobs: %w", err)
		}
		for _, result := range results {
			if !result.UniqueSkippedAsDuplicate {
				queued++
			}
		}
	}
	return queued, nil
}
