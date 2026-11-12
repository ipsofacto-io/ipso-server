package worker

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// The exports a tenant admin asks for through the API (ADR-0111). The API only records the request in
// tenancy.export. A sweep every minute finds the requests that wait for a job and queues one for each, and
// deletes the exports that expired, the same sweep-then-job shape as the premise sweep (ADR-0098). The job
// builds the archive with the code of the operator command and stores it in parts.
const (
	tenantExportSweepKind     = "tenant_export_sweep"
	tenantExportSweepQueue    = "tenant_export_sweep"
	tenantExportSweepEvery    = time.Minute
	tenantExportSweepTimeout  = 30 * time.Second
	tenantExportSweepAttempts = 3

	tenantExportKind  = "tenant_export"
	tenantExportQueue = "tenant_export"
	// An export reads the whole tenant at one snapshot and writes its ciphertext, so it gets the most time a
	// job here has. A tenant that needs more uses the operator command.
	tenantExportTimeout = 30 * time.Minute
	// An export that did not finish is tried three times, and then it is marked failed.
	tenantExportAttempts = 3
	// failTimeout bounds marking an export failed, which must work after the job's own context ended.
	failTimeout = 30 * time.Second
)

// errExportGone is the whole text River stores for a job whose export no longer exists.
var errExportGone = errors.New("the export is gone, expired or already finished")

// sweepExportsFunc is tenancy.SweepExports, and runExportFunc and failExportFunc are tenancy.RunStoredExport
// and tenancy.FailExport. Tests replace them.
type (
	sweepExportsFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID) (tenancy.ExportSweep, error)
	runExportFunc    func(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (tenancy.ExportReport, error)
	failExportFunc   func(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) error
	// insertExportsFunc queues the export jobs and returns how many were new.
	insertExportsFunc func(ctx context.Context, jobs []TenantExportArgs) (int, error)
)

// TenantExportSweepArgs is what the sweep carries: the tenant id and nothing else (ADR-0096).
type TenantExportSweepArgs struct {
	Tenant uuid.UUID `json:"tenant"`
}

// Kind is the kind of the job.
func (TenantExportSweepArgs) Kind() string { return tenantExportSweepKind }

// InsertOpts puts the sweep in its own queue and makes it unique for its kind and tenant while it waits,
// runs, or is due a retry.
func (TenantExportSweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: tenantExportSweepAttempts,
		Queue:       tenantExportSweepQueue,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeStates()},
	}
}

// TenantExportArgs is what an export job carries: the tenant and the export, and never the key it is
// encrypted to, which the job reads from the row.
type TenantExportArgs struct {
	Tenant uuid.UUID `json:"tenant"`
	Export uuid.UUID `json:"export"`
}

// Kind is the kind of the job.
func (TenantExportArgs) Kind() string { return tenantExportKind }

// InsertOpts puts the job in its own queue and makes it unique for its export while it waits, runs, or is
// due a retry, so the sweep of every minute queues one job for an export and no more.
func (TenantExportArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: tenantExportAttempts,
		Queue:       tenantExportQueue,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeStates()},
	}
}

// tenantExportSweepPeriodic inserts the sweep every minute, and once when a client starts. Every worker
// that could lead has to run it, because River elects one leader for each database.
func tenantExportSweepPeriodic(tenant uuid.UUID) *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(tenantExportSweepEvery),
		func() (river.JobArgs, *river.InsertOpts) { return TenantExportSweepArgs{Tenant: tenant}, nil },
		&river.PeriodicJobOpts{ID: tenantExportSweepKind, RunOnStart: true},
	)
}

// tenantExportSweep deletes the exports that expired and queues a job for each export that waits for one.
type tenantExportSweep struct {
	river.WorkerDefaults[TenantExportSweepArgs]
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger
	sweep  sweepExportsFunc
	insert insertExportsFunc
}

func (*tenantExportSweep) Timeout(*river.Job[TenantExportSweepArgs]) time.Duration {
	return tenantExportSweepTimeout
}

// Work refuses a job for another tenant before it touches the database. A failure is stored as an operation
// and a cause class only, and the log line holds counts and the tenant id.
func (w *tenantExportSweep) Work(ctx context.Context, job *river.Job[TenantExportSweepArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.Warn("a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	swept, err := w.sweep(ctx, w.db, w.tenant)
	if err != nil {
		return reduce("sweep exports", err)
	}
	jobs := make([]TenantExportArgs, len(swept.Open))
	for i, id := range swept.Open {
		jobs[i] = TenantExportArgs{Tenant: w.tenant, Export: id}
	}
	queued, err := w.insert(ctx, jobs)
	if err != nil {
		return reduce("queue exports", err)
	}
	// The sweep runs every minute, so a tick that found nothing is not logged at the level of one that did.
	level := slog.LevelDebug
	switch {
	case swept.Failed > 0:
		// A job was lost to a kill that no attempt survived to mark, and this line is the only sign of it.
		level = slog.LevelWarn
	case swept.Deleted > 0 || queued > 0:
		level = slog.LevelInfo
	}
	w.log.Log(ctx, level, "export sweep", "job", job.ID, "tenant", w.tenant, "deleted", swept.Deleted, "failed", swept.Failed, "open", len(swept.Open), "queued", queued)
	return nil
}

// insertExports queues the export jobs. A job already waiting or running for the same export is skipped by its
// unique options and is not counted.
func insertExports(ctx context.Context, jobs []TenantExportArgs) (int, error) {
	return insertJobs(ctx, jobs)
}

// tenantExport builds the archive of one export.
type tenantExport struct {
	river.WorkerDefaults[TenantExportArgs]
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger
	run    runExportFunc
	fail   failExportFunc
}

func (*tenantExport) Timeout(*river.Job[TenantExportArgs]) time.Duration {
	return tenantExportTimeout
}

// Work refuses a job for another tenant before it touches the database. An export that is gone, expired or
// finished is cancelled, a key or a size that no retry can fix marks the export failed and cancels, and
// any other error is retried until the last attempt, which marks the export failed so that the admin can ask
// again. A stop of the process is not a failure: the job is retried at the next start. The error River stores
// is an operation and a cause class, or the fixed text of a sentinel, and never a row or a key.
func (w *tenantExport) Work(ctx context.Context, job *river.Job[TenantExportArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.Warn("a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	report, err := w.run(ctx, w.db, w.tenant, job.Args.Export)
	switch {
	case err == nil:
		w.log.Info("tenant export ready", "job", job.ID, "tenant", w.tenant, "export", job.Args.Export, "rows", report.Total)
		return nil
	case errors.Is(err, tenancy.ErrNoExport):
		w.log.Info("an export is gone, so its job was cancelled", "job", job.ID, "tenant", w.tenant, "export", job.Args.Export)
		return river.JobCancel(errExportGone)
	case errors.Is(err, tenancy.ErrBadRecipient):
		w.markFailed(ctx, job)
		return river.JobCancel(tenancy.ErrBadRecipient)
	case errors.Is(err, tenancy.ErrExportTooLarge):
		w.markFailed(ctx, job)
		return river.JobCancel(tenancy.ErrExportTooLarge)
	}
	if job.Attempt >= job.MaxAttempts && !errors.Is(ctx.Err(), context.Canceled) {
		w.markFailed(ctx, job)
	}
	return reduce("make the export", err)
}

// markFailed marks the export failed in a context of its own, because the one of the job may have ended.
func (w *tenantExport) markFailed(ctx context.Context, job *river.Job[TenantExportArgs]) {
	failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failTimeout)
	defer cancel()
	if err := w.fail(failCtx, w.db, w.tenant, job.Args.Export); err != nil {
		w.log.Error("an export could not be marked failed", "job", job.ID, "tenant", w.tenant, "export", job.Args.Export)
		return
	}
	w.log.Warn("an export failed", "job", job.ID, "tenant", w.tenant, "export", job.Args.Export, "attempt", job.Attempt)
}
