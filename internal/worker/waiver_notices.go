package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const (
	waiverNoticesKind  = "waiver_notices"
	waiverNoticesQueue = "waiver_notices"
	// The sweep reads what is due from the database clock, so an hour is enough for notices counted in
	// days, and a skipped tick only delays the next one (ADR-0096).
	waiverNoticesEvery   = time.Hour
	waiverNoticesTimeout = time.Minute
	// A failing sweep is discarded after three attempts, about 20 seconds with River's default backoff,
	// and the next tick starts a fresh one. With River's default of 25 it would stay retryable for days.
	waiverNoticesAttempts = 3
)

// errOtherTenant is the whole text River stores when a job names a tenant this process does not serve.
var errOtherTenant = errors.New("the job names another tenant")

// notifyFunc is registry.Notify. Tests replace it.
type notifyFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID) (int, error)

// WaiverNoticesArgs is what the job carries: the tenant id and nothing else (ADR-0096).
type WaiverNoticesArgs struct {
	Tenant uuid.UUID `json:"tenant"`
}

// Kind is the kind of the job.
func (WaiverNoticesArgs) Kind() string { return waiverNoticesKind }

// InsertOpts puts the job in its own queue and makes it unique for its kind and tenant while it waits,
// runs, or is due a retry. A completed job is left out of the states, so the next tick can insert one;
// River's default would hold the next tick back until its cleaner removed the completed job.
func (WaiverNoticesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: waiverNoticesAttempts,
		Queue:       waiverNoticesQueue,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{
				rivertype.JobStateAvailable,
				rivertype.JobStatePending,
				rivertype.JobStateRetryable,
				rivertype.JobStateRunning,
				rivertype.JobStateScheduled,
			},
		},
	}
}

// waiverNoticesPeriodic inserts the job every hour, and once when a client starts. Every worker that
// could lead has to run it, because River elects one leader for each database.
func waiverNoticesPeriodic(tenant uuid.UUID) *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(waiverNoticesEvery),
		func() (river.JobArgs, *river.InsertOpts) { return WaiverNoticesArgs{Tenant: tenant}, nil },
		&river.PeriodicJobOpts{ID: waiverNoticesKind, RunOnStart: true},
	)
}

// waiverNotices calls registry.Notify for the tenant this process serves.
type waiverNotices struct {
	river.WorkerDefaults[WaiverNoticesArgs]
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger
	notify notifyFunc
}

func (*waiverNotices) Timeout(*river.Job[WaiverNoticesArgs]) time.Duration {
	return waiverNoticesTimeout
}

// Work refuses a job for another tenant before it touches the database, and cancels it, since a retry
// would refuse it again. A failure is stored as an operation and a cause class only: a database message
// can quote row content, and River keeps the text of every attempt error.
func (w *waiverNotices) Work(ctx context.Context, job *river.Job[WaiverNoticesArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.Warn("a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	recorded, err := w.notify(ctx, w.db, w.tenant)
	if err != nil {
		return reduce("record waiver notices", err)
	}
	w.log.Info("waiver notices recorded", "job", job.ID, "tenant", w.tenant, "recorded", recorded)
	return nil
}

// reduce keeps the operation and the class of the cause and drops the rest of err's text.
func reduce(operation string, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		return fmt.Errorf("%s: SQLSTATE %s", operation, pgErr.Code)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: timed out", operation)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: canceled", operation)
	default:
		return fmt.Errorf("%s: failed", operation)
	}
}
