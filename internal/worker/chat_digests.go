package worker

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/ipsofacto-io/ipso-server/eehooks"
)

const (
	chatDigestsKind     = "chat_digests"
	chatDigestsQueue    = "chat_digests"
	chatDigestsEvery    = time.Hour
	chatDigestsTimeout  = time.Minute
	chatDigestsAttempts = 3
)

// ChatDigestsArgs is what the job carries: the tenant id and nothing else (ADR-0138).
type ChatDigestsArgs struct {
	Tenant uuid.UUID `json:"tenant"`
}

// Kind is the kind of the job.
func (ChatDigestsArgs) Kind() string { return chatDigestsKind }

// InsertOpts puts the job in its own queue and makes it unique for its kind and tenant while it waits,
// runs, or is due a retry.
func (ChatDigestsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: chatDigestsAttempts,
		Queue:       chatDigestsQueue,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: activeStates(),
		},
	}
}

// chatDigestsPeriodic inserts the job every hour, and once when a client starts.
func chatDigestsPeriodic(tenant uuid.UUID) *river.PeriodicJob {
	return river.NewPeriodicJob(
		river.PeriodicInterval(chatDigestsEvery),
		func() (river.JobArgs, *river.InsertOpts) { return ChatDigestsArgs{Tenant: tenant}, nil },
		&river.PeriodicJobOpts{ID: chatDigestsKind, RunOnStart: true},
	)
}

// chatDigests asks the enterprise sender to post waiver and premise digests. A denied feature does nothing,
// so a community worker completes the job without a network call.
type chatDigests struct {
	river.WorkerDefaults[ChatDigestsArgs]
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger
}

func (*chatDigests) Timeout(*river.Job[ChatDigestsArgs]) time.Duration {
	return chatDigestsTimeout
}

// Work refuses a job for another tenant before it touches the database, and cancels it, since a retry
// would refuse it again. A failure is stored as an operation only, so a webhook URL cannot reach river_job.
func (w *chatDigests) Work(ctx context.Context, job *river.Job[ChatDigestsArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.WarnContext(ctx, "a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	if err := eehooks.DeliverChat(ctx, w.db, w.tenant); err != nil {
		return reduce("deliver chat digests", err)
	}
	w.log.InfoContext(ctx, "chat digests finished", "job", job.ID, "tenant", w.tenant)
	return nil
}
