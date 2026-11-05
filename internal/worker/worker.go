// Package worker runs the job runtime of ADR-0096 for one tenant: River on the registry's PostgreSQL,
// started only after the gates of the api role (ADR-0097). The one job built so far is the hourly waiver
// notice sweep.
package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const (
	// riverSchema is the schema goose makes River's tables in (ADR-0097).
	riverSchema = "river"
	// softStop is how long a running job may take to finish after the process is told to stop. Then its
	// context is cancelled. The Compose stop grace period is the same ten seconds.
	softStop = 10 * time.Second
)

// Config is what the worker needs to start.
type Config struct {
	// Pool connects as the application role. Run refuses a role that can bypass row-level security. It
	// has to be a session connection and not a transaction-mode pooler, because River listens for
	// notifications and ipso.tenant is set for one transaction.
	Pool *pgxpool.Pool
	// Tenant is the one tenant this process serves (single-tenant mode, ADR-0093). It must have a row. A
	// job that names another tenant is cancelled before it runs.
	Tenant uuid.UUID
	Log    *slog.Logger
}

// Run runs the start gates, then works jobs until ctx ends. It fails before any job is fetched when the
// connected role could bypass row-level security, when the tenant has no row, or when River's tables are
// missing. When ctx ends, running jobs get softStop to finish.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	// The same pool serves River and the registry. Closing db does not close the pool.
	db := stdlib.OpenDBFromPool(cfg.Pool)
	defer func() { _ = db.Close() }()

	if err := rls.Check(ctx, db); err != nil {
		return err
	}
	if err := tenancy.Require(ctx, db, cfg.Tenant); err != nil {
		return err
	}
	if err := requireRiverTables(ctx, db); err != nil {
		return err
	}

	client, err := newClient(cfg, db, registry.Notify)
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("start the job client: %w", err)
	}
	<-client.Stopped()
	if ctx.Err() == nil {
		return errors.New("the job client stopped")
	}
	return nil
}

func (c Config) validate() error {
	switch {
	case c.Pool == nil:
		return errors.New("a connection pool is required")
	case c.Tenant == uuid.Nil:
		return errors.New("a tenant is required")
	}
	return nil
}

// newClient builds the River client: one queue and one worker for each job kind, the periodic jobs, and
// no reindexer. The reindexer needs the table owner or MAINTAIN, and the application role has neither, so
// reindexing river_job is operations work (ADR-0097).
func newClient(cfg Config, db *sql.DB, notify notifyFunc) (*river.Client[pgx.Tx], error) {
	workers := river.NewWorkers()
	river.AddWorker(workers, &waiverNotices{db: db, tenant: cfg.Tenant, log: cfg.Log, notify: notify})
	return river.NewClient(riverpgxv5.New(cfg.Pool), &river.Config{
		Logger:  cfg.Log,
		Schema:  riverSchema,
		Workers: workers,
		Queues: map[string]river.QueueConfig{
			waiverNoticesQueue: {MaxWorkers: 1},
		},
		PeriodicJobs: []*river.PeriodicJob{
			waiverNoticesPeriodic(cfg.Tenant),
		},
		ReindexerSchedule: river.NeverSchedule(),
		SoftStopTimeout:   softStop,
	})
}

// requireRiverTables refuses to start when the schema was not migrated, which happens when the binary is
// upgraded before ipso-server migrate runs. Without it River would log an error for each fetch.
func requireRiverTables(ctx context.Context, db *sql.DB) error {
	var present bool
	err := db.QueryRowContext(ctx, `
		SELECT to_regclass('river.river_job') IS NOT NULL
		   AND to_regclass('river.river_leader') IS NOT NULL
		   AND to_regclass('river.river_queue') IS NOT NULL`).Scan(&present)
	if err != nil {
		return fmt.Errorf("read the river tables: %w", err)
	}
	if !present {
		return errors.New("the river tables are missing: run ipso-server migrate before the worker")
	}
	return nil
}
