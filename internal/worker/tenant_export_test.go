package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

var exportA = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

func exportSweepJobFor(tenant uuid.UUID) *river.Job[TenantExportSweepArgs] {
	return &river.Job[TenantExportSweepArgs]{JobRow: &rivertype.JobRow{ID: 21}, Args: TenantExportSweepArgs{Tenant: tenant}}
}

func exportJobFor(tenant uuid.UUID, attempt, max int) *river.Job[TenantExportArgs] {
	return &river.Job[TenantExportArgs]{
		JobRow: &rivertype.JobRow{ID: 22, Attempt: attempt, MaxAttempts: max},
		Args:   TenantExportArgs{Tenant: tenant, Export: exportA},
	}
}

func TestTheExportSweepCancelsAJobForAnotherTenantBeforeTheDatabaseIsTouched(t *testing.T) {
	w := &tenantExportSweep{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		sweep: func(context.Context, *sql.DB, uuid.UUID) (tenancy.ExportSweep, error) {
			t.Error("the sweep read exports for a job that names another tenant")
			return tenancy.ExportSweep{}, nil
		},
		insert: func(context.Context, []TenantExportArgs) (int, error) {
			t.Error("the sweep queued exports for a job that names another tenant")
			return 0, nil
		},
	}
	err := w.Work(t.Context(), exportSweepJobFor(tenantB))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) || strings.Contains(err.Error(), tenantA.String()) || strings.Contains(err.Error(), tenantB.String()) {
		t.Fatalf("err = %v, want a cancellation that names no tenant", err)
	}
}

func TestTheExportSweepQueuesOneJobForEachExportThatWaitsForOne(t *testing.T) {
	other := uuid.MustParse("00000000-0000-7000-8000-0000000000e2")
	var swept uuid.UUID
	var queued []TenantExportArgs
	w := &tenantExportSweep{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		sweep: func(_ context.Context, _ *sql.DB, tenant uuid.UUID) (tenancy.ExportSweep, error) {
			swept = tenant
			return tenancy.ExportSweep{Deleted: 1, Open: []uuid.UUID{exportA, other}}, nil
		},
		insert: func(_ context.Context, jobs []TenantExportArgs) (int, error) {
			queued = jobs
			return len(jobs), nil
		},
	}
	if err := w.Work(t.Context(), exportSweepJobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	want := []TenantExportArgs{{Tenant: tenantA, Export: exportA}, {Tenant: tenantA, Export: other}}
	if swept != tenantA || !slices.Equal(queued, want) {
		t.Errorf("swept %s and queued %v, want tenant A and %v", swept, queued, want)
	}
}

func TestTheExportSweepStoresAFailureAsItsOperationAndClassOnly(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "42501", Message: "permission denied", Detail: "Failing row contains (" + canary + ")"}
	tests := []struct {
		name   string
		sweep  error
		insert error
		want   string
	}{
		{"a database error while sweeping", fmt.Errorf("export: delete the expired: %w", pgErr), nil, "sweep exports: SQLSTATE 42501"},
		{"a deadline while sweeping", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), nil, "sweep exports: timed out"},
		{"an insert error", nil, errors.New("insert export jobs: " + canary), "queue exports: failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &tenantExportSweep{
				tenant: tenantA, log: slog.New(slog.DiscardHandler),
				sweep: func(context.Context, *sql.DB, uuid.UUID) (tenancy.ExportSweep, error) {
					return tenancy.ExportSweep{Open: []uuid.UUID{exportA}}, tt.sweep
				},
				insert: func(context.Context, []TenantExportArgs) (int, error) { return 0, tt.insert },
			}
			err := w.Work(t.Context(), exportSweepJobFor(tenantA))
			if err == nil || err.Error() != tt.want || strings.Contains(err.Error(), canary) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEachExportJobIsInItsOwnQueueAndUniqueWhileItWaitsOrRuns(t *testing.T) {
	jobs := []struct {
		name     string
		opts     river.InsertOpts
		queue    string
		attempts int
	}{
		{"tenant_export_sweep", TenantExportSweepArgs{Tenant: tenantA}.InsertOpts(), tenantExportSweepQueue, tenantExportSweepAttempts},
		{"tenant_export", TenantExportArgs{Tenant: tenantA, Export: exportA}.InsertOpts(), tenantExportQueue, tenantExportAttempts},
	}
	for _, job := range jobs {
		t.Run(job.name, func(t *testing.T) {
			if job.opts.Queue != job.queue || job.opts.MaxAttempts != job.attempts || !job.opts.UniqueOpts.ByArgs {
				t.Errorf("queue %q, attempts %d, by args %v", job.opts.Queue, job.opts.MaxAttempts, job.opts.UniqueOpts.ByArgs)
			}
			for _, required := range []rivertype.JobState{
				rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
				rivertype.JobStateScheduled, rivertype.JobStateRetryable,
			} {
				if !slices.Contains(job.opts.UniqueOpts.ByState, required) {
					t.Errorf("state %q is not unique", required)
				}
			}
			if slices.Contains(job.opts.UniqueOpts.ByState, rivertype.JobStateCompleted) {
				t.Error("a completed job holds the next one back")
			}
		})
	}
	if (TenantExportSweepArgs{}).Kind() != "tenant_export_sweep" || (TenantExportArgs{}).Kind() != "tenant_export" {
		t.Error("a kind changed, and River matches stored jobs by it")
	}
}

// A field added to the arguments is a field River stores in river_job.args, outside row-level security. The key
// an export is encrypted to is read from the row, so it is never one of them.
func TestTheExportArgumentsHoldIdsAndNothingElse(t *testing.T) {
	for _, tt := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeFor[TenantExportSweepArgs](), []string{"Tenant"}},
		{reflect.TypeFor[TenantExportArgs](), []string{"Tenant", "Export"}},
	} {
		var got []string
		for i := range tt.typ.NumField() {
			got = append(got, tt.typ.Field(i).Name)
			if tt.typ.Field(i).Type != reflect.TypeFor[uuid.UUID]() {
				t.Errorf("%s.%s is not an id", tt.typ.Name(), tt.typ.Field(i).Name)
			}
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s has fields %v, want %v", tt.typ.Name(), got, tt.want)
		}
	}
}

func TestTheExportJobCancelsAJobForAnotherTenantBeforeTheDatabaseIsTouched(t *testing.T) {
	w := &tenantExport{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		run: func(context.Context, *sql.DB, uuid.UUID, uuid.UUID) (tenancy.ExportReport, error) {
			t.Error("an export ran for a job that names another tenant")
			return tenancy.ExportReport{}, nil
		},
		fail: func(context.Context, *sql.DB, uuid.UUID, uuid.UUID) error {
			t.Error("an export was failed for a job that names another tenant")
			return nil
		},
	}
	err := w.Work(t.Context(), exportJobFor(tenantB, 1, 3))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) || strings.Contains(err.Error(), tenantA.String()) || strings.Contains(err.Error(), tenantB.String()) {
		t.Fatalf("err = %v, want a cancellation that names no tenant", err)
	}
}

// workerFor builds the export job with a run that returns err, and counts the exports it marks failed.
func workerFor(runErr error, failed *int) *tenantExport {
	return &tenantExport{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		run: func(_ context.Context, _ *sql.DB, tenant, id uuid.UUID) (tenancy.ExportReport, error) {
			if tenant != tenantA || id != exportA {
				return tenancy.ExportReport{}, errors.New("the wrong export")
			}
			return tenancy.ExportReport{Tenant: tenant, Total: 12}, runErr
		},
		fail: func(_ context.Context, _ *sql.DB, tenant, id uuid.UUID) error {
			if tenant != tenantA || id != exportA {
				return errors.New("the wrong export")
			}
			*failed++
			return nil
		},
	}
}

func TestTheExportJobCompletesWhenTheExportIsReady(t *testing.T) {
	var failed int
	if err := workerFor(nil, &failed).Work(t.Context(), exportJobFor(tenantA, 1, 3)); err != nil || failed != 0 {
		t.Fatalf("err = %v, failed %d, want a completed job", err, failed)
	}
}

func TestTheExportJobCancelsWhenTheExportIsGone(t *testing.T) {
	var failed int
	err := workerFor(fmt.Errorf("export: claim: %w", tenancy.ErrNoExport), &failed).Work(t.Context(), exportJobFor(tenantA, 1, 3))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) || failed != 0 || !strings.Contains(err.Error(), errExportGone.Error()) {
		t.Fatalf("err = %v, failed %d, want a cancellation and no failure to record", err, failed)
	}
}

// A key that cannot be read and an archive over the cap fail the same way on every attempt, so the export is
// marked failed at once and the job is cancelled with the fixed text of the sentinel.
func TestTheExportJobFailsAtOnceForAKeyOrASizeNoRetryCanFix(t *testing.T) {
	for _, cause := range []error{tenancy.ErrBadRecipient, tenancy.ErrExportTooLarge} {
		t.Run(cause.Error(), func(t *testing.T) {
			var failed int
			err := workerFor(fmt.Errorf("write the export: %w", cause), &failed).Work(t.Context(), exportJobFor(tenantA, 1, 3))
			var cancelled *river.JobCancelError
			if !errors.As(err, &cancelled) || failed != 1 || !strings.Contains(err.Error(), cause.Error()) {
				t.Fatalf("err = %v, failed %d, want a cancellation and one failure", err, failed)
			}
		})
	}
}

func TestTheExportJobRetriesAndFailsTheExportOnItsLastAttempt(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "40001", Message: "could not serialize", Detail: "Failing row contains (" + canary + ")"}
	runErr := fmt.Errorf("export: read identity.principal: %w", pgErr)
	tests := []struct {
		name       string
		attempt    int
		cancelled  bool
		wantFailed int
	}{
		{"the first attempt is retried", 1, false, 0},
		{"the second attempt is retried", 2, false, 0},
		{"the last attempt marks the export failed", 3, false, 1},
		{"a stop of the process on the last attempt is not a failure", 3, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var failed int
			ctx := t.Context()
			if tt.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := workerFor(runErr, &failed).Work(ctx, exportJobFor(tenantA, tt.attempt, 3))
			var cancelled *river.JobCancelError
			if err == nil || errors.As(err, &cancelled) || err.Error() != "make the export: SQLSTATE 40001" || strings.Contains(err.Error(), canary) {
				t.Errorf("err = %v, want the operation and the class, and a retry", err)
			}
			if failed != tt.wantFailed {
				t.Errorf("failed %d, want %d", failed, tt.wantFailed)
			}
		})
	}
}

func TestTheExportJobHasTheMostTimeAJobHasAndTheSweepVeryLittle(t *testing.T) {
	if got := (&tenantExport{}).Timeout(nil); got != tenantExportTimeout || got <= premiseSweepTimeout {
		t.Errorf("the export timeout is %s", got)
	}
	if got := (&tenantExportSweep{}).Timeout(nil); got != tenantExportSweepTimeout || got >= tenantExportTimeout {
		t.Errorf("the sweep timeout is %s", got)
	}
}
