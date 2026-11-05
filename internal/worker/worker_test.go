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
)

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

func jobFor(tenant uuid.UUID) *river.Job[WaiverNoticesArgs] {
	return &river.Job[WaiverNoticesArgs]{JobRow: &rivertype.JobRow{ID: 7}, Args: WaiverNoticesArgs{Tenant: tenant}}
}

func newWorker(notify notifyFunc) *waiverNotices {
	return &waiverNotices{tenant: tenantA, log: slog.New(slog.DiscardHandler), notify: notify}
}

func TestRunRequiresAPoolAndATenant(t *testing.T) {
	if err := Run(t.Context(), Config{Tenant: tenantA}); err == nil || !strings.Contains(err.Error(), "pool") {
		t.Errorf("no pool: err = %v", err)
	}
	if err := (Config{}).validate(); err == nil {
		t.Error("an empty config passed")
	}
}

func TestAJobForAnotherTenantIsCancelledBeforeTheDatabaseIsTouched(t *testing.T) {
	w := newWorker(func(context.Context, *sql.DB, uuid.UUID) (int, error) {
		t.Error("registry.Notify ran for a job that names another tenant")
		return 0, nil
	})
	err := w.Work(t.Context(), jobFor(tenantB))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) {
		t.Fatalf("err = %v, want a cancellation, because a retry would be refused again", err)
	}
	if !strings.Contains(err.Error(), errOtherTenant.Error()) {
		t.Errorf("err = %q, want %q", err, errOtherTenant)
	}
	if strings.Contains(err.Error(), tenantB.String()) || strings.Contains(err.Error(), tenantA.String()) {
		t.Errorf("err = %q names a tenant", err)
	}
}

func TestAJobForTheTenantCallsNotifyOnceForThatTenant(t *testing.T) {
	var calls []uuid.UUID
	w := newWorker(func(_ context.Context, _ *sql.DB, tenant uuid.UUID) (int, error) {
		calls = append(calls, tenant)
		return 3, nil
	})
	if err := w.Work(t.Context(), jobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != tenantA {
		t.Errorf("Notify calls = %v, want one for %s", calls, tenantA)
	}
}

// The text of an attempt error is stored in river_job.errors, so it must hold no row content.
func TestAFailureIsStoredAsItsOperationAndClassOnly(t *testing.T) {
	const secret = "TICKET-SECRET"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			"a database error that quotes a row",
			fmt.Errorf("record waiver notices: %w", &pgconn.PgError{
				Code:    "23514",
				Message: `new row for relation "waiver_notice" violates check constraint`,
				Detail:  "Failing row contains (" + secret + ")",
			}),
			"record waiver notices: SQLSTATE 23514",
		},
		{"a deadline", fmt.Errorf("%s: %w", secret, context.DeadlineExceeded), "record waiver notices: timed out"},
		{"a cancellation", fmt.Errorf("%s: %w", secret, context.Canceled), "record waiver notices: canceled"},
		{"anything else", errors.New("connection refused to " + secret), "record waiver notices: failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorker(func(context.Context, *sql.DB, uuid.UUID) (int, error) { return 0, tt.err })
			err := w.Work(t.Context(), jobFor(tenantA))
			if err == nil || err.Error() != tt.want {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Errorf("err = %q holds row content", err)
			}
		})
	}
}

// River's default unique states include completed, which would hold the next hourly job back until its
// cleaner removed the completed one. It also requires the four states that move a job through the queue.
func TestTheJobIsUniqueWhileItWaitsOrRunsAndNotAfterItCompletes(t *testing.T) {
	opts := WaiverNoticesArgs{Tenant: tenantA}.InsertOpts()
	if !opts.UniqueOpts.ByArgs {
		t.Error("the job is not unique by its tenant")
	}
	if opts.Queue != waiverNoticesQueue || opts.MaxAttempts != waiverNoticesAttempts {
		t.Errorf("queue %q, attempts %d", opts.Queue, opts.MaxAttempts)
	}
	states := opts.UniqueOpts.ByState
	for _, required := range []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateScheduled,
		rivertype.JobStateRetryable,
	} {
		if !slices.Contains(states, required) {
			t.Errorf("state %q is not unique", required)
		}
	}
	for _, done := range []rivertype.JobState{rivertype.JobStateCompleted, rivertype.JobStateDiscarded, rivertype.JobStateCancelled} {
		if slices.Contains(states, done) {
			t.Errorf("state %q holds the next tick back", done)
		}
	}
}

func TestTheArgumentsHoldTheTenantIDAndNothingElse(t *testing.T) {
	if got := (WaiverNoticesArgs{Tenant: tenantA}).Kind(); got != "waiver_notices" {
		t.Errorf("kind = %q", got)
	}
	// A field added to the arguments is a field River stores in river_job.args, outside row-level security.
	typ := reflect.TypeFor[WaiverNoticesArgs]()
	if typ.NumField() != 1 || typ.Field(0).Name != "Tenant" {
		t.Errorf("the arguments have %d fields, want the tenant id only", typ.NumField())
	}
}
