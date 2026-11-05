//go:build integration

package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

// stack is a migrated database with two tenants. Each has a waiver whose 14, 3, and 0 day notices are all
// due, so a worker that serves one tenant has three notices to record and the other tenant's stay unwritten.
// Every row is synthetic.
type stack struct {
	database *pgtest.Database
	app      *sql.DB
}

func newStack(t *testing.T) *stack {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &stack{database: database, app: database.Open(t, pgtest.App)}
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		s.seed(t, tenant)
	}
	return s
}

func (s *stack) seed(t *testing.T, tenant uuid.UUID) {
	t.Helper()
	ctx, id := t.Context(), tenant.String()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pgtest.Exec(ctx, s.app, id, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	scan := func(query string, args ...any) uuid.UUID {
		t.Helper()
		var got uuid.UUID
		if err := pgtest.Scan(ctx, s.app, id, query, args, &got); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return got
	}
	exec(`INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, tenant)
	approver := scan(`INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'synthetic approver') RETURNING id`, tenant)
	scope := scan(`INSERT INTO registry.scope (tenant_id, kind, selector) VALUES ($1, 'org', 'acme') RETURNING id`, tenant)
	decision := uuid.New()
	exec(`
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, '{}', ARRAY[$3::uuid], tstzrange(clock_timestamp() - interval '50 days', NULL, '[)'))`,
		decision, tenant, scope)
	exec(`
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', $4,
		        tstzrange(clock_timestamp() - interval '30 days', clock_timestamp() - interval '1 hour', '[)'), 'TICKET-1')`,
		tenant, decision, scope, approver)
}

func (s *stack) notices(t *testing.T, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), `SELECT count(*) FROM registry.waiver_notice`, nil, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (s *stack) jobs(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.app.QueryRowContext(t.Context(), `SELECT count(*) FROM river.river_job WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// testLog sends what a worker logs to the test, until the worker has stopped.
type testLog struct {
	t      *testing.T
	mu     sync.Mutex
	closed bool
}

func (l *testLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.t.Log(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}

func (l *testLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
}

// start runs a worker for the tenant as the application role. The returned function stops it and checks
// that Run ended without an error. The test cleanup calls it too.
func (s *stack) start(t *testing.T, tenant uuid.UUID) (stop func()) {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), s.database.DSN(pgtest.App))
	if err != nil {
		t.Fatal(err)
	}
	logs := &testLog{t: t}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Pool: pool, Tenant: tenant, Log: slog.New(slog.NewTextHandler(logs, nil))})
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run returned %v after its context ended, want nil", err)
				}
			case <-time.After(30 * time.Second):
				t.Error("the worker did not stop")
			}
			pool.Close()
			logs.close()
		})
	}
	t.Cleanup(stop)
	return stop
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestTwoWorkersRecordADueNoticeOnce(t *testing.T) {
	s := newStack(t)
	s.start(t, tenantA)
	s.start(t, tenantA)

	eventually(t, "the sweep recorded the three notices", func() bool { return s.notices(t, tenantA) == 3 })
	eventually(t, "a sweep completed", func() bool { return s.jobs(t, `kind = 'waiver_notices' AND state = 'completed'`) >= 1 })
	if n := s.notices(t, tenantA); n != 3 {
		t.Errorf("notices with two workers = %d, want 3", n)
	}
	if n := s.jobs(t, `kind = 'waiver_notices' AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled')`); n > 1 {
		t.Errorf("%d sweeps are waiting or running at once, want at most 1 for the tenant", n)
	}
}

func TestARestartRunsTheSweepAgainAndRecordsNothingNew(t *testing.T) {
	s := newStack(t)
	stop := s.start(t, tenantA)
	eventually(t, "the sweep recorded the three notices", func() bool { return s.notices(t, tenantA) == 3 })
	eventually(t, "a sweep completed", func() bool { return s.jobs(t, `kind = 'waiver_notices' AND state = 'completed'`) >= 1 })
	stop()
	before := s.jobs(t, `kind = 'waiver_notices' AND state = 'completed'`)

	s.start(t, tenantA)
	eventually(t, "a sweep ran after the restart", func() bool {
		return s.jobs(t, `kind = 'waiver_notices' AND state = 'completed'`) > before
	})
	if n := s.notices(t, tenantA); n != 3 {
		t.Errorf("notices across a restart = %d, want 3", n)
	}
	if n := s.notices(t, tenantB); n != 0 {
		t.Errorf("notices of the tenant nobody serves = %d, want 0", n)
	}
}

func TestAJobThatNamesAnotherTenantIsCancelledAndWritesNothing(t *testing.T) {
	s := newStack(t)
	s.start(t, tenantA)

	pool, err := pgxpool.New(t.Context(), s.database.DSN(pgtest.App))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// A client with no queues only inserts, as the tool that queues a job for a tenant would.
	inserter, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: riverSchema})
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := inserter.Insert(t.Context(), WaiverNoticesArgs{Tenant: tenantB}, nil)
	if err != nil {
		t.Fatal(err)
	}

	read := func() (state, stored string) {
		t.Helper()
		err := s.app.QueryRowContext(t.Context(), `SELECT state::text, coalesce(errors::text, '') FROM river.river_job WHERE id = $1`, inserted.Job.ID).Scan(&state, &stored)
		if err != nil {
			t.Fatal(err)
		}
		return state, stored
	}
	eventually(t, "the worker cancelled the job of the other tenant", func() bool {
		state, _ := read()
		return state == "cancelled"
	})
	_, stored := read()
	if !strings.Contains(stored, errOtherTenant.Error()) {
		t.Errorf("stored errors = %s, want %q", stored, errOtherTenant)
	}
	if strings.Contains(stored, tenantB.String()) || strings.Contains(stored, tenantA.String()) {
		t.Errorf("stored errors name a tenant: %s", stored)
	}
	// The worker's own sweep still runs, and the other tenant's waiver stays unnoticed.
	eventually(t, "the worker recorded the notices of its own tenant", func() bool { return s.notices(t, tenantA) == 3 })
	if n := s.notices(t, tenantB); n != 0 {
		t.Errorf("notices written for the tenant the job named = %d, want 0", n)
	}
}

func TestTheWorkerRefusesWhatCouldServeTheWrongTenant(t *testing.T) {
	s := newStack(t)
	tests := []struct {
		name string
		dsn  string
	}{
		{"a superuser", s.database.DSN(pgtest.Admin)},
		{"a role with BYPASSRLS", s.database.DSN(pgtest.Bypass)},
		{"a role that switches to BYPASSRLS", s.database.DSNSwitchingRole(pgtest.Member, pgtest.Bypass)},
		{"the migration role, which owns the tables", s.database.DSN(pgtest.Migrate)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := pgxpool.New(t.Context(), tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			if err := Run(t.Context(), Config{Pool: pool, Tenant: tenantA}); !errors.Is(err, rls.ErrRefused) {
				t.Errorf("err = %v, want the start refusal", err)
			}
			if n := s.jobs(t, `true`); n != 0 {
				t.Errorf("%d jobs exist after a refused start, want none", n)
			}
		})
	}

	t.Run("a tenant with no row", func(t *testing.T) {
		pool, err := pgxpool.New(t.Context(), s.database.DSN(pgtest.App))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := Run(t.Context(), Config{Pool: pool, Tenant: uuid.New()}); !errors.Is(err, tenancy.ErrUnknownTenant) {
			t.Errorf("err = %v, want the unknown tenant refusal", err)
		}
	})
}

func TestTheWorkerRefusesADatabaseThatRiverWasNotMigratedIn(t *testing.T) {
	s := newStack(t)
	admin := s.database.Open(t, pgtest.Admin)
	if _, err := admin.ExecContext(t.Context(), `ALTER SCHEMA river RENAME TO river_gone`); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), s.database.DSN(pgtest.App))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	err = Run(t.Context(), Config{Pool: pool, Tenant: tenantA})
	if err == nil || !strings.Contains(err.Error(), "run ipso-server migrate") {
		t.Errorf("err = %v, want it to say to run the migration", err)
	}
}
