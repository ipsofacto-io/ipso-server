//go:build integration

package llmgw

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
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

func newLedger(t *testing.T) (PGLedger, *sql.DB) {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return PGLedger{DB: db.Open(t, pgtest.App)}, db.Open(t, pgtest.Admin)
}

var november = time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)

func usage(t *testing.T, db *sql.DB, tenant uuid.UUID, month time.Time) int64 {
	t.Helper()
	var tokens int64
	err := pgtest.Scan(t.Context(), db, tenant.String(), `SELECT tokens FROM llm.usage WHERE tenant_id = $1 AND month = $2`, []any{tenant, month}, &tokens)
	if errors.Is(err, sql.ErrNoRows) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestLedgerReservesAndSettles(t *testing.T) {
	ledger, admin := newLedger(t)
	ctx := t.Context()
	if err := ledger.Reserve(ctx, tenantA, november, 600, 1000); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, tenantA, november, 500, 1000); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget", err)
	}
	if err := ledger.Settle(ctx, tenantA, november, -400); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, tenantA, november, 500, 1000); err != nil {
		t.Fatal(err)
	}
	if got := usage(t, admin, tenantA, november); got != 700 {
		t.Fatalf("tokens = %d, want 700", got)
	}
	if err := ledger.Settle(ctx, tenantA, november, -5000); err != nil {
		t.Fatal(err)
	}
	if got := usage(t, admin, tenantA, november); got != 0 {
		t.Fatalf("tokens = %d, want 0 after an over-settle", got)
	}
}

func TestLedgerIsPerTenantAndPerMonth(t *testing.T) {
	ledger, admin := newLedger(t)
	tenantB := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	ctx := t.Context()
	if err := ledger.Reserve(ctx, tenantA, november, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, tenantB, november, 1000, 1000); err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	december := november.AddDate(0, 1, 0)
	if err := ledger.Reserve(ctx, tenantA, december, 1000, 1000); err != nil {
		t.Fatalf("next month: %v", err)
	}
	if usage(t, admin, tenantA, november) != 1000 || usage(t, admin, tenantB, november) != 1000 || usage(t, admin, tenantA, december) != 1000 {
		t.Fatal("a reservation landed on the wrong row")
	}
}

func TestLedgerConcurrentReservationsStayWithinTheLimit(t *testing.T) {
	ledger, admin := newLedger(t)
	var granted atomic.Int64
	var wg sync.WaitGroup
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ledger.Reserve(t.Context(), tenantA, november, 10, 100)
			if err == nil {
				granted.Add(1)
			} else if !errors.Is(err, ErrBudget) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 10 || usage(t, admin, tenantA, november) != 100 {
		t.Fatalf("granted %d, total %d, want 10 and 100", granted.Load(), usage(t, admin, tenantA, november))
	}
}

func TestUsageRejectsAMonthThatDoesNotStartOnTheFirst(t *testing.T) {
	ledger, _ := newLedger(t)
	if err := ledger.Reserve(t.Context(), tenantA, november.AddDate(0, 0, 3), 10, 100); err == nil {
		t.Fatal("a mid-month row was accepted")
	}
}

func TestApplicationRoleCannotDeleteUsage(t *testing.T) {
	ledger, _ := newLedger(t)
	if err := ledger.Reserve(t.Context(), tenantA, november, 10, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.DB.ExecContext(t.Context(), `DELETE FROM llm.usage`); err == nil {
		t.Fatal("ipso_app deleted usage rows")
	}
}
