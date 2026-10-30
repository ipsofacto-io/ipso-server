//go:build integration

package migrate_test

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// Synthetic decision ids. No customer data is involved.
const (
	oldDecision   = "00000000-0000-4000-8000-0000000000a1"
	newDecision   = "00000000-0000-4000-8000-0000000000b1"
	thirdDecision = "00000000-0000-4000-8000-0000000000c1"
	atJune        = "2026-06-01"
)

func (s schema) addDecision(t *testing.T, id, valid string) {
	t.Helper()
	s.addDecisionVersion(t, id, 1, valid)
}

func (s schema) addDecisionVersion(t *testing.T, id string, version int, valid string) {
	t.Helper()
	if _, err := s.app.ExecContext(t.Context(), insertVersion, id, version, tenantA, valid, s.orgs[tenantA]); err != nil {
		t.Fatalf("insert %s %s: %v", id, valid, err)
	}
}

func (s schema) trySupersede(t *testing.T, from, to, at string) error {
	t.Helper()
	_, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz)`, tenantA, from, to, at)
	return err
}

func (s schema) supersede(t *testing.T, from, to, at string) {
	t.Helper()
	if err := s.trySupersede(t, from, to, at); err != nil {
		t.Fatalf("supersede %s: %v", from, err)
	}
}

func (s schema) addPeriod(t *testing.T, id, valid string) {
	t.Helper()
	if _, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
		VALUES ($1::uuid, $2::uuid, $3::text::tstzrange)`, tenantA, id, valid); err != nil {
		t.Fatalf("period %s: %v", id, err)
	}
}

// addBaseline records hex fingerprints. Each hex string is one digest.
func (s schema) addBaseline(t *testing.T, id, repo string, hexes []string) error {
	t.Helper()
	_, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
		VALUES ($1::uuid, $2::uuid, $3, (
			SELECT coalesce(array_agg(decode(h, 'hex')), '{}'::bytea[])
			FROM unnest($4::text[]) AS h
		))`, tenantA, id, repo, hexes)
	return err
}

func requireCheck(t *testing.T, err error, message string) {
	t.Helper()
	requireSQLState(t, err, "23514")
	if !strings.Contains(pgError(t, err).Message, message) {
		t.Errorf("message = %q, want it to contain %q", pgError(t, err).Message, message)
	}
}

func TestSupersessionObjectsExist(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	for _, name := range []string{"supersession", "grandfather_period", "baseline"} {
		var found bool
		if err := s.admin.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "registry."+name).Scan(&found); err != nil || !found {
			t.Errorf("registry.%s missing (err %v)", name, err)
		}
	}
}

func TestSupersessionClosesThePriorDecision(t *testing.T) {
	s := migrated(t)
	// The first row has to end, or it would overlap the later row. An open period
	// covers every later instant.
	s.addDecision(t, oldDecision, "[2026-01-01,2026-09-01)")
	s.addDecision(t, newDecision, "[2026-01-01,)")
	// A second current row starts later. The close deletes it instead of trimming it.
	s.addDecisionVersion(t, oldDecision, 2, "[2026-09-01,)")
	// This row already ended, so the close leaves it and archives nothing for it.
	s.addDecision(t, thirdDecision, "[2026-01-01,2026-03-01)")
	s.addDecisionVersion(t, thirdDecision, 2, "[2026-03-01,)")
	// thirdDecision's open row is what gets superseded below, after the first case.

	sleep(t, s.admin)
	before := dbNow(t, s.admin)
	sleep(t, s.admin)
	s.supersede(t, oldDecision, newDecision, atJune)
	sleep(t, s.admin)
	after := dbNow(t, s.admin)

	var (
		lowerOK   bool
		upperOK   bool
		lowerInc  bool
		upperOpen bool
		version   int
	)
	err := s.admin.QueryRowContext(t.Context(), `
		SELECT lower(valid_period) = $2::timestamptz,
		       upper(valid_period) = $3::timestamptz,
		       lower_inc(valid_period),
		       NOT upper_inc(valid_period),
		       version
		FROM registry.decision_version
		WHERE decision_id = $1::uuid`, oldDecision, "2026-01-01", atJune).Scan(&lowerOK, &upperOK, &lowerInc, &upperOpen, &version)
	if err != nil {
		t.Fatalf("current row: %v", err)
	}
	if !lowerOK || !upperOK || !lowerInc || !upperOpen || version != 1 {
		t.Errorf("trimmed row = lower %v upper %v inc %v exclusive %v version %d", lowerOK, upperOK, lowerInc, upperOpen, version)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version WHERE decision_id = $1::uuid`, oldDecision); n != 1 {
		t.Errorf("current rows = %d, want 1", n)
	}
	// The deleted future row and the trimmed row are both archived with a closed sys_period.
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version_history
		WHERE decision_id = $1::uuid AND upper(sys_period) IS NOT NULL`, oldDecision); n != 2 {
		t.Errorf("archived rows = %d, want 2", n)
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version_history
		WHERE decision_id = $1::uuid AND upper_inf(valid_period)`, oldDecision); n != 1 {
		t.Errorf("archived unbounded rows = %d, want 1", n)
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version_history
		WHERE decision_id = $1::uuid AND lower(valid_period) = $2::timestamptz`, oldDecision, "2026-09-01"); n != 1 {
		t.Errorf("archived future rows = %d, want 1", n)
	}
	// The successor is not closed.
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version_history WHERE decision_id = $1::uuid`, newDecision); n != 0 {
		t.Errorf("successor history rows = %d, want 0", n)
	}

	// As known before the supersession, July is still inside the old decision.
	// As known after it, July is not, and March still is.
	inForce := func(id string, valid string, known time.Time) int {
		t.Helper()
		return count(t, s.admin, `
			SELECT count(*) FROM registry.decision_version_all
			WHERE decision_id = $1::uuid
			  AND valid_period @> $2::timestamptz
			  AND sys_period @> $3::timestamptz`, id, valid, known)
	}
	if n := inForce(oldDecision, "2026-07-01", before); n != 1 {
		t.Errorf("old decision in force in July as known before = %d, want 1", n)
	}
	if n := inForce(oldDecision, "2026-07-01", after); n != 0 {
		t.Errorf("old decision in force in July as known after = %d, want 0", n)
	}
	if n := inForce(oldDecision, "2026-03-01", after); n != 1 {
		t.Errorf("old decision in force in March as known after = %d, want 1", n)
	}

	// A row that already ended is not archived when a later row of the same decision is closed.
	s.supersede(t, thirdDecision, newDecision, atJune)
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version
		WHERE decision_id = $1::uuid AND upper(valid_period) = $2::timestamptz`, thirdDecision, "2026-03-01"); n != 1 {
		t.Errorf("the row that already ended was not kept")
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version_history
		WHERE decision_id = $1::uuid AND upper(valid_period) = $2::timestamptz`, thirdDecision, "2026-03-01"); n != 0 {
		t.Errorf("the row that already ended was archived")
	}
}

func TestSupersessionIsRefused(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-07-01,)")
	s.addDecision(t, thirdDecision, "[2026-01-01,)")

	t.Run("the successor does not cover the instant", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, oldDecision, newDecision, atJune), "does not cover")
	})
	t.Run("the old decision does not start before the instant", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, newDecision, thirdDecision, atJune), "at or before")
	})
	t.Run("the old decision does not exist", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, "00000000-0000-4000-8000-0000000000ff", thirdDecision, atJune), "at or before")
	})
	t.Run("the successor does not exist", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, oldDecision, "00000000-0000-4000-8000-0000000000ff", atJune), "does not cover")
	})
	t.Run("a decision cannot supersede itself", func(t *testing.T) {
		err := s.trySupersede(t, oldDecision, oldDecision, atJune)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "supersession_not_self" {
			t.Errorf("constraint = %q, want supersession_not_self", pgError(t, err).ConstraintName)
		}
	})
	t.Run("the instant is infinite", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, oldDecision, thirdDecision, "infinity"), "finite")
	})
	if n := count(t, s.admin, `SELECT count(*) FROM registry.supersession`); n != 0 {
		t.Fatalf("a refused supersession left %d rows", n)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version_history`); n != 0 {
		t.Errorf("a refused supersession archived %d rows", n)
	}

	// The successor now covers June, so the chain can be recorded, and then it cannot loop.
	s.addDecisionVersion(t, newDecision, 2, "[2026-01-01,2026-07-01)")
	s.supersede(t, oldDecision, newDecision, atJune)
	t.Run("the same decision cannot be superseded twice", func(t *testing.T) {
		err := s.trySupersede(t, oldDecision, thirdDecision, atJune)
		requireSQLState(t, err, "23505")
		if pgError(t, err).ConstraintName != "supersession_one_successor" {
			t.Errorf("constraint = %q, want supersession_one_successor", pgError(t, err).ConstraintName)
		}
	})
	// March is before the close, so the old decision still covers it. The refusal is the
	// cycle check, not the close.
	t.Run("a chain cannot loop", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, newDecision, oldDecision, "2026-03-01"), "already superseded")
	})
	s.supersede(t, newDecision, thirdDecision, "2026-03-01")
	t.Run("a longer chain cannot loop", func(t *testing.T) {
		requireCheck(t, s.trySupersede(t, thirdDecision, oldDecision, "2026-02-01"), "already superseded")
	})
}

func TestSupersessionDeletesARowThatStartsAtTheInstant(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-06-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")
	s.supersede(t, oldDecision, newDecision, atJune)
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version WHERE decision_id = $1::uuid`, oldDecision); n != 0 {
		t.Errorf("current rows = %d, want 0", n)
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version_history
		WHERE decision_id = $1::uuid AND lower(valid_period) = $2::timestamptz`, oldDecision, atJune); n != 1 {
		t.Errorf("archived rows starting at the instant = %d, want 1", n)
	}
}

func TestSupersessionDoesNotCloseAnotherTenant(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")
	if _, err := s.app.ExecContext(t.Context(), insertVersion, oldDecision, 1, tenantB, "[2026-01-01,)", s.orgs[tenantB]); err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	s.supersede(t, oldDecision, newDecision, atJune)

	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid AND upper_inf(valid_period)`, tenantA, oldDecision); n != 0 {
		t.Errorf("tenant A still has an open valid period")
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid AND upper_inf(valid_period)`, tenantB, oldDecision); n != 1 {
		t.Errorf("tenant B open rows = %d, want 1", n)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.supersession WHERE tenant_id = $1::uuid`, tenantB); n != 0 {
		t.Errorf("tenant B has %d supersessions", n)
	}
}

func TestSupersessionRefusesRepeatableRead(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")

	ctx := t.Context()
	conn, err := s.app.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN ISOLATION LEVEL REPEATABLE READ`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `ROLLBACK`) }()

	_, err = conn.ExecContext(ctx, `
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz)`, tenantA, oldDecision, newDecision, atJune)
	if pgError(t, err).Code != "0A000" {
		t.Fatalf("want SQLSTATE 0A000, got %v", err)
	}
	if !strings.Contains(pgError(t, err).Message, "repeatable read") {
		t.Errorf("message = %q", pgError(t, err).Message)
	}
	if _, err := conn.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.supersession`); n != 0 {
		t.Errorf("a refused transaction left %d supersessions", n)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version WHERE decision_id = $1::uuid AND upper_inf(valid_period)`, oldDecision); n != 1 {
		t.Errorf("the old decision was closed anyway")
	}
}

// Two writes that name each other as successor. The second waits for the first to commit
// and then fails, so the chain cannot become a cycle.
func TestConcurrentSupersessionsCannotCycle(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	pairs := [][2]string{{oldDecision, newDecision}, {newDecision, oldDecision}}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range pairs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = s.app.ExecContext(ctx, `
				INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz)`,
				tenantA, pairs[i][0], pairs[i][1], atJune)
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		if ctx.Err() != nil {
			t.Fatalf("the writes did not finish: %v", errs)
		}
		// The loser either sees the cycle or sees that the close already removed coverage.
		requireSQLState(t, err, "23514")
	}
	if ok != 1 {
		t.Fatalf("%d writes committed, want 1: %v", ok, errs)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.supersession`); n != 1 {
		t.Errorf("supersessions = %d, want 1", n)
	}
}

// SERIALIZABLE keeps one snapshot, so the second write does not see the first row. PostgreSQL
// aborts one of them instead. Both committing would be a cycle.
func TestSerializableSupersessionsCannotCycle(t *testing.T) {
	s := migrated(t)
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	conns := make([]*sql.Conn, 2)
	for i := range conns {
		conn, err := s.app.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = conn
		t.Cleanup(func() {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
			_ = conn.Close()
		})
		if _, err := conn.ExecContext(ctx, `SET statement_timeout = '10s'`); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, `BEGIN ISOLATION LEVEL SERIALIZABLE`); err != nil {
			t.Fatal(err)
		}
	}

	pairs := [][2]string{{oldDecision, newDecision}, {newDecision, oldDecision}}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range pairs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := conns[i].ExecContext(ctx, `
				INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz)`,
				tenantA, pairs[i][0], pairs[i][1], atJune); err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = conns[i].ExecContext(ctx, `COMMIT`)
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
			continue
		}
		if ctx.Err() != nil {
			t.Fatalf("the writes did not finish: %v", errs)
		}
		code := pgError(t, err).Code
		if code != "40001" && code != "23514" {
			t.Errorf("want serialization_failure or check_violation, got %s: %v", code, err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d writes committed, want 1: %v", ok, errs)
	}
}

func TestCallerCannotBackdateTheNewTables(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")
	before := dbNow(t, s.admin)

	inserts := []struct {
		name  string
		query string
		args  []any
	}{
		{"supersession", `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at, sys_period)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz, '[2000-01-01,2000-02-01)')`,
			[]any{tenantA, oldDecision, newDecision, atJune}},
		{"grandfather period", `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period, sys_period)
			VALUES ($1::uuid, $2::uuid, '[2026-01-01,)', '[2000-01-01,2000-02-01)')`,
			[]any{tenantA, newDecision}},
		{"baseline", `
			INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints, sys_period)
			VALUES ($1::uuid, $2::uuid, 'acme/payments', '{}', '[2000-01-01,2000-02-01)')`,
			[]any{tenantA, newDecision}},
	}
	// The baseline needs the period, so the period insert has to be the second one and the
	// baseline the third. The supersession does not depend on them.
	for _, ins := range inserts {
		t.Run(ins.name, func(t *testing.T) {
			if _, err := s.app.ExecContext(ctx, ins.query, ins.args...); err != nil {
				t.Fatalf("insert: %v", err)
			}
		})
	}
	for _, table := range []string{"registry.supersession", "registry.grandfather_period", "registry.baseline"} {
		var from time.Time
		var open bool
		err := s.admin.QueryRowContext(ctx, `SELECT lower(sys_period), upper(sys_period) IS NULL FROM `+table).Scan(&from, &open)
		if err != nil {
			t.Fatal(err)
		}
		if !open || from.Before(before) {
			t.Errorf("%s sys_period opens at %v (open %v), want an open period from %v or later", table, from, open, before)
		}
	}
}

func TestApplicationRoleCannotChangeSupersessionOrBaselines(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	s.addDecision(t, newDecision, "[2026-01-01,)")
	s.supersede(t, oldDecision, newDecision, atJune)
	s.addPeriod(t, newDecision, "[2026-01-01,)")
	if err := s.addBaseline(t, newDecision, "acme/payments", []string{}); err != nil {
		t.Fatal(err)
	}

	statements := []string{
		`UPDATE registry.supersession SET effective_at = now()`,
		`DELETE FROM registry.supersession`,
		`TRUNCATE registry.supersession`,
		`UPDATE registry.grandfather_period SET valid_period = '[2026-02-01,)'`,
		`DELETE FROM registry.grandfather_period`,
		`TRUNCATE registry.grandfather_period`,
		`UPDATE registry.baseline SET repo = 'acme/other'`,
		`DELETE FROM registry.baseline`,
		`TRUNCATE registry.baseline`,
		`ALTER TABLE registry.supersession DISABLE TRIGGER ALL`,
		`SELECT registry.open_sys_period()`,
		`SELECT registry.supersession_check()`,
		`SELECT registry.supersession_close()`,
		`SELECT registry.baseline_check_fingerprints()`,
	}
	for _, statement := range statements {
		t.Run(statement, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.supersession`); n != 1 {
		t.Errorf("supersessions visible = %d, want 1", n)
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.baseline`); n != 1 {
		t.Errorf("baselines visible = %d, want 1", n)
	}
}

func TestSupersessionFunctionsAreOwnedByTheMigrationRoleAndNotCallable(t *testing.T) {
	s := migrated(t)
	for _, signature := range []string{
		"registry.open_sys_period()",
		"registry.supersession_check()",
		"registry.supersession_close()",
		"registry.baseline_check_fingerprints()",
	} {
		t.Run(signature, func(t *testing.T) {
			var (
				definer bool
				owner   string
				config  string
				app     bool
				public  bool
			)
			err := s.admin.QueryRowContext(t.Context(), `
				SELECT prosecdef, pg_get_userbyid(proowner), coalesce(array_to_string(proconfig, ';'), ''),
				       has_function_privilege($2, oid, 'EXECUTE'),
				       coalesce((SELECT bool_or(grantee = 0) FROM aclexplode(proacl)), false)
				FROM pg_catalog.pg_proc WHERE oid = $1::text::regprocedure`, signature, pgtest.App).Scan(&definer, &owner, &config, &app, &public)
			if err != nil {
				t.Fatal(err)
			}
			if definer {
				t.Error("the function is SECURITY DEFINER, want the caller's rights")
			}
			if owner != pgtest.Migrate {
				t.Errorf("owner = %q, want %q", owner, pgtest.Migrate)
			}
			if want := "search_path=pg_catalog, pg_temp"; config != want {
				t.Errorf("function config = %q, want %q", config, want)
			}
			if app || public {
				t.Errorf("EXECUTE is granted: application role %v, PUBLIC %v", app, public)
			}
		})
	}
}

func TestGrandfatherPeriodAndBaselineRules(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.addPeriod(t, newDecision, "[2026-01-01,)")
	s.addPeriod(t, oldDecision, "[2026-01-01,2026-06-01)")

	t.Run("a second period for one decision", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
			VALUES ($1::uuid, $2::uuid, '[2026-02-01,)')`, tenantA, newDecision)
		requireSQLState(t, err, "23505")
	})
	t.Run("an empty period", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
			VALUES ($1::uuid, $2::uuid, '[2026-01-01,2026-01-01)')`, tenantA, thirdDecision)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "grandfather_period_bounds" {
			t.Errorf("constraint = %q", pgError(t, err).ConstraintName)
		}
	})
	t.Run("a period with no start", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
			VALUES ($1::uuid, $2::uuid, '[,)')`, tenantA, thirdDecision)
		requireSQLState(t, err, "23514")
	})

	digest := strings.Repeat("ab", 32)
	if err := s.addBaseline(t, newDecision, "acme/payments", []string{digest}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := s.addBaseline(t, newDecision, "acme/other", []string{}); err != nil {
		t.Fatalf("empty baseline: %v", err)
	}
	t.Run("a second baseline for one repository", func(t *testing.T) {
		err := s.addBaseline(t, newDecision, "acme/payments", []string{digest})
		requireSQLState(t, err, "23505")
		if pgError(t, err).ConstraintName != "baseline_one_per_repo" {
			t.Errorf("constraint = %q", pgError(t, err).ConstraintName)
		}
	})
	t.Run("no grandfather period", func(t *testing.T) {
		err := s.addBaseline(t, thirdDecision, "acme/payments", []string{})
		requireSQLState(t, err, "23503")
		if pgError(t, err).ConstraintName != "baseline_period" {
			t.Errorf("constraint = %q", pgError(t, err).ConstraintName)
		}
	})
	for _, repo := range []string{"Acme/payments", "acme/*", "acme/..", "acme", "payments"} {
		t.Run("repo "+repo, func(t *testing.T) {
			err := s.addBaseline(t, oldDecision, repo, []string{})
			requireSQLState(t, err, "23514")
			if pgError(t, err).ConstraintName != "baseline_repo" {
				t.Errorf("constraint = %q", pgError(t, err).ConstraintName)
			}
		})
	}
	t.Run("a short fingerprint", func(t *testing.T) {
		requireCheck(t, s.addBaseline(t, oldDecision, "acme/payments", []string{"aa"}), "32 bytes")
	})
	t.Run("a repeated fingerprint", func(t *testing.T) {
		requireCheck(t, s.addBaseline(t, oldDecision, "acme/payments", []string{digest, digest}), "repeated")
	})
	t.Run("a null fingerprint", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
			VALUES ($1::uuid, $2::uuid, 'acme/payments', ARRAY[decode($3, 'hex'), NULL]::bytea[])`,
			tenantA, oldDecision, digest)
		requireSQLState(t, err, "23514")
	})
}

func TestBaselineHoldsAtMost100000Fingerprints(t *testing.T) {
	s := migrated(t)
	s.addPeriod(t, newDecision, "[2026-01-01,)")
	insert := func(n int) error {
		_, err := s.app.ExecContext(t.Context(), `
			INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
			SELECT $1::uuid, $2::uuid, 'acme/payments',
			       array_agg(decode(lpad(to_hex(g), 64, '0'), 'hex'))
			FROM generate_series(1, $3::int) AS g`, tenantA, newDecision, n)
		return err
	}
	if err := insert(100000); err != nil {
		t.Fatalf("100000 fingerprints: %v", err)
	}
	_, err := s.app.ExecContext(t.Context(), `DELETE FROM registry.baseline`)
	// The application role cannot delete. Use the owner to make room for the over-limit insert.
	if err == nil {
		t.Fatal("the application role deleted a baseline")
	}
	if _, err := s.admin.ExecContext(t.Context(), `DELETE FROM registry.baseline`); err != nil {
		t.Fatal(err)
	}
	err = insert(100001)
	requireSQLState(t, err, "23514")
}

// With the triggers off, the CHECK constraint is what bounds the array. Only a superuser
// can switch the triggers off.
func TestBaselineBoundHoldsWhenTriggersAreOff(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.addPeriod(t, newDecision, "[2026-01-01,)")
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints, sys_period)
		SELECT $1::uuid, $2::uuid, 'acme/payments',
		       array_agg(decode(lpad(to_hex(g), 64, '0'), 'hex')),
		       tstzrange(clock_timestamp(), NULL)
		FROM generate_series(1, 100001) AS g`, tenantA, newDecision)
	requireSQLState(t, err, "23514")
	if pgError(t, err).ConstraintName != "baseline_fingerprints_bound" {
		t.Errorf("constraint = %q, want baseline_fingerprints_bound", pgError(t, err).ConstraintName)
	}
}
