//go:build integration

package migrate_test

import (
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func (s schema) tryWaiver(t *testing.T, decision, scope, valid, reason, approver, ticket string) error {
	t.Helper()
	_, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6::text::tstzrange, $7)`,
		tenantA, decision, scope, reason, approver, valid, ticket)
	return err
}

func TestWaiverStaysInsideTheDecisionAndTheCap(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	repo := s.addScope(t, tenantA, org, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")
	sibling := s.addScope(t, tenantA, org, "repo", "acme/billing")
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', ARRAY[$3::uuid], '[2026-01-01,2026-06-01)')`,
		oldDecision, tenantA, repo); err != nil {
		t.Fatal(err)
	}

	if err := s.tryWaiver(t, oldDecision, path, "[2026-02-01,2026-04-01)", "a real exception", "team:platform", "TICKET-1"); err != nil {
		t.Fatalf("path waiver: %v", err)
	}
	if err := s.tryWaiver(t, oldDecision, repo, "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-2"); err != nil {
		t.Fatalf("repo waiver: %v", err)
	}

	t.Run("beyond the decision", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, repo, "[2026-05-01,2026-07-01)", "a real exception", "team:platform", "TICKET-3")
		requireCheck(t, err, "extends beyond the decision")
	})
	t.Run("no decision", func(t *testing.T) {
		err := s.tryWaiver(t, thirdDecision, repo, "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-3")
		requireCheck(t, err, "extends beyond the decision")
	})
	t.Run("a scope outside the decision", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, sibling, "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-3")
		requireCheck(t, err, "outside the decision")
	})
	t.Run("a scope of another tenant", func(t *testing.T) {
		// The scope check runs before the foreign key, so the caller sees the
		// trigger. The key is checked with the triggers off.
		err := s.tryWaiver(t, oldDecision, s.orgs[tenantB], "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-3")
		requireCheck(t, err, "outside the decision")
	})
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', ARRAY[$3::uuid],
		        tstzrange(clock_timestamp() - interval '1 day', NULL, '[)'))`,
		newDecision, tenantA, repo); err != nil {
		t.Fatal(err)
	}
	t.Run("longer than 90 days", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.waiver
				(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
			        tstzrange(clock_timestamp(), clock_timestamp() + interval '90 days' + interval '1 second', '[)'),
			        'TICKET-LONG')`, tenantA, newDecision, repo)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_bounds" {
			t.Errorf("constraint = %q, want waiver_bounds", pgError(t, err).ConstraintName)
		}
	})
	t.Run("exactly 90 days", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.waiver
				(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
			        tstzrange(clock_timestamp(), clock_timestamp() + interval '90 days', '[)'),
			        'TICKET-90')`, tenantA, newDecision, repo)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no end", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.waiver
				(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
			VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
			        tstzrange(clock_timestamp(), NULL, '[)'), 'TICKET-OPEN')`,
			tenantA, newDecision, repo)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_bounds" {
			t.Errorf("constraint = %q, want waiver_bounds", pgError(t, err).ConstraintName)
		}
	})
	for _, tc := range []struct {
		name       string
		valid      string
		constraint string
	}{
		{"an empty period", "[2026-02-01,2026-02-01)", "waiver_bounds"},
		{"a closed end", "[2026-02-01,2026-03-01]", "waiver_bounds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.tryWaiver(t, oldDecision, repo, tc.valid, "a real exception", "team:platform", "TICKET-BAD")
			requireSQLState(t, err, "23514")
			if pgError(t, err).ConstraintName != tc.constraint {
				t.Errorf("constraint = %q, want %s", pgError(t, err).ConstraintName, tc.constraint)
			}
		})
	}
	t.Run("a reason that is too long", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, repo, "[2026-02-01,2026-03-01)", strings.Repeat("a", 2001), "team:platform", "TICKET-BAD")
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_reason" {
			t.Errorf("constraint = %q, want waiver_reason", pgError(t, err).ConstraintName)
		}
	})
	t.Run("a reason with a newline", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, repo, "[2026-02-01,2026-03-01)", "line\nbreak", "team:platform", "TICKET-BAD")
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_reason" {
			t.Errorf("constraint = %q, want waiver_reason", pgError(t, err).ConstraintName)
		}
	})
	t.Run("an approver with surrounding space", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, repo, "[2026-02-01,2026-03-01)", "a real exception", " team:platform", "TICKET-BAD")
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_approver" {
			t.Errorf("constraint = %q, want waiver_approver", pgError(t, err).ConstraintName)
		}
	})
	t.Run("a ticket with surrounding space", func(t *testing.T) {
		err := s.tryWaiver(t, oldDecision, repo, "[2026-02-01,2026-03-01)", "a real exception", "team:platform", " TICKET-BAD")
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_ticket_ref" {
			t.Errorf("constraint = %q, want waiver_ticket_ref", pgError(t, err).ConstraintName)
		}
	})

	var recent bool
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref, sys_period)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        '[2026-03-01,2026-04-01)', 'TICKET-SYS', tstzrange('2000-01-01'::timestamptz, NULL))
		RETURNING lower(sys_period) > '2001-01-01'::timestamptz`,
		tenantA, oldDecision, repo).Scan(&recent); err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Error("a caller-supplied sys_period was stored")
	}
}

func TestWaiverBoundHoldsWhenTriggersAreOff(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref, sys_period)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        tstzrange(clock_timestamp(), clock_timestamp() + interval '90 days' + interval '1 second', '[)'),
		        'TICKET-LONG', tstzrange(clock_timestamp(), NULL))`,
		tenantA, oldDecision, s.orgs[tenantA])
	requireSQLState(t, err, "23514")
	if pgError(t, err).ConstraintName != "waiver_bounds" {
		t.Errorf("constraint = %q, want waiver_bounds", pgError(t, err).ConstraintName)
	}

	// replica skips foreign-key triggers as well as user triggers. Disabling
	// only the user triggers leaves the key in force.
	if _, err := s.admin.ExecContext(ctx, `ALTER TABLE registry.waiver DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	_, err = s.admin.ExecContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        tstzrange(clock_timestamp(), clock_timestamp() + interval '1 day', '[)'),
		        'TICKET-FK')`,
		tenantA, oldDecision, s.orgs[tenantB])
	requireSQLState(t, err, "23503")
	if pgError(t, err).ConstraintName != "waiver_scope" {
		t.Errorf("constraint = %q, want waiver_scope", pgError(t, err).ConstraintName)
	}
}

func TestWaiverNoticesFollowTheDueRule(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', ARRAY[$3::uuid],
		        tstzrange(clock_timestamp() - interval '50 days', NULL, '[)'))`,
		oldDecision, tenantA, org); err != nil {
		t.Fatal(err)
	}
	var due, later string
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        tstzrange(clock_timestamp() - interval '30 days', clock_timestamp() - interval '1 hour', '[)'),
		        'TICKET-DUE')
		RETURNING id`, tenantA, oldDecision, org).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        tstzrange(clock_timestamp(), clock_timestamp() + interval '20 days', '[)'),
		        'TICKET-LATER')
		RETURNING id`, tenantA, oldDecision, org).Scan(&later); err != nil {
		t.Fatal(err)
	}
	var shortID string
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'a real exception', 'team:platform',
		        tstzrange(clock_timestamp() - interval '2 days', clock_timestamp() - interval '1 hour', '[)'),
		        'TICKET-SHORT')
		RETURNING id`, tenantA, oldDecision, org).Scan(&shortID); err != nil {
		t.Fatal(err)
	}

	notice := func(waiver string, days int, ticket string) error {
		t.Helper()
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.waiver_notice (tenant_id, waiver_id, days_before, ticket_ref)
			VALUES ($1::uuid, $2::uuid, $3, $4)`, tenantA, waiver, days, ticket)
		return err
	}
	t.Run("early", func(t *testing.T) {
		requireCheck(t, notice(later, 14, "TICKET-LATER"), "the notice is early")
	})
	t.Run("shorter than the offset", func(t *testing.T) {
		requireCheck(t, notice(shortID, 14, "TICKET-SHORT"), "shorter than the notice")
	})
	t.Run("an offset that is not 14, 3, or 0", func(t *testing.T) {
		err := notice(due, 7, "TICKET-DUE")
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "waiver_notice_days" {
			t.Errorf("constraint = %q, want waiver_notice_days", pgError(t, err).ConstraintName)
		}
	})
	if err := notice(due, 0, "WRONG"); err != nil {
		t.Fatal(err)
	}
	var ticket string
	if err := s.app.QueryRowContext(ctx, `
		SELECT ticket_ref FROM registry.waiver_notice
		WHERE tenant_id = $1::uuid AND waiver_id = $2::uuid AND days_before = 0`,
		tenantA, due).Scan(&ticket); err != nil {
		t.Fatal(err)
	}
	if ticket != "TICKET-DUE" {
		t.Errorf("ticket_ref = %q, want TICKET-DUE", ticket)
	}
	t.Run("a second notice for the same offset", func(t *testing.T) {
		err := notice(due, 0, "TICKET-DUE")
		requireSQLState(t, err, "23505")
		if pgError(t, err).ConstraintName != "waiver_notice_once" {
			t.Errorf("constraint = %q, want waiver_notice_once", pgError(t, err).ConstraintName)
		}
	})

	tx, err := s.app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT registry.record_waiver_notices()`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("notices with no tenant = %d, want 0", n)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT registry.record_waiver_notices()`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	// The 0-day notice for the due waiver is already recorded. 14 and 3 remain,
	// and the short waiver still needs its 0-day notice.
	if n != 3 {
		t.Errorf("sweep = %d, want 3", n)
	}
}

func TestApplicationRoleCannotChangeWaivers(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.addDecision(t, oldDecision, "[2026-01-01,)")
	if err := s.tryWaiver(t, oldDecision, s.orgs[tenantA], "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-1"); err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`UPDATE registry.waiver SET reason = 'changed'`,
		`DELETE FROM registry.waiver`,
		`TRUNCATE registry.waiver`,
		`UPDATE registry.waiver_notice SET days_before = 0`,
		`DELETE FROM registry.waiver_notice`,
		`TRUNCATE registry.waiver_notice`,
		`ALTER TABLE registry.waiver DISABLE TRIGGER ALL`,
		`SELECT registry.waiver_check()`,
		`SELECT registry.waiver_notice_check()`,
	}
	for _, statement := range statements {
		t.Run(statement, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.waiver`); n != 1 {
		t.Errorf("waivers visible = %d, want 1", n)
	}
}

func TestWaiverFunctionsAreOwnedByTheMigrationRole(t *testing.T) {
	s := migrated(t)
	functions := []struct {
		signature string
		callable  bool
	}{
		{"registry.waiver_check()", false},
		{"registry.waiver_notice_check()", false},
		{"registry.record_waiver_notices()", true},
	}
	for _, f := range functions {
		t.Run(f.signature, func(t *testing.T) {
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
				FROM pg_catalog.pg_proc WHERE oid = $1::text::regprocedure`, f.signature, pgtest.App).Scan(
				&definer, &owner, &config, &app, &public)
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
			if app != f.callable || public {
				t.Errorf("EXECUTE: application role %v (want %v), PUBLIC %v", app, f.callable, public)
			}
		})
	}
}
