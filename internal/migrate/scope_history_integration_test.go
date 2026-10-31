//go:build integration

package migrate_test

import (
	"database/sql"
	"testing"
)

func closureDepths(t *testing.T, s schema, id string) map[string]int {
	t.Helper()
	rows, err := s.admin.QueryContext(t.Context(), `
		SELECT ancestor_id::text, depth FROM registry.scope_closure WHERE descendant_id = $1::uuid`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]int{}
	for rows.Next() {
		var ancestor string
		var depth int
		if err := rows.Scan(&ancestor, &depth); err != nil {
			t.Fatal(err)
		}
		got[ancestor] = depth
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}

func wantDepths(t *testing.T, got, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("closure = %v, want %v", got, want)
		return
	}
	for id, depth := range want {
		if got[id] != depth {
			t.Errorf("ancestor %s at depth %d, want %d", id, got[id], depth)
		}
	}
}

func TestReparentRewritesTheClosureAndKeepsTheOldChain(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	payments := s.addScope(t, tenantA, org, "domain", "payments")
	labs := s.addScope(t, tenantA, org, "domain", "labs")
	repo := s.addScope(t, tenantA, payments, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")

	if _, err := s.app.ExecContext(ctx, `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
		UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`, tenantA, repo, labs); err != nil {
		t.Fatal(err)
	}

	wantDepths(t, closureDepths(t, s, repo), map[string]int{repo: 0, labs: 1, org: 2})
	wantDepths(t, closureDepths(t, s, path), map[string]int{path: 0, repo: 1, labs: 2, org: 3})

	var oldParent string
	if err := s.admin.QueryRowContext(ctx, `
		SELECT parent_id::text FROM registry.scope_history WHERE id = $1::uuid`, repo).Scan(&oldParent); err != nil {
		t.Fatal(err)
	}
	if oldParent != payments {
		t.Errorf("archived parent = %s, want %s", oldParent, payments)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.scope_history WHERE id = $1::uuid`, path); n != 0 {
		t.Errorf("the path was archived %d times, want 0: its selector did not change", n)
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.scope_closure_history
		WHERE descendant_id = $1::uuid AND ancestor_id = $2::uuid`, repo, payments); n != 1 {
		t.Errorf("closed edges to the old domain = %d, want 1", n)
	}

	var abuts bool
	if err := s.admin.QueryRowContext(ctx, `
		SELECT bool_and(lower(c.sys_period) = upper(h.sys_period))
		FROM registry.scope c
		JOIN registry.scope_history h ON h.tenant_id = c.tenant_id AND h.id = c.id
		WHERE c.id = $1::uuid`, repo).Scan(&abuts); err != nil {
		t.Fatal(err)
	}
	if !abuts {
		t.Error("the current period does not start where the archived period ends")
	}
}

func TestReparentRewritesAnInheritedSelector(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	from := s.addScope(t, tenantA, org, "repo", "acme/payments")
	to := s.addScope(t, tenantA, org, "repo", "acme/other")
	path := s.addScope(t, tenantA, from, "path", "infra/**")
	env := s.addScope(t, tenantA, path, "env", "prod")

	if _, err := s.app.ExecContext(ctx, `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
		UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`, tenantA, path, to); err != nil {
		t.Fatal(err)
	}

	if got := s.effective(t, path); got.repo != "acme/other" || got.path != "infra/**" {
		t.Errorf("path selector = %+v, want repo acme/other and path infra/**", got)
	}
	if got := s.effective(t, env); got.repo != "acme/other" || got.path != "infra/**" || got.env != "prod" {
		t.Errorf("env selector = %+v, want repo acme/other under infra/**", got)
	}
	var archived string
	if err := s.admin.QueryRowContext(ctx, `
		SELECT match_repo FROM registry.scope_history WHERE id = $1::uuid`, env).Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if archived != "acme/payments" {
		t.Errorf("archived env repo = %q, want acme/payments", archived)
	}
	var sameCut bool
	if err := s.admin.QueryRowContext(ctx, `
		SELECT lower(path.sys_period) = lower(env.sys_period)
		FROM registry.scope AS path, registry.scope AS env
		WHERE path.id = $1::uuid AND env.id = $2::uuid`, path, env).Scan(&sameCut); err != nil {
		t.Fatal(err)
	}
	if !sameCut {
		t.Error("the path and the env did not archive at the same transaction time")
	}
}

func TestReparentRejectsACycleAnIllegalParentAndAForeignOrg(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")
	repo := s.addScope(t, tenantA, domain, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")
	other := s.addScope(t, tenantA, "", "org", "other")

	t.Run("cycle", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
			UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`, tenantA, repo, path)
		requireCheck(t, err, "descendant")
	})
	t.Run("illegal parent", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
			UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`, tenantA, path, domain)
		requireCheck(t, err, "cannot sit under")
	})
	t.Run("repo owner", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
			UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`, tenantA, domain, other)
		requireCheck(t, err, "repo owner")
		var parent string
		if err := s.admin.QueryRowContext(ctx, `SELECT parent_id::text FROM registry.scope WHERE id = $1::uuid`, domain).Scan(&parent); err != nil {
			t.Fatal(err)
		}
		if parent != org {
			t.Errorf("domain parent = %s, want it unchanged", parent)
		}
	})
}

func TestASecondReparentInTheSameTransactionUsesANewCut(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	payments := s.addScope(t, tenantA, org, "domain", "payments")
	labs := s.addScope(t, tenantA, org, "domain", "labs")
	repo := s.addScope(t, tenantA, payments, "repo", "acme/payments")

	tx, err := s.app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registry.scope SET parent_id = $2::uuid WHERE id = $1::uuid`, repo, labs); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registry.scope SET parent_id = $2::uuid WHERE id = $1::uuid`, repo, payments); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var parent string
	if err := s.admin.QueryRowContext(ctx, `SELECT parent_id::text FROM registry.scope WHERE id = $1::uuid`, repo).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != payments {
		t.Errorf("parent = %s, want the original domain", parent)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.scope_history WHERE id = $1::uuid`, repo); n != 2 {
		t.Errorf("history rows = %d, want 2", n)
	}
}

func TestScopeChangesRefuseRepeatableRead(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	labs := s.addScope(t, tenantA, org, "domain", "labs")
	repo := s.addScope(t, tenantA, org, "repo", "acme/payments")

	t.Run("insert", func(t *testing.T) {
		tx, err := s.app.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO registry.scope (tenant_id, parent_id, kind, selector)
			VALUES ($1::uuid, $2::uuid, 'domain', 'billing')`, tenantA, org)
		if pgError(t, err).Code != "0A000" {
			t.Fatalf("want SQLSTATE 0A000, got %v", err)
		}
	})
	t.Run("re-parent", func(t *testing.T) {
		tx, err := s.app.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(ctx, `UPDATE registry.scope SET parent_id = $2::uuid WHERE id = $1::uuid`, repo, labs)
		if pgError(t, err).Code != "0A000" {
			t.Fatalf("want SQLSTATE 0A000, got %v", err)
		}
	})
}

func TestRetirementKeepsHistoryAndReleasesTheScopeId(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	repo := s.addScope(t, tenantA, org, "repo", "acme/payments")
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', ARRAY[$3::uuid], '[2026-01-01,2026-06-01)')`,
		decision, tenantA, repo); err != nil {
		t.Fatal(err)
	}
	if err := s.tryWaiver(t, decision, repo, "[2026-02-01,2026-04-01)", "a real exception", "team:platform", "TICKET-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.app.ExecContext(ctx, `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
		DELETE FROM registry.scope AS s USING cfg WHERE s.id = $2::uuid`, tenantA, repo); err != nil {
		t.Fatalf("a waiver blocked retirement: %v", err)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.scope_closure WHERE descendant_id = $1::uuid`, repo); n != 0 {
		t.Errorf("current closure rows = %d, want 0", n)
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.scope_closure_history
		WHERE descendant_id = $1::uuid AND ancestor_id = $1::uuid AND upper(sys_period) IS NOT NULL`, repo); n != 1 {
		t.Errorf("archived self edges = %d, want 1", n)
	}

	_, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ('00000000-0000-4000-8000-0000000000d2'::uuid, 1, $1::uuid, '{}', ARRAY[$2::uuid], '[2026-01-01,)')`,
		tenantA, repo)
	requireSQLState(t, err, "23503")

	if _, err := s.app.ExecContext(ctx, `
		UPDATE registry.decision_version SET version = 2 WHERE decision_id = $1::uuid`, decision); err != nil {
		t.Fatalf("keeping the retired reference: %v", err)
	}

	err = s.tryWaiver(t, decision, repo, "[2026-02-01,2026-03-01)", "a real exception", "team:platform", "TICKET-2")
	requireCheck(t, err, "outside the decision")
}

func TestScopeChangeRefusesAnotherTenant(t *testing.T) {
	s := migrated(t)
	org := s.orgs[tenantA]
	labs := s.addScope(t, tenantA, org, "domain", "labs")
	repo := s.addScope(t, tenantA, org, "repo", "acme/payments")

	_, err := s.app.ExecContext(t.Context(), `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1, true))
		UPDATE registry.scope AS s SET parent_id = $3::uuid FROM cfg WHERE s.id = $2::uuid`,
		tenantB, repo, labs)
	requireSQLState(t, err, "42501")
	var parent string
	if err := s.admin.QueryRowContext(t.Context(), `SELECT parent_id::text FROM registry.scope WHERE id = $1::uuid`, repo).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != org {
		t.Errorf("parent = %s, want it unchanged", parent)
	}
}

func TestReparentIgnoresACallerSuppliedCut(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	payments := s.addScope(t, tenantA, org, "domain", "payments")
	labs := s.addScope(t, tenantA, org, "domain", "labs")
	repo := s.addScope(t, tenantA, payments, "repo", "acme/payments")

	tx, err := s.app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.scope_cut', '2000-01-01 00:00:00.000000', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registry.scope SET parent_id = $2::uuid WHERE id = $1::uuid`, repo, labs); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var recent bool
	if err := s.admin.QueryRowContext(ctx, `
		SELECT upper(sys_period) > '2020-01-01'::timestamptz
		FROM registry.scope_history WHERE id = $1::uuid`, repo).Scan(&recent); err != nil {
		t.Fatal(err)
	}
	if !recent {
		t.Error("the archived period ends at the caller-supplied cut")
	}
}
