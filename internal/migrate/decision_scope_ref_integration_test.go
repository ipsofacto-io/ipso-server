//go:build integration

package migrate_test

import (
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// The read of Resolve finds decisions through registry.decision_scope_ref, so a decision with no row there
// is invisible to it, and enforcement would fail open (ADR-0168). These are the pairs of tenant, scope and
// decision that a version names and the table lacks. The table may hold more: it keeps a scope that a later
// version dropped.
const missingScopeRefs = `
	SELECT count(*)
	FROM (
	    SELECT tenant_id, decision_id, unnest(scope_refs) AS scope_id FROM registry.decision_version_all
	) AS v
	WHERE NOT EXISTS (
	    SELECT 1 FROM registry.decision_scope_ref AS r
	    WHERE r.tenant_id = v.tenant_id AND r.scope_id = v.scope_id AND r.decision_id = v.decision_id)`

func TestEveryVersionIsInTheScopeLookupAfterEveryWritePath(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")
	rows := func(tenant string) int {
		return count(t, s.admin, `SELECT count(*) FROM registry.decision_scope_ref WHERE tenant_id = $1::uuid`, tenant)
	}
	check := func(step string, wantRows int) {
		t.Helper()
		if n := count(t, s.admin, missingScopeRefs); n != 0 {
			t.Errorf("%s: %d pairs of a version are not in decision_scope_ref", step, n)
		}
		if n := rows(tenantA); n != wantRows {
			t.Errorf("%s: decision_scope_ref holds %d rows for the tenant, want %d", step, n, wantRows)
		}
	}

	s.insert(t, tenantA, 1, "[2026-01-01,)")
	check("an insert", 1)

	// An update that adds a scope writes it, and the archived row is in the history table.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `UPDATE registry.decision_version SET scope_refs = ARRAY[$1::uuid, $2::uuid] WHERE decision_id = $3::uuid`, org, domain, decision); err != nil {
		t.Fatal(err)
	}
	check("an update that adds a scope", 2)

	// An update that drops one keeps its row, because a closed version still names it. The read keeps the
	// overlap test on scope_refs, so the row never adds a decision to an answer.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `UPDATE registry.decision_version SET scope_refs = ARRAY[$1::uuid] WHERE decision_id = $2::uuid`, domain, decision); err != nil {
		t.Fatal(err)
	}
	check("an update that drops a scope", 2)

	// An update that changes no scope adds nothing.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `UPDATE registry.decision_version SET body = '{"statement":"again"}' WHERE decision_id = $1::uuid`, decision); err != nil {
		t.Fatal(err)
	}
	check("an update of the body", 2)

	// A delete moves the version to the history table, and the lookup keeps its rows.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `DELETE FROM registry.decision_version WHERE decision_id = $1::uuid`, decision); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1::uuid`, tenantA); n != 0 {
		t.Fatalf("%d current versions are left", n)
	}
	check("a delete", 2)

	// Another tenant has its own rows, and the same decision id is a different row there.
	s.insert(t, tenantB, 1, "[2026-01-01,)")
	check("a decision of another tenant", 2)
	if n := rows(tenantB); n != 1 {
		t.Errorf("tenant B has %d rows, want 1", n)
	}
}

// The application role reads the table through its policy and cannot write it, so the only writer is the
// trigger. A row it could add or remove would hide a decision from Resolve.
func TestTheApplicationRoleCannotWriteTheScopeLookup(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	if n := countAs(t, s.app, tenantA, `SELECT count(*) FROM registry.decision_scope_ref`); n != 1 {
		t.Fatalf("tenant A reads %d rows, want 1", n)
	}
	if n := countAs(t, s.app, tenantB, `SELECT count(*) FROM registry.decision_scope_ref`); n != 0 {
		t.Fatalf("tenant B reads %d rows of tenant A", n)
	}

	for name, query := range map[string]string{
		"insert": `INSERT INTO registry.decision_scope_ref (tenant_id, scope_id, decision_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		"update": `UPDATE registry.decision_scope_ref SET decision_id = $3::uuid WHERE tenant_id = $1::uuid AND scope_id = $2::uuid`,
		"delete": `DELETE FROM registry.decision_scope_ref WHERE tenant_id = $1::uuid AND scope_id = $2::uuid AND decision_id = $3::uuid`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pgtest.Exec(ctx, s.app, tenantA, query, tenantA, s.orgs[tenantA], decision)
			requireSQLState(t, err, "42501")
		})
	}
}

// A deployment that holds decisions before migration 00045 has them indexed by the migration, current and
// closed versions alike, and row-level security is forced again on both decision tables afterwards.
func TestTheMigrationIndexesTheDecisionsThatExist(t *testing.T) {
	db := server.NewDatabase(t)
	ctx := t.Context()
	if _, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 44); err != nil {
		t.Fatalf("migrate to 44: %v", err)
	}
	app, admin := db.Open(t, pgtest.App), db.Open(t, pgtest.Admin)

	scope := func(tenant, parent, kind, selector string) string {
		t.Helper()
		var id string
		if err := pgtest.Scan(ctx, app, tenant, `
			INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, nullif($2, '')::uuid, $3, $4) RETURNING id`,
			[]any{tenant, parent, kind, selector}, &id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	write := func(tenant, query string, args ...any) {
		t.Helper()
		if _, err := pgtest.Exec(ctx, app, tenant, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	orgA := scope(tenantA, "", "org", "acme")
	domainA := scope(tenantA, orgA, "domain", "payments")
	orgB := scope(tenantB, "", "org", "acme")

	// Tenant A: one decision revised once, so a closed version names the org and the current one names the
	// domain, and a second decision that names both. Tenant B: one decision.
	write(tenantA, insertVersion, decision, 1, tenantA, "[2026-01-01,)", orgA)
	write(tenantA, `UPDATE registry.decision_version SET version = 2, scope_refs = ARRAY[$1::uuid] WHERE decision_id = $2::uuid`, domainA, decision)
	write(tenantA, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ('00000000-0000-4000-8000-0000000000d2', 1, $1::uuid, '{}', ARRAY[$2::uuid, $3::uuid], '[2026-01-01,)')`, tenantA, orgA, domainA)
	write(tenantB, insertVersion, decision, 1, tenantB, "[2026-01-01,)", orgB)

	applied, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 45)
	if err != nil || len(applied) != 1 || applied[0] != "00045_decision_scope_ref.sql" {
		t.Fatalf("%v %v", applied, err)
	}

	// The decision of tenant A names the org in a closed version and the domain in the current one, and the
	// second decision names both. Tenant B has its own.
	for tenant, want := range map[string]int{tenantA: 4, tenantB: 1} {
		if n := count(t, admin, `SELECT count(*) FROM registry.decision_scope_ref WHERE tenant_id = $1::uuid`, tenant); n != want {
			t.Errorf("tenant %s: %d rows, want %d", tenant, n, want)
		}
	}
	if n := count(t, admin, missingScopeRefs); n != 0 {
		t.Errorf("%d pairs of a version are not in decision_scope_ref", n)
	}
	if n := countAs(t, app, tenantA, `SELECT count(*) FROM registry.decision_scope_ref`); n != 4 {
		t.Errorf("tenant A reads %d rows through its policy, want 4", n)
	}

	for _, table := range []string{"registry.decision_version", "registry.decision_version_history", "registry.decision_scope_ref"} {
		var enabled, forced bool
		if err := admin.QueryRowContext(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatal(err)
		}
		if !enabled || !forced {
			t.Errorf("row-level security on %s: enabled %t, forced %t", table, enabled, forced)
		}
	}
}
