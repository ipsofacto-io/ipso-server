//go:build integration

package migrate_test

import (
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// Every searchable term of every version (current and closed) must exist in
// registry.decision_search_term so keyword search never misses a matching decision (ADR-0169).
const missingSearchTerms = `
	SELECT count(*)
	FROM (
	    SELECT tenant_id, decision_id, unnest(registry.decision_search_terms(body)) AS term
	    FROM registry.decision_version_all
	) AS v
	WHERE NOT EXISTS (
	    SELECT 1 FROM registry.decision_search_term AS r
	    WHERE r.tenant_id = v.tenant_id AND r.term = v.term AND r.decision_id = v.decision_id)`

func TestEveryVersionIsInTheSearchTermLookupAfterEveryWritePath(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	orgA := s.orgs[tenantA]
	domainA := s.addScope(t, tenantA, orgA, "domain", "payments")

	checkComplete := func(step string) {
		t.Helper()
		if n := count(t, s.admin, missingSearchTerms); n != 0 {
			t.Errorf("%s: %d (tenant, term, decision) rows are missing from decision_search_term", step, n)
		}
	}
	hasTerm := func(tenant, term string) bool {
		t.Helper()
		return count(t, s.admin, `SELECT count(*) FROM registry.decision_search_term WHERE tenant_id = $1::uuid AND term = $2`, tenant, term) > 0
	}

	// Insert a non-sensitive decision with id, slug, title, statement, and tags.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid,
		        '{"id":"01J9Z000000000000000000001","slug":"deny-egress-prod","title":"Production firewall","statement":"Block unrestricted egress.","tags":["iso-27001","networking"]}',
		        ARRAY[$3::uuid], '[2026-01-01,)')`,
		decision, tenantA, orgA); err != nil {
		t.Fatal(err)
	}
	checkComplete("insert")
	for _, want := range []string{"01j9z000000000000000000001", "deny-egress-prod", "egress", "production", "firewall", "iso-27001", "27001", "networking"} {
		if !hasTerm(tenantA, want) {
			t.Errorf("insert: expected term %q in decision_search_term", want)
		}
	}

	// An update that changes only scope_refs leaves search terms intact.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `
		UPDATE registry.decision_version SET scope_refs = ARRAY[$1::uuid, $2::uuid] WHERE decision_id = $3::uuid`,
		orgA, domainA, decision); err != nil {
		t.Fatal(err)
	}
	checkComplete("update scope_refs only")

	// An update that replaces body terms adds the new terms and keeps the old ones (append-only for history).
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `
		UPDATE registry.decision_version
		SET version = 2,
		    body = '{"id":"01J9Z000000000000000000001","slug":"deny-egress-prod","title":"Zero trust gateway","statement":"Enforce mutual TLS.","tags":["zero-trust"]}'
		WHERE decision_id = $1::uuid`, decision); err != nil {
		t.Fatal(err)
	}
	checkComplete("update body")
	for _, want := range []string{"firewall", "gateway", "mutual", "zero-trust"} {
		if !hasTerm(tenantA, want) {
			t.Errorf("update body: expected term %q in decision_search_term", want)
		}
	}

	// A sensitive decision indexes only slug and EDR id, never title, statement, or tags (ADR-0072).
	const secretDecision = "00000000-0000-4000-8000-0000000000d9"
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid,
		        '{"id":"01J9Z000000000000000000099","slug":"vault-host","title":"Confidential HSM Cluster","statement":"Secret internal endpoint.","tags":["sensitive","hsm-secret"]}',
		        ARRAY[$3::uuid], '[2026-01-01,)')`,
		secretDecision, tenantA, orgA); err != nil {
		t.Fatal(err)
	}
	checkComplete("insert sensitive")
	for _, want := range []string{"vault-host", "vault", "host", "01j9z000000000000000000099"} {
		if !hasTerm(tenantA, want) {
			t.Errorf("sensitive insert: expected slug/id term %q", want)
		}
	}
	for _, forbidden := range []string{"confidential", "hsm", "cluster", "secret", "endpoint", "hsm-secret", "sensitive"} {
		if hasTerm(tenantA, forbidden) {
			t.Errorf("sensitive insert: forbidden redacted term %q was indexed", forbidden)
		}
	}

	// Deleting the current version archives it to history; lookup rows remain for historical reads.
	if _, err := pgtest.Exec(ctx, s.app, tenantA, `DELETE FROM registry.decision_version WHERE decision_id = $1::uuid`, decision); err != nil {
		t.Fatal(err)
	}
	checkComplete("delete")
	if !hasTerm(tenantA, "gateway") {
		t.Errorf("delete: expected archived term 'gateway' to stay in decision_search_term")
	}

	// Another tenant's rows stay isolated.
	s.insert(t, tenantB, 1, "[2026-01-01,)")
	checkComplete("other tenant insert")
	if !hasTerm(tenantB, "synthetic") {
		t.Errorf("tenant B: expected term 'synthetic'")
	}
	if hasTerm(tenantB, "firewall") {
		t.Errorf("tenant B: unexpectedly saw tenant A's term 'firewall'")
	}
}

func TestTheApplicationRoleCannotWriteTheSearchTermLookup(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	if n := countAs(t, s.app, tenantA, `SELECT count(*) FROM registry.decision_search_term`); n == 0 {
		t.Fatal("tenant A reads 0 rows, want > 0")
	}
	if n := countAs(t, s.app, tenantB, `SELECT count(*) FROM registry.decision_search_term`); n != 0 {
		t.Fatalf("tenant B reads %d rows of tenant A", n)
	}

	for name, query := range map[string]string{
		"insert": `INSERT INTO registry.decision_search_term (tenant_id, term, decision_id) VALUES ($1::uuid, 'tamper', $2::uuid)`,
		"update": `UPDATE registry.decision_search_term SET term = 'tamper' WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`,
		"delete": `DELETE FROM registry.decision_search_term WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pgtest.Exec(ctx, s.app, tenantA, query, tenantA, decision)
			requireSQLState(t, err, "42501")
		})
	}
}

func TestTheMigrationIndexesExistingDecisionsForSearch(t *testing.T) {
	db := server.NewDatabase(t)
	ctx := t.Context()
	if _, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 45); err != nil {
		t.Fatalf("migrate to 45: %v", err)
	}
	app, admin := db.Open(t, pgtest.App), db.Open(t, pgtest.Admin)

	scope := func(tenant, kind, selector string) string {
		t.Helper()
		var id string
		if err := pgtest.Scan(ctx, app, tenant, `
			INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, NULL, $2, $3) RETURNING id`,
			[]any{tenant, kind, selector}, &id); err != nil {
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
	orgA := scope(tenantA, "org", "acme")
	orgB := scope(tenantB, "org", "acme")

	// Tenant A: one revised decision (v1 archived with "legacy", v2 current with "modern") and one sensitive decision.
	write(tenantA, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{"slug":"net-rule","title":"Legacy firewall","statement":"Block legacy ports."}', ARRAY[$3::uuid], '[2026-01-01,)')`,
		decision, tenantA, orgA)
	write(tenantA, `
		UPDATE registry.decision_version
		SET version = 2, body = '{"slug":"net-rule","title":"Modern firewall","statement":"Block open egress."}'
		WHERE decision_id = $1::uuid`, decision)
	write(tenantA, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ('00000000-0000-4000-8000-0000000000d2', 1, $1::uuid,
		        '{"id":"01J9Z000000000000000000002","slug":"vault-only","title":"Redacted secret","tags":["sensitive"]}',
		        ARRAY[$2::uuid], '[2026-01-01,)')`, tenantA, orgA)
	write(tenantB, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{"slug":"tenant-b-rule","title":"Tenant B encryption"}', ARRAY[$3::uuid], '[2026-01-01,)')`,
		decision, tenantB, orgB)

	applied, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 46)
	if err != nil || len(applied) != 1 || applied[0] != "00046_decision_search_term.sql" {
		t.Fatalf("%v %v", applied, err)
	}

	if n := count(t, admin, missingSearchTerms); n != 0 {
		t.Errorf("%d (tenant, term, decision) rows are missing after backfill", n)
	}
	// Both the archived v1 term ("legacy") and current v2 term ("modern") must be present.
	for _, term := range []string{"legacy", "modern", "firewall", "vault-only", "01j9z000000000000000000002"} {
		if n := countAs(t, app, tenantA, `SELECT count(*) FROM registry.decision_search_term WHERE term = '`+term+`'`); n != 1 {
			t.Errorf("tenant A: term %q has %d rows, want 1", term, n)
		}
	}
	// Redacted title of sensitive decision must not be backfilled.
	if n := countAs(t, app, tenantA, `SELECT count(*) FROM registry.decision_search_term WHERE term = 'redacted'`); n != 0 {
		t.Errorf("tenant A: sensitive title term 'redacted' was backfilled (%d rows)", n)
	}
	// Tenant B sees only its own terms.
	if n := countAs(t, app, tenantB, `SELECT count(*) FROM registry.decision_search_term WHERE term = 'encryption'`); n != 1 {
		t.Errorf("tenant B: expected term 'encryption', got %d rows", n)
	}
	if n := countAs(t, app, tenantB, `SELECT count(*) FROM registry.decision_search_term WHERE term = 'firewall'`); n != 0 {
		t.Errorf("tenant B: leaked tenant A term 'firewall'")
	}

	// Unusable GIN index is dropped; lookup PK exists.
	if n := count(t, admin, `SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'registry'::regnamespace AND relname = 'decision_version_fts'`); n != 0 {
		t.Errorf("index registry.decision_version_fts still exists")
	}
	if n := count(t, admin, `SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'registry'::regnamespace AND relname = 'decision_search_term_pkey'`); n != 1 {
		t.Errorf("index registry.decision_search_term_pkey missing")
	}

	// FORCE ROW LEVEL SECURITY must be active on all three tables after the migration.
	for _, table := range []string{"registry.decision_version", "registry.decision_version_history", "registry.decision_search_term"} {
		var enabled, forced bool
		if err := admin.QueryRowContext(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatal(err)
		}
		if !enabled || !forced {
			t.Errorf("row-level security on %s: enabled %t, forced %t", table, enabled, forced)
		}
	}
}
