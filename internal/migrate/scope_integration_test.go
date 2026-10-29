//go:build integration

package migrate_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// effective is the effective selector of a scope node, with "" for NULL.
type effective struct {
	org, repo, path, env string
}

func (s schema) effective(t *testing.T, id string) effective {
	t.Helper()
	var e effective
	err := s.admin.QueryRowContext(t.Context(), `
		SELECT match_org, coalesce(match_repo, ''), coalesce(match_path, ''), coalesce(match_env, '')
		FROM registry.scope WHERE id = $1::uuid`, id).Scan(&e.org, &e.repo, &e.path, &e.env)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestScopeObjectsExist(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	for _, name := range []string{"scope", "scope_closure"} {
		var found bool
		if err := s.admin.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "registry."+name).Scan(&found); err != nil || !found {
			t.Errorf("registry.%s missing (err %v)", name, err)
		}
	}
	for _, index := range []string{"scope_candidates", "decision_version_scope_refs_gin", "decision_version_history_scope_refs_gin"} {
		var found bool
		if err := s.admin.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "registry."+index).Scan(&found); err != nil || !found {
			t.Errorf("index registry.%s missing (err %v)", index, err)
		}
	}

	// Reads are hot and writes are rare, so the GIN indexes skip the pending list, which would
	// otherwise be scanned by a read right after a burst of writes.
	for _, index := range []string{"decision_version_scope_refs_gin", "decision_version_history_scope_refs_gin"} {
		var options string
		err := s.admin.QueryRowContext(ctx, `SELECT coalesce(array_to_string(reloptions, ','), '') FROM pg_catalog.pg_class WHERE oid = $1::text::regclass`, "registry."+index).Scan(&options)
		if err != nil {
			t.Fatal(err)
		}
		if options != "fastupdate=off" {
			t.Errorf("index %s options = %q, want fastupdate=off", index, options)
		}
	}

	// The history table is written by the archive trigger only, so the scope_refs rules stay off it.
	if n := count(t, s.admin, `SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid = 'registry.decision_version_history'::regclass AND contype IN ('p', 'c', 'x')`); n != 0 {
		t.Errorf("history table has %d key or check constraints, want 0", n)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid = 'registry.decision_version_history'::regclass AND NOT tgisinternal`); n != 0 {
		t.Errorf("history table has %d triggers, want 0", n)
	}
}

// kinds in the order of the matrix below.
var kinds = []string{"org", "domain", "service", "repo", "path", "env"}

// allowedParents is the section of ADR-0051 that fixes the parents of each kind.
var allowedParents = map[string][]string{
	"domain":  {"org"},
	"service": {"org", "domain"},
	"repo":    {"org", "domain", "service"},
	"path":    {"repo"},
	"env":     {"org", "repo", "path"},
}

// selectorFor gives a selector that is valid for the kind under the org "acme".
func selectorFor(kind string) string {
	switch kind {
	case "repo":
		return "acme/payments"
	case "path":
		return "infra/**"
	case "env":
		return "prod"
	default:
		return "payments"
	}
}

// Every pair of child kind and parent kind is tried, so a rule that is too loose or too strict fails.
func TestScopeParentRules(t *testing.T) {
	s := migrated(t)

	// One node of each kind, a chain under the org so that each kind has a parent to try.
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")
	service := s.addScope(t, tenantA, domain, "service", "billing")
	repo := s.addScope(t, tenantA, service, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")
	nodes := map[string]string{"org": org, "domain": domain, "service": service, "repo": repo, "path": path}

	for _, child := range kinds[1:] {
		for _, parentKind := range kinds[:5] {
			t.Run(child+" under "+parentKind, func(t *testing.T) {
				_, err := s.tryScope(t, tenantA, nodes[parentKind], child, selectorFor(child))
				if slices.Contains(allowedParents[child], parentKind) {
					if err != nil {
						t.Errorf("want the insert to succeed: %v", err)
					}
					return
				}
				requireSQLState(t, err, "23514")
			})
		}
	}

	t.Run("an org has no parent", func(t *testing.T) {
		_, err := s.tryScope(t, tenantA, org, "org", "other")
		requireSQLState(t, err, "23514")
	})
	for _, kind := range kinds[1:] {
		t.Run(kind+" needs a parent", func(t *testing.T) {
			_, err := s.tryScope(t, tenantA, "", kind, selectorFor(kind))
			requireSQLState(t, err, "23514")
		})
	}
	t.Run("an unknown kind", func(t *testing.T) {
		_, err := s.tryScope(t, tenantA, org, "team", "payments")
		requireSQLState(t, err, "23514")
	})
}

func TestScopeParentMustBeInTheSameTenant(t *testing.T) {
	s := migrated(t)

	// The parent exists, but in tenant A.
	_, err := s.tryScope(t, tenantB, s.orgs[tenantA], "domain", "payments")
	requireSQLState(t, err, "23503")

	_, err = s.tryScope(t, tenantA, "00000000-0000-4000-8000-0000000000ff", "domain", "payments")
	requireSQLState(t, err, "23503")
}

func TestRepoOwnerMustBeTheOrgOfItsParent(t *testing.T) {
	s := migrated(t)
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")

	for _, parent := range []string{org, domain} {
		_, err := s.tryScope(t, tenantA, parent, "repo", "other/payments")
		requireSQLState(t, err, "23514")
	}
	s.addScope(t, tenantA, domain, "repo", "acme/payments")
}

func TestEffectiveSelectorFollowsTheParentChain(t *testing.T) {
	s := migrated(t)
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")
	service := s.addScope(t, tenantA, domain, "service", "billing")
	repo := s.addScope(t, tenantA, service, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")
	pathEnv := s.addScope(t, tenantA, path, "env", "prod")
	repoEnv := s.addScope(t, tenantA, repo, "env", "dev")
	orgEnv := s.addScope(t, tenantA, org, "env", "staging")
	globRepo := s.addScope(t, tenantA, org, "repo", "acme/infra-*")
	globPath := s.addScope(t, tenantA, globRepo, "path", "**/*.tf")

	tests := []struct {
		name string
		id   string
		want effective
	}{
		{"org", org, effective{org: "acme"}},
		{"domain", domain, effective{org: "acme"}},
		{"service", service, effective{org: "acme"}},
		{"repo", repo, effective{org: "acme", repo: "acme/payments"}},
		{"path", path, effective{org: "acme", repo: "acme/payments", path: "infra/**"}},
		{"env under a path", pathEnv, effective{org: "acme", repo: "acme/payments", path: "infra/**", env: "prod"}},
		{"env under a repo", repoEnv, effective{org: "acme", repo: "acme/payments", env: "dev"}},
		{"env under an org", orgEnv, effective{org: "acme", env: "staging"}},
		{"glob repo", globRepo, effective{org: "acme", repo: "acme/infra-*"}},
		{"path under a glob repo", globPath, effective{org: "acme", repo: "acme/infra-*", path: "**/*.tf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.effective(t, tt.id); got != tt.want {
				t.Errorf("effective selector = %+v, want %+v", got, tt.want)
			}
		})
	}

	// repo_key is the literal repo, and empty for a node that is org-wide or holds a glob.
	keys := map[string]string{org: "", domain: "", repo: "acme/payments", path: "acme/payments", orgEnv: "", globRepo: "", globPath: ""}
	for id, want := range keys {
		var got string
		if err := s.admin.QueryRowContext(t.Context(), `SELECT repo_key FROM registry.scope WHERE id = $1::uuid`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("repo_key of %s = %q, want %q", id, got, want)
		}
	}
}

func TestCallerCannotSetTheDerivedColumns(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]

	before := dbNow(t, s.admin)
	var id string
	err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector, match_org, match_repo, match_path, match_env, sys_period)
		VALUES ($1::uuid, $2::uuid, 'repo', 'acme/payments', 'evil', 'evil/x', '**', 'dev', '[2000-01-01,2000-02-01)')
		RETURNING id`, tenantA, org).Scan(&id)
	if err != nil {
		t.Fatalf("insert with supplied derived columns: %v", err)
	}
	if got, want := s.effective(t, id), (effective{org: "acme", repo: "acme/payments"}); got != want {
		t.Errorf("effective selector = %+v, want %+v", got, want)
	}
	var (
		from time.Time
		open bool
	)
	if err := s.admin.QueryRowContext(ctx, `SELECT lower(sys_period), upper(sys_period) IS NULL FROM registry.scope WHERE id = $1::uuid`, id).Scan(&from, &open); err != nil {
		t.Fatal(err)
	}
	if !open || from.Before(before) {
		t.Errorf("sys_period opens at %v (open %v), want an open period from %v or later", from, open, before)
	}

	// The stored repo_key is generated, so a caller cannot write it.
	_, err = s.app.ExecContext(ctx, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector, repo_key)
		VALUES ($1::uuid, $2::uuid, 'repo', 'acme/other', 'x')`, tenantA, org)
	requireSQLState(t, err, "428C9")
}

func TestClosureHoldsEveryAncestorOfANode(t *testing.T) {
	s := migrated(t)
	org := s.orgs[tenantA]
	domain := s.addScope(t, tenantA, org, "domain", "payments")
	repo := s.addScope(t, tenantA, domain, "repo", "acme/payments")
	path := s.addScope(t, tenantA, repo, "path", "infra/**")
	env := s.addScope(t, tenantA, path, "env", "prod")
	otherTenantOrg := s.orgs[tenantB]

	ancestors := func(node string) map[string]int {
		rows, err := s.admin.QueryContext(t.Context(), `SELECT ancestor_id, depth FROM registry.scope_closure WHERE descendant_id = $1::uuid`, node)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		got := make(map[string]int)
		for rows.Next() {
			var id string
			var depth int
			if err := rows.Scan(&id, &depth); err != nil {
				t.Fatal(err)
			}
			got[id] = depth
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}

	tests := []struct {
		node string
		want map[string]int
	}{
		{org, map[string]int{org: 0}},
		{domain, map[string]int{domain: 0, org: 1}},
		{repo, map[string]int{repo: 0, domain: 1, org: 2}},
		{path, map[string]int{path: 0, repo: 1, domain: 2, org: 3}},
		{env, map[string]int{env: 0, path: 1, repo: 2, domain: 3, org: 4}},
		{otherTenantOrg, map[string]int{otherTenantOrg: 0}},
	}
	for _, tt := range tests {
		got := ancestors(tt.node)
		if len(got) != len(tt.want) {
			t.Errorf("node %s: closure = %v, want %v", tt.node, got, tt.want)
			continue
		}
		for id, depth := range tt.want {
			if got[id] != depth {
				t.Errorf("node %s: ancestor %s at depth %d, want %d", tt.node, id, got[id], depth)
			}
		}
	}

	// A closure row never crosses a tenant.
	if n := count(t, s.admin, `
		SELECT count(*) FROM registry.scope_closure c
		JOIN registry.scope a ON a.id = c.ancestor_id
		JOIN registry.scope d ON d.id = c.descendant_id
		WHERE a.tenant_id <> c.tenant_id OR d.tenant_id <> c.tenant_id`); n != 0 {
		t.Errorf("%d closure rows cross a tenant", n)
	}
}

func TestApplicationRoleCannotChangeScopesOrWriteTheClosure(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	org := s.orgs[tenantA]
	s.addScope(t, tenantA, org, "domain", "payments")

	statements := map[string]string{
		"update a scope":             `UPDATE registry.scope SET selector = 'other'`,
		"delete a scope":             `DELETE FROM registry.scope`,
		"truncate scopes":            `TRUNCATE registry.scope`,
		"insert a closure row":       `INSERT INTO registry.scope_closure SELECT tenant_id, id, id, 0 FROM registry.scope LIMIT 1`,
		"update a closure row":       `UPDATE registry.scope_closure SET depth = 9`,
		"delete a closure row":       `DELETE FROM registry.scope_closure`,
		"truncate the closure":       `TRUNCATE registry.scope_closure`,
		"disable the scope triggers": `ALTER TABLE registry.scope DISABLE TRIGGER ALL`,
		"call the closure trigger":   `SELECT registry.scope_write_closure()`,
		"call the scope trigger":     `SELECT registry.scope_prepare()`,
		"call the refs trigger":      `SELECT registry.decision_version_check_scope_refs()`,
	}
	for name, statement := range statements {
		t.Run(name, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.scope`); n != 3 {
		t.Errorf("scopes = %d, want 3: both orgs and the domain", n)
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.scope_closure`); n != 4 {
		t.Errorf("closure rows = %d, want 4", n)
	}
}

func TestScopeFunctionsAreOwnedByTheMigrationRoleAndNotCallable(t *testing.T) {
	s := migrated(t)
	functions := []struct {
		signature string
		definer   bool
	}{
		{"registry.scope_prepare()", false},
		{"registry.scope_write_closure()", true},
		{"registry.decision_version_check_scope_refs()", false},
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
				FROM pg_catalog.pg_proc WHERE oid = $1::text::regprocedure`, f.signature, pgtest.App).Scan(&definer, &owner, &config, &app, &public)
			if err != nil {
				t.Fatal(err)
			}
			if definer != f.definer {
				t.Errorf("SECURITY DEFINER = %v, want %v", definer, f.definer)
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

func TestScopeRefsMustNameScopesOfTheSameTenant(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	own := s.orgs[tenantA]
	foreign := s.orgs[tenantB]

	insert := func(refs []string) error {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1::uuid, 1, $2::uuid, '{}', $3::text[]::uuid[], '[2026-01-01,)')`, decision, tenantA, pgArray(refs))
		return err
	}
	tests := []struct {
		name  string
		refs  []string
		state string
	}{
		{"empty", []string{}, "23514"},
		{"a NULL element", []string{own, "NULL"}, "23503"},
		{"a scope that does not exist", []string{"00000000-0000-4000-8000-0000000000ff"}, "23503"},
		{"a scope of another tenant", []string{foreign}, "23503"},
		{"one good and one foreign", []string{own, foreign}, "23503"},
		{"more than the limit", repeat(own, 101), "23514"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireSQLState(t, insert(tt.refs), tt.state)
		})
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version`); n != 0 {
		t.Fatalf("a refused insert left %d rows", n)
	}

	if err := insert([]string{own, own}); err != nil {
		t.Fatalf("a repeated reference to a real scope: %v", err)
	}

	// An update is checked too, and a refused update archives nothing.
	_, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET scope_refs = ARRAY[$1::uuid] WHERE decision_id = $2::uuid`, foreign, decision)
	requireSQLState(t, err, "23503")
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version_history`); n != 0 {
		t.Errorf("a refused update archived %d rows", n)
	}
	other := s.addScope(t, tenantA, own, "domain", "payments")
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET scope_refs = ARRAY[$1::uuid] WHERE decision_id = $2::uuid`, other, decision); err != nil {
		t.Fatalf("an update to a real scope: %v", err)
	}
	if n := count(t, s.admin, `SELECT count(*) FROM registry.decision_version_history`); n != 1 {
		t.Errorf("history rows = %d, want 1", n)
	}
}

// The GIN indexes serve the overlap query of resolution, so the planner must be able to use them.
func TestScopeRefsOverlapUsesTheIndexes(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET version = 2`); err != nil {
		t.Fatal(err)
	}

	// With so few rows the planner prefers a sequential scan, so the test turns that off to
	// show that an index path exists for the overlap operator on both tables.
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(ctx, `
		EXPLAIN (FORMAT TEXT)
		SELECT decision_id FROM registry.decision_version_all WHERE scope_refs && ARRAY[$1::uuid]`, s.orgs[tenantA])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, index := range []string{"decision_version_scope_refs_gin", "decision_version_history_scope_refs_gin"} {
		if !strings.Contains(plan.String(), index) {
			t.Errorf("the plan does not use %s:\n%s", index, plan.String())
		}
	}
}

// pgArray renders text array input. The bare word NULL is a NULL element.
func pgArray(elements []string) string {
	return "{" + strings.Join(elements, ",") + "}"
}

func repeat(element string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = element
	}
	return out
}

// With the triggers off, the CHECK constraint is the only thing left between an unbounded or
// empty scope_refs and decision_version. Only a superuser can switch the triggers off.
func TestScopeRefsConstraintHoldsWhenTriggersAreOff(t *testing.T) {
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
	for name, refs := range map[string][]string{
		"empty":          {},
		"a NULL":         {s.orgs[tenantA], "NULL"},
		"over the limit": repeat(s.orgs[tenantA], 101),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := conn.ExecContext(ctx, `
				INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
				VALUES ($1::uuid, 1, $2::uuid, '{}', $3::text[]::uuid[], '[2026-01-01,)', '[2026-01-01,)')`,
				decision, tenantA, pgArray(refs))
			requireSQLState(t, err, "23514")
			if pgErr := pgError(t, err); pgErr.ConstraintName != "decision_version_scope_refs_valid" {
				t.Errorf("constraint = %q, want decision_version_scope_refs_valid", pgErr.ConstraintName)
			}
		})
	}
}

func TestScopeRefsAcceptsExactlyTheLimit(t *testing.T) {
	s := migrated(t)
	_, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', $3::text[]::uuid[], '[2026-01-01,)')`,
		decision, tenantA, pgArray(repeat(s.orgs[tenantA], 100)))
	if err != nil {
		t.Fatalf("100 references: %v", err)
	}
}

// A body of exactly 1 MiB of text is accepted, and one byte more is refused, on insert and on update.
func TestDecisionBodyIsCapped(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	const limit = 1 << 20
	var overhead int
	if err := s.admin.QueryRowContext(ctx, `SELECT octet_length(jsonb_build_object('x', '')::text)`).Scan(&overhead); err != nil {
		t.Fatal(err)
	}
	insert := func(id string, size int) error {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1::uuid, 1, $2::uuid, jsonb_build_object('x', repeat('a', $3::int)), ARRAY[$4::uuid], '[2026-01-01,)')`,
			id, tenantA, size, s.orgs[tenantA])
		return err
	}

	if err := insert("00000000-0000-4000-8000-0000000000e1", limit-overhead); err != nil {
		t.Fatalf("a body of exactly the limit: %v", err)
	}
	err := insert("00000000-0000-4000-8000-0000000000e2", limit-overhead+1)
	requireSQLState(t, err, "23514")
	if pgErr := pgError(t, err); pgErr.ConstraintName != "decision_version_body_size" {
		t.Errorf("constraint = %q, want decision_version_body_size", pgErr.ConstraintName)
	}

	_, err = s.app.ExecContext(ctx, `
		UPDATE registry.decision_version SET body = jsonb_build_object('x', repeat('a', $1::int))
		WHERE decision_id = '00000000-0000-4000-8000-0000000000e1'::uuid`, limit-overhead+1)
	requireSQLState(t, err, "23514")
}

// With the triggers off, the CHECK constraint is what keeps an env row from carrying a path
// without a repo, which no parent chain can produce.
func TestEnvScopeWithAPathNeedsARepo(t *testing.T) {
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
	insert := func(repo, path any) error {
		_, err := conn.ExecContext(ctx, `
			INSERT INTO registry.scope (tenant_id, parent_id, kind, selector, match_org, match_repo, match_path, match_env)
			VALUES ($1::uuid, $2::uuid, 'env', 'prod', 'acme', $3::text, $4::text, 'prod')`, tenantA, s.orgs[tenantA], repo, path)
		return err
	}
	err = insert(nil, "infra/**")
	requireSQLState(t, err, "23514")
	if pgErr := pgError(t, err); pgErr.ConstraintName != "scope_effective_shape" {
		t.Errorf("constraint = %q, want scope_effective_shape", pgErr.ConstraintName)
	}
	if err := insert("acme/payments", "infra/**"); err != nil {
		t.Errorf("a path with a repo: %v", err)
	}
	if err := insert(nil, nil); err != nil {
		t.Errorf("an env with neither: %v", err)
	}
}
