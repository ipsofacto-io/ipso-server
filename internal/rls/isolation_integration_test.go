//go:build integration

package rls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

const (
	tenantA = "00000000-0000-4000-8000-00000000000a"
	tenantB = "00000000-0000-4000-8000-00000000000b"

	decisionKeep = pgtest.DecisionKeep
	decisionFrom = pgtest.DecisionFrom
	decisionTo   = pgtest.DecisionTo
)

// tenantCall is what every policy compares tenant_id to. The function body is the
// nullif(current_setting(...)) expression. It is leakproof so the planner can still
// use an index. An inline current_setting is not, and the decisions read then scans
// every row.
const tenantCall = "ipso.current_tenant()"

func TestApplicationRoleCannotBypassRowLevelSecurity(t *testing.T) {
	db := migrated(t)
	admin := db.Open(t, pgtest.Admin)
	var superuser, bypass bool
	if err := admin.QueryRowContext(t.Context(), `
		SELECT rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = $1`, pgtest.App).
		Scan(&superuser, &bypass); err != nil {
		t.Fatal(err)
	}
	if superuser || bypass {
		t.Fatalf("application role superuser %v BYPASSRLS %v", superuser, bypass)
	}
	var owned int
	if err := admin.QueryRowContext(t.Context(), `
		SELECT count(*) FROM pg_catalog.pg_class WHERE relowner = $1::text::regrole`, pgtest.App).
		Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned != 0 {
		t.Fatalf("application role owns %d relations", owned)
	}
}

func TestEveryTenantTableIsForcedAndPoliciesUseTheSessionTenant(t *testing.T) {
	db := migrated(t)
	admin := db.Open(t, pgtest.Admin)
	ctx := t.Context()

	tables, err := tenantTables(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	wantTables := policyTables()
	if strings.Join(tables, "\n") != strings.Join(wantTables, "\n") {
		t.Fatalf("tenant tables =\n%s\nwant\n%s", strings.Join(tables, "\n"), strings.Join(wantTables, "\n"))
	}

	var unforced int
	if err := admin.QueryRowContext(ctx, `
		SELECT count(*)
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE c.relkind IN ('r', 'p')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
		  AND NOT (c.relrowsecurity AND c.relforcerowsecurity)`).Scan(&unforced); err != nil {
		t.Fatal(err)
	}
	if unforced != 0 {
		t.Fatalf("%d tenant tables are missing forced row-level security", unforced)
	}

	var (
		leakproof  bool
		volatile   string
		body       string
		appExec    bool
		bypassExec bool
	)
	if err := admin.QueryRowContext(ctx, `
		SELECT p.proleakproof, p.provolatile, p.prosrc,
		       has_function_privilege('ipso_app', p.oid, 'execute'),
		       has_function_privilege('ipso_bypass', p.oid, 'execute')
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
		WHERE n.nspname = 'ipso' AND p.proname = 'current_tenant'`).
		Scan(&leakproof, &volatile, &body, &appExec, &bypassExec); err != nil {
		t.Fatal(err)
	}
	if !leakproof || volatile != "s" || !appExec || bypassExec {
		t.Fatalf("current_tenant leakproof %v volatile %q app %v bypass %v", leakproof, volatile, appExec, bypassExec)
	}
	if !strings.Contains(strings.ToLower(body), "nullif(current_setting('ipso.tenant'") {
		t.Fatalf("current_tenant body = %q", body)
	}

	got, err := policies(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	want := expectedPolicies()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("policies =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	views, err := admin.QueryContext(ctx, `
		SELECT n.nspname || '.' || c.relname, coalesce(array_to_string(c.reloptions, ','), '')
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE c.relkind = 'v'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = views.Close() }()
	n := 0
	for views.Next() {
		var name, options string
		if err := views.Scan(&name, &options); err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.Contains(options, "security_invoker=true") {
			t.Errorf("view %s options %q, want security_invoker=true", name, options)
		}
	}
	if err := views.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no tenant view")
	}
}

func TestCrossTenantReadsAndWritesFail(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	admin := db.Open(t, pgtest.Admin)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)
	seedTombstones(t, db, tenantA, tenantB)

	for _, table := range policyTables() {
		t.Run(table, func(t *testing.T) {
			if got := countAs(t, app, tenantB, table, tenantA); got != 0 {
				t.Fatalf("tenant B sees %d of tenant A's rows", got)
			}
			if got := countAs(t, app, tenantA, table, tenantA); got == 0 {
				t.Fatal("tenant A sees none of its rows")
			}
			before := countAdmin(t, admin, table, tenantA)
			res, err := pgtest.Exec(t.Context(), app, tenantB,
				fmt.Sprintf(`UPDATE %s SET tenant_id = tenant_id WHERE tenant_id = $1::uuid`, table), tenantA)
			if err == nil {
				n, affErr := res.RowsAffected()
				if affErr != nil {
					t.Fatal(affErr)
				}
				if n != 0 {
					t.Fatalf("update changed %d rows", n)
				}
			}
			res, err = pgtest.Exec(t.Context(), app, tenantB,
				fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $1::uuid`, table), tenantA)
			if err == nil {
				n, affErr := res.RowsAffected()
				if affErr != nil {
					t.Fatal(affErr)
				}
				if n != 0 {
					t.Fatalf("delete removed %d rows", n)
				}
			}
			if got := countAdmin(t, admin, table, tenantA); got != before {
				t.Fatalf("tenant A rows = %d, want %d", got, before)
			}
		})
	}

	for _, smuggle := range smuggleInserts() {
		t.Run("insert "+smuggle.table, func(t *testing.T) {
			_, err := pgtest.Exec(t.Context(), app, tenantB, smuggle.query, smuggle.args...)
			if err == nil {
				t.Fatal("insert of tenant A's id succeeded")
			}
			if smuggle.policy && sqlState(err) != "42501" {
				t.Fatalf("sqlstate = %s, want 42501 (%v)", sqlState(err), err)
			}
		})
	}
}

func TestASessionWithNoTenantSeesNoRow(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	pgtest.SeedEveryTable(t, app, tenantA)

	var n int
	if err := app.QueryRowContext(t.Context(), `SELECT count(*) FROM registry.scope`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rows with no tenant = %d, want 0", n)
	}

	conn, err := app.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	tx, err := conn.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(t.Context(), `SELECT count(*) FROM registry.scope`).Scan(&n); err != nil {
		t.Fatalf("read after the transaction-local setting ended: %v", err)
	}
	if n != 0 {
		t.Fatalf("rows after the setting ended = %d, want 0", n)
	}
}

// The restore and offboard commands skip triggers for one transaction with session_replication_role. Only
// the migration role holds that grant. The application role must not, or a request could skip the
// triggers that stamp transaction time and keep history (ADR-0100).
func TestOnlyTheMigrationRoleMaySkipTriggers(t *testing.T) {
	db := migrated(t)
	for role, wantErr := range map[string]bool{pgtest.App: true, pgtest.Migrate: false} {
		conn := db.Open(t, role)
		tx, err := conn.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(t.Context(), `SELECT set_config('session_replication_role', 'replica', true)`)
		_ = tx.Rollback()
		if gotErr := err != nil; gotErr != wantErr {
			t.Errorf("%s set session_replication_role: error %v, want an error %v", role, err, wantErr)
		}
		if wantErr && sqlState(err) != "42501" {
			t.Errorf("%s: sqlstate = %s, want 42501 (%v)", role, sqlState(err), err)
		}
	}
}

func TestApplicationRoleCannotSetRoleToTheMigrationRole(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	if _, err := app.ExecContext(t.Context(), `SET ROLE ipso_migrate`); err == nil {
		t.Fatal("SET ROLE ipso_migrate succeeded")
	}
}

func TestBypassRLSSeesEveryTenantAndIsRefusedAtStart(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)

	admin := db.Open(t, pgtest.Admin)
	for _, statement := range []string{
		`GRANT USAGE ON SCHEMA registry TO ipso_bypass`,
		`GRANT SELECT ON ALL TABLES IN SCHEMA registry TO ipso_bypass`,
	} {
		if _, err := admin.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	bypass := db.Open(t, pgtest.Bypass)
	var n int
	if err := bypass.QueryRowContext(t.Context(), `SELECT count(*) FROM registry.scope`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("BYPASSRLS sees %d scope rows, want both tenants", n)
	}
	if err := Check(t.Context(), bypass); !errors.Is(err, ErrRefused) {
		t.Fatalf("Check = %v, want the start refusal", err)
	}
}

// seedTombstones writes the one row the application role cannot: the tombstone of an offboarded tenant. The
// migration role writes it, with ipso.tenant set, the way the offboard command does.
func seedTombstones(t *testing.T, db *pgtest.Database, tenants ...string) {
	t.Helper()
	migrator := db.Open(t, pgtest.Migrate)
	for _, tenant := range tenants {
		if _, err := pgtest.Exec(t.Context(), migrator, tenant,
			`INSERT INTO tenancy.offboarding (tenant_id, deleted_rows, deleted_jobs, key_destroyed) VALUES ($1::uuid, 1, 0, true)`, tenant); err != nil {
			t.Fatalf("tombstone of %s: %v", tenant, err)
		}
	}
}

type smuggle struct {
	table  string
	query  string
	args   []any
	policy bool
}

func smuggleInserts() []smuggle {
	return []smuggle{
		{"registry.scope", `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1::uuid, NULL, 'org', 'smuggled')`, []any{tenantA}, true},
		{"identity.principal", `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1::uuid, 'human', 'Bea')`, []any{tenantA}, true},
		{"llm.usage", `INSERT INTO llm.usage (tenant_id, month, tokens) VALUES ($1::uuid, '2026-02-01', 1)`, []any{tenantA}, true},
		{"tenancy.tenant", `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1::uuid, 'smuggled')`, []any{tenantA}, true},
		{"tenancy.tenant_key", `INSERT INTO tenancy.tenant_key (tenant_id, wrapped_dek) VALUES ($1::uuid, decode(repeat('ab', 60), 'hex'))`, []any{tenantA}, true},
		{"tenancy.installation", `INSERT INTO tenancy.installation (installation_id, tenant_id) VALUES (987654321, $1::uuid)`, []any{tenantA}, true},
		// The application role has no INSERT on the tombstone at all, so the privilege check refuses it.
		{"tenancy.offboarding", `INSERT INTO tenancy.offboarding (tenant_id, deleted_rows, deleted_jobs, key_destroyed) VALUES ($1::uuid, 0, 0, false)`, []any{tenantA}, false},
		{"identity.login", `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1::uuid, $1::uuid, 'https://idp.example.test', 'smuggled')`, []any{tenantA}, true},
		// The stamp trigger reads the login as the caller's tenant, so it refuses this row (23514) before the
		// policy is asked (42501). Either way the insert fails, and the policy stays as a second line.
		{"identity.session", `INSERT INTO identity.session (tenant_id, login_id, token_sha256) VALUES ($1::uuid, $1::uuid, sha256(convert_to('smuggled', 'UTF8')))`, []any{tenantA}, false},
		{"registry.premise_host_allow", `INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1::uuid, 'smuggled.example', true)`, []any{tenantA}, true},
		{"registry.grandfather_period", `INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period) VALUES ($1::uuid, $2::uuid, '[2021-01-01,)')`, []any{tenantA, decisionTo}, true},
		{"proposals.proposal", `
			INSERT INTO proposals.proposal
				(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
			VALUES ($1::uuid, '{}', 0.5, 'm', 'p', 'acme/payments', 9, 'comment2',
			        'https://github.com/acme/payments/pull/9', decode(repeat('cd', 32), 'hex'), 0)`, []any{tenantA}, true},
		{"registry.decision_version_history", `
			INSERT INTO registry.decision_version_history
				(decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
			VALUES ($1::uuid, 1, $2::uuid, '{}', '{}', '[2020-01-01,)', '[2020-01-01,2020-02-01)')`,
			[]any{decisionKeep, tenantA}, false},
		{"registry.scope_history", `
			INSERT INTO registry.scope_history (tenant_id, id, kind, selector, match_org, sys_period)
			VALUES ($1::uuid, $2::uuid, 'org', 'acme', 'acme', '[2020-01-01,2020-02-01)')`,
			[]any{tenantA, decisionKeep}, false},
		{"registry.scope_closure", `
			INSERT INTO registry.scope_closure (tenant_id, descendant_id, ancestor_id, depth)
			VALUES ($1::uuid, $2::uuid, $2::uuid, 0)`, []any{tenantA, decisionKeep}, false},
		{"registry.scope_closure_history", `
			INSERT INTO registry.scope_closure_history (tenant_id, descendant_id, ancestor_id, depth, sys_period)
			VALUES ($1::uuid, $2::uuid, $2::uuid, 0, '[2020-01-01,2020-02-01)')`,
			[]any{tenantA, decisionKeep}, false},
	}
}

func countAs(t *testing.T, db *sql.DB, session, table, rowTenant string) int {
	t.Helper()
	var n int
	query := fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1::uuid`, table)
	if err := pgtest.Scan(t.Context(), db, session, query, []any{rowTenant}, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countAdmin(t *testing.T, db *sql.DB, table, rowTenant string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1::uuid`, table), rowTenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func tenantTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname || '.' || c.relname
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE c.relkind IN ('r', 'p')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func policies(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT n.nspname || '.' || c.relname,
		       pg_get_userbyid(pol.polroles[1]),
		       CASE pol.polcmd
		           WHEN 'r' THEN 'SELECT'
		           WHEN 'a' THEN 'INSERT'
		           WHEN 'w' THEN 'UPDATE'
		           WHEN 'd' THEN 'DELETE'
		           ELSE pol.polcmd::text
		       END,
		       coalesce(pg_get_expr(pol.polqual, pol.polrelid), ''),
		       coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '')
		FROM pg_catalog.pg_policy AS pol
		JOIN pg_catalog.pg_class AS c ON c.oid = pol.polrelid
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var table, role, cmd, using, check string
		if err := rows.Scan(&table, &role, &cmd, &using, &check); err != nil {
			return nil, err
		}
		for _, expr := range []string{using, check} {
			if expr == "" {
				continue
			}
			if !strings.Contains(strings.ToLower(expr), tenantCall) {
				return nil, fmt.Errorf("policy on %s for %s %s expression %q", table, role, cmd, expr)
			}
		}
		if using == "" && check == "" {
			return nil, fmt.Errorf("policy on %s for %s %s has no expression", table, role, cmd)
		}
		got = append(got, table+" "+role+" "+cmd)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(got)
	return got, nil
}

func policyTables() []string {
	tables := []string{
		"identity.action_log",
		"identity.login",
		"identity.principal",
		"identity.session",
		"llm.usage",
		"proposals.agent_proposal",
		"proposals.approval",
		"proposals.check_proposal",
		"proposals.proposal",
		"registry.baseline",
		"registry.decision_version",
		"registry.decision_version_history",
		"registry.grandfather_period",
		"registry.premise_clearance",
		"registry.premise_evaluation",
		"registry.premise_host_allow",
		"registry.premise_reason",
		"registry.scope",
		"registry.scope_closure",
		"registry.scope_closure_history",
		"registry.scope_history",
		"registry.supersession",
		"registry.waiver",
		"registry.waiver_notice",
		"tenancy.installation",
		"tenancy.offboarding",
		"tenancy.tenant",
		"tenancy.tenant_key",
	}
	sort.Strings(tables)
	return tables
}

func expectedPolicies() []string {
	app := map[string]string{
		"identity.action_log":               "SELECT INSERT",
		"identity.login":                    "SELECT INSERT",
		"identity.principal":                "SELECT INSERT",
		"identity.session":                  "SELECT INSERT DELETE",
		"llm.usage":                         "SELECT INSERT UPDATE",
		"proposals.agent_proposal":          "SELECT INSERT",
		"proposals.approval":                "SELECT INSERT",
		"proposals.check_proposal":          "SELECT INSERT",
		"proposals.proposal":                "SELECT INSERT",
		"registry.baseline":                 "SELECT INSERT",
		"registry.decision_version":         "SELECT INSERT UPDATE DELETE",
		"registry.decision_version_history": "SELECT",
		"registry.grandfather_period":       "SELECT INSERT",
		"registry.premise_clearance":        "SELECT INSERT",
		"registry.premise_evaluation":       "SELECT INSERT",
		"registry.premise_host_allow":       "SELECT INSERT",
		"registry.premise_reason":           "SELECT INSERT",
		"registry.scope":                    "SELECT INSERT UPDATE DELETE",
		"registry.scope_closure":            "SELECT",
		"registry.scope_closure_history":    "SELECT",
		"registry.scope_history":            "SELECT",
		"registry.supersession":             "SELECT INSERT",
		"registry.waiver":                   "SELECT INSERT",
		"registry.waiver_notice":            "SELECT INSERT",
		"tenancy.installation":              "SELECT INSERT",
		"tenancy.offboarding":               "SELECT",
		"tenancy.tenant":                    "SELECT INSERT",
		"tenancy.tenant_key":                "SELECT INSERT",
	}
	// The migration role reads, writes and deletes every tenant table, because the restore and offboard
	// commands run as it (ADR-0100). The exceptions are the tables a restore does not write, the table
	// the triggers of the migration role already write, and the tombstone, which is written once and never
	// deleted. The scope tree also keeps the UPDATE of 00013.
	migrate := make(map[string]string)
	for _, table := range policyTables() {
		migrate[table] = "SELECT INSERT DELETE"
	}
	migrate["identity.session"] = "SELECT DELETE"
	// A binding is unique across tenants, so an export leaves it out and a restore does not write it.
	migrate["tenancy.installation"] = "SELECT DELETE"
	migrate["tenancy.tenant"] = "SELECT DELETE"
	migrate["tenancy.tenant_key"] = "SELECT DELETE"
	migrate["tenancy.offboarding"] = "SELECT INSERT"
	migrate["registry.scope"] = "SELECT INSERT UPDATE DELETE"
	var lines []string
	for table, cmds := range app {
		for _, cmd := range strings.Fields(cmds) {
			lines = append(lines, table+" "+pgtest.App+" "+cmd)
		}
	}
	for table, cmds := range migrate {
		for _, cmd := range strings.Fields(cmds) {
			lines = append(lines, table+" "+pgtest.Migrate+" "+cmd)
		}
	}
	sort.Strings(lines)
	return lines
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
