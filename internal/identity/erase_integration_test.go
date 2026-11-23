//go:build integration

package identity_test

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// TestErasePrincipalNameReplacesTheStoredNameAndLeavesTheChain checks the four copies, the role
// binding, the closed login, the action log, a repeat, and a SCIM provision that must not write the
// name back.
func TestErasePrincipalNameReplacesTheStoredNameAndLeavesTheChain(t *testing.T) {
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := database.Open(t, pgtest.App)
	admin := database.Open(t, pgtest.Admin)
	addTenant(t, db, tenantA)
	ada := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	nerissa := principal(t, db, tenantA, identity.KindHuman, "Nerissa Quill", nil)
	bea := principal(t, db, tenantA, identity.KindHuman, "Bea", nil)
	if err := grant(t, db, tenantA, ada, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant(t, db, tenantA, nerissa, identity.RoleViewer, nil); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantA, nerissa, idp, "nerissa-1"); err != nil {
		t.Fatal(err)
	}
	var login uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT id FROM identity.login WHERE tenant_id = $1 AND principal_id = $2`, []any{tenantA, nerissa}, &login); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.session (tenant_id, login_id, token_sha256) VALUES ($1, $2, $3)`,
		tenantA, login, bytesOf(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name)
		VALUES ($1, $2, 'nerissa-1', 'nerissa@example.test')`, tenantA, nerissa); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by)
		VALUES ($1, $2, 'Nerissa Quill', 'viewer', $3), ($1, $4, 'Bea', 'viewer', $3)`,
		tenantA, bytesOf(2), ada, bytesOf(3)); err != nil {
		t.Fatal(err)
	}
	org := insertID(t, db, tenantA, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'acme') RETURNING id`)
	decision := uuid.MustParse("00000000-0000-7000-8000-0000000000e1")
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($2, 1, $1, jsonb_build_object('slug', 'use-tls', 'title', 'Use TLS'), ARRAY[$3::uuid], '[2026-01-01,)')`,
		tenantA, decision, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'Nerissa Quill', $4, '[2026-05-01,2026-06-10)', 'OPS-1')`,
		tenantA, decision, org, nerissa); err != nil {
		t.Fatal(err)
	}

	before, err := identity.VerifyLog(t.Context(), db, tenantA)
	if err != nil || !before.Intact {
		t.Fatalf("chain before: %+v %v", before, err)
	}
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, nerissa); err != nil {
		t.Fatal(err)
	}
	after, err := identity.VerifyLog(t.Context(), db, tenantA)
	if err != nil || !after.Intact || after.Entries != before.Entries+1 {
		t.Fatalf("chain after: %+v %v, before %d", after, err, before.Entries)
	}
	if textCount(t, admin, "Nerissa Quill") != 0 || textCount(t, admin, "nerissa@example.test") != 0 {
		t.Fatal("a table still holds the old name")
	}

	var gotName string
	var erased bool
	var gotID uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT id, name, name_erased FROM identity.principal WHERE tenant_id = $1 AND id = $2`,
		[]any{tenantA, nerissa}, &gotID, &gotName, &erased); err != nil {
		t.Fatal(err)
	}
	if gotID != nerissa || gotName != identity.ErasedName || !erased {
		t.Fatalf("principal = %s %q erased %v", gotID, gotName, erased)
	}
	var userName string
	var active bool
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT user_name, active FROM identity.scim_user WHERE tenant_id = $1 AND principal_id = $2`,
		[]any{tenantA, nerissa}, &userName, &active); err != nil {
		t.Fatal(err)
	}
	if userName != identity.ErasedUserName(nerissa) || active {
		t.Fatalf("scim user = %q active %v", userName, active)
	}
	var approver string
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT approver FROM registry.waiver WHERE tenant_id = $1 AND approver_id = $2`,
		[]any{tenantA, nerissa}, &approver); err != nil {
		t.Fatal(err)
	}
	if approver != identity.ErasedName {
		t.Fatalf("approver = %q", approver)
	}
	var invited, kept int
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT count(*) FILTER (WHERE name = 'erased'), count(*) FILTER (WHERE name = 'Bea')
		FROM identity.invitation WHERE tenant_id = $1`, []any{tenantA}, &invited, &kept); err != nil {
		t.Fatal(err)
	}
	if invited != 1 || kept != 1 {
		t.Fatalf("invitations erased %d, kept %d", invited, kept)
	}
	var roles, sessions, openLogins int
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT
		  (SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1 AND principal_id = $2),
		  (SELECT count(*) FROM identity.session WHERE tenant_id = $1 AND login_id = $3),
		  (SELECT count(*) FROM identity.login WHERE tenant_id = $1 AND principal_id = $2 AND closed_at IS NULL)`,
		[]any{tenantA, nerissa, login}, &roles, &sessions, &openLogins); err != nil {
		t.Fatal(err)
	}
	if roles != 1 || sessions != 0 || openLogins != 0 {
		t.Fatalf("roles %d, sessions %d, open logins %d", roles, sessions, openLogins)
	}
	var beaName string
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT name FROM identity.principal WHERE tenant_id = $1 AND id = $2`, []any{tenantA, bea}, &beaName); err != nil {
		t.Fatal(err)
	}
	if beaName != "Bea" {
		t.Fatalf("another person is %q", beaName)
	}
	actions, err := identity.Actions(t.Context(), db, tenantA, 20)
	if err != nil {
		t.Fatal(err)
	}
	var entry *identity.Action
	for i := range actions {
		if actions[i].Action == identity.ActionErasePrincipalName {
			entry = &actions[i]
		}
	}
	if entry == nil || entry.Principal != ada || entry.Subject != nerissa.String() || strings.Contains(entry.Subject, "Nerissa") {
		t.Fatalf("log entry %+v", entry)
	}
	logged := len(actions)
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, nerissa); err != nil {
		t.Fatal(err)
	}
	again, err := identity.Actions(t.Context(), db, tenantA, 20)
	if err != nil || len(again) != logged {
		t.Fatalf("a repeat wrote an entry: %d to %d (%v)", logged, len(again), err)
	}

	restored, created, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, idp, "nerissa-1", "nerissa@example.test", "Nerissa Quill")
	if err != nil || !created || restored.ID != nerissa || restored.Name != identity.ErasedName || restored.UserName != identity.ErasedUserName(nerissa) {
		t.Fatalf("reprovision: %+v created %v err %v", restored, created, err)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, idp, "nerissa-1"); err != nil {
		t.Fatal(err)
	}
	if err := identity.SetSCIMName(t.Context(), db, tenantA, "nerissa-1", "Nerissa Quill"); err != nil {
		t.Fatal(err)
	}
	if err := identity.UpdateSCIMUserName(t.Context(), db, tenantA, "nerissa-1", "nerissa@example.test"); err != nil {
		t.Fatal(err)
	}
	active = true
	if err := identity.ReplaceSCIMUser(t.Context(), db, tenantA, "nerissa-1", "other@example.test", "Someone Else", &active); err != nil {
		t.Fatal(err)
	}
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT p.name, u.user_name FROM identity.principal p
		JOIN identity.scim_user u ON u.tenant_id = p.tenant_id AND u.principal_id = p.id
		WHERE p.tenant_id = $1 AND p.id = $2`, []any{tenantA, nerissa}, &gotName, &userName); err != nil {
		t.Fatal(err)
	}
	if gotName != identity.ErasedName || userName != identity.ErasedUserName(nerissa) {
		t.Fatalf("after SCIM the name is %q and the filter key is %q", gotName, userName)
	}
	if textCount(t, admin, "Nerissa Quill") != 0 || textCount(t, admin, "nerissa@example.test") != 0 || textCount(t, admin, "Someone Else") != 0 || textCount(t, admin, "other@example.test") != 0 {
		t.Fatal("a SCIM write stored a name")
	}

	for _, statement := range []string{
		`UPDATE identity.principal SET name = 'Nerissa Quill' WHERE tenant_id = $1 AND id = $2`,
		`UPDATE identity.principal SET name_erased = false WHERE tenant_id = $1 AND id = $2`,
		`UPDATE identity.invitation SET name = 'Nerissa Quill' WHERE tenant_id = $1 AND name = 'erased' AND $2::uuid IS NOT NULL`,
		`UPDATE registry.waiver SET approver = 'Nerissa Quill' WHERE tenant_id = $1 AND approver_id = $2`,
		`UPDATE identity.scim_user SET user_name = 'nerissa@example.test' WHERE tenant_id = $1 AND principal_id = $2`,
	} {
		_, err := pgtest.Exec(t.Context(), db, tenantA.String(), statement, tenantA, nerissa)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23514" {
			t.Errorf("%s: %v, want check_violation", statement, err)
		}
	}
}

func TestErasePrincipalNameRefusesTheOnlyAdminAndAnyoneWhoIsNotAPerson(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	ada := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", ada)
	if err := grant(t, db, tenantA, ada, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, ada); !errors.Is(err, identity.ErrLastAdmin) {
		t.Fatalf("the only admin: %v", err)
	}
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, agent); !errors.Is(err, identity.ErrNotPerson) {
		t.Fatalf("an agent: %v", err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.principal (tenant_id, id, kind, name) VALUES ($1, $2, 'operator', 'operator')`,
		tenantA, identity.OperatorPrincipal); err != nil {
		t.Fatal(err)
	}
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, identity.OperatorPrincipal); !errors.Is(err, identity.ErrNotPerson) {
		t.Fatalf("the operator: %v", err)
	}
	if err := identity.ErasePrincipalName(t.Context(), db, tenantA, ada, uuid.New()); !errors.Is(err, identity.ErrUnknownPrincipal) {
		t.Fatalf("an unknown person: %v", err)
	}
	var name string
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		SELECT name FROM identity.principal WHERE tenant_id = $1 AND id = $2`, []any{tenantA, ada}, &name); err != nil {
		t.Fatal(err)
	}
	if name != "Ada" {
		t.Fatalf("the refused erasure stored %q", name)
	}
}

func bytesOf(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}

func insertID(t *testing.T, db *sql.DB, tenant uuid.UUID, query string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), query, []any{tenant}, &id); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return id
}

// textCount is how many text values in tenant tables contain needle. It reads as the admin so a
// row the application role cannot see still counts.
func textCount(t *testing.T, admin *sql.DB, needle string) int {
	t.Helper()
	rows, err := admin.QueryContext(t.Context(), `
		SELECT n.nspname, c.relname, a.attname
		FROM pg_catalog.pg_attribute a
		JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attnum > 0 AND NOT a.attisdropped
		  AND a.atttypid IN ('text'::regtype, 'varchar'::regtype)
		  AND c.relkind = 'r'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var columns [][3]string
	for rows.Next() {
		var schema, table, column string
		if err := rows.Scan(&schema, &table, &column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, [3]string{schema, table, column})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, col := range columns {
		query := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s LIKE '%%' || $1 || '%%'`,
			pgx.Identifier{col[0], col[1]}.Sanitize(), pgx.Identifier{col[2]}.Sanitize())
		var n int
		if err := admin.QueryRowContext(t.Context(), query, needle).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		total += n
	}
	return total
}
