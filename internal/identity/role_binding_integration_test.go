//go:build integration

package identity_test

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// grant inserts a role binding as the application role in the binding's tenant.
func grant(t *testing.T, db *sql.DB, tenant, principal uuid.UUID, role string, scope any) error {
	t.Helper()
	_, err := pgtest.Exec(t.Context(), db, tenant.String(), `
		INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id) VALUES ($1, $2, $3, $4)`,
		tenant, principal, role, scope)
	return err
}

func scopeIn(t *testing.T, db *sql.DB, tenant uuid.UUID, parent any, kind, selector string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, $2, $3, $4) RETURNING id`,
		[]any{tenant, parent, kind, selector}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

func stateOf(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// An agent holds the agent role and nothing else, and a person never holds it (ADR-0076, ADR-0108).
func TestARoleBindingSuitsThePrincipalsKind(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	for _, tc := range []struct {
		principal uuid.UUID
		role      string
		state     string
	}{
		{person, identity.RoleAgent, "23514"},
		{agent, identity.RoleViewer, "23514"},
		{agent, identity.RoleApprover, "23514"},
		{agent, identity.RoleAdmin, "23514"},
		{agent, identity.RoleAgent, ""},
		{person, identity.RoleAdmin, ""},
		{person, identity.RoleViewer, ""},
	} {
		if got := stateOf(grant(t, db, tenantA, tc.principal, tc.role, nil)); got != tc.state {
			t.Errorf("%s to %s: SQLSTATE %q, want %q", tc.role, tc.principal, got, tc.state)
		}
	}
}

// Only the roles whose actions name a scope may be bound to one, and only the seven roles exist.
func TestOnlyTheScopedRolesTakeAScope(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	for _, role := range []string{identity.RoleViewer, identity.RoleAuditor, identity.RoleAdmin, "owner"} {
		if got := stateOf(grant(t, db, tenantA, person, role, org)); got != "23514" {
			t.Errorf("%s on a scope: SQLSTATE %q, want 23514", role, got)
		}
	}
	if got := stateOf(grant(t, db, tenantA, person, "owner", nil)); got != "23514" {
		t.Errorf("an unknown role: SQLSTATE %q, want 23514", got)
	}
	for _, role := range []string{identity.RoleContributor, identity.RoleDecisionOwner, identity.RoleApprover} {
		if err := grant(t, db, tenantA, person, role, org); err != nil {
			t.Errorf("%s on a scope: %v", role, err)
		}
	}
	if err := grant(t, db, tenantA, agent, identity.RoleAgent, org); err != nil {
		t.Errorf("an agent on a scope: %v", err)
	}
}

// A binding names a principal and a scope of its own tenant, once.
func TestABindingStaysInItsTenantAndIsUnique(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	other := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	theirs := scopeIn(t, db, tenantB, nil, "org", "globex")
	// The kind check reads the principal in the binding's tenant, where it does not exist.
	if got := stateOf(grant(t, db, tenantA, other, identity.RoleAdmin, nil)); got != "23514" {
		t.Errorf("a principal of tenant B: SQLSTATE %q, want 23514", got)
	}
	if got := stateOf(grant(t, db, tenantA, person, identity.RoleApprover, theirs)); got != "23503" {
		t.Errorf("a scope of tenant B: SQLSTATE %q, want 23503", got)
	}
	if err := grant(t, db, tenantA, person, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if got := stateOf(grant(t, db, tenantA, person, identity.RoleAdmin, nil)); got != "23505" {
		t.Errorf("the same tenant-wide binding twice: SQLSTATE %q, want 23505", got)
	}
}

// A bound scope cannot be retired, so no binding outlives the node it narrows to. Once unbound, it can.
func TestABoundScopeCannotBeRetired(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	repo := scopeIn(t, db, tenantA, org, "repo", "acme/api")
	if err := grant(t, db, tenantA, person, identity.RoleApprover, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `DELETE FROM registry.scope WHERE id = $1`, repo); stateOf(err) != "23503" {
		t.Fatalf("retiring a bound scope: %v", err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `DELETE FROM identity.role_binding WHERE scope_id = $1`, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `DELETE FROM registry.scope WHERE id = $1`, repo); err != nil {
		t.Fatalf("retiring an unbound scope: %v", err)
	}
}

// Get reads the bindings with the principal, and a removed binding is gone on the next read. The
// application role cannot rewrite a binding: it removes one and grants another.
func TestGetReadsTheBindingsAsTheyAreNow(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	if err := grant(t, db, tenantA, person, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant(t, db, tenantA, person, identity.RoleApprover, org); err != nil {
		t.Fatal(err)
	}
	got, err := identity.Get(t.Context(), db, tenantA, person)
	if err != nil {
		t.Fatal(err)
	}
	want := map[identity.Grant]bool{{Role: identity.RoleAdmin}: true, {Role: identity.RoleApprover, Scope: org}: true}
	if len(got.Grants) != len(want) {
		t.Fatalf("grants %+v", got.Grants)
	}
	for _, g := range got.Grants {
		if !want[g] {
			t.Errorf("unexpected grant %+v", g)
		}
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.role_binding SET role = 'auditor'`); err == nil {
		t.Error("the application role rewrote a binding")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `DELETE FROM identity.role_binding WHERE role = 'admin'`); err != nil {
		t.Fatal(err)
	}
	got, err = identity.Get(t.Context(), db, tenantA, person)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 1 || got.Grants[0].Role != identity.RoleApprover {
		t.Fatalf("after the removal: %+v", got.Grants)
	}
	// Tenant B reads none of tenant A's bindings, even for A's principal id.
	if _, err := identity.Get(t.Context(), db, tenantB, person); !errors.Is(err, identity.ErrUnknownPrincipal) {
		t.Fatalf("tenant B read tenant A's principal: %v", err)
	}
}
