//go:build integration

package authz

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

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

func migrated(t *testing.T) *sql.DB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.Open(t, pgtest.App)
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

func targetsOf(t *testing.T, db *sql.DB, tenant uuid.UUID, scopes ...uuid.UUID) [][]uuid.UUID {
	t.Helper()
	chains, err := Targets(t.Context(), db, tenant, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return chains
}

func sameSet(a, b []uuid.UUID) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	less := func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) }
	slices.SortFunc(a, less)
	slices.SortFunc(b, less)
	return slices.Equal(a, b)
}

// Targets reads each scope with every ancestor from the closure, in the order asked, and a scope the
// tenant does not have comes back with no chain.
func TestTargetsReadsTheChainsOfTheTenantsOwnScopes(t *testing.T) {
	db := migrated(t)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	payments := scopeIn(t, db, tenantA, org, "domain", "payments")
	labs := scopeIn(t, db, tenantA, org, "domain", "labs")
	repo := scopeIn(t, db, tenantA, payments, "repo", "acme/payments")
	chains := targetsOf(t, db, tenantA, repo, labs, uuid.New())
	if len(chains) != 3 {
		t.Fatalf("chains %v", chains)
	}
	if !sameSet(chains[0], []uuid.UUID{repo, payments, org}) {
		t.Errorf("the repo's chain %v", chains[0])
	}
	if !sameSet(chains[1], []uuid.UUID{labs, org}) {
		t.Errorf("labs' chain %v", chains[1])
	}
	if len(chains[2]) != 0 {
		t.Errorf("an unknown scope's chain %v", chains[2])
	}
	// Tenant B does not see tenant A's tree, even by id.
	if theirs := targetsOf(t, db, tenantB, repo); len(theirs) != 1 || len(theirs[0]) != 0 {
		t.Errorf("tenant B read tenant A's closure: %v", theirs)
	}
	for _, c := range []struct {
		name   string
		tenant uuid.UUID
		scopes []uuid.UUID
	}{
		{"no tenant", uuid.Nil, []uuid.UUID{repo}},
		{"no scope", tenantA, nil},
		{"too many scopes", tenantA, make([]uuid.UUID, maxTargets+1)},
	} {
		if _, err := Targets(t.Context(), db, c.tenant, c.scopes); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
}

// A scoped approver may approve below their scope and not beside it, and coverage follows the tree when
// a scope moves (ADR-0056).
func TestAScopedApproverFollowsTheTree(t *testing.T) {
	db := migrated(t)
	p := newPolicy(t)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	payments := scopeIn(t, db, tenantA, org, "domain", "payments")
	labs := scopeIn(t, db, tenantA, org, "domain", "labs")
	repo := scopeIn(t, db, tenantA, payments, "repo", "acme/payments")
	onPayments := []identity.Grant{{Role: identity.RoleApprover, Scope: payments}}
	approve := func(grants []identity.Grant, scopes ...uuid.UUID) bool {
		t.Helper()
		return ask(t, p, Input{
			Kind:    identity.KindHuman,
			Grants:  grants,
			Action:  DecisionApprove,
			Targets: targetsOf(t, db, tenantA, scopes...),
		})
	}
	if !approve(onPayments, repo) {
		t.Error("an approver on payments may not approve for its repo")
	}
	if !approve(onPayments, payments) {
		t.Error("an approver on payments may not approve at payments")
	}
	if approve(onPayments, labs) {
		t.Error("an approver on payments approved for labs")
	}
	if approve(onPayments, org) {
		t.Error("an approver on payments approved at the org above it")
	}
	if approve(onPayments, repo, labs) {
		t.Error("a decision with one scope outside the binding was approved")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE registry.scope SET parent_id = $1 WHERE id = $2`, labs, repo); err != nil {
		t.Fatal(err)
	}
	if approve(onPayments, repo) {
		t.Error("the approver on payments still covers the repo after it moved to labs")
	}
	if !approve([]identity.Grant{{Role: identity.RoleApprover, Scope: labs}}, repo) {
		t.Error("an approver on labs does not cover the repo that moved under it")
	}
}
