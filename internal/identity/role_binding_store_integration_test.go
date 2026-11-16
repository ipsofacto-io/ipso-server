//go:build integration

package identity_test

import (
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func logCount(t *testing.T, db *sql.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `SELECT count(*) FROM identity.action_log WHERE tenant_id = $1`, []any{tenant}, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func adminCount(t *testing.T, db *sql.DB, tenant uuid.UUID) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `
		SELECT count(*) FROM identity.role_binding
		WHERE tenant_id = $1 AND role = 'admin' AND scope_id IS NULL`, []any{tenant}, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGrantListAndRevokeARoleBinding(t *testing.T) {
	db := migrated(t)
	admin := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	if err := grant(t, db, tenantA, admin, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	person := principal(t, db, tenantA, identity.KindHuman, "Vera", nil)
	other := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	org := scopeIn(t, db, tenantA, nil, "org", "acme")
	elsewhere := scopeIn(t, db, tenantB, nil, "org", "globex")
	ctx := t.Context()

	var wide, scoped identity.RoleBinding
	if err := identity.WithAction(ctx, db, tenantA, admin, "api.grant_role_binding", func(tx *sql.Tx) (string, error) {
		var err error
		wide, err = identity.GrantRoleBinding(ctx, tx, person, identity.RoleContributor, uuid.Nil)
		if err != nil {
			return "", err
		}
		scoped, err = identity.GrantRoleBinding(ctx, tx, person, identity.RoleApprover, org)
		return "granted", err
	}); err != nil {
		t.Fatal(err)
	}
	if wide.PrincipalID != person || wide.Role != identity.RoleContributor || wide.ScopeID != uuid.Nil || wide.ID == uuid.Nil {
		t.Fatalf("the tenant-wide binding is %+v", wide)
	}
	if scoped.ScopeID != org || scoped.Role != identity.RoleApprover {
		t.Fatalf("the scoped binding is %+v", scoped)
	}

	listed, err := identity.ListRoleBindings(ctx, db, tenantA, uuid.Nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) < 2 || listed[0].ID != scoped.ID || listed[1].ID != wide.ID {
		t.Fatalf("the page is %+v, want %s then %s first", listed, scoped.ID, wide.ID)
	}
	rest, err := identity.ListRoleBindings(ctx, db, tenantA, scoped.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) == 0 || rest[0].ID != wide.ID {
		t.Fatalf("the page before %s is %+v", scoped.ID, rest)
	}

	logs := logCount(t, db, tenantA)
	err = identity.WithAction(ctx, db, tenantA, admin, "api.grant_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.GrantRoleBinding(ctx, tx, other, identity.RoleViewer, uuid.Nil)
		return "", err
	})
	if !errors.Is(err, identity.ErrUnknownPrincipal) {
		t.Fatalf("a principal of another tenant: %v", err)
	}
	err = identity.WithAction(ctx, db, tenantA, admin, "api.grant_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.GrantRoleBinding(ctx, tx, person, identity.RoleViewer, elsewhere)
		return "", err
	})
	if !errors.Is(err, identity.ErrUnknownScope) {
		t.Fatalf("a scope of another tenant: %v", err)
	}
	err = identity.WithAction(ctx, db, tenantA, admin, "api.grant_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.GrantRoleBinding(ctx, tx, person, identity.RoleAgent, uuid.Nil)
		return "", err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("a person given agent: %v", err)
	}
	if logCount(t, db, tenantA) != logs {
		t.Fatal("a refused grant was logged")
	}

	if err := identity.WithAction(ctx, db, tenantA, admin, "api.revoke_role_binding", func(tx *sql.Tx) (string, error) {
		got, err := identity.RevokeRoleBinding(ctx, tx, scoped.ID)
		if err != nil {
			return "", err
		}
		if got.ID != scoped.ID || got.ScopeID != org {
			t.Fatalf("the revoke returned %+v", got)
		}
		return "revoked", nil
	}); err != nil {
		t.Fatal(err)
	}
	err = identity.WithAction(ctx, db, tenantA, admin, "api.revoke_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.RevokeRoleBinding(ctx, tx, scoped.ID)
		return "", err
	})
	if !errors.Is(err, identity.ErrUnknownBinding) {
		t.Fatalf("a second revoke: %v", err)
	}
}

func TestTheOnlyAdminCannotBeRevoked(t *testing.T) {
	db := migrated(t)
	admin := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	if err := grant(t, db, tenantA, admin, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	listed, err := identity.ListRoleBindings(ctx, db, tenantA, uuid.Nil, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("the bindings are %+v (%v)", listed, err)
	}
	logs := logCount(t, db, tenantA)
	err = identity.WithAction(ctx, db, tenantA, admin, "api.revoke_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.RevokeRoleBinding(ctx, tx, listed[0].ID)
		return "", err
	})
	if !errors.Is(err, identity.ErrLastAdmin) {
		t.Fatalf("the only admin: %v", err)
	}
	if adminCount(t, db, tenantA) != 1 || logCount(t, db, tenantA) != logs {
		t.Fatal("the refused revoke removed the admin or was logged")
	}

	second := principal(t, db, tenantA, identity.KindHuman, "Bea", nil)
	if err := identity.WithAction(ctx, db, tenantA, admin, "api.grant_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.GrantRoleBinding(ctx, tx, second, identity.RoleAdmin, uuid.Nil)
		return "second admin", err
	}); err != nil {
		t.Fatal(err)
	}
	if err := identity.WithAction(ctx, db, tenantA, admin, "api.revoke_role_binding", func(tx *sql.Tx) (string, error) {
		_, err := identity.RevokeRoleBinding(ctx, tx, listed[0].ID)
		return "revoked", err
	}); err != nil {
		t.Fatal(err)
	}
	if adminCount(t, db, tenantA) != 1 {
		t.Fatalf("%d admins remain", adminCount(t, db, tenantA))
	}
}

// Two revokes of the two remaining admins cannot both commit: the rows are locked in id order first.
func TestTwoRevokesOfTheLastTwoAdminsLeaveOne(t *testing.T) {
	db := migrated(t)
	first := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	second := principal(t, db, tenantA, identity.KindHuman, "Bea", nil)
	if err := grant(t, db, tenantA, first, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := grant(t, db, tenantA, second, identity.RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	listed, err := identity.ListRoleBindings(t.Context(), db, tenantA, uuid.Nil, 10)
	if err != nil || len(listed) != 2 {
		t.Fatalf("the bindings are %+v (%v)", listed, err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i, binding := range listed {
		go func() {
			defer wg.Done()
			errs[i] = identity.WithAction(t.Context(), db, tenantA, first, "api.revoke_role_binding", func(tx *sql.Tx) (string, error) {
				_, err := identity.RevokeRoleBinding(t.Context(), tx, binding.ID)
				return "revoked", err
			})
		}()
	}
	wg.Wait()
	refused := 0
	for _, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, identity.ErrLastAdmin):
			refused++
		default:
			t.Fatalf("a revoke failed with %v", err)
		}
	}
	if refused != 1 || adminCount(t, db, tenantA) != 1 {
		t.Fatalf("refused %d, admins %d, errors %v", refused, adminCount(t, db, tenantA), errs)
	}
}
