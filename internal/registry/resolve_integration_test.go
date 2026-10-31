//go:build integration

package registry

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A session with no tenant matches no row, whatever the rows hold. The queries read the tenant
// from the setting that Resolve sets and from nothing else.
func TestQueriesMatchNothingWithoutATenant(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	r.decision(t, tenantA, uuid.New(), "[2026-01-01,)", org)
	later := time.Now().Add(time.Minute)
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	// The same three queries as Resolve, on one connection that never sets ipso.tenant.
	scopes, err := r.app.QueryContext(t.Context(), selectingScopes, "acme", "acme/x", later)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scopes.Close() }()
	if scopes.Next() {
		t.Error("the scope query returned a row for a session with no tenant")
	}

	closure, err := r.app.QueryContext(t.Context(), ancestorsOfMatched, []uuid.UUID{org}, later)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closure.Close() }()
	if closure.Next() {
		t.Error("the closure query returned a row for a session with no tenant")
	}

	decisions, err := r.app.QueryContext(t.Context(), decisionsInForce, []uuid.UUID{org}, valid, later)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = decisions.Close() }()
	if decisions.Next() {
		t.Error("the decision query returned a row for a session with no tenant")
	}

	// With the tenant set to the other tenant, the same rows stay invisible.
	got, err := Resolve(t.Context(), r.app, tenantB, Subject{Repo: "acme/x"}, valid, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("tenant B resolved %d decisions of tenant A", len(got))
	}
}

// The tenant is set for one transaction only, so a pooled connection never carries it to the
// next caller.
func TestResolveDoesNotLeaveTheTenantOnTheConnection(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	r.decision(t, tenantA, uuid.New(), "[2026-01-01,)", org)

	r.app.SetMaxOpenConns(1)
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	got, err := Resolve(t.Context(), r.app, tenantA, Subject{Repo: "acme/x"}, valid, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("decisions = %d, want 1", len(got))
	}

	var setting string
	if err := r.app.QueryRowContext(t.Context(), `SELECT coalesce(current_setting('ipso.tenant', true), '')`).Scan(&setting); err != nil {
		t.Fatal(err)
	}
	if setting != "" {
		t.Errorf("the connection kept ipso.tenant = %q", setting)
	}
}

// A damaged scope row, written around the constraints, fails the call. It never makes a
// decision drop out of the answer.
func TestResolveFailsClosedOnADamagedScope(t *testing.T) {
	str := func(s string) *string { return &s }
	tests := []struct {
		name string
		repo *string // match_repo, NULL when nil
		path *string // match_path, NULL when nil
	}{
		{"a repo pattern with a bracket", str("acme/pay*["), nil},
		{"an empty path that is not NULL", str("acme/payments"), str("")},
		{"a path with a negation", str("acme/payments"), str("!infra")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRegistryDB(t)
			ctx := t.Context()
			org := r.scope(t, tenantA, uuid.Nil, "org", "acme")

			// session_replication_role = replica skips the triggers, and only a superuser can
			// set it. The CHECK constraints stay on, and an env row leaves match_repo and
			// match_path free except that a path needs a repo.
			conn, err := r.admin.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			_, err = conn.ExecContext(ctx, `
				INSERT INTO registry.scope (tenant_id, parent_id, kind, selector, match_org, match_repo, match_path, match_env)
				VALUES ($1, $2, 'env', 'prod', 'acme', $3, $4, 'prod')`, tenantA, org, tt.repo, tt.path)
			if err != nil {
				t.Fatal(err)
			}

			_, err = Resolve(ctx, r.app, tenantA, Subject{Repo: "acme/payments", Path: "a/b", Env: "prod"},
				time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), time.Now().Add(time.Minute))
			if !errors.Is(err, ErrInvalidSelector) {
				t.Errorf("err = %v, want ErrInvalidSelector", err)
			}
		})
	}
}

// A matched scope with no closure row of its own means the closure was changed around the
// triggers. The answer would silently lose every decision that applies through its ancestors,
// so the call fails.
func TestResolveFailsClosedOnADamagedClosure(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	r.decision(t, tenantA, uuid.New(), "[2026-01-01,)", org)
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	known := time.Now().Add(time.Minute)
	subject := Subject{Repo: "acme/payments"}

	got, err := Resolve(ctx, r.app, tenantA, subject, valid, known)
	if err != nil || len(got) != 1 {
		t.Fatalf("before the damage: %d decisions, err %v, want 1 and none", len(got), err)
	}

	// Only a superuser can delete closure rows. The trigger is the only writer for everyone else.
	if _, err := r.admin.ExecContext(ctx, `DELETE FROM registry.scope_closure WHERE descendant_id = $1 AND ancestor_id = $1`, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, r.app, tenantA, subject, valid, known); !errors.Is(err, ErrDamagedClosure) {
		t.Errorf("err = %v, want ErrDamagedClosure", err)
	}
}
