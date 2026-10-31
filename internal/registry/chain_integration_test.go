//go:build integration

package registry

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSupersessionChainCycle(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	a := uuid.New()
	b := uuid.New()
	r.decision(t, tenantA, a, "[2026-01-01,)", repo)
	r.decision(t, tenantA, b, "[2026-01-01,)", repo)
	if _, err := r.admin.ExecContext(ctx, `ALTER TABLE registry.supersession DISABLE TRIGGER supersession_check`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, pair := range [][2]uuid.UUID{{a, b}, {b, a}} {
		if _, err := r.app.ExecContext(ctx, `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
			VALUES ($1, $2, $3, $4)`, tenantA, pair[0], pair[1], at); err != nil {
			t.Fatal(err)
		}
	}
	_, err := SupersessionChain(ctx, r.app, tenantA, a, time.Now())
	if !errors.Is(err, ErrDamagedChain) {
		t.Fatalf("cycle: %v", err)
	}
}

func TestSupersessionChainLimit(t *testing.T) {
	previous := chainNodeLimit
	chainNodeLimit = 2
	t.Cleanup(func() { chainNodeLimit = previous })

	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, id := range ids {
		r.decision(t, tenantA, id, "[2026-01-01,)", repo)
	}
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := range 2 {
		if _, err := r.app.ExecContext(ctx, `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
			VALUES ($1, $2, $3, $4)`, tenantA, ids[i], ids[i+1], at); err != nil {
			t.Fatal(err)
		}
	}
	_, err := SupersessionChain(ctx, r.app, tenantA, ids[0], time.Now())
	if !errors.Is(err, ErrDamagedChain) {
		t.Fatalf("limit: %v", err)
	}
}
