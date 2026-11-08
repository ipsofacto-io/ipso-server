//go:build integration

package registry

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// DecisionScopes names the scopes of every row of a decision whatever its valid period, once each, counts the
// decisions the tenant has no row for, and never reads another tenant's rows.
func TestDecisionScopesNamesTheScopesOfEveryRowAndCountsTheMissing(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	api := r.scope(t, tenantA, org, "repo", "acme/api")
	web := r.scope(t, tenantA, org, "repo", "acme/web")
	one := uuid.MustParse("00000000-0000-7000-8000-0000000000e1")
	two := uuid.MustParse("00000000-0000-7000-8000-0000000000e2")
	r.decision(t, tenantA, one, "[2026-01-01,)", api, web)
	r.decisionBetween(t, tenantA, two, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), api)
	r.decision(t, tenantB, uuid.MustParse("00000000-0000-7000-8000-0000000000e3"), "[2026-01-01,)", r.scope(t, tenantB, uuid.Nil, "org", "globex"))

	scopes, missing, err := DecisionScopes(t.Context(), r.app, tenantA, []uuid.UUID{one, two, one})
	if err != nil || missing != 0 {
		t.Fatalf("DecisionScopes = %v, %d, %v", scopes, missing, err)
	}
	slices.SortFunc(scopes, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	want := []uuid.UUID{api, web}
	slices.SortFunc(want, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	if !slices.Equal(scopes, want) {
		t.Fatalf("scopes %v, want %v: each scope once, the past row included", scopes, want)
	}

	// Another tenant's decision, and one nobody has, are missing.
	_, missing, err = DecisionScopes(t.Context(), r.app, tenantA, []uuid.UUID{one, uuid.MustParse("00000000-0000-7000-8000-0000000000e3"), uuid.New()})
	if err != nil || missing != 2 {
		t.Fatalf("missing = %d, %v, want 2", missing, err)
	}
	if _, _, err := DecisionScopes(t.Context(), r.app, uuid.Nil, []uuid.UUID{one}); err == nil {
		t.Fatal("a call with no tenant was answered")
	}
	if _, _, err := DecisionScopes(t.Context(), r.app, tenantA, nil); err == nil {
		t.Fatal("a call with no decision was answered")
	}
}
