//go:build integration

package registry

import (
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// decisionVersion inserts one version of a decision whose body holds edrID as its id, as the application role.
func (r registryDB) decisionVersion(t *testing.T, tenant, id uuid.UUID, version int, edrID, valid string, scope uuid.UUID) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), r.app, tenant.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, $2, $3, jsonb_build_object('id', $4::text), ARRAY[$5::uuid], $6::text::tstzrange)`,
		id, version, tenant, edrID, scope, valid); err != nil {
		t.Fatalf("insert decision version: %v", err)
	}
}

func TestDecisionsByEDRIDKeepsAnIdThatOneDecisionHoldsAsKnownAtATime(t *testing.T) {
	r := newRegistryDB(t)
	rootA := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	rootB := r.scope(t, tenantB, uuid.Nil, "org", "acme")
	one := uuid.MustParse("00000000-0000-4000-8000-0000000000f1")
	two := uuid.MustParse("00000000-0000-4000-8000-0000000000f2")
	three := uuid.MustParse("00000000-0000-4000-8000-0000000000f3")
	four := uuid.MustParse("00000000-0000-4000-8000-0000000000f4")
	elsewhere := uuid.MustParse("00000000-0000-4000-8000-0000000000f5")
	const idOne, idTwo, idTwice, idOnlyElsewhere = "01M5QJ0V9EVXKR4C89XNBNT5GG", "01M6B5CJM06Z03BNN7F7GG7KCP", "01M6C49B800A33HVBTN854789M", "01M7BK3EQ8W4Y2N6XD5T9RFH7C"

	before := mark(t, r.admin)
	// Decision one has two versions with one id, and a later version does not make it two decisions.
	r.decisionVersion(t, tenantA, one, 1, idOne, "[2026-01-01,2026-06-01)", rootA)
	r.decisionVersion(t, tenantA, one, 2, idOne, "[2026-06-01,)", rootA)
	r.decisionVersion(t, tenantA, two, 1, idTwo, "[2026-01-01,)", rootA)
	// Two decisions that hold the same id are never guessed between.
	r.decisionVersion(t, tenantA, three, 1, idTwice, "[2026-01-01,)", rootA)
	r.decisionVersion(t, tenantA, four, 1, idTwice, "[2026-01-01,)", rootA)
	// Another tenant's decision with an id of tenant A's changes nothing there, and its own id is not found.
	r.decisionVersion(t, tenantB, elsewhere, 1, idTwo, "[2026-01-01,)", rootB)
	r.decisionVersion(t, tenantB, uuid.MustParse("00000000-0000-4000-8000-0000000000f6"), 1, idOnlyElsewhere, "[2026-01-01,)", rootB)
	after := mark(t, r.admin)

	ids := []string{idOne, idTwo, idTwice, idOnlyElsewhere, "01M7NOBODYHOLDSTHISIDATALL"}
	got, err := DecisionsByEDRID(t.Context(), r.app, tenantA, ids, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[idOne] != one || got[idTwo] != two {
		t.Errorf("decisions = %v, want %s for %s and %s for %s only", got, one, idOne, two, idTwo)
	}
	if _, ok := got[idTwice]; ok {
		t.Error("an id that two decisions hold was matched")
	}
	if _, ok := got[idOnlyElsewhere]; ok {
		t.Error("an id of another tenant was matched")
	}

	// As known before the decisions were recorded, nothing is found.
	earlier, err := DecisionsByEDRID(t.Context(), r.app, tenantA, ids, before)
	if err != nil || len(earlier) != 0 {
		t.Errorf("as known before = %v, %v, want nothing", earlier, err)
	}

	// Tenant B holds idTwo once, in its own decision.
	b, err := DecisionsByEDRID(t.Context(), r.app, tenantB, []string{idTwo}, after)
	if err != nil || len(b) != 1 || b[idTwo] != elsewhere {
		t.Errorf("tenant B = %v, %v", b, err)
	}
}
