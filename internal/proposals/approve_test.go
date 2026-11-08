package proposals

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// Approve checks what it is given before it touches the store, so a nil transaction proves each refusal.
func TestApproveRefusesAnOutcomeThatDoesNotMatchItsDecision(t *testing.T) {
	id := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := &registry.NewDecision{Body: []byte(`{"slug":"x","title":"X"}`), ScopeRefs: []uuid.UUID{id}, ValidFrom: time.Now()}
	for name, c := range map[string]struct {
		tenant, approver, proposal uuid.UUID
		queue                      Queue
		outcome                    string
		decision                   *registry.NewDecision
	}{
		"no tenant":                         {uuid.Nil, id, id, QueueProposals, OutcomeApproved, decision},
		"no approver":                       {id, uuid.Nil, id, QueueProposals, OutcomeApproved, decision},
		"no proposal":                       {id, id, uuid.Nil, QueueProposals, OutcomeApproved, decision},
		"no queue":                          {id, id, id, 0, OutcomeApproved, decision},
		"an approval, no decision":          {id, id, id, QueueProposals, OutcomeApproved, nil},
		"a rejection, a decision":           {id, id, id, QueueAgentProposals, OutcomeRejected, decision},
		"an outcome of neither":             {id, id, id, QueueProposals, "maybe", nil},
		"an outcome of neither, a decision": {id, id, id, QueueProposals, "maybe", decision},
	} {
		if _, err := Approve(t.Context(), nil, c.tenant, c.approver, c.queue, c.proposal, c.outcome, c.decision); !errors.Is(err, registry.ErrInvalidQuery) {
			t.Errorf("%s: %v, want ErrInvalidQuery", name, err)
		}
	}
}
