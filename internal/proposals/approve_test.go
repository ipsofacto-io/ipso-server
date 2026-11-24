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

// ApproveCheck checks what it is given before it touches the store, so a nil transaction proves each refusal.
func TestApproveCheckRefusesWhatItIsNotGiven(t *testing.T) {
	id := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	for name, c := range map[string]struct {
		tenant, approver, decision, proposal uuid.UUID
		outcome                              string
	}{
		"no tenant":           {uuid.Nil, id, id, id, OutcomeApproved},
		"no approver":         {id, uuid.Nil, id, id, OutcomeApproved},
		"no decision":         {id, id, uuid.Nil, id, OutcomeApproved},
		"no drafted check":    {id, id, id, uuid.Nil, OutcomeRejected},
		"an outcome of none":  {id, id, id, id, ""},
		"an outcome of other": {id, id, id, id, "maybe"},
	} {
		if _, err := ApproveCheck(t.Context(), nil, c.tenant, c.approver, c.decision, c.proposal, c.outcome); !errors.Is(err, registry.ErrInvalidQuery) {
			t.Errorf("%s: %v, want ErrInvalidQuery", name, err)
		}
	}
}

func TestMatchApprovedHumanLLMChecksEnforcesParity(t *testing.T) {
	id := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	warnDraft := []byte(`{"checks":[{"engine":"llm","target":"diff","mode":"warn","llm_spec":{"version":1,"target":"diff","rubric":"Must require TLS 1.3"}}]}`)
	blockDraft := []byte(`{"checks":[{"engine":"llm","target":"diff","mode":"block","max_age_days":7,"llm_spec":{"version":1,"target":"diff","rubric":"Must require TLS 1.3","fixtures":[{"id":"ok","input":"MinVersion: tls.VersionTLS13","expect":"allow"},{"id":"bad","input":"MinVersion: tls.VersionTLS12","expect":"deny"}]}}]}`)

	// Escalating mode from warn in the draft to block in the approved decision body is rejected.
	if _, err := matchApprovedHumanLLMChecks(id, []byte(`{"slug":"tls","title":"TLS","checks":[{"engine":"llm","target":"diff","mode":"block"}]}`), warnDraft); !errors.Is(err, registry.ErrInvalidQuery) {
		t.Fatalf("mode mismatch got %v, want ErrInvalidQuery", err)
	}
	// Changing target between draft and approved decision body is rejected.
	if _, err := matchApprovedHumanLLMChecks(id, []byte(`{"slug":"tls","title":"TLS","checks":[{"engine":"llm","target":"terraform-plan","mode":"warn"}]}`), warnDraft); !errors.Is(err, registry.ErrInvalidQuery) {
		t.Fatalf("target mismatch got %v, want ErrInvalidQuery", err)
	}
	// Changing max_age_days between draft and approved decision body is rejected.
	if _, err := matchApprovedHumanLLMChecks(id, []byte(`{"slug":"tls","title":"TLS","checks":[{"engine":"llm","target":"diff","mode":"block","max_age_days":14}]}`), blockDraft); !errors.Is(err, registry.ErrInvalidQuery) {
		t.Fatalf("max_age_days mismatch got %v, want ErrInvalidQuery", err)
	}
	// Matching block check succeeds with mode=block and max_age_days=7.
	planned, err := matchApprovedHumanLLMChecks(id, []byte(`{"slug":"tls","title":"TLS","checks":[{"engine":"llm","target":"diff","mode":"block","max_age_days":7}]}`), blockDraft)
	if err != nil || len(planned) != 1 || planned[0].Mode != "block" || planned[0].MaxAgeDays == nil || *planned[0].MaxAgeDays != 7 {
		t.Fatalf("matching block check got %+v, %v", planned, err)
	}
}
