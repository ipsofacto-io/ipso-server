//go:build integration

package proposals

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type checkInboxAnswer struct {
	CheckProposals []struct {
		ID              uuid.UUID       `json:"id"`
		Status          string          `json:"status"`
		DecisionID      uuid.UUID       `json:"decision_id"`
		DecisionVersion int             `json:"decision_version"`
		Engine          string          `json:"engine"`
		Target          string          `json:"target"`
		Rego            string          `json:"rego"`
		Fixtures        json.RawMessage `json:"fixtures"`
		Repaired        bool            `json:"repaired"`
		Model           string          `json:"model_id"`
	} `json:"check_proposals"`
}

func readChecks(t *testing.T, db *sql.DB, tenant uuid.UUID, query string) checkInboxAnswer {
	t.Helper()
	recorder := httptest.NewRecorder()
	Handler(db, func(*http.Request) (uuid.UUID, bool) { return tenant, true }).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/check-proposals"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body)
	}
	var answer checkInboxAnswer
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

func TestCheckProposalWaitsInTheReviewQueue(t *testing.T) {
	db := newDB(t)
	llm := &scriptedLLM{answers: []string{answer(envRule)}}
	check, _, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
	if err != nil {
		t.Fatal(err)
	}
	if created, err := ProposeCheck(t.Context(), db, tenantA, check); err != nil || !created {
		t.Fatalf("created %v err %v", created, err)
	}
	if created, err := ProposeCheck(t.Context(), db, tenantA, check); err != nil || created {
		t.Fatalf("again: created %v err %v", created, err)
	}
	answer := readChecks(t, db, tenantA, "")
	if len(answer.CheckProposals) != 1 {
		t.Fatalf("queue %+v", answer)
	}
	got := answer.CheckProposals[0]
	if got.Status != "pending" || got.DecisionID != testDecision || got.DecisionVersion != 1 || got.Engine != "opa" ||
		got.Target != "agent-edit" || got.Rego != check.Rego() || got.Repaired || got.Model != "test-model" ||
		!strings.Contains(string(got.Fixtures), "service/.env") {
		t.Fatalf("check proposal %+v", got)
	}
	if other := readChecks(t, db, tenantB, ""); len(other.CheckProposals) != 0 {
		t.Fatalf("tenant B read %+v", other)
	}
}

func TestProposeCheckRefusesARuleThatFailsAFixture(t *testing.T) {
	db := newDB(t)
	llm := &scriptedLLM{answers: []string{answer(envRule)}}
	check, _, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
	if err != nil {
		t.Fatal(err)
	}
	check.Fixtures = append([]Fixture{}, check.Fixtures...)
	check.Fixtures[1].Deny = true
	check.Fixtures = append(check.Fixtures, Fixture{Tool: "write", Path: "README.md"})
	if created, err := ProposeCheck(t.Context(), db, tenantA, check); !errors.Is(err, ErrCheckFailed) || created {
		t.Fatalf("created %v err %v", created, err)
	}
	if answer := readChecks(t, db, tenantA, ""); len(answer.CheckProposals) != 0 {
		t.Fatalf("queue %+v", answer)
	}
}

func TestDatabaseCannotHoldAFailingOrApprovedCheck(t *testing.T) {
	db := newDB(t)
	ctx := t.Context()
	insert := func(status string, total, passed int, rego, digest string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO proposals.check_proposal
				(tenant_id, status, decision_id, decision_version, spec, rego, rego_sha256, fixtures,
				 fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
			VALUES ($1, $2, $3, 1, '{}', $4, sha256(convert_to($5, 'UTF8')), '[{}, {}]', $6, $7, false, 'm', 'p')`,
			tenantA, status, testDecision, rego, digest, total, passed)
		return err
	}
	const rego = "package p\n"
	for _, tc := range []struct {
		name, status   string
		total, passed  int
		digest, constr string
	}{
		{"failing fixture", "pending", 2, 1, rego, "check_proposal_fixtures_pass"},
		{"approved", "approved", 2, 2, rego, "check_proposal_status"},
		{"digest of other text", "pending", 2, 2, "package q\n", "check_proposal_rego_sha256"},
	} {
		if err := insert(tc.status, tc.total, tc.passed, rego, tc.digest); err == nil || !strings.Contains(err.Error(), tc.constr) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := insert("pending", 2, 2, rego, rego); err != nil {
		t.Fatalf("valid row: %v", err)
	}
	for _, statement := range []string{`UPDATE proposals.check_proposal SET status = 'approved'`, `UPDATE proposals.check_proposal SET fixtures_passed = 1`, `DELETE FROM proposals.check_proposal`} {
		if _, err := db.ExecContext(ctx, statement); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v", statement, err)
		}
	}
}
