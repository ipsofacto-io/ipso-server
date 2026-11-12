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
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
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
		_, err := pgtest.Exec(ctx, db, tenantA.String(), `
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

// A person answers a drafted check once, and a check with an answer leaves the review queue while its row stays
// pending, which its constraint demands (ADR-0086, ADR-0116). The answer must name the decision the check is for,
// and a check of another tenant is not found.
func TestADraftedCheckIsAnsweredOnceAndLeavesTheQueue(t *testing.T) {
	db := newDB(t)
	ctx := t.Context()
	llm := &scriptedLLM{answers: []string{answer(envRule)}}
	check, _, err := DraftCheck(ctx, llm.complete, checkRequest(envFixtures))
	if err != nil {
		t.Fatal(err)
	}
	if created, err := ProposeCheck(ctx, db, tenantA, check); err != nil || !created {
		t.Fatalf("created %v err %v", created, err)
	}
	queue := readChecks(t, db, tenantA, "")
	if len(queue.CheckProposals) != 1 {
		t.Fatalf("queue %+v", queue)
	}
	proposal := queue.CheckProposals[0].ID
	var approver uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Ada') RETURNING id`,
		[]any{tenantA}, &approver); err != nil {
		t.Fatal(err)
	}
	// decide runs ApproveCheck in a READ COMMITTED transaction of the tenant, as the API does.
	decide := func(tenant, decision, id uuid.UUID, outcome string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := ApproveCheck(ctx, tx, tenant, approver, decision, id, outcome); err != nil {
			return err
		}
		return tx.Commit()
	}

	if err := decide(tenantA, uuid.New(), proposal, OutcomeApproved); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("a check of another decision: %v, want ErrNotFound", err)
	}
	if err := decide(tenantA, testDecision, uuid.New(), OutcomeApproved); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("no such check: %v, want ErrNotFound", err)
	}
	if err := decide(tenantB, testDecision, proposal, OutcomeApproved); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("a check of another tenant: %v, want ErrNotFound", err)
	}
	if err := decide(tenantA, testDecision, proposal, "maybe"); !errors.Is(err, registry.ErrInvalidQuery) {
		t.Errorf("an outcome of neither: %v, want ErrInvalidQuery", err)
	}
	if got := readChecks(t, db, tenantA, ""); len(got.CheckProposals) != 1 {
		t.Fatalf("a refused answer changed the queue: %+v", got)
	}

	if err := decide(tenantA, testDecision, proposal, OutcomeRejected); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got := readChecks(t, db, tenantA, ""); len(got.CheckProposals) != 0 {
		t.Fatalf("a decided check is still in the queue: %+v", got)
	}
	var status, outcome string
	var by uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `
		SELECT p.status, a.outcome, a.approver_id
		FROM proposals.check_proposal p JOIN proposals.check_approval a ON a.tenant_id = p.tenant_id AND a.proposal_id = p.id
		WHERE p.tenant_id = $1 AND p.id = $2`, []any{tenantA, proposal}, &status, &outcome, &by); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || outcome != OutcomeRejected || by != approver {
		t.Fatalf("the row is %q, the answer %q by %s", status, outcome, by)
	}

	// A check is decided once, whatever the second answer says, and the refusal is the unique constraint.
	for _, again := range []string{OutcomeApproved, OutcomeRejected} {
		var pg *pgconn.PgError
		if err := decide(tenantA, testDecision, proposal, again); !errors.As(err, &pg) || pg.Code != "23505" {
			t.Errorf("a second answer %q: %v, want a unique violation", again, err)
		}
	}
}
