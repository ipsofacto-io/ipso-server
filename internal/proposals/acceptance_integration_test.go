//go:build integration

package proposals

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func seedPerson(t *testing.T, db *sql.DB, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', $2) RETURNING id`,
		[]any{tenant, name}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// seed inserts n proposals of one kind for a model and prompt version. A proposal is answered by the
// person and the outcome of its position in answers, and is pending when it has no answer.
type seeding struct {
	kind    string
	model   string
	prompt  string
	answers []verdict
	pending int
}

type verdict struct {
	by      uuid.UUID
	outcome string
}

var seededNumber int

func seedProposals(t *testing.T, db *sql.DB, tenant uuid.UUID, s seeding) {
	t.Helper()
	ctx, tenantID := t.Context(), tenant.String()
	for i := range len(s.answers) + s.pending {
		seededNumber++
		n := seededNumber
		var id uuid.UUID
		var insert string
		switch s.kind {
		case KindPRDecision:
			insert = `
				INSERT INTO proposals.proposal (tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
				VALUES ($1, '{"title":"t"}'::jsonb, 0.9, $2, $3, 'acme/api', $4::int, 'issuecomment' || $4::int::text,
					'https://github.com/acme/api/pull/' || $4::int::text, sha256(convert_to($4::int::text, 'UTF8')), 0)
				RETURNING id`
		case KindTrackerDecision:
			insert = `
				INSERT INTO proposals.tracker_proposal (tenant_id, connector, payload, confidence, model_id, prompt_version, external_id, source_url, source_sha256, candidate_index)
				VALUES ($1, 'github_issues', '{"title":"t"}'::jsonb, 0.9, $2, $3, 'issue-' || $4::int::text,
					'https://github.com/acme/api/issues/' || $4::int::text, sha256(convert_to($4::int::text, 'UTF8')), 0)
				RETURNING id`
		case KindCheck:
			insert = `
				INSERT INTO proposals.check_proposal (tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
				VALUES ($1, uuidv7(), 1, '{}'::jsonb, 'package p' || $4::int::text, sha256(convert_to('package p' || $4::int::text, 'UTF8')),
					'[{},{}]'::jsonb, 2, 2, false, $2, $3)
				RETURNING id`
		default:
			t.Fatalf("unknown kind %q", s.kind)
		}
		if err := pgtest.Scan(ctx, db, tenantID, insert, []any{tenant, s.model, s.prompt, n}, &id); err != nil {
			t.Fatalf("seed a %s proposal: %v", s.kind, err)
		}
		if i >= len(s.answers) {
			continue
		}
		a := s.answers[i]
		var answerSQL string
		switch s.kind {
		case KindPRDecision:
			answerSQL = `INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome, decision_id) VALUES ($1, $2, $3, $4::text, CASE WHEN $4::text = 'approved' THEN uuidv7() END)`
		case KindTrackerDecision:
			answerSQL = `INSERT INTO proposals.tracker_approval (tenant_id, proposal_id, approver_id, outcome, decision_id) VALUES ($1, $2, $3, $4::text, CASE WHEN $4::text = 'approved' THEN uuidv7() END)`
		case KindCheck:
			answerSQL = `INSERT INTO proposals.check_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, $4::text)`
		}
		if _, err := pgtest.Exec(ctx, db, tenantID, answerSQL, tenant, id, a.by, a.outcome); err != nil {
			t.Fatalf("answer a %s proposal: %v", s.kind, err)
		}
	}
}

func verdicts(by uuid.UUID, approved, rejected int) []verdict {
	out := make([]verdict, 0, approved+rejected)
	for range approved {
		out = append(out, verdict{by, OutcomeApproved})
	}
	for range rejected {
		out = append(out, verdict{by, OutcomeRejected})
	}
	return out
}

func TestAcceptanceReadsTheAnswersByKindPromptVersionAndModel(t *testing.T) {
	db := newDB(t)
	ada, grace := seedPerson(t, db, tenantA, "Ada"), seedPerson(t, db, tenantA, "Grace")
	bob := seedPerson(t, db, tenantB, "Bob")

	// Eight approvals and two rejections, answered by two people, and two proposals still pending: the
	// rate is 0.8 whoever answered, and the pending ones are not in it.
	seedProposals(t, db, tenantA, seeding{kind: KindPRDecision, model: "m1", prompt: "pr-decision-v2", pending: 2,
		answers: slices.Concat(verdicts(ada, 5, 1), verdicts(grace, 3, 1))})
	// An earlier prompt version with two answers is a row of its own, with no rate.
	seedProposals(t, db, tenantA, seeding{kind: KindPRDecision, model: "m1", prompt: "pr-decision-v1", pending: 2, answers: verdicts(ada, 1, 1)})
	// The same prompt version on another model is another row.
	seedProposals(t, db, tenantA, seeding{kind: KindPRDecision, model: "m2", prompt: "pr-decision-v2", answers: verdicts(grace, 1, 3)})
	// Six of ten drafted checks approved is under the target.
	seedProposals(t, db, tenantA, seeding{kind: KindCheck, model: "m1", prompt: "check-rule-v4", answers: verdicts(ada, 6, 4)})
	// A check a person wrote is approved on creation and is not the model's work.
	seedProposals(t, db, tenantA, seeding{kind: KindCheck, model: HumanAuthoredModel, prompt: "llm-check-v1", answers: verdicts(ada, 5, 0)})
	seedProposals(t, db, tenantA, seeding{kind: KindTrackerDecision, model: "m2", prompt: "tracker-decision-v1", pending: 2, answers: verdicts(grace, 1, 0)})
	// Another tenant's proposals are not in this tenant's report, and this tenant's are not in theirs.
	seedProposals(t, db, tenantB, seeding{kind: KindPRDecision, model: "m1", prompt: "pr-decision-v2", pending: 3, answers: verdicts(bob, 2, 0)})

	report, err := Acceptance(t.Context(), db, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tenant != tenantA || report.Target != 0.7 || report.MinAnswered != AcceptanceMinAnswered {
		t.Fatalf("report header %+v", report)
	}
	type want struct {
		kind, prompt, model         string
		approved, rejected, pending int
		rate                        float64
		hasRate, meets              bool
	}
	wants := []want{
		{KindCheck, "check-rule-v4", "m1", 6, 4, 0, 0.6, true, false},
		{KindPRDecision, "pr-decision-v1", "m1", 1, 1, 2, 0, false, false},
		{KindPRDecision, "pr-decision-v2", "m1", 8, 2, 2, 0.8, true, true},
		{KindPRDecision, "pr-decision-v2", "m2", 1, 3, 0, 0, false, false},
		{KindTrackerDecision, "tracker-decision-v1", "m2", 1, 0, 2, 0, false, false},
	}
	if len(report.Rows) != len(wants) {
		t.Fatalf("rows = %+v, want %d", report.Rows, len(wants))
	}
	for i, w := range wants {
		row := report.Rows[i]
		if row.Kind != w.kind || row.PromptVersion != w.prompt || row.Model != w.model || row.Approved != w.approved || row.Rejected != w.rejected || row.Pending != w.pending {
			t.Errorf("row %d = %+v, want %+v", i, row, w)
			continue
		}
		if w.hasRate != (row.Rate != nil) || w.hasRate != (row.MeetsTarget != nil) {
			t.Errorf("row %d reports a rate %v and a verdict %v, want reported %v", i, row.Rate, row.MeetsTarget, w.hasRate)
			continue
		}
		if w.hasRate && (*row.Rate != w.rate || *row.MeetsTarget != w.meets) {
			t.Errorf("row %d rate %v meets %v, want %v and %v", i, *row.Rate, *row.MeetsTarget, w.rate, w.meets)
		}
	}

	other, err := Acceptance(t.Context(), db, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Rows) != 1 || other.Rows[0].Approved != 2 || other.Rows[0].Pending != 3 || other.Rows[0].Rate != nil {
		t.Fatalf("tenant B report %+v", other.Rows)
	}
}

func TestAcceptanceOfATenantWithNoProposalsHasNoRows(t *testing.T) {
	db := newDB(t)
	report, err := Acceptance(t.Context(), db, tenantA)
	if err != nil || report.Rows == nil || len(report.Rows) != 0 {
		t.Fatalf("report %+v err %v, want an empty list of rows", report, err)
	}
	if _, err := Acceptance(t.Context(), db, uuid.Nil); err == nil {
		t.Fatal("a report was read for no tenant")
	}
}
