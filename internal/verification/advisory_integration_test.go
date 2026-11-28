//go:build integration

package verification

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func advisoryVerdict() AdvisoryVerdict {
	prompt := sha256.Sum256([]byte("prompt file"))
	return AdvisoryVerdict{
		AdvisoryCheck: AdvisoryCheck{
			RepositoryID: 42, PullNumber: 7, HeadSHA: strings.Repeat("ab", 20),
			DecisionID: uuid.MustParse("0190c7b8-0000-7000-8000-0000000000d1"), DecisionVersion: 2, CheckIndex: 1,
		},
		Repo:          "acme/payments",
		BaseSHA:       strings.Repeat("cd", 20),
		Assessment:    Deviates,
		Cited:         []Place{{Path: "db/schema.sql", StartLine: 3, EndLine: 9}},
		Reason:        "The change adds a MySQL table, and the decision keeps new services on PostgreSQL.",
		ModelID:       "served-model",
		PromptVersion: "pr-advisory-v1",
		InputSHA256:   sha256.Sum256([]byte("input")),
		PromptSHA256:  prompt[:],
	}
}

func TestStoreAdvisoryWritesOnceAndFixesTheResult(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	v := advisoryVerdict()
	created, err := StoreAdvisory(ctx, s.app, tenantA, v)
	if err != nil || !created {
		t.Fatalf("first store: created %v, %v", created, err)
	}
	again, err := StoreAdvisory(ctx, s.app, tenantA, v)
	if err != nil || again {
		t.Fatalf("a repeat must insert nothing: created %v, %v", again, err)
	}
	var mode, result, cited string
	if err := s.admin.QueryRowContext(ctx, `
		SELECT mode, result, cited::text FROM verification.advisory_verdict WHERE tenant_id = $1`, tenantA,
	).Scan(&mode, &result, &cited); err != nil {
		t.Fatal(err)
	}
	if mode != "advise" || result != "advisory" || cited != `[{"path": "db/schema.sql", "end_line": 9, "start_line": 3}]` {
		t.Fatalf("stored mode %q, result %q, cited %s", mode, result, cited)
	}

	found, err := HasAdvisory(ctx, s.app, tenantA, v.AdvisoryCheck)
	if err != nil || !found {
		t.Fatalf("the check has a verdict: %v, %v", found, err)
	}
	other, err := HasAdvisory(ctx, s.app, tenantB, v.AdvisoryCheck)
	if err != nil || other {
		t.Fatalf("another tenant sees the verdict: %v, %v", other, err)
	}
}

func TestStoreAdvisoryRefusesWhatTheTableRefuses(t *testing.T) {
	s := newStore(t)
	for _, c := range []struct {
		name string
		edit func(*AdvisoryVerdict)
	}{
		{"a result word as the assessment", func(v *AdvisoryVerdict) { v.Assessment = "pass" }},
		{"a deviation with no place", func(v *AdvisoryVerdict) { v.Cited = nil }},
		{"eleven places", func(v *AdvisoryVerdict) {
			for range 10 {
				v.Cited = append(v.Cited, Place{Path: "a.go", StartLine: 1, EndLine: 1})
			}
		}},
		{"a reason with a newline", func(v *AdvisoryVerdict) { v.Reason = "first\nsecond" }},
		{"a reason too long", func(v *AdvisoryVerdict) { v.Reason = strings.Repeat("x", MaxReasonRunes+1) }},
		{"no model id", func(v *AdvisoryVerdict) { v.ModelID = "" }},
		{"an uppercase repository", func(v *AdvisoryVerdict) { v.Repo = "Acme/Payments" }},
		{"a place with no line", func(v *AdvisoryVerdict) { v.Cited = []Place{{Path: "a.go"}} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := advisoryVerdict()
			c.edit(&v)
			if created, err := StoreAdvisory(t.Context(), s.app, tenantA, v); err == nil || created {
				t.Fatalf("stored: created %v, %v", created, err)
			}
		})
	}
}

// The table, not only the Go writer, refuses a result other than advisory and a mode other than advise from
// the llm-advisory engine (ADR-0152 decision 5), and a deviation that names no place.
func TestAdvisoryVerdictTableRefusesABlockingOrFailingVerdict(t *testing.T) {
	s := newStore(t)
	insert := func(column, value, assessment, cited string) error {
		_, err := pgtest.Exec(t.Context(), s.app, tenantA.String(), `
			INSERT INTO verification.advisory_verdict
				(tenant_id, repository_id, repo, pull_number, head_sha, base_sha, decision_id, decision_version, check_index,
				 assessment, cited, reason, model_id, prompt_version, input_sha256, `+column+`)
			VALUES ($1, 1, 'acme/web', 1, repeat('ab', 20), repeat('cd', 20), gen_random_uuid(), 1, 0,
			        $2, $3::jsonb, 'A reason.', 'm', 'pr-advisory-v1', sha256('input'), $4)`,
			tenantA, assessment, cited, value)
		return err
	}
	for _, c := range []struct {
		column, value, assessment, cited, constraint string
	}{
		{"result", "pass", "complies", "[]", "advisory_verdict_result"},
		{"result", "fail", "deviates", `[{"path":"a.go","start_line":1,"end_line":1}]`, "advisory_verdict_result"},
		{"result", "error", "unclear", "[]", "advisory_verdict_result"},
		{"mode", "block", "deviates", `[{"path":"a.go","start_line":1,"end_line":1}]`, "advisory_verdict_mode"},
		{"mode", "warn", "complies", "[]", "advisory_verdict_mode"},
		{"mode", "advise", "deviates", "[]", "advisory_verdict_cited"},
		{"mode", "advise", "fail", "[]", "advisory_verdict_assessment"},
	} {
		err := insert(c.column, c.value, c.assessment, c.cited)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != c.constraint {
			t.Errorf("%s %s with %s: %v, want %s", c.column, c.value, c.assessment, err, c.constraint)
		}
	}
	if err := insert("mode", "advise", "complies", "[]"); err != nil {
		t.Fatalf("the fixed values are refused: %v", err)
	}
}

func TestReuseAdvisoryCopiesOnlyTheSameInput(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	v := advisoryVerdict()
	if _, err := StoreAdvisory(ctx, s.app, tenantA, v); err != nil {
		t.Fatal(err)
	}
	next := v.AdvisoryCheck
	next.HeadSHA = strings.Repeat("ef", 20)
	newBase := strings.Repeat("12", 20)

	otherInput := sha256.Sum256([]byte("other input"))
	if reused, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, v.PromptVersion, otherInput, v.PromptSHA256); err != nil || reused {
		t.Fatalf("another input must not reuse: %v, %v", reused, err)
	}
	otherPrompt := sha256.Sum256([]byte("another prompt file"))
	if reused, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, v.PromptVersion, v.InputSHA256, otherPrompt[:]); err != nil || reused {
		t.Fatalf("another prompt file must not reuse: %v, %v", reused, err)
	}
	if reused, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, v.PromptVersion, v.InputSHA256, nil); err != nil || reused {
		t.Fatalf("a check with no prompt file must not reuse one with a prompt file: %v, %v", reused, err)
	}
	if reused, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, "pr-advisory-v2", v.InputSHA256, v.PromptSHA256); err != nil || reused {
		t.Fatalf("another prompt version must not reuse: %v, %v", reused, err)
	}
	if reused, err := ReuseAdvisory(ctx, s.app, tenantB, next, newBase, v.PromptVersion, v.InputSHA256, v.PromptSHA256); err != nil || reused {
		t.Fatalf("another tenant must not reuse: %v, %v", reused, err)
	}
	reused, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, v.PromptVersion, v.InputSHA256, v.PromptSHA256)
	if err != nil || !reused {
		t.Fatalf("the same input must reuse: %v, %v", reused, err)
	}
	var base, assessment, reason string
	if err := s.admin.QueryRowContext(ctx, `
		SELECT base_sha, assessment, reason FROM verification.advisory_verdict WHERE tenant_id = $1 AND head_sha = $2`,
		tenantA, next.HeadSHA).Scan(&base, &assessment, &reason); err != nil {
		t.Fatal(err)
	}
	if base != newBase || assessment != v.Assessment || reason != v.Reason {
		t.Fatalf("copied base %s, assessment %s, reason %q", base, assessment, reason)
	}
	if again, err := ReuseAdvisory(ctx, s.app, tenantA, next, newBase, v.PromptVersion, v.InputSHA256, v.PromptSHA256); err != nil || again {
		t.Fatalf("a second copy to the same head must insert nothing: %v, %v", again, err)
	}
}

func TestListAdvisoryFiltersPagesEnrichesAndIsolatesTenants(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	var scopeA uuid.UUID
	if err := s.admin.QueryRowContext(ctx, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'acme') RETURNING id`, tenantA).Scan(&scopeA); err != nil {
		t.Fatal(err)
	}
	insertDecision := func(id uuid.UUID, version int, body string) {
		t.Helper()
		if _, err := pgtest.Exec(ctx, s.app, tenantA.String(), `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1, $2, $3, $4::jsonb, ARRAY[$5::uuid], '[2026-01-01,)'::tstzrange)`,
			id, version, tenantA, body, scopeA); err != nil {
			t.Fatal(err)
		}
	}

	d1 := uuid.MustParse("0190c7b8-0000-7000-8000-0000000000d1")
	d2 := uuid.MustParse("0190c7b8-0000-7000-8000-0000000000d2")
	dSens := uuid.MustParse("0190c7b8-0000-7000-8000-0000000000d3")
	insertDecision(d1, 2, `{"title":"Keep PostgreSQL"}`)
	insertDecision(d2, 1, `{"title":"No raw SQL"}`)
	insertDecision(dSens, 1, `{"title":"Secret deal","sensitive":true}`)

	v1 := advisoryVerdict()
	v1.DecisionID = d1
	v1.DecisionVersion = 2
	v1.CheckIndex = 0
	if _, err := StoreAdvisory(ctx, s.app, tenantA, v1); err != nil {
		t.Fatal(err)
	}

	v2 := advisoryVerdict()
	v2.DecisionID = d2
	v2.DecisionVersion = 1
	v2.CheckIndex = 0
	v2.Assessment = Complies
	v2.Cited = nil
	v2.Reason = "Uses parameterized queries."
	if _, err := StoreAdvisory(ctx, s.app, tenantA, v2); err != nil {
		t.Fatal(err)
	}

	v3 := advisoryVerdict()
	v3.Repo = "acme/web"
	v3.RepositoryID = 43
	v3.PullNumber = 9
	v3.DecisionID = dSens
	v3.DecisionVersion = 1
	v3.CheckIndex = 0
	v3.Assessment = Unclear
	v3.Cited = nil
	v3.Reason = "Not enough context in diff."
	if _, err := StoreAdvisory(ctx, s.app, tenantA, v3); err != nil {
		t.Fatal(err)
	}

	// Tenant B row must never leak to Tenant A.
	vb := advisoryVerdict()
	vb.DecisionID = d1
	if _, err := StoreAdvisory(ctx, s.app, tenantB, vb); err != nil {
		t.Fatal(err)
	}

	// ListAdvisoryForHead returns deterministic decision/version/check order for PR 7 head.
	headItems, err := ListAdvisoryForHead(ctx, s.app, tenantA, v1.RepositoryID, v1.PullNumber, v1.HeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(headItems) != 2 || headItems[0].DecisionID != d1 || headItems[0].DecisionTitle != "Keep PostgreSQL" ||
		headItems[1].DecisionID != d2 || headItems[1].DecisionTitle != "No raw SQL" {
		t.Fatalf("head items = %+v", headItems)
	}
	if headItems[0].PullURL != "https://github.com/acme/payments/pull/7" || headItems[0].Mode != "advise" || headItems[0].Result != "advisory" {
		t.Fatalf("unexpected head item metadata: %+v", headItems[0])
	}

	// ListAdvisory returns newest first, omits sensitive title, and pages via before.
	page1, err := ListAdvisory(ctx, s.app, tenantA, AdvisoryFilter{}, 2, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || page1[0].DecisionID != dSens || page1[0].DecisionTitle != "" || page1[1].DecisionID != d2 {
		t.Fatalf("page1 = %+v", page1)
	}
	page2, err := ListAdvisory(ctx, s.app, tenantA, AdvisoryFilter{}, 2, page1[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 1 || page2[0].DecisionID != d1 || page2[0].DecisionTitle != "Keep PostgreSQL" {
		t.Fatalf("page2 = %+v", page2)
	}

	// Filters narrow by repo, decision, pull_number, and assessment.
	byRepo, err := ListAdvisory(ctx, s.app, tenantA, AdvisoryFilter{Repo: "ACME/Web", PullNumber: 9, Assessment: Unclear}, 10, uuid.Nil)
	if err != nil || len(byRepo) != 1 || byRepo[0].DecisionID != dSens {
		t.Fatalf("byRepo = %+v, %v", byRepo, err)
	}
	byDecision, err := ListAdvisory(ctx, s.app, tenantA, AdvisoryFilter{Decision: d1}, 10, uuid.Nil)
	if err != nil || len(byDecision) != 1 || byDecision[0].Assessment != Deviates {
		t.Fatalf("byDecision = %+v, %v", byDecision, err)
	}

	// Tenant B sees only its own row.
	bItems, err := ListAdvisory(ctx, s.app, tenantB, AdvisoryFilter{}, 10, uuid.Nil)
	if err != nil || len(bItems) != 1 || bItems[0].DecisionTitle != "" {
		t.Fatalf("tenantB = %+v, %v", bItems, err)
	}
}
