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
