//go:build integration

package proposals

import (
	"slices"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso/pkg/templates"
)

// A drafted template check is stored once per decision version and template, for its tenant only, and waits in
// the review queue (ADR-0165).
func TestTemplateCheckWaitsInTheReviewQueue(t *testing.T) {
	db := newDB(t)
	llm := &schemaLLM{scriptedLLM: scriptedLLM{answers: []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":true}`}}}
	check, _, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest())
	if err != nil {
		t.Fatal(err)
	}
	if created, err := ProposeTemplateCheck(t.Context(), db, tenantA, check); err != nil || !created {
		t.Fatalf("created %v err %v", created, err)
	}
	if created, err := ProposeTemplateCheck(t.Context(), db, tenantA, check); err != nil || created {
		t.Fatalf("again: created %v err %v", created, err)
	}
	other, _ := templates.Lookup("ipso:go/use-slog")
	check.Template = other
	if created, err := ProposeTemplateCheck(t.Context(), db, tenantA, check); err != nil || !created {
		t.Fatalf("another template: created %v err %v", created, err)
	}
	if got := readChecks(t, db, tenantA, ""); len(got.CheckProposals) != 2 {
		t.Fatalf("queue %+v", got)
	}
	if other := readChecks(t, db, tenantB, ""); len(other.CheckProposals) != 0 {
		t.Fatalf("tenant B read %+v", other)
	}
}

func TestDatabaseCannotHoldABadTemplateCheck(t *testing.T) {
	db := newDB(t)
	ctx := t.Context()
	insert := func(engine string, target, ref, rego any, total int, repaired bool) error {
		_, err := pgtest.Exec(ctx, db, tenantA.String(), `
			INSERT INTO proposals.check_proposal
				(tenant_id, decision_id, decision_version, engine, target, ref, spec, rego, rego_sha256, fixtures,
				 fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
			VALUES ($1, $2, 1, $3, $4, $5, '{}', $6::text, sha256(convert_to($6::text, 'UTF8')),
				(SELECT coalesce(jsonb_agg('{}'::jsonb), '[]'::jsonb) FROM generate_series(1, $7::int)), $7, $7, $8, 'm', 'p')`,
			tenantA, testDecision, engine, target, ref, rego, total, repaired)
		return err
	}
	const rego = "package p\n"
	for _, tc := range []struct {
		name     string
		engine   string
		target   any
		ref      any
		rego     any
		total    int
		repaired bool
		constr   string
	}{
		{"a ref that is a path", "semgrep", nil, ".ipso/checks/x.yaml", nil, 0, false, "check_proposal_ref"},
		{"a ref with no prefix", "semgrep", nil, "go/use-slog", nil, 0, false, "check_proposal_ref"},
		{"a semgrep check with no ref", "semgrep", nil, nil, rego, 2, false, "check_proposal_fixtures_pass|check_proposal_target"},
		{"a semgrep template with a target", "semgrep", "diff", "ipso:go/use-slog", nil, 0, false, "check_proposal_target"},
		{"a plan template on agent edits", "opa", "agent-edit", "ipso:aws/ebs-encrypted", nil, 0, false, "check_proposal_target"},
		{"a plan template with no target", "opa", nil, "ipso:aws/ebs-encrypted", nil, 0, false, "check_proposal_target"},
		{"an llm template", "llm", "diff", "ipso:go/use-slog", nil, 0, false, "check_proposal_target"},
		{"a template with rego", "semgrep", nil, "ipso:go/use-slog", rego, 0, false, "check_proposal_rego"},
		{"a template with fixtures", "semgrep", nil, "ipso:go/use-slog", nil, 2, false, "check_proposal_fixtures_pass"},
		{"a repaired template", "semgrep", nil, "ipso:go/use-slog", nil, 0, true, "check_proposal_fixtures_pass"},
		{"a rego check with no rego", "opa", "agent-edit", nil, nil, 2, false, "check_proposal_rego"},
		{"a rego check with no target", "opa", nil, nil, rego, 2, false, "check_proposal_target"},
	} {
		err := insert(tc.engine, tc.target, tc.ref, tc.rego, tc.total, tc.repaired)
		if err == nil || !slices.ContainsFunc(strings.Split(tc.constr, "|"), func(c string) bool { return strings.Contains(err.Error(), `"`+c+`"`) }) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.constr)
		}
	}
	if err := insert("semgrep", nil, "ipso:go/use-slog", nil, 0, false); err != nil {
		t.Fatalf("valid semgrep template: %v", err)
	}
	if err := insert("opa", "terraform-plan", "ipso:aws/ebs-encrypted", nil, 0, false); err != nil {
		t.Fatalf("valid plan template: %v", err)
	}
	if err := insert("opa", "agent-edit", nil, rego, 2, false); err != nil {
		t.Fatalf("valid rego check: %v", err)
	}
	if err := insert("semgrep", nil, "ipso:go/use-slog", nil, 0, false); err == nil || !strings.Contains(err.Error(), "check_proposal_template_once") {
		t.Fatalf("the same template twice: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE proposals.check_proposal SET ref = 'ipso:go/no-panic'`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("update: %v", err)
	}
}
