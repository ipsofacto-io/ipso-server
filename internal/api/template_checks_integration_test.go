//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso/pkg/templates"
)

const (
	edrTemplates = "01M5C5QEHHNXJ3D7X2ZCMGXQTA"
	edrMovedOn   = "01M5C5QEHHNXJ3D7X2ZCMGXQTB"
)

// A check the model drafted by choosing a built-in template waits in the review queue with its ref and no Rego,
// an agent cannot answer it, a person approves it, and the accepted read serves the ref and no Rego. A template
// check approved for a version that is no longer in force is held with no ref (ADR-0165).
func TestATemplateCheckWaitsForAPersonAndIsServedAsARef(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})

	decision := f.seedDecisionVersions(t, tenantA, f.org, "encrypted-volumes", edrTemplates, "[2026-01-01,)")
	moved := f.seedDecisionVersions(t, tenantA, f.org, "logging", edrMovedOn, "[2026-01-01,2026-03-01)", "[2026-03-01,)")
	propose := func(decision uuid.UUID, version int, ref string) {
		t.Helper()
		tmpl, ok := templates.Lookup(ref)
		if !ok {
			t.Fatalf("no template %s", ref)
		}
		check := proposals.TemplateCheck{DecisionID: decision, Version: version, Template: tmpl, Model: "test-model", PromptVersion: "check-template-v2"}
		if created, err := proposals.ProposeTemplateCheck(t.Context(), f.db, tenantA, check); err != nil || !created {
			t.Fatalf("propose %s: created %v err %v", ref, created, err)
		}
		if created, err := proposals.ProposeTemplateCheck(t.Context(), f.db, tenantA, check); err != nil || created {
			t.Fatalf("propose %s again: created %v err %v", ref, created, err)
		}
	}
	propose(decision, 1, "ipso:aws/ebs-encrypted")
	propose(decision, 1, "ipso:go/use-slog")
	propose(moved, 1, "ipso:go/use-slog")

	get := func(subject, target, key string) []any {
		t.Helper()
		w := c.exchange(t, handler, http.MethodGet, target, f.token(t, subject), "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
		}
		return list(answerOf(t, w), key)
	}
	byRef := map[string]map[string]any{}
	var drafted []uuid.UUID
	for _, raw := range get(personA, "/v1/check-proposals", "check_proposals") {
		item := raw.(map[string]any)
		ref, _ := item["ref"].(string)
		if ref == "" {
			continue
		}
		byRef[item["decision_id"].(string)+" "+ref] = item
		drafted = append(drafted, uuid.MustParse(item["id"].(string)))
	}
	if len(drafted) != 3 {
		t.Fatalf("the queue holds %d template checks, want 3: %v", len(drafted), byRef)
	}
	plan := byRef[decision.String()+" ipso:aws/ebs-encrypted"]
	slog := byRef[decision.String()+" ipso:go/use-slog"]
	if plan["engine"] != "opa" || plan["target"] != "terraform-plan" || plan["rego"] != nil || plan["status"] != "pending" {
		t.Fatalf("plan template %v", plan)
	}
	if slog["engine"] != "semgrep" || slog["target"] != nil || slog["rego"] != nil || len(slog["fixtures"].([]any)) != 0 {
		t.Fatalf("semgrep template %v", slog)
	}
	spec, _ := json.Marshal(slog["spec"])
	if string(spec) != `{"languages":["go"],"ref":"ipso:go/use-slog","title":"Go logging uses slog"}` {
		t.Fatalf("semgrep template spec %s", spec)
	}
	if items := get(personA, "/v1/accepted-checks?repo=acme%2Fapi", "accepted_checks"); len(intersect(idsOf(items), drafted)) != 0 {
		t.Fatalf("an unanswered template check is accepted: %v", items)
	}

	approve := func(subject string, item map[string]any, want int) {
		t.Helper()
		target := checkApprovalPath(uuid.MustParse(item["decision_id"].(string)), uuid.MustParse(item["id"].(string)))
		w := c.exchange(t, handler, http.MethodPost, target, f.token(t, subject), "application/json", []byte(`{"outcome":"approved"}`))
		if w.Code != want {
			t.Fatalf("%s answers %s: status %d %s, want %d", subject, target, w.Code, w.Body.String(), want)
		}
	}
	for _, item := range byRef {
		approve(agentA, item, http.StatusForbidden)
	}
	if left := get(personA, "/v1/check-proposals", "check_proposals"); len(intersect(idsOf(left), drafted)) != 3 {
		t.Fatal("an agent's answer took a template check out of the queue")
	}
	for _, item := range byRef {
		approve(approverA, item, http.StatusCreated)
	}
	if left := get(personA, "/v1/check-proposals", "check_proposals"); len(intersect(idsOf(left), drafted)) != 0 {
		t.Fatal("an approved template check is still in the queue")
	}

	accepted := map[string]map[string]any{}
	for _, raw := range get(agentA, "/v1/accepted-checks?repo=acme%2Fapi", "accepted_checks") {
		item := raw.(map[string]any)
		accepted[item["id"].(string)] = item
	}
	for key, want := range map[string]map[string]any{
		decision.String() + " ipso:aws/ebs-encrypted": {"decision_id": decision.String(), "edr_id": edrTemplates, "decision_version": 1.0, "version_in_force": 1.0, "engine": "opa", "target": "terraform-plan", "ref": "ipso:aws/ebs-encrypted", "rego": nil, "rego_sha256": nil},
		decision.String() + " ipso:go/use-slog":       {"decision_id": decision.String(), "edr_id": edrTemplates, "decision_version": 1.0, "version_in_force": 1.0, "engine": "semgrep", "target": nil, "ref": "ipso:go/use-slog", "rego": nil, "rego_sha256": nil},
		moved.String() + " ipso:go/use-slog":          {"decision_id": moved.String(), "edr_id": edrMovedOn, "decision_version": 1.0, "version_in_force": 2.0, "engine": "semgrep", "target": nil, "rego": nil, "rego_sha256": nil},
	} {
		item := accepted[byRef[key]["id"].(string)]
		delete(item, "id")
		if !mapsEqual(item, want) {
			t.Errorf("%s = %v, want %v", key, item, want)
		}
	}
}

func intersect(ids []string, drafted []uuid.UUID) []string {
	var out []string
	for _, id := range ids {
		if slices.Contains(drafted, uuid.MustParse(id)) {
			out = append(out, id)
		}
	}
	return out
}
