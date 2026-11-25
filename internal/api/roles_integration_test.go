//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

type operation struct {
	op, method, target string
	body               []byte
}

// operations is one valid call of every operation of the document but the upload, which is not a
// person's route (ADR-0102).
func (f *fixture) operations(t *testing.T) []operation {
	t.Helper()
	valid, known := at(f.valid), at(f.known)
	subject := "repo=acme%2Fapi&path=docs%2Fa.md&env=prod"
	resolve, err := json.Marshal(map[string]any{"repo": "acme/api", "env": "prod", "paths": []string{"docs/a.md"}, "valid": f.valid, "known": f.known})
	if err != nil {
		t.Fatal(err)
	}
	verifiability, err := json.Marshal(map[string]any{"title": "Require TLS 1.3", "statement": "All services must require TLS 1.3 on ingress"})
	if err != nil {
		t.Fatal(err)
	}
	llmEval, err := json.Marshal(map[string]any{"target": "diff", "rubric": "Must require TLS 1.3", "redacted_input": "MinVersion: tls.VersionTLS13"})
	if err != nil {
		t.Fatal(err)
	}
	return []operation{
		{"resolve", http.MethodPost, "/v1/resolve", resolve},
		{"analyze_verifiability", http.MethodPost, "/v1/verifiability", verifiability},
		{"evaluate_llm_check", http.MethodPost, "/v1/llm/evaluate", llmEval},
		{"list_decisions", http.MethodGet, "/v1/decisions?valid=" + valid + "&known=" + known, nil},
		{"list_decisions_health", http.MethodGet, "/v1/decisions/health?valid=" + valid + "&known=" + known, nil},
		{"get_decision", http.MethodGet, "/v1/decisions/use-tls?valid=" + valid + "&known=" + known, nil},
		{"get_decision_health", http.MethodGet, "/v1/decisions/use-tls/health?valid=" + valid + "&known=" + known, nil},
		{"list_scopes", http.MethodGet, "/v1/scopes?known=" + known, nil},
		{"list_waivers", http.MethodGet, "/v1/waivers?valid=" + valid + "&known=" + known, nil},
		{"list_premise_reasons", http.MethodGet, "/v1/premise-reasons", nil},
		{"list_premise_hosts", http.MethodGet, "/v1/premise-hosts", nil},
		{"list_proposals", http.MethodGet, "/v1/proposals", nil},
		{"list_agent_proposals", http.MethodGet, "/v1/agent-proposals", nil},
		{"list_human_proposals", http.MethodGet, "/v1/human-proposals", nil},
		{"list_check_proposals", http.MethodGet, "/v1/check-proposals", nil},
		{"list_accepted_checks", http.MethodGet, "/v1/accepted-checks?repo=acme%2Fapi", nil},
		{"get_llm_policy", http.MethodGet, "/v1/llm-policy", nil},
		{"list_freshness_policies", http.MethodGet, "/v1/freshness-policies", nil},
		{"list_agent_pins", http.MethodGet, "/v1/agent-pins", nil},
		{"audit_decisions", http.MethodGet, "/v1/audit/decisions?" + subject + "&valid=" + valid + "&known=" + known, nil},
		{"audit_beliefs", http.MethodGet, "/v1/audit/beliefs?" + subject + "&valid=" + valid + "&then=" + at(f.before) + "&now=" + known, nil},
		{"audit_merges", http.MethodGet, "/v1/audit/merges?" + subject + "&at=" + valid + "&known=" + known + "&sha=" + seededSHA, nil},
		{"audit_supersessions", http.MethodGet, "/v1/audit/supersessions/" + f.old.String() + "?known=" + known, nil},
		{"audit_waivers", http.MethodGet, "/v1/audit/waivers?known=" + known + "&now=" + valid, nil},
		{"read_audit_log", http.MethodGet, "/v1/audit-log?after=0", nil},
		{"list_verdicts", http.MethodGet, "/v1/verdicts?repo=acme%2Fapi&decision=use-tls", nil},
	}
}

// Against the store, a person with no role is refused every operation with the document's plain 403,
// a viewer is refused the audit routes and served the rest, and an auditor is served all of them.
func TestEveryOperationAsksTheRoleOfTheCaller(t *testing.T) {
	f := newFixture(t)
	f.enableLLM(t)
	c := newContract(t)
	// Five subjects make 26 calls each for one tenant, past the default burst of 20.
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	operations := f.operations(t)
	// The writes are called in writes_integration_test.go, each as every role.
	// The export routes are called in exports_integration_test.go, as every role.
	// The invitation routes are called in invitations_integration_test.go, as every role.
	// The role binding routes are called in role_bindings_integration_test.go, as every role.
	if len(operations)+len(writeOps)+len(exportOps)+len(invitationOps)+len(roleBindingOps) != len(mayCall) {
		t.Fatalf("%d operations here, %d writes, %d export reads, %d invitation reads and %d role binding reads, %d in the matrix", len(operations), len(writeOps), len(exportOps), len(invitationOps), len(roleBindingOps), len(mayCall))
	}
	contentType := func(o operation) string {
		if o.body != nil {
			return "application/json"
		}
		return ""
	}
	roleOf := map[string]string{
		nobodyA:      "",
		viewerA:      identity.RoleViewer,
		auditorA:     identity.RoleAuditor,
		contributorA: identity.RoleContributor,
		personA:      identity.RoleAdmin,
	}
	for _, o := range operations {
		for subject, role := range roleOf {
			served := slices.Contains(mayCall[o.op], role)
			w := c.exchange(t, handler, o.method, o.target, f.token(t, subject), contentType(o), o.body)
			switch {
			case served && w.Code != http.StatusOK:
				t.Errorf("%s as %s: %d %s", o.op, subject, w.Code, w.Body.String())
			case !served && !refusedPlainly(t, w):
				t.Errorf("%s as %s: %d %s, want a plain 403", o.op, subject, w.Code, w.Body.String())
			}
		}
	}
}

// A call the policy refuses never runs, so an agent's refused call writes no action log row (ADR-0090).
func TestARefusedAgentCallIsNotLogged(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{})
	for _, o := range f.operations(t) {
		if slices.Contains(mayCall[o.op], identity.RoleAgent) {
			continue
		}
		if w := call(t, handler, o.method, o.target, f.token(t, agentA)); !refusedPlainly(t, w) {
			t.Errorf("%s as the agent: %d %s", o.op, w.Code, w.Body.String())
		}
	}
	actions, err := identity.Actions(t.Context(), f.db, tenantA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("refused calls were logged: %+v", actions)
	}
}

// Roles are read on every request, so a binding removed or added takes effect on the next call.
func TestABindingChangeAppliesOnTheNextRequest(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{})
	viewer := f.callers[viewerA]
	scopes := "/v1/scopes?known=" + at(f.known)
	audit := "/v1/audit/waivers?known=" + at(f.known) + "&now=" + at(f.valid)
	if w := call(t, handler, http.MethodGet, audit, f.token(t, viewerA)); !refusedPlainly(t, w) {
		t.Fatalf("the viewer read the audit: %d", w.Code)
	}
	f.exec(t, `INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'auditor')`, viewer.Tenant, viewer.Principal)
	if w := call(t, handler, http.MethodGet, audit, f.token(t, viewerA)); w.Code != http.StatusOK {
		t.Fatalf("the new auditor: %d %s", w.Code, w.Body.String())
	}
	if _, err := pgtest.Exec(t.Context(), f.db, viewer.Tenant.String(), `DELETE FROM identity.role_binding WHERE principal_id = $1`, viewer.Principal); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{scopes, audit} {
		if w := call(t, handler, http.MethodGet, target, f.token(t, viewerA)); !refusedPlainly(t, w) {
			t.Errorf("%s after the revoke: %d %s", target, w.Code, w.Body.String())
		}
	}
}
