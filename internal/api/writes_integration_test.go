//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// scribe sends the writes of ADR-0109 through the real handler against PostgreSQL and checks each request and
// each answer against api/openapi.yaml.
type scribe struct {
	t *testing.T
	f *fixture
	c contract
	h http.Handler
}

func newScribe(t *testing.T) scribe {
	t.Helper()
	f := newFixture(t)
	return scribe{t: t, f: f, c: newContract(t), h: f.handler(t, Limits{Rate: 1000, Burst: 1000})}
}

// send sends a request the document allows, as the subject, and returns the status and the answer.
func (s scribe) send(subject, method, target string, body any) (int, map[string]any) {
	s.t.Helper()
	var payload []byte
	contentType := ""
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			s.t.Fatal(err)
		}
		contentType = "application/json"
	}
	w := s.c.exchange(s.t, s.h, method, target, s.f.token(s.t, subject), contentType, payload)
	var answer map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &answer)
	}
	return w.Code, answer
}

// expect sends a request and requires the status.
func (s scribe) expect(want int, subject, method, target string, body any) map[string]any {
	s.t.Helper()
	code, answer := s.send(subject, method, target, body)
	if code != want {
		s.t.Fatalf("%s %s as %s: status %d %v, want %d", method, target, subject, code, answer, want)
	}
	return answer
}

// raw sends a request as it is, even one the document would not allow, and does not check it.
func (s scribe) raw(subject, method, target, contentType, body string) *httptest.ResponseRecorder {
	s.t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Authorization", s.f.token(s.t, subject))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

func (s scribe) count(tenant uuid.UUID, query string, args ...any) int {
	s.t.Helper()
	var n int
	if err := pgtest.Scan(s.t.Context(), s.f.db, tenant.String(), query, append([]any{tenant}, args...), &n); err != nil {
		s.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (s scribe) logged() []identity.Action {
	s.t.Helper()
	actions, err := identity.Actions(s.t.Context(), s.f.db, tenantA, 500)
	if err != nil {
		s.t.Fatal(err)
	}
	return actions
}

func idOf(t *testing.T, answer map[string]any, key string) uuid.UUID {
	t.Helper()
	text, _ := answer[key].(string)
	id, err := uuid.Parse(text)
	if err != nil {
		t.Fatalf("%s in %v is not an id: %v", key, answer, err)
	}
	return id
}

const tlsPremise = `{"id":"tls-version","statement":"TLS 1.3 is the minimum","every":7,"probe":{"url":"https://status.example.com/tls.json","pointer":"/min","equals":"1.3"}}`

// approval is an approval with the decision the person wrote.
func approval(slug string, refs []uuid.UUID, premises ...string) map[string]any {
	body := map[string]any{"slug": slug, "title": "Title of " + slug}
	if len(premises) > 0 {
		raw := make([]json.RawMessage, len(premises))
		for i, p := range premises {
			raw[i] = json.RawMessage(p)
		}
		body["premises"] = raw
	}
	return map[string]any{
		"outcome":  "approved",
		"decision": map[string]any{"body": body, "scope_refs": refs, "valid_from": "2026-02-01T00:00:00Z"},
	}
}

// Every write is called as a person with the role, and each exchange matches the document. The chain builds on
// itself: a decision made by an approval is superseded, grandfathered, baselined, and its premise is cleared.
func TestEveryWriteMatchesTheDocumentAndIsLogged(t *testing.T) {
	s := newScribe(t)
	f := s.f
	scopes := func(parent uuid.UUID, kind, selector string) uuid.UUID {
		a := s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/scopes", map[string]any{"parent_id": parent, "kind": kind, "selector": selector})
		return idOf(t, a, "id")
	}
	service := scopes(f.org, "service", "billing")
	domain := scopes(f.org, "domain", "payments")
	moved := s.expect(http.StatusOK, ownerA, http.MethodPut, "/v1/scopes/"+service.String()+"/parent", map[string]any{"parent_id": domain})
	if moved["parent_id"] != domain.String() {
		t.Fatalf("the service is under %v, want %s", moved["parent_id"], domain)
	}
	s.expect(http.StatusNoContent, ownerA, http.MethodDelete, "/v1/scopes/"+service.String(), nil)
	if n := s.count(tenantA, `SELECT count(*) FROM registry.scope WHERE tenant_id = $1 AND id = $2`, service); n != 0 {
		t.Fatalf("the retired scope is still there")
	}

	approved := s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval",
		approval("use-mtls", []uuid.UUID{f.org}, tlsPremise))
	mtls := idOf(t, approved, "decision_id")
	if approved["outcome"] != "approved" || idOf(t, approved, "proposal_id") != f.proposal {
		t.Fatalf("the approval answered %v", approved)
	}

	s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/supersessions",
		map[string]any{"from_decision": f.api, "to_decision": mtls, "effective_at": "2026-03-01T00:00:00Z"})
	s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/decisions/"+mtls.String()+"/grandfather-period",
		map[string]any{"valid_from": "2026-03-01T00:00:00Z"})
	baseline := s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/decisions/"+mtls.String()+"/baselines",
		map[string]any{"repo": "acme/api", "fingerprints": []string{aDigest, strings.Repeat("b", 64)}})
	if baseline["fingerprint_count"] != float64(2) {
		t.Fatalf("the baseline answered %v", baseline)
	}
	waiver := s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/waivers", map[string]any{
		"decision_id": f.tls, "scope_id": f.repo, "reason": "the migration is under way", "ticket_ref": "OPS-9",
		"valid_from": "2026-06-01T00:00:00Z", "expires_at": "2026-07-01T00:00:00Z",
	})
	waiverID := idOf(t, waiver, "id")

	// A premise with no open reason cannot be cleared. The worker opens one with a failed evaluation.
	clearance := "/v1/decisions/" + mtls.String() + "/premises/tls-version/clearance"
	s.expect(http.StatusNotFound, ownerA, http.MethodPost, clearance, map[string]any{})
	opened, err := registry.RecordEvaluation(t.Context(), f.db, tenantA, registry.Evaluation{
		Ref: registry.PremiseRef{Decision: mtls, ID: "tls-version"}, Result: "fail",
		URL: "https://status.example.com/tls.json", Pointer: "/min", Expected: []byte(`"1.3"`), Observed: []byte(`"1.2"`),
		BodySHA256: bytes.Repeat([]byte{0xab}, 32),
	})
	if err != nil || !opened {
		t.Fatalf("open a review reason: %v, %v", opened, err)
	}
	before := len(s.logged())
	s.expect(http.StatusCreated, ownerA, http.MethodPost, clearance, map[string]any{})
	s.expect(http.StatusNotFound, ownerA, http.MethodPost, clearance, map[string]any{})

	host := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/premise-hosts", map[string]any{"host": "Status.Example.com", "allowed": true})
	if host["host"] != "status.example.com" {
		t.Fatalf("the host was stored as %v", host["host"])
	}
	agentApproved := s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/agent-proposals/"+f.agentProposal.String()+"/approval",
		approval("pin-api-versions", []uuid.UUID{f.repo}))
	if agentApproved["decision_id"] == nil {
		t.Fatalf("the agent proposal wrote no decision: %v", agentApproved)
	}

	// The waiver names the person who recorded it, taken from the session and not from the body.
	var approverID uuid.UUID
	var approverName string
	if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `SELECT approver_id, approver FROM registry.waiver WHERE id = $2 AND tenant_id = $1`,
		[]any{tenantA, waiverID}, &approverID, &approverName); err != nil {
		t.Fatal(err)
	}
	if approverID != f.callers[approverA].Principal || approverName != "Alma" {
		t.Fatalf("the waiver names %s %q", approverID, approverName)
	}
	// The approval and the decision are linked, and the decision exists once.
	var linked uuid.UUID
	if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `SELECT decision_id FROM proposals.approval WHERE tenant_id = $1 AND proposal_id = $2`,
		[]any{tenantA, f.proposal}, &linked); err != nil || linked != mtls {
		t.Fatalf("the approval names %s, want %s (%v)", linked, mtls, err)
	}
	if n := s.count(tenantA, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1 AND decision_id = $2`, mtls); n != 1 {
		t.Fatalf("the decision has %d versions", n)
	}

	// Each write left one entry naming the person who made it, and the failed attempt left none.
	byAction := map[string]identity.Action{}
	for _, a := range s.logged() {
		if _, dup := byAction[a.Action]; dup && a.Action != "api.create_scope" {
			t.Errorf("%s was logged twice", a.Action)
		}
		byAction[a.Action] = a
	}
	for _, op := range writeOps {
		entry, ok := byAction["api."+op]
		if !ok {
			t.Errorf("no log entry for %s", op)
			continue
		}
		if entry.PrincipalKind != identity.KindHuman || entry.Responsible != entry.Principal {
			t.Errorf("%s was logged for %+v", op, entry)
		}
	}
	if byAction["api.record_waiver"].Principal != f.callers[approverA].Principal || byAction["api.create_scope"].Principal != f.callers[ownerA].Principal ||
		byAction["api.allow_premise_host"].Principal != f.callers[personA].Principal {
		t.Errorf("the log names the wrong people: %+v", byAction)
	}
	if len(s.logged()) != before+3 {
		t.Errorf("%d entries after the clearance, host and agent approval, from %d", len(s.logged()), before)
	}
}

// A refusal of the role policy stores nothing and logs nothing: not for an agent, and not for a person whose
// role does not hold the action.
func TestAWriteTheRoleDoesNotAllowStoresAndLogsNothing(t *testing.T) {
	s := newScribe(t)
	f := s.f
	probe := func(op string) (method, target string, body map[string]any) {
		switch op {
		case "create_scope":
			return http.MethodPost, "/v1/scopes", map[string]any{"parent_id": f.org, "kind": "domain", "selector": "denied"}
		case "reparent_scope":
			return http.MethodPut, "/v1/scopes/" + f.docs.String() + "/parent", map[string]any{"parent_id": f.org}
		case "retire_scope":
			return http.MethodDelete, "/v1/scopes/" + f.prod.String(), nil
		case "record_supersession":
			return http.MethodPost, "/v1/supersessions", map[string]any{"from_decision": f.api, "to_decision": f.tls, "effective_at": "2026-03-01T00:00:00Z"}
		case "record_grandfather_period":
			return http.MethodPost, "/v1/decisions/" + f.tls.String() + "/grandfather-period", map[string]any{"valid_from": "2026-03-01T00:00:00Z"}
		case "record_baseline":
			return http.MethodPost, "/v1/decisions/" + f.tls.String() + "/baselines", map[string]any{"repo": "acme/api", "fingerprints": []string{aDigest}}
		case "record_waiver":
			return http.MethodPost, "/v1/waivers", map[string]any{"decision_id": f.tls, "scope_id": f.repo, "reason": "x", "ticket_ref": "OPS-2",
				"valid_from": "2026-06-01T00:00:00Z", "expires_at": "2026-07-01T00:00:00Z"}
		case "clear_premise_reason":
			return http.MethodPost, "/v1/decisions/" + f.tls.String() + "/premises/tls-version/clearance", map[string]any{}
		case "allow_premise_host":
			return http.MethodPost, "/v1/premise-hosts", map[string]any{"host": "denied.example.com", "allowed": true}
		case "approve_proposal":
			return http.MethodPost, "/v1/proposals/" + f.proposal.String() + "/approval", approval("denied", []uuid.UUID{f.org})
		default:
			return http.MethodPost, "/v1/agent-proposals/" + f.agentProposal.String() + "/approval", approval("denied", []uuid.UUID{f.org})
		}
	}
	tables := `(SELECT count(*) FROM registry.scope WHERE tenant_id = $1) + (SELECT count(*) FROM registry.supersession WHERE tenant_id = $1)
		+ (SELECT count(*) FROM registry.grandfather_period WHERE tenant_id = $1) + (SELECT count(*) FROM registry.baseline WHERE tenant_id = $1)
		+ (SELECT count(*) FROM registry.waiver WHERE tenant_id = $1) + (SELECT count(*) FROM registry.premise_host_allow WHERE tenant_id = $1)
		+ (SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1) + (SELECT count(*) FROM proposals.approval WHERE tenant_id = $1)
		+ (SELECT count(*) FROM proposals.agent_approval WHERE tenant_id = $1) + (SELECT count(*) FROM identity.action_log WHERE tenant_id = $1)`
	rows := s.count(tenantA, `SELECT `+tables)
	roleOf := map[string]string{agentA: identity.RoleAgent, viewerA: identity.RoleViewer, auditorA: identity.RoleAuditor, contributorA: identity.RoleContributor, nobodyA: ""}
	for subject, role := range roleOf {
		for _, op := range writeOps {
			if slices.Contains(mayCall[op], role) {
				t.Fatalf("the matrix lets %q %s", role, op)
			}
			method, target, body := probe(op)
			payload, _ := json.Marshal(body)
			if body == nil {
				payload = nil
			}
			w := s.raw(subject, method, target, "application/json", string(payload))
			if !refusedPlainly(t, w) {
				t.Errorf("%s as %s: %d %s, want a plain 403", op, subject, w.Code, w.Body)
			}
		}
	}
	if after := s.count(tenantA, `SELECT `+tables); after != rows {
		t.Fatalf("a refused write changed %d rows", after-rows)
	}
}

// An approval takes its approver from the session. A body that names an approver is a 400, and the decision
// is written once, with the approval, in one transaction.
func TestAnApprovalWritesItsDecisionOnceAndAFailureWritesNothing(t *testing.T) {
	s := newScribe(t)
	f := s.f
	target := "/v1/proposals/" + f.proposal.String() + "/approval"
	rows := func() int {
		return s.count(tenantA, `SELECT (SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1) + (SELECT count(*) FROM proposals.approval WHERE tenant_id = $1)
			+ (SELECT count(*) FROM identity.action_log WHERE tenant_id = $1)`)
	}
	start := rows()
	withApprover := approval("use-mtls", []uuid.UUID{f.org})
	withApprover["approver"] = "someone"
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"an approver in the body":          {mustJSON(t, withApprover), http.StatusBadRequest},
		"a rejection with a decision":      {`{"outcome":"rejected","decision":{"body":{"slug":"x","title":"X"},"scope_refs":["` + f.org.String() + `"],"valid_from":"2026-02-01T00:00:00Z"}}`, http.StatusBadRequest},
		"a slug that is not a slug":        {mustJSON(t, approval("Not A Slug", []uuid.UUID{f.org})), http.StatusBadRequest},
		"no title":                         {`{"outcome":"approved","decision":{"body":{"slug":"x"},"scope_refs":["` + f.org.String() + `"],"valid_from":"2026-02-01T00:00:00Z"}}`, http.StatusBadRequest},
		"a scope the tenant lacks":         {mustJSON(t, approval("x", []uuid.UUID{uuid.New()})), http.StatusBadRequest},
		"a premise the sweep cannot probe": {mustJSON(t, approval("x", []uuid.UUID{f.org}, `{"id":"Bad_Id","every":7}`)), http.StatusBadRequest},
		"too many premises":                {mustJSON(t, approval("x", []uuid.UUID{f.org}, slices.Repeat([]string{tlsPremise}, 21)...)), http.StatusBadRequest},
		"a body that is a list":            {`{"outcome":"approved","decision":{"body":[1],"scope_refs":["` + f.org.String() + `"],"valid_from":"2026-02-01T00:00:00Z"}}`, http.StatusBadRequest},
	} {
		if w := s.raw(approverA, http.MethodPost, target, "application/json", c.body); w.Code != c.want {
			t.Errorf("%s: status %d %s, want %d", name, w.Code, w.Body, c.want)
		}
	}
	if rows() != start {
		t.Fatalf("a refused approval stored %d rows", rows()-start)
	}

	// An unknown proposal is 404, and another tenant's proposal is the same.
	s.expect(http.StatusNotFound, approverA, http.MethodPost, "/v1/proposals/"+uuid.NewString()+"/approval", approval("x", []uuid.UUID{f.org}))
	if rows() != start {
		t.Fatalf("an approval of no proposal stored %d rows", rows()-start)
	}

	s.expect(http.StatusCreated, approverA, http.MethodPost, target, approval("use-mtls", []uuid.UUID{f.org}))
	afterFirst := rows()
	s.expect(http.StatusConflict, approverA, http.MethodPost, target, approval("use-mtls-again", []uuid.UUID{f.org}))
	s.expect(http.StatusConflict, ownerA, http.MethodPost, target, map[string]any{"outcome": "rejected"})
	if rows() != afterFirst {
		t.Fatalf("a second answer stored %d rows", rows()-afterFirst)
	}
	if n := s.count(tenantA, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1 AND body->>'slug' = 'use-mtls-again'`); n != 0 {
		t.Fatal("the second decision was stored")
	}

	// A rejection writes no decision and needs the role over the whole tenant.
	before := s.count(tenantA, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1`)
	rejected := s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/agent-proposals/"+f.agentProposal.String()+"/approval", map[string]any{"outcome": "rejected"})
	if rejected["decision_id"] != nil || rejected["outcome"] != "rejected" {
		t.Fatalf("the rejection answered %v", rejected)
	}
	if after := s.count(tenantA, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1`); after != before {
		t.Fatal("a rejection wrote a decision")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A request that is under the 1 MiB request cap can still hold a decision whose stored text form is over it:
// jsonb writes 1e2000 in full. The route refuses it with a client error and stores nothing, and never answers
// with the database error (ADR-0051, ADR-0092).
func TestADecisionBodyWhoseTextFormIsOverOneMiBIsRefused(t *testing.T) {
	s := newScribe(t)
	f := s.f
	body := `{"slug":"big","title":"Big","x":[` + strings.TrimSuffix(strings.Repeat("1e2000,", 600), ",") + `]}`
	request := `{"outcome":"approved","decision":{"body":` + body + `,"scope_refs":["` + f.org.String() + `"],"valid_from":"2026-02-01T00:00:00Z"}}`
	if len(request) >= 1<<20 {
		t.Fatalf("the request is %d bytes, which the request cap refuses before this check", len(request))
	}
	w := s.raw(approverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", "application/json", request)
	if w.Code != http.StatusRequestEntityTooLarge || errorOf(t, w) != errTooLarge {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "violates") || strings.Contains(w.Body.String(), "check") {
		t.Fatalf("the answer carries the database error: %s", w.Body)
	}
	if n := s.count(tenantA, `SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1 AND body->>'slug' = 'big'`); n != 0 {
		t.Fatal("the row was stored")
	}
	if n := s.count(tenantA, `SELECT count(*) FROM proposals.approval WHERE tenant_id = $1`); n != 0 {
		t.Fatal("the approval was stored")
	}
	if len(s.logged()) != 0 {
		t.Fatal("the refused write was logged")
	}
	// The same decision with a short body is fine.
	s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", approval("big", []uuid.UUID{f.org}))
}

// A scoped approver reaches only the decisions, waivers and approvals inside its scope, and a rejection and
// the supersession it does not hold are refused whole.
func TestAScopedApproverIsLimitedToItsScope(t *testing.T) {
	s := newScribe(t)
	f := s.f
	waiver := func(scope uuid.UUID) map[string]any {
		return map[string]any{"decision_id": f.api, "scope_id": scope, "reason": "x", "ticket_ref": "OPS-3",
			"valid_from": "2026-06-01T00:00:00Z", "expires_at": "2026-07-01T00:00:00Z"}
	}
	s.expect(http.StatusCreated, repoApproverA, http.MethodPost, "/v1/waivers", waiver(f.docs))
	s.expect(http.StatusForbidden, repoApproverA, http.MethodPost, "/v1/waivers", waiver(f.org))
	s.expect(http.StatusForbidden, repoApproverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", approval("wide", []uuid.UUID{f.org}))
	s.expect(http.StatusForbidden, repoApproverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", approval("mixed", []uuid.UUID{f.repo, f.org}))
	s.expect(http.StatusForbidden, repoApproverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", map[string]any{"outcome": "rejected"})
	s.expect(http.StatusForbidden, repoApproverA, http.MethodPost, "/v1/supersessions",
		map[string]any{"from_decision": f.api, "to_decision": f.tls, "effective_at": "2026-03-01T00:00:00Z"})
	if n := s.count(tenantA, `SELECT count(*) FROM proposals.approval WHERE tenant_id = $1`); n != 0 {
		t.Fatal("a refused approval was stored")
	}
	s.expect(http.StatusCreated, repoApproverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", approval("narrow", []uuid.UUID{f.repo, f.docs}))
	// A waiver is covered by its one scope (ADR-0108), and reads are tenant-wide, so a decision the tenant does
	// not have is a 404 to a scoped approver as to any other.
	s.expect(http.StatusNotFound, repoApproverA, http.MethodPost, "/v1/waivers", map[string]any{"decision_id": uuid.New(), "scope_id": f.docs, "reason": "x", "ticket_ref": "OPS-4",
		"valid_from": "2026-06-01T00:00:00Z", "expires_at": "2026-07-01T00:00:00Z"})
	s.expect(http.StatusNotFound, approverA, http.MethodPost, "/v1/waivers", map[string]any{"decision_id": uuid.New(), "scope_id": f.docs, "reason": "x", "ticket_ref": "OPS-4",
		"valid_from": "2026-06-01T00:00:00Z", "expires_at": "2026-07-01T00:00:00Z"})
}

// The tree refuses what would corrupt it, and the refusal is a 409 that says nothing about which rule.
func TestScopeWritesRefuseWhatWouldBreakTheTree(t *testing.T) {
	s := newScribe(t)
	f := s.f
	scope := "/v1/scopes/"
	// A scope with a child cannot be retired.
	s.expect(http.StatusConflict, ownerA, http.MethodDelete, scope+f.repo.String(), nil)
	// A move under the node's own descendant, and under a parent of a kind it cannot sit under.
	s.expect(http.StatusConflict, ownerA, http.MethodPut, scope+f.repo.String()+"/parent", map[string]any{"parent_id": f.docs})
	s.expect(http.StatusConflict, ownerA, http.MethodPut, scope+f.docs.String()+"/parent", map[string]any{"parent_id": f.prod})
	// A repo whose owner is not the org above its new parent.
	other := idOf(t, s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/scopes", map[string]any{"kind": "org", "selector": "initech"}), "id")
	s.expect(http.StatusConflict, ownerA, http.MethodPut, scope+f.repo.String()+"/parent", map[string]any{"parent_id": other})
	// An org has no parent, whether the move is under its own descendant or beside it.
	s.expect(http.StatusConflict, ownerA, http.MethodPut, scope+f.org.String()+"/parent", map[string]any{"parent_id": f.repo})
	if w := s.raw(ownerA, http.MethodPut, scope+other.String()+"/parent", "application/json", mustJSON(t, map[string]any{"parent_id": f.org})); w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
		t.Errorf("an org given a parent: status %d %s", w.Code, w.Body)
	}
	for _, c := range []map[string]any{
		{"parent_id": f.org, "kind": "org", "selector": "acme"},
		{"kind": "repo", "selector": "acme/api"},
		{"parent_id": f.org, "kind": "service", "selector": "Not A Name"},
		{"parent_id": f.org, "kind": "repo", "selector": "acme/**"},
		{"parent_id": f.org, "kind": "region", "selector": "eu"},
	} {
		if w := s.raw(ownerA, http.MethodPost, "/v1/scopes", "application/json", mustJSON(t, c)); w.Code != http.StatusBadRequest {
			t.Errorf("%v: status %d %s, want 400", c, w.Code, w.Body)
		}
	}
	// A parent the tenant does not have is 404, and a scope that a role binding names cannot be retired.
	s.expect(http.StatusNotFound, ownerA, http.MethodPost, "/v1/scopes", map[string]any{"parent_id": uuid.New(), "kind": "domain", "selector": "ghost"})
	leaf := idOf(t, s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/scopes", map[string]any{"parent_id": f.org, "kind": "service", "selector": "ledger"}), "id")
	approver := f.callers[approverA]
	f.exec(t, `INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id) VALUES ($1, $2, 'contributor', $3)`, tenantA, approver.Principal, leaf)
	s.expect(http.StatusConflict, ownerA, http.MethodDelete, scope+leaf.String(), nil)
	if _, err := pgtest.Exec(t.Context(), f.db, tenantA.String(), `DELETE FROM identity.role_binding WHERE scope_id = $1`, leaf); err != nil {
		t.Fatal(err)
	}
	s.expect(http.StatusNoContent, ownerA, http.MethodDelete, scope+leaf.String(), nil)
	s.expect(http.StatusNotFound, ownerA, http.MethodDelete, scope+leaf.String(), nil)
	// Another tenant's admin cannot touch this tenant's scope: it is not there for them.
	s.expect(http.StatusNotFound, personB, http.MethodDelete, scope+f.prod.String(), nil)
	if n := s.count(tenantA, `SELECT count(*) FROM registry.scope WHERE tenant_id = $1 AND id = $2`, f.prod); n != 1 {
		t.Fatal("another tenant retired the scope")
	}
}

// A supersession, a grandfather period and a baseline each refuse what the registry would refuse, as a 409,
// and a bad value as a 400. Nothing is logged for a write that did not happen.
func TestSupersessionPeriodAndBaselineRefuseWhatTheRegistryRefuses(t *testing.T) {
	s := newScribe(t)
	f := s.f
	post := func(want int, target string, body map[string]any) {
		t.Helper()
		s.expect(want, ownerA, http.MethodPost, target, body)
	}
	super := func(from, to uuid.UUID, at string) map[string]any {
		return map[string]any{"from_decision": from, "to_decision": to, "effective_at": at}
	}
	// A decision cannot replace itself, an unknown decision is 404, and an instant the decisions do not span is 409.
	if w := s.raw(ownerA, http.MethodPost, "/v1/supersessions", "application/json", mustJSON(t, super(f.api, f.api, "2026-03-01T00:00:00Z"))); w.Code != http.StatusBadRequest {
		t.Errorf("a decision that replaces itself: %d", w.Code)
	}
	post(http.StatusNotFound, "/v1/supersessions", super(f.api, uuid.New(), "2026-03-01T00:00:00Z"))
	post(http.StatusConflict, "/v1/supersessions", super(f.api, f.tls, "2025-06-01T00:00:00Z"))
	post(http.StatusCreated, "/v1/supersessions", super(f.api, f.tls, "2026-03-01T00:00:00Z"))
	post(http.StatusConflict, "/v1/supersessions", super(f.api, f.tls, "2026-03-01T00:00:00Z"))
	if n := s.count(tenantA, `SELECT count(*) FROM registry.supersession WHERE tenant_id = $1 AND from_decision = $2`, f.api); n != 1 {
		t.Fatalf("%d supersessions of the decision", n)
	}

	// A baseline waits for the grandfather period, and each is recorded once.
	baseline := "/v1/decisions/" + f.tls.String() + "/baselines"
	period := "/v1/decisions/" + f.tls.String() + "/grandfather-period"
	repo := map[string]any{"repo": "acme/api", "fingerprints": []string{aDigest}}
	post(http.StatusConflict, baseline, repo)
	post(http.StatusNotFound, "/v1/decisions/"+uuid.NewString()+"/grandfather-period", map[string]any{"valid_from": "2026-03-01T00:00:00Z"})
	if w := s.raw(ownerA, http.MethodPost, period, "application/json", `{"valid_from":"2026-03-01T00:00:00Z","valid_until":"2026-02-01T00:00:00Z"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a period that ends before it starts: %d", w.Code)
	}
	post(http.StatusCreated, period, map[string]any{"valid_from": "2026-03-01T00:00:00Z", "valid_until": "2026-09-01T00:00:00Z"})
	post(http.StatusConflict, period, map[string]any{"valid_from": "2026-04-01T00:00:00Z"})
	post(http.StatusCreated, baseline, repo)
	post(http.StatusConflict, baseline, repo)
	for name, body := range map[string]string{
		"an uppercase repo":    `{"repo":"Acme/Api","fingerprints":["` + aDigest + `"]}`,
		"a short fingerprint":  `{"repo":"acme/api","fingerprints":["abcd"]}`,
		"an uppercase digest":  `{"repo":"acme/api","fingerprints":["` + strings.ToUpper(aDigest) + `"]}`,
		"a repeated digest":    `{"repo":"acme/web","fingerprints":["` + aDigest + `","` + aDigest + `"]}`,
		"no fingerprint":       `{"repo":"acme/web","fingerprints":[]}`,
		"a missing repo field": `{"fingerprints":["` + aDigest + `"]}`,
	} {
		if w := s.raw(ownerA, http.MethodPost, baseline, "application/json", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d %s, want 400", name, w.Code, w.Body)
		}
	}
	if n := s.count(tenantA, `SELECT count(*) FROM registry.baseline WHERE tenant_id = $1`); n != 1 {
		t.Fatalf("%d baselines", n)
	}
	// Three successes were logged, and no refusal.
	if got := len(s.logged()); got != 3 {
		t.Fatalf("%d log entries, want 3", got)
	}
}

// A waiver refuses a period that is too long or outside the decision, and a reason or a ticket the table would
// refuse is a 400.
func TestAWaiverRefusesWhatTheTableRefuses(t *testing.T) {
	s := newScribe(t)
	f := s.f
	waiver := func(decision uuid.UUID, from, to string) map[string]any {
		return map[string]any{"decision_id": decision, "scope_id": f.repo, "reason": "synthetic", "ticket_ref": "OPS-5", "valid_from": from, "expires_at": to}
	}
	s.expect(http.StatusConflict, approverA, http.MethodPost, "/v1/waivers", waiver(f.old, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z"))
	for name, body := range map[string]string{
		"91 days":             mustJSON(t, waiver(f.tls, "2026-06-01T00:00:00Z", "2026-09-01T00:00:00Z")),
		"no length":           mustJSON(t, waiver(f.tls, "2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z")),
		"a space at the end":  strings.Replace(mustJSON(t, waiver(f.tls, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")), `"synthetic"`, `"synthetic "`, 1),
		"an approver":         strings.Replace(mustJSON(t, waiver(f.tls, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")), `"reason"`, `"approver":"x","reason"`, 1),
		"a control character": strings.Replace(mustJSON(t, waiver(f.tls, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")), `"OPS-5"`, `"OPS\u0007"`, 1),
	} {
		if w := s.raw(approverA, http.MethodPost, "/v1/waivers", "application/json", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d %s, want 400", name, w.Code, w.Body)
		}
	}
	s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/waivers", waiver(f.tls, "2026-06-01T00:00:00Z", "2026-08-30T00:00:00Z"))
	if n := s.count(tenantA, `SELECT count(*) FROM registry.waiver WHERE tenant_id = $1 AND ticket_ref = 'OPS-5'`); n != 1 {
		t.Fatalf("%d waivers", n)
	}
	// An approver who is an agent is refused by the policy and by the trigger. The trigger is the second guard.
	agent := f.callers[agentA]
	if _, err := pgtest.Exec(t.Context(), f.db, tenantA.String(), `
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'x', 'agent', $4, '[2026-06-01,2026-06-02)', 'OPS-6')`, tenantA, f.tls, f.repo, agent.Principal); err == nil {
		t.Fatal("the database let an agent approve a waiver")
	}
}

// The allowlist is append-only and the latest row for a host decides. A host is a DNS name, and an address or
// a name with characters outside ASCII is refused.
func TestThePremiseAllowlistTakesDNSNamesOnly(t *testing.T) {
	s := newScribe(t)
	allowed := func() bool {
		ok, err := registry.HostAllowed(t.Context(), s.f.db, tenantA, "status.example.com")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if allowed() {
		t.Fatal("an empty allowlist allowed a host")
	}
	s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/premise-hosts", map[string]any{"host": "status.example.com", "allowed": true})
	if !allowed() {
		t.Fatal("the host is not allowed")
	}
	s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/premise-hosts", map[string]any{"host": "status.example.com", "allowed": false})
	if allowed() {
		t.Fatal("the withdrawn host is allowed")
	}
	for _, host := range []string{"10.0.0.1", "localhost", "exämple.com", "a b.example.com", "-bad.example.com", "http://example.com", "example.com/path", ""} {
		if w := s.raw(personA, http.MethodPost, "/v1/premise-hosts", "application/json", mustJSON(t, map[string]any{"host": host, "allowed": true})); w.Code != http.StatusBadRequest {
			t.Errorf("host %q: status %d %s, want 400", host, w.Code, w.Body)
		}
	}
	if w := s.raw(personA, http.MethodPost, "/v1/premise-hosts", "application/json", `{"host":"example.com"}`); w.Code != http.StatusBadRequest {
		t.Errorf("no allowed field: %d", w.Code)
	}
	if n := s.count(tenantA, `SELECT count(*) FROM registry.premise_host_allow WHERE tenant_id = $1`); n != 2 {
		t.Fatalf("%d allowlist rows", n)
	}
}

// A session cookie that is sent from another site cannot write: the origin check of ADR-0099 covers every
// route that is not a safe method, with no wiring of its own.
func TestACookieWriteFromAnotherSiteIsRefused(t *testing.T) {
	f := newFixture(t)
	token, err := authn.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	sessions := &Sessions{
		Origin: "https://ipso.example.test",
		Lookup: func(_ context.Context, got []byte) (Caller, SessionStatus) {
			if !bytes.Equal(got, token) {
				return Caller{}, SessionUnknown
			}
			return f.callers[ownerA], SessionFound
		},
	}
	handler := f.handlerWith(t, Limits{Rate: 1000, Burst: 1000}, sessions)
	cookie := authn.NewSessionCookie(token, time.Now().Add(time.Hour), time.Now())
	send := func(site string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/scopes", strings.NewReader(fmt.Sprintf(`{"parent_id":"%s","kind":"domain","selector":"cookie-%s"}`, f.org, strings.ReplaceAll(site, "-", ""))))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, site := range []string{"cross-site", "same-site"} {
		if w := send(site); w.Code != http.StatusForbidden {
			t.Errorf("a %s write: status %d %s", site, w.Code, w.Body)
		}
	}
	rows := func() int {
		var n int
		if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `SELECT count(*) FROM registry.scope WHERE tenant_id = $1 AND selector LIKE 'cookie-%'`, []any{tenantA}, &n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rows() != 0 {
		t.Fatal("a refused cookie write was stored")
	}
	if w := send("same-origin"); w.Code != http.StatusCreated {
		t.Fatalf("a same-origin write: status %d %s", w.Code, w.Body)
	}
	if rows() != 1 {
		t.Fatal("the same-origin write was not stored")
	}
}

// A proposal that a person has answered leaves the review queues, whatever the answer was, so the inbox lists
// what still waits (ADR-0062, ADR-0076).
func TestADecidedProposalLeavesItsQueue(t *testing.T) {
	s := newScribe(t)
	f := s.f
	listed := func(queue, key string, id uuid.UUID) bool {
		_, answer := s.send(viewerA, http.MethodGet, "/v1/"+queue, nil)
		for _, item := range list(answer, key) {
			if item.(map[string]any)["id"] == id.String() {
				return true
			}
		}
		return false
	}
	if !listed("proposals", "proposals", f.proposal) || !listed("agent-proposals", "agent_proposals", f.agentProposal) {
		t.Fatal("a pending proposal is not in its queue")
	}
	s.expect(http.StatusCreated, approverA, http.MethodPost, "/v1/proposals/"+f.proposal.String()+"/approval", approval("queued", []uuid.UUID{f.org}))
	s.expect(http.StatusCreated, ownerA, http.MethodPost, "/v1/agent-proposals/"+f.agentProposal.String()+"/approval", map[string]any{"outcome": "rejected"})
	if listed("proposals", "proposals", f.proposal) || listed("agent-proposals", "agent_proposals", f.agentProposal) {
		t.Fatal("a decided proposal is still in its queue")
	}
}
