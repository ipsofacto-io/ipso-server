package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// mayCall is who may call each operation, by operationId, as ADR-0108 states it. It is written apart
// from the routes and the policy, so a change to either fails here until this says the same.
var mayCall = func() map[string][]string {
	every := identity.Roles
	auditors := []string{identity.RoleAuditor, identity.RoleAdmin}
	return map[string][]string{
		"resolve":              every,
		"list_decisions":       every,
		"get_decision":         every,
		"list_scopes":          every,
		"list_waivers":         every,
		"list_proposals":       every,
		"list_agent_proposals": every,
		"list_check_proposals": every,
		"audit_decisions":      auditors,
		"audit_beliefs":        auditors,
		"audit_merges":         auditors,
		"audit_supersessions":  auditors,
		"audit_waivers":        auditors,
		"list_verdicts":        every,

		// The writes of ADR-0109, by the roles that hold the action in policy.rego.
		"create_scope":              {identity.RoleDecisionOwner, identity.RoleAdmin},
		"reparent_scope":            {identity.RoleDecisionOwner, identity.RoleAdmin},
		"retire_scope":              {identity.RoleDecisionOwner, identity.RoleAdmin},
		"record_supersession":       {identity.RoleDecisionOwner},
		"record_grandfather_period": {identity.RoleDecisionOwner},
		"record_baseline":           {identity.RoleDecisionOwner},
		"record_waiver":             {identity.RoleApprover, identity.RoleDecisionOwner},
		"clear_premise_reason":      {identity.RoleDecisionOwner},
		"allow_premise_host":        {identity.RoleAdmin},
		"approve_proposal":          {identity.RoleApprover, identity.RoleDecisionOwner},
		"approve_agent_proposal":    {identity.RoleApprover, identity.RoleDecisionOwner},
	}
}()

// writeOps are the operations that change the registry, who a person takes them as (ADR-0109).
var writeOps = []string{
	"create_scope", "reparent_scope", "retire_scope", "record_supersession", "record_grandfather_period",
	"record_baseline", "record_waiver", "clear_premise_reason", "allow_premise_host", "approve_proposal",
	"approve_agent_proposal",
}

// the five audit routes of ADR-0055.
var auditOps = []string{"audit_decisions", "audit_beliefs", "audit_merges", "audit_supersessions", "audit_waivers"}

// reached is a stand-in for every route's handler, so a test sees whether the guard let a call through.
type reached struct{ calls int }

func (h *reached) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.calls++
	w.WriteHeader(http.StatusOK)
}

// principalAs is a principal of the kind its role needs, holding that role over the whole tenant, or
// a person with no role when role is empty.
func principalAs(role string) identity.Principal {
	p := identity.Principal{ID: someone, Kind: identity.KindHuman, Name: "Ada"}
	if role == identity.RoleAgent {
		p.Kind, p.Sponsor = identity.KindAgent, uuid.MustParse("00000000-0000-4000-8000-0000000000bb")
	}
	if role != "" {
		p.Grants = []identity.Grant{{Role: role}}
	}
	return p
}

// fakeStore stands in for what the guard reads of a scoped call: the scopes each decision names, and the chain
// of ancestors of each scope. A nil map means the permissive default, where every decision names scopeX and
// every scope sits directly under rootScope.
type fakeStore struct {
	decisions map[uuid.UUID][]uuid.UUID
	chains    map[uuid.UUID][]uuid.UUID
}

var (
	rootScope = uuid.MustParse("00000000-0000-4000-8000-0000000000a0")
	scopeX    = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
)

func (f fakeStore) decisionScopes(_ context.Context, _ uuid.UUID, decisions []uuid.UUID) ([]uuid.UUID, int, error) {
	var out []uuid.UUID
	missing := 0
	for _, d := range slices.Compact(slices.SortedFunc(slices.Values(decisions), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })) {
		if f.decisions == nil {
			out = append(out, scopeX)
			continue
		}
		scopes, ok := f.decisions[d]
		if !ok {
			missing++
		}
		out = append(out, scopes...)
	}
	return out, missing, nil
}

func (f fakeStore) chainsOf(_ context.Context, _ uuid.UUID, scopes []uuid.UUID) ([][]uuid.UUID, error) {
	out := make([][]uuid.UUID, 0, len(scopes))
	for _, s := range scopes {
		if f.chains == nil {
			out = append(out, []uuid.UUID{s, rootScope})
			continue
		}
		out = append(out, f.chains[s])
	}
	return out, nil
}

// guardedAs is the API with the real routes, their patterns, operations and actions, in front of a stand-in
// handler, and the principal read as p. extra mounts more handlers on the mux the way a careless change
// would, around the route table.
func guardedAs(t *testing.T, p identity.Principal, stand http.Handler, extra func(*http.ServeMux)) http.Handler {
	t.Helper()
	return guardedStore(t, p, stand, extra, fakeStore{})
}

// guardedStore is guardedAs with the store a scoped call reads.
func guardedStore(t *testing.T, p identity.Principal, stand http.Handler, extra func(*http.ServeMux), store fakeStore) http.Handler {
	t.Helper()
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g, _, err := newGuard(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	g.principals = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) { return p, nil }
	g.decisionScopes, g.chains = store.decisionScopes, store.chainsOf
	stubbed := routes(nil, time.Now, nil)
	for i := range stubbed {
		stubbed[i].handler = stand
	}
	mux, table := mount(stubbed, nil)
	if extra != nil {
		extra(mux)
	}
	return g.serve(mux, table)
}

// targetOf is a request target for a pattern's path.
func targetOf(path string) string {
	return strings.NewReplacer(
		"{ref}", "use-tls",
		"{decisionID}", "00000000-0000-7000-8000-000000000003",
		"{id}", "00000000-0000-7000-8000-000000000004",
		"{premiseID}", "tls-version",
	).Replace(path)
}

const (
	idDecisionA = "00000000-0000-7000-8000-000000000003"
	idDecisionB = "00000000-0000-7000-8000-000000000005"
	idScope     = "00000000-0000-4000-8000-0000000000a1"
	aDigest     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// bodyOf is a valid body for an operation that takes one, and the empty string for one that takes none.
func bodyOf(op string) string {
	switch op {
	case "create_scope":
		return `{"parent_id":"` + idScope + `","kind":"repo","selector":"acme/api"}`
	case "reparent_scope":
		return `{"parent_id":"` + idScope + `"}`
	case "record_supersession":
		return `{"from_decision":"` + idDecisionA + `","to_decision":"` + idDecisionB + `","effective_at":"2026-06-01T00:00:00Z"}`
	case "record_grandfather_period":
		return `{"valid_from":"2026-01-01T00:00:00Z"}`
	case "record_baseline":
		return `{"repo":"acme/api","fingerprints":["` + aDigest + `"]}`
	case "record_waiver":
		return `{"decision_id":"` + idDecisionA + `","scope_id":"` + idScope + `","reason":"synthetic","ticket_ref":"OPS-1","valid_from":"2026-05-01T00:00:00Z","expires_at":"2026-06-01T00:00:00Z"}`
	case "clear_premise_reason":
		return `{}`
	case "allow_premise_host":
		return `{"host":"example.com","allowed":true}`
	case "approve_proposal", "approve_agent_proposal":
		return `{"outcome":"approved","decision":{"body":{"slug":"use-tls","title":"Use TLS"},"scope_refs":["` + idScope + `"],"valid_from":"2026-01-01T00:00:00Z"}}`
	}
	return ""
}

// callBody is call with a JSON body.
func callBody(t *testing.T, handler http.Handler, method, target, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// refusedPlainly holds for a 403 whose body is the error code and nothing else.
func refusedPlainly(t *testing.T, w *httptest.ResponseRecorder) bool {
	t.Helper()
	if w.Code != http.StatusForbidden {
		return false
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("a refusal that is not JSON: %q", w.Body.String())
	}
	return len(body) == 1 && body["error"] == errForbidden
}

func TestTheMatrixNamesEveryOperation(t *testing.T) {
	for pattern, op := range operations(t, loadDocument(t)) {
		if op == "upload_verdicts" {
			continue
		}
		if _, ok := mayCall[op]; !ok {
			t.Errorf("%s (%s) has no row in the matrix", pattern, op)
		}
	}
	for _, op := range auditOps {
		if _, ok := mayCall[op]; !ok {
			t.Errorf("the audit route %s has no row", op)
		}
	}
}

// Every role, and a person with no role, on every operation of the document. A refusal is 403 with the
// error code alone, and the route does not run. An allowed call reaches the route, or, for an agent,
// the agent log after the policy, which this unreachable store refuses with 500.
func TestEveryRoleOnEveryOperation(t *testing.T) {
	for pattern, op := range operations(t, loadDocument(t)) {
		if op == "upload_verdicts" {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		for _, role := range append([]string{""}, identity.Roles...) {
			name := role
			if name == "" {
				name = "no role"
			}
			t.Run(op+"/"+name, func(t *testing.T) {
				stand := &reached{}
				handler := guardedAs(t, principalAs(role), stand, nil)
				w := callBody(t, handler, method, targetOf(path), "Bearer good", bodyOf(op))
				allowed := slices.Contains(mayCall[op], role)
				switch {
				case !allowed:
					if !refusedPlainly(t, w) || stand.calls != 0 {
						t.Fatalf("status %d, %d runs, body %s: want a plain 403 and no run", w.Code, stand.calls, w.Body)
					}
				case role == identity.RoleAgent:
					if w.Code != http.StatusInternalServerError || stand.calls != 0 {
						t.Fatalf("status %d, %d runs: want the agent log to be asked, and refuse", w.Code, stand.calls)
					}
				default:
					if w.Code != http.StatusOK || stand.calls != 1 {
						t.Fatalf("status %d, %d runs: want the route to run", w.Code, stand.calls)
					}
				}
			})
		}
	}
}

// The five audit routes of ADR-0055 answer 403 to every role but the auditor and the admin.
func TestTheFiveAuditRoutesRefuseARoleWithoutAuditRead(t *testing.T) {
	ops := operations(t, loadDocument(t))
	for _, role := range []string{"", identity.RoleViewer, identity.RoleContributor, identity.RoleDecisionOwner, identity.RoleApprover, identity.RoleAgent} {
		for pattern, op := range ops {
			if !slices.Contains(auditOps, op) {
				continue
			}
			method, path, _ := strings.Cut(pattern, " ")
			stand := &reached{}
			w := call(t, guardedAs(t, principalAs(role), stand, nil), method, targetOf(path), "Bearer good")
			if !refusedPlainly(t, w) || stand.calls != 0 {
				t.Errorf("%q on %s: status %d, %d runs", role, op, w.Code, stand.calls)
			}
		}
	}
}

// A handler put on the mux around the route table has no action, so no role reaches it, not even the
// admin. A caller with no token still learns nothing but 401.
func TestAHandlerMountedWithoutARouteIsRefused(t *testing.T) {
	stand, sneaky := &reached{}, &reached{}
	extra := func(mux *http.ServeMux) { mux.Handle("GET /v1/sneaky", sneaky) }
	handler := guardedAs(t, principalAs(identity.RoleAdmin), stand, extra)
	if w := call(t, handler, http.MethodGet, "/v1/sneaky", "Bearer good"); !refusedPlainly(t, w) || sneaky.calls != 0 {
		t.Fatalf("status %d, %d runs", w.Code, sneaky.calls)
	}
	if w := call(t, handler, http.MethodGet, "/v1/sneaky", ""); w.Code != http.StatusUnauthorized || sneaky.calls != 0 {
		t.Fatalf("without a token: status %d, %d runs", w.Code, sneaky.calls)
	}
	// The routes in the table still run.
	if w := call(t, handler, http.MethodGet, "/v1/scopes", "Bearer good"); w.Code != http.StatusOK || stand.calls != 1 {
		t.Fatalf("a mounted route: status %d, %d runs", w.Code, stand.calls)
	}
}

// A route that names no action, or one the policy does not know, runs for no one.
func TestARouteWithoutAKnownActionIsRefused(t *testing.T) {
	for _, action := range []authz.Action{"", "registry.write"} {
		db, err := sql.Open("pgx", unreachable)
		if err != nil {
			t.Fatal(err)
		}
		g, _, err := newGuard(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Policy: testPolicy(t)})
		if err != nil {
			t.Fatal(err)
		}
		g.principals = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
			return principalAs(identity.RoleAdmin), nil
		}
		stand := &reached{}
		mux, table := mount([]route{{"GET /v1/thing", "get_thing", action, nil, nil, stand}}, nil)
		if w := call(t, g.serve(mux, table), http.MethodGet, "/v1/thing", "Bearer good"); !refusedPlainly(t, w) || stand.calls != 0 {
			t.Errorf("action %q: status %d, %d runs", action, w.Code, stand.calls)
		}
		_ = db.Close()
	}
}

// Every route a person calls names an action the policy knows, and the CI route names none, because the
// CI identity and the installation mapping authorize it (ADR-0102).
func TestEveryRouteNamesAnActionThePolicyKnows(t *testing.T) {
	for _, rt := range routes(nil, time.Now, nil) {
		if !slices.Contains(authz.Actions, rt.action) {
			t.Errorf("%s names %q, which the policy does not know", rt.pattern, rt.action)
		}
	}
	for _, rt := range ciRoutes(nil, nil) {
		if rt.action != "" {
			t.Errorf("the CI route %s names %q", rt.pattern, rt.action)
		}
	}
}

// An unknown route is 404 to a principal who holds a role, and 403 to one who holds none, so a principal
// with no role cannot list the routes either.
func TestAnUnknownRouteIs404ToARoleAnd403ToNone(t *testing.T) {
	stand := &reached{}
	if w := call(t, guardedAs(t, principalAs(identity.RoleViewer), stand, nil), http.MethodGet, "/v1/nothing", "Bearer good"); w.Code != http.StatusNotFound {
		t.Errorf("a viewer: status %d", w.Code)
	}
	if w := call(t, guardedAs(t, principalAs(""), stand, nil), http.MethodGet, "/v1/nothing", "Bearer good"); !refusedPlainly(t, w) {
		t.Errorf("no role: status %d", w.Code)
	}
	if stand.calls != 0 {
		t.Error("a route ran")
	}
}

// A small tree: rootScope above org, org above repoA, repoB and repoC. Three decisions: one names repoA, one
// repoB, and one both.
var (
	orgScope   = uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	otherOrg   = uuid.MustParse("00000000-0000-4000-8000-0000000000b2")
	repoA      = uuid.MustParse("00000000-0000-4000-8000-0000000000c1")
	repoB      = uuid.MustParse("00000000-0000-4000-8000-0000000000c2")
	repoC      = uuid.MustParse("00000000-0000-4000-8000-0000000000c3")
	elsewhere  = uuid.MustParse("00000000-0000-4000-8000-0000000000c4")
	decOnA     = uuid.MustParse("00000000-0000-7000-8000-0000000000d1")
	decOnB     = uuid.MustParse("00000000-0000-7000-8000-0000000000d2")
	decOnBoth  = uuid.MustParse("00000000-0000-7000-8000-0000000000d3")
	decOnC     = uuid.MustParse("00000000-0000-7000-8000-0000000000d4")
	decMissing = uuid.MustParse("00000000-0000-7000-8000-0000000000d5")
)

func treeStore() fakeStore {
	return fakeStore{
		decisions: map[uuid.UUID][]uuid.UUID{
			decOnA:    {repoA},
			decOnB:    {repoB},
			decOnBoth: {repoA, repoB},
			decOnC:    {repoA, repoC},
		},
		chains: map[uuid.UUID][]uuid.UUID{
			orgScope:  {orgScope, rootScope},
			otherOrg:  {otherOrg, rootScope},
			repoA:     {repoA, orgScope, rootScope},
			repoB:     {repoB, orgScope, rootScope},
			repoC:     {repoC, orgScope, rootScope},
			elsewhere: {elsewhere, otherOrg, rootScope},
		},
	}
}

// holder is a person holding role, over the whole tenant or, when scope is set, at one scope and below.
func holder(role string, scope uuid.UUID) identity.Principal {
	p := principalAs(role)
	if scope != uuid.Nil {
		p.Grants = []identity.Grant{{Role: role, Scope: scope}}
	}
	return p
}

func supersede(from, to uuid.UUID) string {
	return `{"from_decision":"` + from.String() + `","to_decision":"` + to.String() + `","effective_at":"2026-06-01T00:00:00Z"}`
}

// A supersession names two decisions, and the binding has to cover every scope of both. A decision the tenant
// has no row for is covered by a binding over the whole tenant only, so a scoped principal cannot tell it from
// one outside its scope.
func TestASupersessionNeedsEveryScopeOfBothDecisionsCovered(t *testing.T) {
	for _, c := range []struct {
		name string
		who  identity.Principal
		body string
		want int
	}{
		{"the whole tenant, two decisions", holder(identity.RoleDecisionOwner, uuid.Nil), supersede(decOnA, decOnB), http.StatusOK},
		{"the org above both", holder(identity.RoleDecisionOwner, orgScope), supersede(decOnA, decOnB), http.StatusOK},
		{"one repo, a decision on it and one on another repo", holder(identity.RoleDecisionOwner, repoA), supersede(decOnA, decOnB), http.StatusForbidden},
		{"one repo, a decision on it and one on two repos", holder(identity.RoleDecisionOwner, repoA), supersede(decOnA, decOnBoth), http.StatusForbidden},
		{"one repo, two decisions that name only it", holder(identity.RoleDecisionOwner, repoA), supersede(decOnA, decOnA), http.StatusOK},
		{"another org", holder(identity.RoleDecisionOwner, otherOrg), supersede(decOnA, decOnB), http.StatusForbidden},
		{"a scoped owner, a decision the tenant does not have", holder(identity.RoleDecisionOwner, orgScope), supersede(decOnA, decMissing), http.StatusForbidden},
		{"the whole tenant, a decision the tenant does not have", holder(identity.RoleDecisionOwner, uuid.Nil), supersede(decOnA, decMissing), http.StatusOK},
		{"an approver, who does not supersede", holder(identity.RoleApprover, uuid.Nil), supersede(decOnA, decOnB), http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			stand := &reached{}
			w := callBody(t, guardedStore(t, c.who, stand, nil, treeStore()), http.MethodPost, "/v1/supersessions", "Bearer good", c.body)
			if w.Code != c.want || (c.want == http.StatusOK) != (stand.calls == 1) {
				t.Fatalf("status %d, %d runs, body %s: want %d", w.Code, stand.calls, w.Body, c.want)
			}
			if c.want == http.StatusForbidden && !refusedPlainly(t, w) {
				t.Fatalf("the refusal is not the plain 403: %s", w.Body)
			}
		})
	}
}

// Moving a node needs the binding to cover the node and the place it moves to, and retiring needs the node.
func TestScopeWritesNeedTheNodeAndTheParentCovered(t *testing.T) {
	move := func(id, parent uuid.UUID) (string, string) {
		return "/v1/scopes/" + id.String() + "/parent", `{"parent_id":"` + parent.String() + `"}`
	}
	for _, c := range []struct {
		name   string
		who    identity.Principal
		method string
		target string
		body   string
		want   int
	}{
		{"move inside the subtree", holder(identity.RoleDecisionOwner, orgScope), http.MethodPut, func() string { t, _ := move(repoA, repoB); return t }(), func() string { _, b := move(repoA, repoB); return b }(), http.StatusOK},
		{"move out of the subtree", holder(identity.RoleDecisionOwner, orgScope), http.MethodPut, func() string { t, _ := move(repoA, elsewhere); return t }(), func() string { _, b := move(repoA, elsewhere); return b }(), http.StatusForbidden},
		{"move into the subtree from outside", holder(identity.RoleDecisionOwner, orgScope), http.MethodPut, func() string { t, _ := move(elsewhere, repoA); return t }(), func() string { _, b := move(elsewhere, repoA); return b }(), http.StatusForbidden},
		{"retire inside", holder(identity.RoleDecisionOwner, orgScope), http.MethodDelete, "/v1/scopes/" + repoA.String(), "", http.StatusOK},
		{"retire outside", holder(identity.RoleDecisionOwner, orgScope), http.MethodDelete, "/v1/scopes/" + elsewhere.String(), "", http.StatusForbidden},
		{"retire a scope the tenant does not have, scoped", holder(identity.RoleDecisionOwner, orgScope), http.MethodDelete, "/v1/scopes/" + decMissing.String(), "", http.StatusForbidden},
		{"retire as a viewer", holder(identity.RoleViewer, uuid.Nil), http.MethodDelete, "/v1/scopes/" + repoA.String(), "", http.StatusForbidden},
		{"an admin retires", holder(identity.RoleAdmin, uuid.Nil), http.MethodDelete, "/v1/scopes/" + repoA.String(), "", http.StatusOK},
		{"create under a covered parent", holder(identity.RoleDecisionOwner, orgScope), http.MethodPost, "/v1/scopes", `{"parent_id":"` + repoA.String() + `","kind":"path","selector":"docs/**"}`, http.StatusOK},
		{"create under a parent outside", holder(identity.RoleDecisionOwner, orgScope), http.MethodPost, "/v1/scopes", `{"parent_id":"` + elsewhere.String() + `","kind":"path","selector":"docs/**"}`, http.StatusForbidden},
		{"create an org, scoped", holder(identity.RoleDecisionOwner, orgScope), http.MethodPost, "/v1/scopes", `{"kind":"org","selector":"acme"}`, http.StatusForbidden},
		{"create an org, whole tenant", holder(identity.RoleAdmin, uuid.Nil), http.MethodPost, "/v1/scopes", `{"kind":"org","selector":"acme"}`, http.StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			stand := &reached{}
			w := callBody(t, guardedStore(t, c.who, stand, nil, treeStore()), c.method, c.target, "Bearer good", c.body)
			if w.Code != c.want || (c.want == http.StatusOK) != (stand.calls == 1) {
				t.Fatalf("status %d, %d runs, body %s: want %d", w.Code, stand.calls, w.Body, c.want)
			}
		})
	}
}

// A rejection writes no decision and names no scope, so only a binding over the whole tenant covers it. An
// approval needs every scope of the decision the approver wrote.
func TestAnApprovalNeedsTheScopesOfItsDecisionAndARejectionTheWholeTenant(t *testing.T) {
	approve := func(refs ...uuid.UUID) string {
		quoted := make([]string, len(refs))
		for i, ref := range refs {
			quoted[i] = `"` + ref.String() + `"`
		}
		return `{"outcome":"approved","decision":{"body":{"slug":"a","title":"A"},"scope_refs":[` + strings.Join(quoted, ",") + `],"valid_from":"2026-01-01T00:00:00Z"}}`
	}
	for _, c := range []struct {
		name string
		who  identity.Principal
		body string
		want int
	}{
		{"approve inside the subtree", holder(identity.RoleApprover, orgScope), approve(repoA, repoB), http.StatusOK},
		{"approve a decision with one scope outside", holder(identity.RoleApprover, orgScope), approve(repoA, elsewhere), http.StatusForbidden},
		{"reject, scoped", holder(identity.RoleApprover, orgScope), `{"outcome":"rejected"}`, http.StatusForbidden},
		{"reject, whole tenant", holder(identity.RoleApprover, uuid.Nil), `{"outcome":"rejected"}`, http.StatusOK},
		{"reject, whole tenant owner", holder(identity.RoleDecisionOwner, uuid.Nil), `{"outcome":"rejected"}`, http.StatusOK},
		{"approve with no decision", holder(identity.RoleApprover, uuid.Nil), `{"outcome":"approved"}`, http.StatusBadRequest},
		{"approve with no scope", holder(identity.RoleApprover, uuid.Nil), approve(), http.StatusBadRequest},
		{"an outcome that is neither", holder(identity.RoleApprover, uuid.Nil), `{"outcome":"maybe"}`, http.StatusBadRequest},
		{"an approver in the body", holder(identity.RoleApprover, uuid.Nil), `{"outcome":"rejected","approver":"someone"}`, http.StatusBadRequest},
		{"a contributor", holder(identity.RoleContributor, uuid.Nil), `{"outcome":"rejected"}`, http.StatusForbidden},
	} {
		for _, target := range []string{"/v1/proposals/" + idScope + "/approval", "/v1/agent-proposals/" + idScope + "/approval"} {
			t.Run(c.name+" "+target, func(t *testing.T) {
				stand := &reached{}
				w := callBody(t, guardedStore(t, c.who, stand, nil, treeStore()), http.MethodPost, target, "Bearer good", c.body)
				if w.Code != c.want || (c.want == http.StatusOK) != (stand.calls == 1) {
					t.Fatalf("status %d, %d runs, body %s: want %d", w.Code, stand.calls, w.Body, c.want)
				}
			})
		}
	}
}

// A decision names up to 100 scopes and a supersession names two decisions, so a call can name more than the
// policy takes at once. It is asked in chunks and every chunk must cover, and a call that names more than a
// thousand is refused rather than judged in part.
func TestACallThatNamesManyScopesIsAskedInChunks(t *testing.T) {
	store := treeStore()
	mint := func(n int, under uuid.UUID) []uuid.UUID {
		out := make([]uuid.UUID, n)
		for i := range out {
			out[i] = uuid.MustParse("00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(strconv.Itoa(i+1))) + strconv.Itoa(i+1))
			store.chains[out[i]] = []uuid.UUID{out[i], under, rootScope}
		}
		return out
	}
	inside := mint(250, orgScope)
	store.decisions[decOnA] = inside[:125]
	store.decisions[decOnB] = inside[125:]
	owner := func(scope uuid.UUID) identity.Principal { return holder(identity.RoleDecisionOwner, scope) }

	run := func(who identity.Principal, s fakeStore) (int, int) {
		stand := &reached{}
		w := callBody(t, guardedStore(t, who, stand, nil, s), http.MethodPost, "/v1/supersessions", "Bearer good", supersede(decOnA, decOnB))
		return w.Code, stand.calls
	}
	if code, runs := run(owner(orgScope), store); code != http.StatusOK || runs != 1 {
		t.Errorf("250 scopes under the binding: status %d, %d runs", code, runs)
	}
	if code, runs := run(owner(uuid.Nil), store); code != http.StatusOK || runs != 1 {
		t.Errorf("250 scopes, whole tenant: status %d, %d runs", code, runs)
	}
	// One scope in the last chunk sits under another org.
	store.chains[inside[249]] = []uuid.UUID{inside[249], otherOrg, rootScope}
	if code, runs := run(owner(orgScope), store); code != http.StatusForbidden || runs != 0 {
		t.Errorf("one scope outside in the last chunk: status %d, %d runs", code, runs)
	}
	// More than a thousand is refused, even to a binding over the whole tenant.
	store.decisions[decOnA] = mint(maxCallTargets+1, orgScope)
	if code, runs := run(owner(uuid.Nil), store); code != http.StatusForbidden || runs != 0 {
		t.Errorf("%d scopes: status %d, %d runs", maxCallTargets+1, code, runs)
	}
}

// A scoped route that names no targets function runs for no one, a tenant-wide owner included.
func TestAScopedRouteWithNoTargetsIsRefused(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	g, _, err := newGuard(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Policy: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	g.principals = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
		return holder(identity.RoleDecisionOwner, uuid.Nil), nil
	}
	g.decisionScopes, g.chains = fakeStore{}.decisionScopes, fakeStore{}.chainsOf
	stand := &reached{}
	mux, table := mount([]route{{"POST /v1/thing", "thing", authz.ScopeWrite, nil, nil, stand}}, nil)
	if w := callBody(t, g.serve(mux, table), http.MethodPost, "/v1/thing", "Bearer good", `{}`); !refusedPlainly(t, w) || stand.calls != 0 {
		t.Fatalf("status %d, %d runs", w.Code, stand.calls)
	}
}

// failingBody is a body that records whether anything read it.
type failingBody struct{ read bool }

func (f *failingBody) Read([]byte) (int, error) { f.read = true; return 0, io.EOF }
func (f *failingBody) Close() error             { return nil }

// A principal who could not take the action anywhere is refused before the body is read, so a viewer or an
// agent learns nothing from a 400, a 413 or a 415, and the server spends nothing on its body.
func TestARoleThatCannotTakeAScopedActionIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	for _, who := range []identity.Principal{principalAs(""), principalAs(identity.RoleViewer), principalAs(identity.RoleAuditor), principalAs(identity.RoleAgent), holder(identity.RoleAdmin, uuid.Nil)} {
		for _, target := range []struct{ method, path string }{
			{http.MethodPost, "/v1/supersessions"},
			{http.MethodPost, "/v1/waivers"},
			{http.MethodPost, "/v1/proposals/" + idScope + "/approval"},
		} {
			body := &failingBody{}
			r := httptest.NewRequest(target.method, target.path, body)
			r.Header.Set("Authorization", "Bearer good")
			r.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()
			stand := &reached{}
			guardedAs(t, who, stand, nil).ServeHTTP(w, r)
			if !refusedPlainly(t, w) || stand.calls != 0 || body.read {
				t.Errorf("%v on %s: status %d, read %v, %d runs", who.Grants, target.path, w.Code, body.read, stand.calls)
			}
		}
	}
}

// A principal who may take the action meets the body checks of the guard: the content type, the cap, and a
// body the route can read. The handler never runs on a body that fails them.
func TestAScopedWriteRefusesABodyItCannotRead(t *testing.T) {
	owner := holder(identity.RoleDecisionOwner, uuid.Nil)
	good := bodyOf("record_waiver")
	for _, c := range []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{"no content type", "", good, http.StatusUnsupportedMediaType},
		{"text", "text/plain", good, http.StatusUnsupportedMediaType},
		{"not JSON", "application/json", `{`, http.StatusBadRequest},
		{"an unknown field", "application/json", strings.Replace(good, `"reason"`, `"approver":"x","reason"`, 1), http.StatusBadRequest},
		{"a tenant in the body", "application/json", strings.Replace(good, `"reason"`, `"tenant_id":"`+tenantA.String()+`","reason"`, 1), http.StatusBadRequest},
		{"data after the body", "application/json", good + good, http.StatusBadRequest},
		{"no scope", "application/json", `{"reason":"x"}`, http.StatusBadRequest},
		{"over the cap", "application/json", `{"reason":"` + strings.Repeat("a", 2<<20) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			stand := &reached{}
			r := httptest.NewRequest(http.MethodPost, "/v1/waivers", strings.NewReader(c.body))
			r.Header.Set("Authorization", "Bearer good")
			if c.contentType != "" {
				r.Header.Set("Content-Type", c.contentType)
			}
			w := httptest.NewRecorder()
			guardedStore(t, owner, stand, nil, treeStore()).ServeHTTP(w, r)
			if w.Code != c.want || stand.calls != 0 {
				t.Fatalf("status %d, %d runs, body %s: want %d", w.Code, stand.calls, w.Body, c.want)
			}
		})
	}
}

// The handler reads the bytes the targets were read from, so what the policy covers is what it writes.
func TestTheHandlerGetsTheBytesTheTargetsWereReadFrom(t *testing.T) {
	var got []byte
	stand := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	body := bodyOf("record_waiver")
	w := callBody(t, guardedStore(t, holder(identity.RoleApprover, uuid.Nil), stand, nil, treeStore()), http.MethodPost, "/v1/waivers", "Bearer good", body)
	if w.Code != http.StatusOK || string(got) != body {
		t.Fatalf("status %d, handler read %q", w.Code, got)
	}
	// An unscoped write reaches the handler with its body unread.
	w = callBody(t, guardedStore(t, holder(identity.RoleAdmin, uuid.Nil), stand, nil, treeStore()), http.MethodPost, "/v1/premise-hosts", "Bearer good", bodyOf("allow_premise_host"))
	if w.Code != http.StatusOK || string(got) != bodyOf("allow_premise_host") {
		t.Fatalf("status %d, handler read %q", w.Code, got)
	}
}

func TestPathParamsReadTheWildcardsOfAPattern(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          map[string]string
		ok            bool
	}{
		{"POST /v1/decisions/{decisionID}/premises/{premiseID}/clearance", "/v1/decisions/abc/premises/tls-version/clearance", map[string]string{"decisionID": "abc", "premiseID": "tls-version"}, true},
		{"DELETE /v1/scopes/{id}", "/v1/scopes/abc", map[string]string{"id": "abc"}, true},
		{"DELETE /v1/scopes/{id}", "/v1/scopes/a%2Fb", map[string]string{"id": "a/b"}, true},
		{"DELETE /v1/scopes/{id}", "/v1/scopes/", nil, false},
		{"DELETE /v1/scopes/{id}", "/v1/scopes/a/b", nil, false},
		{"DELETE /v1/scopes/{id}", "/v1/waivers/abc", nil, false},
		{"DELETE /v1/scopes/{id}", "/v1/scopes/%zz", nil, false},
		{"POST /v1/supersessions", "/v1/supersessions", map[string]string{}, true},
	} {
		got, ok := pathParams(c.pattern, c.path)
		if ok != c.ok || (ok && !maps.Equal(got, c.want)) {
			t.Errorf("%s on %s: %v %v, want %v %v", c.pattern, c.path, got, ok, c.want, c.ok)
		}
	}
}
