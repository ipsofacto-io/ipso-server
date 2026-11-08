package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
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
	}
}()

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

// guardedAs is the API with the real routes, their patterns, operations and actions, in front of a stand-in
// handler, and the principal read as p. extra mounts more handlers on the mux the way a careless change
// would, around the route table.
func guardedAs(t *testing.T, p identity.Principal, stand http.Handler, extra func(*http.ServeMux)) http.Handler {
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
	stubbed := routes(nil, time.Now)
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
	return strings.NewReplacer("{ref}", "use-tls", "{decisionID}", "00000000-0000-7000-8000-000000000003").Replace(path)
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
				w := call(t, handler, method, targetOf(path), "Bearer good")
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
		mux, table := mount([]route{{"GET /v1/thing", "get_thing", action, nil, stand}}, nil)
		if w := call(t, g.serve(mux, table), http.MethodGet, "/v1/thing", "Bearer good"); !refusedPlainly(t, w) || stand.calls != 0 {
			t.Errorf("action %q: status %d, %d runs", action, w.Code, stand.calls)
		}
		_ = db.Close()
	}
}

// Every route a person calls names an action the policy knows, and the CI route names none, because the
// CI identity and the installation mapping authorize it (ADR-0102).
func TestEveryRouteNamesAnActionThePolicyKnows(t *testing.T) {
	for _, rt := range routes(nil, time.Now) {
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
