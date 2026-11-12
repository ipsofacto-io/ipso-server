//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/config"
	verrors "github.com/pb33f/libopenapi-validator/errors"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// contract checks every request sent and every answer received against api/openapi.yaml, formats
// included.
type contract struct {
	validator validator.Validator
}

func newContract(t *testing.T) contract {
	t.Helper()
	v, errs := validator.NewValidator(loadDocument(t), config.WithFormatAssertions())
	if len(errs) > 0 {
		t.Fatalf("build the validator: %v", errs)
	}
	return contract{validator: v}
}

// exchange sends one request through handler, checks both sides against the document, and returns
// the answer. A request without a token fails the document's security, so only its answer is checked.
func (c contract) exchange(t *testing.T, handler http.Handler, method, target, authorization, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := func() *http.Request {
		r := httptest.NewRequest(method, target, bytes.NewReader(body))
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		return r
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request())
	var ok bool
	var problems []*verrors.ValidationError
	if authorization == "" {
		ok, problems = c.validator.ValidateHttpResponse(request(), w.Result())
	} else {
		ok, problems = c.validator.ValidateHttpRequestResponse(request(), w.Result())
	}
	if !ok {
		for _, problem := range problems {
			t.Errorf("%s %s (%d): %s: %s", method, target, w.Code, problem.Message, problem.Reason)
			for _, failure := range problem.SchemaValidationErrors {
				t.Errorf("  %s: %s", failure.FieldPath, failure.Reason)
			}
		}
	}
	return w
}

func answerOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var answer map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer is not a JSON object: %v", err)
	}
	return answer
}

func list(answer map[string]any, key string) []any {
	items, _ := answer[key].([]any)
	return items
}

func at(when time.Time) string { return url.QueryEscape(when.Format(time.RFC3339Nano)) }

// Every operation of the document is called as a person of tenant A, and both sides of every
// exchange match the document. Each answer holds the rows seeded for it, so the check covers real
// items and not only empty lists.
func TestEveryOperationMatchesTheDocument(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{})
	token := f.token(t, personA)
	valid, known := at(f.valid), at(f.known)
	subject := "repo=acme%2Fapi&path=docs%2Fa.md&env=prod"
	resolve, err := json.Marshal(map[string]any{
		"repo": "acme/api", "env": "prod", "paths": []string{"docs/a.md", "main.go"}, "valid": f.valid, "known": f.known,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op, method, target string
		body               []byte
		check              func(t *testing.T, answer map[string]any)
	}{
		{"resolve", http.MethodPost, "/v1/resolve", resolve, func(t *testing.T, a map[string]any) {
			resolutions := list(a, "resolutions")
			decisions := list(a, "decisions")
			if len(resolutions) != 2 || len(decisions) != 2 {
				t.Errorf("%v", a)
			}
			ids := map[string]bool{}
			for _, raw := range decisions {
				decision := raw.(map[string]any)
				id, _ := decision["id"].(string)
				if id == "" || ids[id] || decision["body"] == nil {
					t.Errorf("decision %v", decision)
				}
				ids[id] = true
			}
			for _, raw := range resolutions {
				resolution := raw.(map[string]any)
				if _, carried := resolution["decisions"]; carried {
					t.Errorf("a path carries decision bodies: %v", resolution)
				}
				named := list(resolution, "decision_ids")
				if len(named) != 2 {
					t.Errorf("path %v", resolution)
				}
				for _, id := range named {
					if !ids[id.(string)] {
						t.Errorf("path names %v, which is not in decisions", id)
					}
				}
			}
		}},
		{"list_decisions", http.MethodGet, "/v1/decisions?valid=" + valid + "&known=" + known + "&limit=10", nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "decisions")) != 2 {
				t.Errorf("%v", a)
			}
		}},
		{"get_decision", http.MethodGet, "/v1/decisions/use-tls?valid=" + valid + "&known=" + known, nil, func(t *testing.T, a map[string]any) {
			if d := list(a, "decisions"); len(d) != 1 || d[0].(map[string]any)["id"] != f.tls.String() {
				t.Errorf("%v", a)
			}
		}},
		{"list_scopes", http.MethodGet, "/v1/scopes?known=" + known, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "scopes")) != 4 {
				t.Errorf("%v", a)
			}
		}},
		{"list_waivers", http.MethodGet, "/v1/waivers?valid=" + valid + "&known=" + known, nil, func(t *testing.T, a map[string]any) {
			if w := list(a, "waivers"); len(w) != 1 || w[0].(map[string]any)["id"] != f.waiver.String() {
				t.Errorf("%v", a)
			}
		}},
		{"list_proposals", http.MethodGet, "/v1/proposals?limit=10", nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "proposals")) != 1 {
				t.Errorf("%v", a)
			}
		}},
		{"list_agent_proposals", http.MethodGet, "/v1/agent-proposals", nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "agent_proposals")) != 1 {
				t.Errorf("%v", a)
			}
		}},
		{"list_check_proposals", http.MethodGet, "/v1/check-proposals", nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "check_proposals")) != 1 {
				t.Errorf("%v", a)
			}
		}},
		{"audit_decisions", http.MethodGet, "/v1/audit/decisions?" + subject + "&valid=" + valid + "&known=" + known, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "decisions")) != 2 {
				t.Errorf("%v", a)
			}
		}},
		{"audit_beliefs", http.MethodGet, "/v1/audit/beliefs?" + subject + "&valid=" + valid + "&then=" + at(f.before) + "&now=" + known, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "added")) != 2 {
				t.Errorf("%v", a)
			}
		}},
		{"audit_merges", http.MethodGet, "/v1/audit/merges?" + subject + "&at=" + valid + "&known=" + known, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "decisions")) != 2 {
				t.Errorf("%v", a)
			}
		}},
		{"audit_supersessions", http.MethodGet, "/v1/audit/supersessions/" + f.old.String() + "?known=" + known, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "links")) != 1 || len(list(a, "versions")) != 2 {
				t.Errorf("%v", a)
			}
		}},
		{"audit_waivers", http.MethodGet, "/v1/audit/waivers?known=" + known + "&now=" + valid, nil, func(t *testing.T, a map[string]any) {
			if len(list(a, "waivers")) != 1 {
				t.Errorf("%v", a)
			}
		}},
		{"list_verdicts", http.MethodGet, "/v1/verdicts?repo=acme%2Fapi&decision=use-tls&limit=10", nil, func(t *testing.T, a map[string]any) {
			if v := list(a, "verdicts"); len(v) != 1 || v[0].(map[string]any)["upload_id"] != f.uploads[tenantA].String() {
				t.Errorf("%v", a)
			}
		}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			contentType := ""
			if tc.body != nil {
				contentType = "application/json"
			}
			w := c.exchange(t, handler, tc.method, tc.target, token, contentType, tc.body)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			tc.check(t, answerOf(t, w))
		})
	}
	if t.Failed() {
		return
	}
	t.Run("every operation is covered", func(t *testing.T) {
		// 14 are called above as a person, the writes in writes_integration_test.go, and the two reads of the export
		// in exports_integration_test.go. upload_verdicts is called as a CI job in upload_integration_test.go.
		if got, want := 14+len(writeOps)+len(exportOps)+1, len(operations(t, loadDocument(t))); got != want {
			t.Fatalf("%d operations covered, the document has %d", got, want)
		}
	})
}

// Every operation refuses a request without a token, and the refusal matches the document.
func TestEveryOperationRefusesARequestWithoutAToken(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{})
	for pattern := range operations(t, loadDocument(t)) {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.NewReplacer("{ref}", "use-tls", "{decisionID}", f.old.String(), "{id}", f.org.String(), "{premiseID}", "tls-version").Replace(path)
		t.Run(pattern, func(t *testing.T) {
			w := c.exchange(t, handler, method, path, "", "", nil)
			if w.Code != http.StatusUnauthorized || errorOf(t, w) != errUnauthorized {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// Tenant B reads only its own rows, and tenant A's ids answer the same as ids no one has.
func TestATenantReadsOnlyItsOwnRows(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{})
	token := f.token(t, personB)
	valid, known := at(f.valid), at(f.known)

	w := c.exchange(t, handler, http.MethodGet, "/v1/decisions?valid="+valid+"&known="+known, token, "", nil)
	if d := list(answerOf(t, w), "decisions"); len(d) != 1 || d[0].(map[string]any)["id"] != f.other.String() {
		t.Fatalf("tenant B decisions: %s", w.Body.String())
	}
	for _, target := range []string{
		"/v1/decisions/" + f.tls.String() + "?valid=" + valid + "&known=" + known,
		"/v1/decisions/" + uuid.NewString() + "?valid=" + valid + "&known=" + known,
	} {
		w := c.exchange(t, handler, http.MethodGet, target, token, "", nil)
		answer := answerOf(t, w)
		if w.Code != http.StatusOK || answer["decisions"] == nil || len(list(answer, "decisions")) != 0 || answer["valid"] != f.valid.Format(time.RFC3339Nano) {
			t.Fatalf("%s: %d %s", target, w.Code, w.Body.String())
		}
	}
	// Tenant B has a verdict of its own, and tenant A's is not in its list.
	w = c.exchange(t, handler, http.MethodGet, "/v1/verdicts", token, "", nil)
	if v := list(answerOf(t, w), "verdicts"); len(v) != 1 || v[0].(map[string]any)["upload_id"] != f.uploads[tenantB].String() {
		t.Fatalf("tenant B verdicts: %s", w.Body.String())
	}
	w = c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fapi", token, "", nil)
	if v := list(answerOf(t, w), "verdicts"); v == nil || len(v) != 0 {
		t.Fatalf("tenant B asked for tenant A's repository: %s", w.Body.String())
	}
	for _, tc := range []struct{ target, key string }{
		{"/v1/scopes?known=" + known, "scopes"},
		{"/v1/waivers?valid=" + valid + "&known=" + known, "waivers"},
		{"/v1/agent-proposals", "agent_proposals"},
	} {
		w := c.exchange(t, handler, http.MethodGet, tc.target, token, "", nil)
		for _, item := range list(answerOf(t, w), tc.key) {
			id := item.(map[string]any)["id"]
			if id == f.org.String() || id == f.repo.String() || id == f.waiver.String() {
				t.Fatalf("%s: tenant B read tenant A's %v", tc.target, id)
			}
		}
		if tc.key != "scopes" && len(list(answerOf(t, w), tc.key)) != 0 {
			t.Fatalf("%s: %s", tc.target, w.Body.String())
		}
	}
}

// A request that smuggles a tenant is refused, and the tenant of the token is the only one read.
func TestARequestCannotNameATenant(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{})
	token := f.token(t, personA)
	for _, target := range []string{
		"/v1/decisions?tenant=" + tenantB.String(),
		"/v1/audit/waivers?known=" + at(f.known) + "&now=" + at(f.known) + "&tenant_id=" + tenantB.String(),
		"/v1/proposals?Tenant=" + tenantB.String(),
		"/v1/verdicts?tenant_id=" + tenantB.String(),
	} {
		w := c.exchange(t, handler, http.MethodGet, target, token, "", nil)
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Fatalf("%s: %d %s", target, w.Code, w.Body.String())
		}
	}
	body := []byte(`{"repo":"acme/api","env":"prod","paths":["a"],"tenant_id":"` + tenantB.String() + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/resolve", bytes.NewReader(body))
	r.Header.Set("Authorization", token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
		t.Fatalf("a tenant in the body: %d %s", w.Code, w.Body.String())
	}
}

func TestResolveRefusesABodyItCannotRead(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{})
	token := f.token(t, personA)
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		code                    string
	}{
		{"no content type", "", `{"repo":"acme/api","env":"prod","paths":["a"]}`, http.StatusUnsupportedMediaType, errUnsupportedMedia},
		{"text", "text/plain", `{"repo":"acme/api","env":"prod","paths":["a"]}`, http.StatusUnsupportedMediaType, errUnsupportedMedia},
		{"an unknown field", "application/json", `{"repo":"acme/api","env":"prod","paths":["a"],"all":true}`, http.StatusBadRequest, errInvalidQuery},
		{"trailing data", "application/json", `{"repo":"acme/api","env":"prod","paths":["a"]} {}`, http.StatusBadRequest, errInvalidQuery},
		{"no env", "application/json", `{"repo":"acme/api","paths":["a"]}`, http.StatusBadRequest, errInvalidQuery},
		{"no paths", "application/json", `{"repo":"acme/api","env":"prod","paths":[]}`, http.StatusBadRequest, errInvalidQuery},
		{"over the cap", "application/json", `{"repo":"acme/api","env":"prod","paths":["` + strings.Repeat("a", 2<<20) + `"]}`, http.StatusRequestEntityTooLarge, errTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(tc.body))
			r.Header.Set("Authorization", token)
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || errorOf(t, w) != tc.code {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if ok, problems := c.validator.ValidateHttpResponse(httptest.NewRequest(http.MethodPost, "/v1/resolve", nil), w.Result()); !ok {
				t.Fatalf("the answer does not match the document: %v", problems[0].Message)
			}
		})
	}
}

// A token that maps to a principal the tenant does not have is refused, and an unknown route is
// 404 only once the caller is known.
func TestAnUnknownPrincipalAndAnUnknownRoute(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{})
	for _, tc := range []struct {
		subject, target string
		status          int
		code            string
	}{
		{ghost, "/v1/scopes", http.StatusForbidden, errForbidden},
		{"nobody", "/v1/scopes", http.StatusForbidden, errForbidden},
		{personA, "/v1/nothing", http.StatusNotFound, errNotFound},
		{personA, "/v2/scopes", http.StatusNotFound, errNotFound},
	} {
		w := call(t, handler, http.MethodGet, tc.target, f.token(t, tc.subject))
		if w.Code != tc.status || errorOf(t, w) != tc.code {
			t.Fatalf("%s %s: %d %s", tc.subject, tc.target, w.Code, w.Body.String())
		}
	}
	w := call(t, handler, http.MethodGet, "/v1/scopes", "Bearer "+f.auth.Token("https://another.example.test", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a token for another audience: %d", w.Code)
	}
}

// An agent's call is logged before it runs, and the log names the person who sponsors the agent. A
// person's call is not an agent action and is not logged here.
func TestAnAgentsCallIsLoggedWithItsSponsor(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{})
	if w := call(t, handler, http.MethodGet, "/v1/scopes?known="+at(f.known), f.token(t, agentA)); w.Code != http.StatusOK {
		t.Fatalf("agent: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, handler, http.MethodGet, "/v1/scopes", f.token(t, personA)); w.Code != http.StatusOK {
		t.Fatalf("person: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, handler, http.MethodGet, "/v1/nothing", f.token(t, agentA)); w.Code != http.StatusNotFound {
		t.Fatalf("agent on no route: %d", w.Code)
	}
	actions, err := identity.Actions(t.Context(), f.db, tenantA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("%d actions logged, want 1: %+v", len(actions), actions)
	}
	got := actions[0]
	if got.Action != "api.list_scopes" || got.Principal != f.callers[agentA].Principal || got.Responsible != f.callers[personA].Principal || got.Subject != "/v1/scopes?known="+at(f.known) {
		t.Fatalf("%+v", got)
	}
}

func TestLimitsHoldAgainstTheStore(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	known := at(f.known)

	capped := f.handler(t, Limits{ResponseBytes: 64})
	w := c.exchange(t, capped, http.MethodGet, "/v1/decisions?known="+known, f.token(t, personA), "", nil)
	if w.Code != http.StatusInternalServerError || errorOf(t, w) != errResponseTooLarge {
		t.Fatalf("over the response cap: %d %s", w.Code, w.Body.String())
	}

	limited := f.handler(t, Limits{Rate: rate.Every(time.Hour), Burst: 2})
	for i := range 2 {
		if w := c.exchange(t, limited, http.MethodGet, "/v1/scopes?known="+known, f.token(t, personA), "", nil); w.Code != http.StatusOK {
			t.Fatalf("call %d: %d", i, w.Code)
		}
	}
	w = c.exchange(t, limited, http.MethodGet, "/v1/scopes?known="+known, f.token(t, personA), "", nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("third call: %d %v", w.Code, w.Header())
	}
	if w := c.exchange(t, limited, http.MethodGet, "/v1/scopes?known="+known, f.token(t, personB), "", nil); w.Code != http.StatusOK {
		t.Fatalf("tenant B was limited by tenant A: %d", w.Code)
	}
}

// The session cookie is a second way to satisfy the document's security, so an exchange that carries
// only the cookie matches the document in both directions, and so does the 401 of a cookie that is no
// session.
func TestAnExchangeWithTheSessionCookieMatchesTheDocument(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
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
			return f.callers[personA], SessionFound
		},
	}
	handler := f.handlerWith(t, Limits{}, sessions)
	cookie := authn.NewSessionCookie(token, time.Now().Add(time.Hour), time.Now())
	unknown, err := authn.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	other := authn.NewSessionCookie(unknown, time.Now().Add(time.Hour), time.Now())

	for name, tc := range map[string]struct {
		cookie *http.Cookie
		want   int
	}{
		"a session":                   {cookie, http.StatusOK},
		"a cookie that is no session": {other, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/v1/decisions", nil)
				r.AddCookie(&http.Cookie{Name: tc.cookie.Name, Value: tc.cookie.Value})
				return r
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request())
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body)
			}
			if ok, problems := c.validator.ValidateHttpRequestResponse(request(), w.Result()); !ok {
				for _, problem := range problems {
					t.Errorf("%s: %s", problem.Message, problem.Reason)
				}
			}
		})
	}
}
