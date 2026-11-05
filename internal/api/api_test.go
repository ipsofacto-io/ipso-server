package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

const documentPath = "../../api/openapi.yaml"

// unreachable is a store no test can reach, so a test that gets past the guard's own checks sees
// the store fail.
const unreachable = "postgres://nobody@127.0.0.1:1/none?connect_timeout=1&sslmode=disable"

func loadDocument(t *testing.T) libopenapi.Document {
	t.Helper()
	spec, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	document, err := libopenapi.NewDocument(spec)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// operations is every operation of the document as "METHOD path" to its operationId.
func operations(t *testing.T, document libopenapi.Document) map[string]string {
	t.Helper()
	model, err := document.BuildV3Model()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for path, item := range model.Model.Paths.PathItems.FromOldest() {
		for method, operation := range item.GetOperations().FromOldest() {
			out[strings.ToUpper(method)+" "+path] = operation.OperationId
		}
	}
	return out
}

func TestDocumentIsValidOpenAPI31(t *testing.T) {
	document := loadDocument(t)
	if version := document.GetVersion(); version != "3.1.0" {
		t.Fatalf("the document is OpenAPI %q, want 3.1.0", version)
	}
	v, errs := validator.NewValidator(document)
	if len(errs) > 0 {
		t.Fatalf("build the validator: %v", errs)
	}
	if ok, problems := v.ValidateDocument(); !ok {
		for _, problem := range problems {
			t.Errorf("%s: %s", problem.Message, problem.Reason)
		}
	}
}

// The document describes exactly the routes the API mounts, under the same operationIds, so a route
// cannot be added, dropped, or renamed without the contract.
func TestRoutesAreTheDocumentsOperations(t *testing.T) {
	want := operations(t, loadDocument(t))
	got := map[string]string{}
	for _, rt := range routes(nil, time.Now) {
		if _, seen := got[rt.pattern]; seen {
			t.Errorf("%s is mounted twice", rt.pattern)
		}
		got[rt.pattern] = rt.op
	}
	for pattern, op := range want {
		if got[pattern] != op {
			t.Errorf("%s: the document says %q, the API mounts %q", pattern, op, got[pattern])
		}
	}
	for pattern := range got {
		if _, ok := want[pattern]; !ok {
			t.Errorf("%s is mounted but not in the document", pattern)
		}
	}
}

// queryKeys is every operation of the document as "METHOD path" to the query keys it lists, sorted.
func queryKeys(t *testing.T, document libopenapi.Document) map[string][]string {
	t.Helper()
	model, err := document.BuildV3Model()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for path, item := range model.Model.Paths.PathItems.FromOldest() {
		for method, operation := range item.GetOperations().FromOldest() {
			var keys []string
			for _, parameter := range slices.Concat(item.Parameters, operation.Parameters) {
				if parameter.In == "query" {
					keys = append(keys, parameter.Name)
				}
			}
			slices.Sort(keys)
			out[strings.ToUpper(method)+" "+path] = keys
		}
	}
	return out
}

// Each route reads exactly the query keys the document lists for it, and the guard refuses any
// other, so a misspelt key is 400 and never a default. No route reads a tenant key.
func TestRoutesReadTheDocumentsQueryKeys(t *testing.T) {
	want := queryKeys(t, loadDocument(t))
	for _, rt := range routes(nil, time.Now) {
		got := slices.Sorted(slices.Values(rt.keys))
		if !slices.Equal(got, want[rt.pattern]) {
			t.Errorf("%s reads %v, the document lists %v", rt.pattern, got, want[rt.pattern])
		}
		for _, key := range rt.keys {
			if strings.EqualFold(key, "tenant") || strings.EqualFold(key, "tenant_id") {
				t.Errorf("%s reads the tenant key %q", rt.pattern, key)
			}
		}
	}
}

// Every operation reads. POST /v1/resolve is the one exception, and it reads too: a list of paths
// does not fit a URL. No endpoint writes before authorization (IPSO-66).
func TestEveryOperationIsAGetButResolve(t *testing.T) {
	for pattern := range operations(t, loadDocument(t)) {
		if !strings.HasPrefix(pattern, "GET ") && pattern != "POST /v1/resolve" {
			t.Errorf("%s is not a read", pattern)
		}
	}
}

type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, raw string) (authn.Claims, error) {
	if raw != "good" {
		return authn.Claims{}, errors.New("the token does not verify")
	}
	return authn.Claims{Subject: "agent-1"}, nil
}

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	someone = uuid.MustParse("00000000-0000-4000-8000-0000000000aa")
)

func callerOf(tenant uuid.UUID) CallerFunc {
	return func(context.Context, authn.Claims) (Caller, bool) {
		return Caller{Tenant: tenant, Principal: someone}, true
	}
}

func newAPI(t *testing.T, callers CallerFunc, limits Limits) http.Handler {
	t.Helper()
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler, err := New(Config{DB: db, Verifier: fakeVerifier{}, Callers: callers, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func call(t *testing.T, handler http.Handler, method, target, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q", got)
	}
	var body errorBody
	decoder := json.NewDecoder(w.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		t.Fatalf("the body is not an error: %v", err)
	}
	return body.Error
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for name, cfg := range map[string]Config{
		"no database": {Verifier: fakeVerifier{}, Callers: callerOf(tenantA)},
		"no verifier": {DB: db, Callers: callerOf(tenantA)},
		"no callers":  {DB: db, Verifier: fakeVerifier{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted it")
			}
		})
	}
}

// A caller who has proved nothing learns nothing: not which routes exist, not which methods they take.
func TestGuardRefusesACallerWithoutAGoodToken(t *testing.T) {
	handler := newAPI(t, callerOf(tenantA), Limits{})
	for _, tc := range []struct {
		name, method, target, authorization, challenge string
	}{
		{"no token", http.MethodGet, "/v1/decisions", "", `Bearer realm="ipso"`},
		{"another scheme", http.MethodGet, "/v1/decisions", "Basic Z29vZA==", `Bearer realm="ipso"`},
		{"a token in the query", http.MethodGet, "/v1/decisions?access_token=good", "", `Bearer realm="ipso"`},
		{"a bad token", http.MethodGet, "/v1/decisions", "Bearer bad", `Bearer realm="ipso", error="invalid_token"`},
		{"an unknown path", http.MethodGet, "/v1/nothing", "", `Bearer realm="ipso"`},
		{"an unknown method", http.MethodDelete, "/v1/decisions", "", `Bearer realm="ipso"`},
		{"outside v1", http.MethodGet, "/", "", `Bearer realm="ipso"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := call(t, handler, tc.method, tc.target, tc.authorization)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401", w.Code)
			}
			if got := w.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate is %q, want %q", got, tc.challenge)
			}
			if got := errorOf(t, w); got != errUnauthorized {
				t.Errorf("error %q", got)
			}
		})
	}
}

func TestGuardRefusesATokenThatSpeaksForNoOne(t *testing.T) {
	for name, callers := range map[string]CallerFunc{
		"no caller": func(context.Context, authn.Claims) (Caller, bool) { return Caller{}, false },
		"no tenant": func(context.Context, authn.Claims) (Caller, bool) {
			return Caller{Principal: someone}, true
		},
		"no principal": func(context.Context, authn.Claims) (Caller, bool) {
			return Caller{Tenant: tenantA}, true
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := call(t, newAPI(t, callers, Limits{}), http.MethodGet, "/v1/decisions", "Bearer good")
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", w.Code)
			}
			if got := errorOf(t, w); got != errForbidden {
				t.Errorf("error %q", got)
			}
		})
	}
}

// A query that names a tenant, repeats a key, names a key the route does not read, or does not
// parse is refused before the store is read, on every route.
func TestGuardRefusesAQueryNoRouteReads(t *testing.T) {
	handler := newAPI(t, callerOf(tenantA), Limits{})
	for _, target := range []string{
		"/v1/decisions?tenant=" + tenantB.String(),
		"/v1/proposals?TENANT_ID=" + tenantB.String(),
		"/v1/audit/waivers?known=2026-01-01T00:00:00Z&known=2027-01-01T00:00:00Z&now=2026-01-01T00:00:00Z",
		"/v1/check-proposals?limit=1&limit=2",
		"/v1/scopes?known=%zz",
		"/v1/proposals?limt=5",
		"/v1/audit/merges?repo=acme/api&at=2026-06-01T00:00:00Z&knwon=2026-01-01T00:00:00Z",
		"/v1/decisions?valid=2026-06-01T00:00:00Z&Known=2026-01-01T00:00:00Z",
		"POST /v1/resolve?known=2026-01-01T00:00:00Z",
	} {
		t.Run(target, func(t *testing.T) {
			method, path, found := strings.Cut(target, " ")
			if !found {
				method, path = http.MethodGet, target
			}
			w := call(t, handler, method, path, "Bearer good")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", w.Code)
			}
			if got := errorOf(t, w); got != errInvalidQuery {
				t.Errorf("error %q", got)
			}
		})
	}
}

// A store that cannot be read answers only "internal", never why.
func TestGuardHidesWhyTheStoreFailed(t *testing.T) {
	w := call(t, newAPI(t, callerOf(tenantA), Limits{}), http.MethodGet, "/v1/decisions", "Bearer good")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", w.Code)
	}
	if got := errorOf(t, w); got != errInternal {
		t.Errorf("error %q", got)
	}
}

func TestGuardLimitsEachTenantOnItsOwn(t *testing.T) {
	tenant := tenantA
	callers := func(context.Context, authn.Claims) (Caller, bool) {
		return Caller{Tenant: tenant, Principal: someone}, true
	}
	handler := newAPI(t, callers, Limits{Rate: rate.Every(time.Hour), Burst: 1})
	// The repeated key is refused after the limit is taken and before the store is read.
	const target = "/v1/decisions?limit=1&limit=2"
	if w := call(t, handler, http.MethodGet, target, "Bearer good"); w.Code != http.StatusBadRequest {
		t.Fatalf("first call: status %d, want 400", w.Code)
	}
	w := call(t, handler, http.MethodGet, target, "Bearer good")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second call: status %d, want 429", w.Code)
	}
	if got := errorOf(t, w); got != errRateLimited {
		t.Errorf("error %q", got)
	}
	retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || retry < 1 || retry > 3600 {
		t.Errorf("Retry-After is %q", w.Header().Get("Retry-After"))
	}
	tenant = tenantB
	if w := call(t, handler, http.MethodGet, target, "Bearer good"); w.Code != http.StatusBadRequest {
		t.Fatalf("another tenant: status %d, want 400", w.Code)
	}
}

func TestLimitsDefaults(t *testing.T) {
	got := Limits{}.WithDefaults()
	want := Limits{Timeout: 10 * time.Second, RequestBytes: 1 << 20, ResponseBytes: 4 << 20, Rate: 10, Burst: 20}
	if got != want {
		t.Fatalf("defaults %+v, want %+v", got, want)
	}
	set := Limits{Timeout: time.Second, RequestBytes: 1, ResponseBytes: 2, Rate: 3, Burst: 4}
	if got := set.WithDefaults(); got != set {
		t.Fatalf("a set limit changed: %+v", got)
	}
}

func slogDiscard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestBoundedPassesAnAnswerUnderTheCap(t *testing.T) {
	handler := bounded(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Route", "yes")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "12345")
	}), Limits{Timeout: time.Second, ResponseBytes: 5}, slogDiscard())
	w := call(t, handler, http.MethodGet, "/", "")
	if w.Code != http.StatusAccepted || w.Body.String() != "12345" || w.Header().Get("X-Route") != "yes" {
		t.Fatalf("status %d, body %q, headers %v", w.Code, w.Body.String(), w.Header())
	}
}

// An answer over the cap is refused whole. Nothing of it reaches the caller, so a cut-short audit
// answer cannot pass for a complete one.
func TestBoundedRefusesAnAnswerOverTheCap(t *testing.T) {
	handler := bounded(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Route", "yes")
		_, _ = io.WriteString(w, `{"decisions":[`)
		_, _ = io.WriteString(w, strings.Repeat("x", 64))
	}), Limits{Timeout: time.Second, ResponseBytes: 32}, slogDiscard())
	w := call(t, handler, http.MethodGet, "/", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "decisions") || w.Header().Get("X-Route") != "" {
		t.Fatalf("part of the answer was sent: %q, %v", w.Body.String(), w.Header())
	}
	if got := errorOf(t, w); got != errResponseTooLarge {
		t.Errorf("error %q", got)
	}
}

func TestBoundedEndsARequestPastItsDeadline(t *testing.T) {
	handler := bounded(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		_, _ = io.WriteString(w, "late")
	}), Limits{Timeout: 20 * time.Millisecond, ResponseBytes: 1 << 10}, slogDiscard())
	w := call(t, handler, http.MethodGet, "/", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
	if got := errorOf(t, w); got != errTimeout {
		t.Errorf("error %q", got)
	}
}

func TestLoggedSubjectIsOneBoundedLine(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/decisions/"+strings.Repeat("a", 400)+"?known=x", nil)
	got := loggedSubject(r)
	if n := len([]rune(got)); n != maxLoggedSubject {
		t.Fatalf("%d runes, want %d", n, maxLoggedSubject)
	}
	if !strings.HasPrefix(got, "/v1/decisions/aaa") {
		t.Fatalf("subject %q", got)
	}
	r = httptest.NewRequest(http.MethodGet, "/v1/scopes", nil)
	r.URL.RawQuery = "known=a\nb"
	if got := loggedSubject(r); got != "/v1/scopes?known=a b" {
		t.Fatalf("subject %q", got)
	}
}
