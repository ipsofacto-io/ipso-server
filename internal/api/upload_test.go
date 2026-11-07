package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

// fakeRuns accepts the token "ci-good" and no other, as a verifier for GitHub Actions tokens would.
type fakeRuns struct{}

func (fakeRuns) VerifyRun(_ context.Context, raw string) (authn.RunClaims, error) {
	if raw != "ci-good" {
		return authn.RunClaims{}, errors.New("the token does not verify")
	}
	return authn.RunClaims{Owner: "Acme", Name: "API", RepositoryID: 1, OwnerID: 2, RunID: 3, RunAttempt: 1}, nil
}

// uploadsOf answers every lookup with the mapping and status given and counts the lookups.
type uploadsOf struct {
	mapping Mapping
	status  MappingStatus
	lookups int
}

func (u *uploadsOf) uploads() *Uploads {
	return &Uploads{Verifier: fakeRuns{}, Lookup: func(context.Context, authn.RunClaims) (Mapping, MappingStatus) {
		u.lookups++
		return u.mapping, u.status
	}}
}

func newUploadAPI(t *testing.T, uploads *Uploads, sessions *Sessions, limits Limits) http.Handler {
	t.Helper()
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler, err := New(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Uploads: uploads, Sessions: sessions, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func upload(t *testing.T, handler http.Handler, target, authorization, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

const goodBody = `{"check":"plan","report":{"report_version":1,"ipso_version":"0.5.0","evaluated_at":"2026-11-07T10:00:00Z",` +
	`"env":"prod","build_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",` +
	`"plan_sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210","verdicts":[]}}`

func found() *uploadsOf {
	return &uploadsOf{mapping: Mapping{Tenant: tenantA, Installation: 42}, status: MappingFound}
}

func TestAnUploadNeedsAGitHubActionsToken(t *testing.T) {
	u := found()
	handler := newUploadAPI(t, u.uploads(), nil, Limits{})
	for _, tc := range []struct {
		name, authorization, challenge string
	}{
		{"no token", "", `Bearer realm="ipso"`},
		{"another scheme", "Basic Y2k6Z29vZA==", `Bearer realm="ipso"`},
		{"a person's token", "Bearer good", `Bearer realm="ipso", error="invalid_token"`},
		{"a bad token", "Bearer bad", `Bearer realm="ipso", error="invalid_token"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := upload(t, handler, "/v1/verdicts", tc.authorization, "application/json", goodBody)
			if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != tc.challenge || errorOf(t, w) != errUnauthorized {
				t.Fatalf("status %d, challenge %q", w.Code, w.Header().Get("WWW-Authenticate"))
			}
		})
	}
	if u.lookups != 0 {
		t.Errorf("%d tenants were looked up for callers who proved nothing", u.lookups)
	}
}

func TestACITokenOpensNoOtherRoute(t *testing.T) {
	handler := newUploadAPI(t, found().uploads(), nil, Limits{})
	for _, target := range []string{"/v1/verdicts", "/v1/decisions", "/v1/scopes", "/v1/nothing"} {
		w := call(t, handler, http.MethodGet, target, "Bearer ci-good")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with a CI token: status %d, want 401", target, w.Code)
		}
	}
}

// The upload reads no cookie. A browser that holds a session cannot be made to upload, and a session
// does not stand in for a CI token.
func TestAnUploadNeverReadsASessionCookie(t *testing.T) {
	looked := 0
	sessions := &Sessions{Origin: "https://ipso.example.test", Lookup: func(context.Context, []byte) (Caller, SessionStatus) {
		looked++
		return Caller{Tenant: tenantA, Principal: someone}, SessionFound
	}}
	u := found()
	handler := newUploadAPI(t, u.uploads(), sessions, Limits{})
	r := httptest.NewRequest(http.MethodPost, "/v1/verdicts", strings.NewReader(goodBody))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-ipso-session", Value: strings.Repeat("a", 43)})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || looked != 0 || u.lookups != 0 {
		t.Fatalf("status %d, %d session lookups, %d tenant lookups", w.Code, looked, u.lookups)
	}
}

func TestTheMappingDecidesWhoMayUpload(t *testing.T) {
	for name, tc := range map[string]struct {
		u          uploadsOf
		wantStatus int
		wantError  string
		retry      string
	}{
		"no installation of the tenant": {uploadsOf{status: MappingUnknown}, http.StatusForbidden, errForbidden, ""},
		"a busy mapping":                {uploadsOf{status: MappingBusy}, http.StatusTooManyRequests, errRateLimited, "1"},
		"a failed mapping":              {uploadsOf{status: MappingFailed}, http.StatusServiceUnavailable, errUnavailable, ""},
		"found with no tenant":          {uploadsOf{status: MappingFound, mapping: Mapping{Installation: 42}}, http.StatusForbidden, errForbidden, ""},
		"found with no installation":    {uploadsOf{status: MappingFound, mapping: Mapping{Tenant: tenantA}}, http.StatusForbidden, errForbidden, ""},
	} {
		t.Run(name, func(t *testing.T) {
			u := tc.u
			w := upload(t, newUploadAPI(t, u.uploads(), nil, Limits{}), "/v1/verdicts", "Bearer ci-good", "application/json", goodBody)
			if w.Code != tc.wantStatus || errorOf(t, w) != tc.wantError || w.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
			}
		})
	}
}

// The tenant's budget is spent after the mapping, and only by a run the tenant owns.
func TestUploadsSpendTheBudgetOfTheTenantTheyMapTo(t *testing.T) {
	u := found()
	handler := newUploadAPI(t, u.uploads(), nil, Limits{Rate: 0.001, Burst: 1})
	first := upload(t, handler, "/v1/verdicts", "Bearer ci-good", "application/json", goodBody)
	if first.Code == http.StatusTooManyRequests {
		t.Fatalf("the first upload was limited")
	}
	second := upload(t, handler, "/v1/verdicts", "Bearer ci-good", "application/json", goodBody)
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" || errorOf(t, second) != errRateLimited {
		t.Fatalf("second upload: status %d", second.Code)
	}
	// Another tenant has a bucket of its own, and a run that maps to no tenant spends none.
	u.mapping.Tenant = tenantB
	if third := upload(t, handler, "/v1/verdicts", "Bearer ci-good", "application/json", goodBody); third.Code == http.StatusTooManyRequests {
		t.Errorf("tenant B was limited by tenant A's uploads")
	}
	u.status = MappingUnknown
	for range 5 {
		if w := upload(t, handler, "/v1/verdicts", "Bearer ci-good", "application/json", goodBody); w.Code != http.StatusForbidden {
			t.Fatalf("an unmapped run: status %d, want 403", w.Code)
		}
	}
}

func TestAnUploadTakesNoQuery(t *testing.T) {
	for _, target := range []string{
		"/v1/verdicts?tenant_id=" + tenantB.String(),
		"/v1/verdicts?tenant=" + tenantB.String(),
		"/v1/verdicts?repo=acme/api",
		"/v1/verdicts?x=1",
		"/v1/verdicts?%zz",
	} {
		w := upload(t, newUploadAPI(t, found().uploads(), nil, Limits{}), target, "Bearer ci-good", "application/json", goodBody)
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("%s: status %d", target, w.Code)
		}
	}
}

// Everything the body can get wrong is refused before the store is asked, so none of these reach the
// unreachable database (which would answer 500).
func TestAnUploadIsRefusedBeforeAnythingIsStored(t *testing.T) {
	handler := newUploadAPI(t, found().uploads(), nil, Limits{})
	withTenant := strings.Replace(goodBody, `{"check":"plan",`, `{"tenant_id":"`+tenantB.String()+`","check":"plan",`, 1)
	for name, tc := range map[string]struct {
		contentType, body string
		status            int
		code              string
	}{
		"no content type":      {"", goodBody, http.StatusUnsupportedMediaType, errUnsupportedMedia},
		"text":                 {"text/plain", goodBody, http.StatusUnsupportedMediaType, errUnsupportedMedia},
		"a tenant in the body": {"application/json", withTenant, http.StatusBadRequest, errInvalidQuery},
		"not JSON":             {"application/json", "plan", http.StatusBadRequest, errInvalidQuery},
		"an empty body":        {"application/json", "", http.StatusBadRequest, errInvalidQuery},
		"a report of another check": {"application/json", strings.Replace(goodBody, `"check":"plan"`, `"check":"ci"`, 1),
			http.StatusBadRequest, errInvalidQuery},
		"over the cap": {"application/json", `{"check":"plan","report":"` + strings.Repeat("a", 2<<20) + `"}`, http.StatusRequestEntityTooLarge, errTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			w := upload(t, handler, "/v1/verdicts", "Bearer ci-good", tc.contentType, tc.body)
			if w.Code != tc.status || errorOf(t, w) != tc.code {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
}

// A good upload reaches the store, and a store that fails answers only "internal", never why.
func TestAGoodUploadReachesTheStore(t *testing.T) {
	w := upload(t, newUploadAPI(t, found().uploads(), nil, Limits{}), "/v1/verdicts", "Bearer ci-good", "application/json", goodBody)
	if w.Code != http.StatusInternalServerError || errorOf(t, w) != errInternal {
		t.Fatalf("status %d", w.Code)
	}
}

// Without uploads the route does not exist: a caller with no token gets 401 as on every route, and a CI
// token is not a person's token. A person's token reaches the unknown-route answer, 404, which the
// contract tests check against the store.
func TestWithoutUploadsTheRouteIsUnknown(t *testing.T) {
	handler := newAPI(t, callerOf(tenantA), Limits{})
	for _, authorization := range []string{"", "Bearer ci-good"} {
		if w := upload(t, handler, "/v1/verdicts", authorization, "application/json", goodBody); w.Code != http.StatusUnauthorized {
			t.Errorf("authorization %q: status %d, want 401", authorization, w.Code)
		}
	}
}

func TestNewRefusesUploadsItCannotRun(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	lookup := func(context.Context, authn.RunClaims) (Mapping, MappingStatus) { return Mapping{}, MappingUnknown }
	for name, uploads := range map[string]*Uploads{
		"no verifier": {Lookup: lookup},
		"no lookup":   {Verifier: fakeRuns{}},
	} {
		if _, err := New(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Uploads: uploads}); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

// The list reads a page and two filters, and refuses what does not parse before the store is asked.
func TestTheListRefusesAQueryItCannotReadBeforeTheStore(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	h := &verdictRoutes{db: db}
	list := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r = r.WithContext(context.WithValue(r.Context(), callerKey{}, Caller{Tenant: tenantA, Principal: someone}))
		w := httptest.NewRecorder()
		h.list(w, r)
		return w
	}
	for _, target := range []string{
		"/v1/verdicts?limit=0",
		"/v1/verdicts?limit=101",
		"/v1/verdicts?limit=x",
		"/v1/verdicts?before=not-a-uuid",
		"/v1/verdicts?before=00000000-0000-0000-0000-000000000000",
		"/v1/verdicts?repo=not%20a%20repo",
		"/v1/verdicts?repo=a/b/c",
		"/v1/verdicts?decision=Not%20A%20Slug",
	} {
		if w := list(target); w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("%s: status %d, want 400", target, w.Code)
		}
	}
	// A good query reaches the store, which fails here, and the answer does not say why.
	for _, target := range []string{"/v1/verdicts", "/v1/verdicts?repo=Acme/API&decision=use-tls&limit=5", "/v1/verdicts?decision=01M5QJ0V9EVXKR4C89XNBNT5GG"} {
		if w := list(target); w.Code != http.StatusInternalServerError || errorOf(t, w) != errInternal {
			t.Errorf("%s: status %d, want 500", target, w.Code)
		}
	}
	// Without a tenant in the context nothing is read.
	w := httptest.NewRecorder()
	h.list(w, httptest.NewRequest(http.MethodGet, "/v1/verdicts", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no caller: status %d, want 401", w.Code)
	}
}
