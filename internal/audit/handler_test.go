package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMissingTenant(t *testing.T) {
	h := Handler(nil, nil)
	rec := get(h, "/v1/audit/decisions?repo=acme/payments&valid=2026-03-01T00:00:00Z&known=2026-03-01T00:00:00Z")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertError(t, rec, "unauthorized")
	if strings.Contains(rec.Body.String(), "acme") {
		t.Fatalf("body echoes the query: %s", rec.Body)
	}
}

func TestTenantFromFalse(t *testing.T) {
	h := Handler(nil, func(*http.Request) (uuid.UUID, bool) { return uuid.Nil, false })
	rec := get(h, "/v1/audit/waivers?known=2026-03-01T00:00:00Z&now=2026-03-01T00:00:00Z")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	assertError(t, rec, "unauthorized")
}

func TestNilTenantIsUnauthorized(t *testing.T) {
	h := Handler(nil, func(*http.Request) (uuid.UUID, bool) {
		return uuid.Nil, true
	})
	rec := get(h, "/v1/audit/merges?repo=acme/payments&at=2026-03-01T00:00:00Z")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSmuggledTenantKey(t *testing.T) {
	called := false
	h := Handler(nil, func(*http.Request) (uuid.UUID, bool) {
		called = true
		return uuid.MustParse("00000000-0000-4000-8000-00000000000a"), true
	})
	for _, raw := range []string{
		"/v1/audit/decisions?tenant=00000000-0000-4000-8000-00000000000b",
		"/v1/audit/decisions?tenant_id=00000000-0000-4000-8000-00000000000b",
		"/v1/audit/decisions?Tenant=other",
		"/v1/audit/beliefs?TENANT_ID=",
	} {
		rec := get(h, raw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", raw, rec.Code)
		}
		assertError(t, rec, "invalid query")
		if strings.Contains(rec.Body.String(), "00000000-0000-4000-8000-00000000000b") {
			t.Fatalf("body echoes the tenant: %s", rec.Body)
		}
	}
	if called {
		t.Fatal("tenant function ran for a smuggled tenant key")
	}
}

func TestRejectedQueries(t *testing.T) {
	h := allowTenant()
	cases := []string{
		"/v1/audit/decisions",
		"/v1/audit/decisions?repo=acme/payments",
		"/v1/audit/decisions?repo=acme/payments&valid=yesterday&known=2026-03-01T00:00:00Z",
		"/v1/audit/decisions?repo=acme/payments&valid=2026-03-01T00:00:00&known=2026-03-01T00:00:00Z",
		"/v1/audit/decisions?repo=not%20a%20repo&valid=2026-03-01T00:00:00Z&known=2026-03-01T00:00:00Z",
		"/v1/audit/decisions?repo=acme/payments&repo=acme/other&valid=2026-03-01T00:00:00Z&known=2026-03-01T00:00:00Z",
		"/v1/audit/beliefs?repo=acme/payments&valid=2026-03-01T00:00:00Z&then=2026-03-01T00:00:00Z",
		"/v1/audit/supersessions/not-a-uuid?known=2026-03-01T00:00:00Z",
		"/v1/audit/supersessions/00000000-0000-0000-0000-000000000000?known=2026-03-01T00:00:00Z",
		"/v1/audit/waivers?known=2026-03-01T00:00:00Z",
	}
	for _, raw := range cases {
		rec := get(h, raw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body %s", raw, rec.Code, rec.Body)
		}
		assertError(t, rec, "invalid query")
	}
}

func TestMethodAndPath(t *testing.T) {
	h := allowTenant()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/decisions", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", rec.Code)
	}

	rec = get(h, "/v1/audit/other")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d", rec.Code)
	}
}

func allowTenant() http.Handler {
	return Handler(nil, func(*http.Request) (uuid.UUID, bool) {
		return uuid.MustParse("00000000-0000-4000-8000-00000000000a"), true
	})
}

func get(h http.Handler, raw string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, raw, nil))
	return rec
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body errorBody
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Error != want {
		t.Fatalf("error = %q, want %q", body.Error, want)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}
