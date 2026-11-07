//go:build integration

package controlplane

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const ciAudience = "https://ipso.example.test/ci"

var otherTenant = uuid.MustParse("00000000-0000-4000-8000-00000000000b")

// uploadStack is a stack whose control plane also takes verdict uploads from a stand-in for the GitHub
// Actions issuer, and asks a fake GitHub App which installation covers a repository.
type uploadStack struct {
	*stack
	ci     *authntest.Server
	github *fakeApp
	admin  *sql.DB
}

func newUploadStack(t *testing.T) *uploadStack {
	t.Helper()
	s := newStack(t)
	return &uploadStack{
		stack:  s,
		ci:     authntest.NewServer(t),
		github: &fakeApp{byRepo: map[string]integrations.Installation{"acme/api": {ID: 42, AccountID: 9}}},
		admin:  s.database.Open(t, pgtest.Admin),
	}
}

func (u *uploadStack) config() Config {
	cfg := u.stack.config(false)
	cfg.CIAudience, cfg.CIIssuer, cfg.Repositories = ciAudience, u.ci.Server.URL, u.github
	return cfg
}

// job is the token of a job in repo, whose repository has id repositoryID and whose owner has id ownerID.
func (u *uploadStack) job(repo string, repositoryID, ownerID int64) string {
	claims := map[string]any{
		"repository":          repo,
		"repository_id":       strconv.FormatInt(repositoryID, 10),
		"repository_owner_id": strconv.FormatInt(ownerID, 10),
		"run_id":              "5001",
		"run_attempt":         "1",
		"sha":                 strings.Repeat("ab", 20),
		"ref":                 "refs/heads/main",
		"event_name":          "push",
		"workflow_ref":        repo + "/.github/workflows/ci.yml@refs/heads/main",
	}
	var options []authntest.TokenOption
	for name, value := range claims {
		options = append(options, authntest.Claim(name, value))
	}
	return u.ci.Token(ciAudience, nil, options...)
}

func (u *uploadStack) uploads(t *testing.T, repo string) int {
	t.Helper()
	var n int
	if err := u.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload WHERE repo = $1`, repo).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func post(handler http.Handler, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"check": "plan",
		"report": map[string]any{
			"report_version": 1, "ipso_version": "0.5.0", "evaluated_at": "2026-11-07T10:00:00Z", "env": "prod",
			"build_sha256": strings.Repeat("ab", 32), "plan_sha256": strings.Repeat("cd", 32),
			"verdicts": []any{map[string]any{"decision_id": "01M5QJ0V9EVXKR4C89XNBNT5GG", "slug": "use-tls", "check_index": 0, "mode": "block", "result": "fail", "violations": 1}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/verdicts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func (u *uploadStack) bind(t *testing.T, owner uuid.UUID, installation int64) {
	t.Helper()
	if _, err := tenancy.BindInstallation(t.Context(), u.app, tenancy.BindOptions{Tenant: owner, Installation: installation}); err != nil {
		t.Fatal(err)
	}
}

// A run is stored for the tenant that owns the installation of its repository, and a person of that tenant
// reads it back.
func TestAnUploadIsStoredForTheTenantThatOwnsTheInstallation(t *testing.T) {
	u := newUploadStack(t)
	u.bind(t, tenant, 42)
	handler := u.handler(t, u.config())

	rec := post(handler, u.job("Acme/API", 77, 9))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if n := u.uploads(t, "acme/api"); n != 1 {
		t.Fatalf("%d uploads, want 1", n)
	}
	var installation int64
	if err := u.admin.QueryRowContext(t.Context(), `SELECT installation_id FROM verification.upload WHERE tenant_id = $1`, tenant).Scan(&installation); err != nil || installation != 42 {
		t.Errorf("installation %d, %v; want 42 under the tenant", installation, err)
	}
	if again := post(handler, u.job("Acme/API", 77, 9)); again.Code != http.StatusOK {
		t.Errorf("a repeat: status %d, want 200", again.Code)
	}
	if n := u.uploads(t, "acme/api"); n != 1 {
		t.Errorf("%d uploads after a repeat, want 1", n)
	}

	person := u.apiAuth.Token(apiAudience, nil, subject("person-1"))
	read := get(handler, "/v1/verdicts?repo=acme/api", person)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"run_url":"https://github.com/acme/api/actions/runs/5001"`) {
		t.Errorf("read: status %d: %s", read.Code, read.Body)
	}
	// The person's token opens no upload, and the job's token opens no read.
	if rec := post(handler, person); rec.Code != http.StatusUnauthorized {
		t.Errorf("a person's token on the upload: status %d, want 401", rec.Code)
	}
	if rec := get(handler, "/v1/verdicts", u.job("Acme/API", 77, 9)); rec.Code != http.StatusUnauthorized {
		t.Errorf("a job's token on the read: status %d, want 401", rec.Code)
	}
}

// Every way a run can fail to belong to this process's tenant is the same 403 and stores nothing.
func TestARunNoInstallationOfThisTenantOwnsIsRefused(t *testing.T) {
	u := newUploadStack(t)
	// Another tenant owns installation 43, and installation 44 is bound to nobody.
	if _, err := pgtest.Exec(t.Context(), u.app, otherTenant.String(), `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'other')`, otherTenant); err != nil {
		t.Fatal(err)
	}
	u.bind(t, otherTenant, 43)
	u.bind(t, tenant, 42)
	u.github.byRepo["acme/theirs"] = integrations.Installation{ID: 43, AccountID: 9}
	u.github.byRepo["acme/unbound"] = integrations.Installation{ID: 44, AccountID: 9}
	handler := u.handler(t, u.config())

	for name, tc := range map[string]struct {
		repo         string
		repositoryID int64
		ownerID      int64
	}{
		"an installation of another tenant":    {"acme/theirs", 78, 9},
		"an installation nobody bound":         {"acme/unbound", 79, 9},
		"an App that is not on the repository": {"acme/stranger", 80, 9},
		"an installation on another account":   {"acme/api", 81, 10},
	} {
		rec := post(handler, u.job(tc.repo, tc.repositoryID, tc.ownerID))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), otherTenant.String()) {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		if n := u.uploads(t, tc.repo); n != 0 {
			t.Errorf("%s: %d uploads stored", name, n)
		}
	}
	// The other tenant's rows are not written by a process that serves this one, either.
	var n int
	if err := u.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d uploads in the database, %v; want none", n, err)
	}
}

// GitHub answering badly is 503, and is not kept as an answer.
func TestAFailingGitHubIsUnavailableAndNothingIsStored(t *testing.T) {
	u := newUploadStack(t)
	u.bind(t, tenant, 42)
	handler := u.handler(t, u.config())
	u.github.err = errors.New("github: status 502")
	rec := post(handler, u.job("acme/api", 77, 9))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "unavailable") || strings.Contains(rec.Body.String(), "502") {
		t.Errorf("status %d: %s", rec.Code, rec.Body)
	}
	u.github.err = nil
	if rec := post(handler, u.job("acme/api", 77, 9)); rec.Code != http.StatusCreated {
		t.Errorf("after GitHub recovers: status %d, want 201", rec.Code)
	}
}

// The tenant of an installation is read from the database on every upload, so removing the binding stops
// the next upload even while the GitHub answer is still kept.
func TestRemovingTheBindingStopsTheNextUpload(t *testing.T) {
	u := newUploadStack(t)
	u.bind(t, tenant, 42)
	handler := u.handler(t, u.config())
	if rec := post(handler, u.job("acme/api", 77, 9)); rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if _, err := u.admin.ExecContext(t.Context(), `DELETE FROM tenancy.installation`); err != nil {
		t.Fatal(err)
	}
	callsBefore := u.github.calls
	if rec := post(handler, u.job("acme/api", 77, 9)); rec.Code != http.StatusForbidden {
		t.Errorf("after the binding was removed: status %d, want 403", rec.Code)
	}
	if u.github.calls != callsBefore {
		t.Errorf("GitHub was called %d more times, want 0: the installation was kept", u.github.calls-callsBefore)
	}
}

func TestStartRefusesUploadsItCannotServe(t *testing.T) {
	u := newUploadStack(t)
	u.github.verifyErr = errors.New("the app permissions are not the set in section 3.1")
	if _, err := New(t.Context(), u.config()); err == nil || !strings.Contains(err.Error(), "GitHub App") {
		t.Errorf("an App that fails its check: %v", err)
	}
	u.github.verifyErr = nil
	cfg := u.config()
	cfg.CIIssuer = "http://plain.example.test"
	if _, err := New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "CI authorization server") {
		t.Errorf("an issuer over http: %v", err)
	}
	// Without the settings the route does not exist.
	handler := u.handler(t, u.stack.config(false))
	if rec := post(handler, u.job("acme/api", 77, 9)); rec.Code != http.StatusUnauthorized {
		t.Errorf("uploads off: status %d, want 401", rec.Code)
	}
}
