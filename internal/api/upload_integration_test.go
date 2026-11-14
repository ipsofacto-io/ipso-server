//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

const ciAudience = "https://ipso.example.test/ci"

const (
	decisionTLS  = "01M5QJ0V9EVXKR4C89XNBNT5GG"
	decisionPin  = "01M6B5CJM06Z03BNN7F7GG7KCP"
	uploadedRepo = "acme/uploaded"
)

// ci is a second authorization server that stands in for GitHub Actions: its tokens carry the claims of a
// job, and the API verifies them against its own keys.
type ci struct {
	*authntest.Server
	// maps is what Lookup answers for each repository id, and is the tenant the run is stored under.
	maps map[int64]Mapping
	// status is what Lookup answers when the repository id is not in maps.
	status MappingStatus
}

// uploadHandler is the API with uploads on, and a person verifier too, so one handler serves the upload
// and the read.
func (f *fixture) uploadHandler(t *testing.T, limits Limits) (http.Handler, *ci) {
	t.Helper()
	runs := &ci{Server: authntest.NewServer(t), maps: map[int64]Mapping{}, status: MappingUnknown}
	verifier, _, err := authn.Discover(t.Context(), runs.Server.Server.Client(), runs.Server.Server.URL, ciAudience)
	if err != nil {
		t.Fatal(err)
	}
	people, _, err := authn.Discover(t.Context(), f.auth.Server.Client(), f.auth.Server.URL, audience)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{
		DB:       f.db,
		Verifier: people,
		Callers: func(_ context.Context, claims authn.Claims) (Caller, bool) {
			caller, ok := f.callers[claims.Subject]
			return caller, ok
		},
		Policy: testPolicy(t),
		Uploads: &Uploads{Verifier: verifier, Lookup: func(_ context.Context, run authn.RunClaims) (Mapping, MappingStatus) {
			if mapping, ok := runs.maps[run.RepositoryID]; ok {
				return mapping, MappingFound
			}
			return Mapping{}, runs.status
		}},
		Limits: limits,
		// A read that names no transaction time is read at the time of the database that stamps the rows.
		Now: f.databaseNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, runs
}

// databaseNow is the clock of the database, which sets the transaction time of every row. The test database
// runs in a virtual machine whose clock need not equal this process's.
func (f *fixture) databaseNow() time.Time {
	var now time.Time
	if err := f.admin.QueryRowContext(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		panic(err)
	}
	return now
}

// token is the token of a job in repo, with run and attempt, as GitHub would sign it.
func (c *ci) token(repo string, repositoryID, run int64, attempt int) string {
	claims := map[string]any{
		"repository":          repo,
		"repository_id":       strconv.FormatInt(repositoryID, 10),
		"repository_owner_id": "9919",
		"run_id":              strconv.FormatInt(run, 10),
		"run_attempt":         strconv.Itoa(attempt),
		"sha":                 strings.Repeat("c0", 20),
		"ref":                 "refs/pull/5/merge",
		"event_name":          "pull_request",
		"workflow_ref":        repo + "/.github/workflows/ci.yml@refs/pull/5/merge",
	}
	var options []authntest.TokenOption
	for name, value := range claims {
		options = append(options, authntest.Claim(name, value))
	}
	return "Bearer " + c.Token(ciAudience, nil, options...)
}

// uploadBody is a plan report with two verdicts, one of which fails.
func uploadBody(t *testing.T, mutate func(upload, report map[string]any)) []byte {
	t.Helper()
	report := map[string]any{
		"report_version": 1,
		"ipso_version":   "0.5.0",
		"evaluated_at":   "2026-11-07T10:00:00Z",
		"env":            "prod",
		"build_sha256":   strings.Repeat("ab", 32),
		"plan_sha256":    strings.Repeat("cd", 32),
		"verdicts": []any{
			map[string]any{"decision_id": decisionTLS, "slug": "use-tls", "check_index": 0, "mode": "block", "result": "fail", "violations": 3},
			map[string]any{"decision_id": decisionPin, "slug": "pin-versions", "check_index": 0, "mode": "warn", "result": "pass", "violations": 0},
		},
	}
	upload := map[string]any{"check": "plan", "report": report, "sarif_sha256": strings.Repeat("ef", 32)}
	if mutate != nil {
		mutate(upload, report)
	}
	body, err := json.Marshal(upload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (f *fixture) count(t *testing.T, tenant uuid.UUID, table, repo string) int {
	t.Helper()
	var n int
	query := `SELECT count(*) FROM ` + table + ` AS t WHERE t.tenant_id = $1`
	args := []any{tenant}
	if table == "verification.upload" {
		query += ` AND t.repo = $2`
		args = append(args, repo)
	} else {
		query += ` AND t.upload_id IN (SELECT id FROM verification.upload WHERE repo = $2)`
		args = append(args, repo)
	}
	if err := pgtest.Scan(t.Context(), f.db, tenant.String(), query, args, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func raw(handler http.Handler, method, target, authorization, contentType string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
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

// The upload and the read match the document on both sides, and the same run uploading the same content
// twice stores it once.
func TestAnUploadMatchesTheDocumentAndIsStoredOnce(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, runs := f.uploadHandler(t, Limits{})
	runs.maps[501] = Mapping{Tenant: tenantA, Installation: 42}
	body := uploadBody(t, nil)

	first := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 7001, 1), "application/json", body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first upload: status %d: %s", first.Code, first.Body.String())
	}
	created := answerOf(t, first)
	if created["verdicts"] != float64(2) || created["id"] == "" {
		t.Fatalf("first upload answered %v", created)
	}

	// The same run, attempt and content is the same upload: 200, the first id, and no new row.
	again := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 7001, 1), "application/json", body)
	if again.Code != http.StatusOK || answerOf(t, again)["id"] != created["id"] {
		t.Fatalf("repeat: status %d: %s", again.Code, again.Body.String())
	}
	if n := f.count(t, tenantA, "verification.upload", uploadedRepo); n != 1 {
		t.Errorf("%d uploads after a repeat, want 1", n)
	}
	if n := f.count(t, tenantA, "verification.verdict", uploadedRepo); n != 2 {
		t.Errorf("%d verdicts after a repeat, want 2", n)
	}

	// A new attempt of the run, and other content of the same attempt, are new uploads.
	second := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 7001, 2), "application/json", body)
	other := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 7001, 1), "application/json",
		uploadBody(t, func(_, report map[string]any) { report["env"] = "stage" }))
	if second.Code != http.StatusCreated || other.Code != http.StatusCreated {
		t.Fatalf("attempt 2: %d, other content: %d", second.Code, other.Code)
	}
	if n := f.count(t, tenantA, "verification.upload", uploadedRepo); n != 3 {
		t.Errorf("%d uploads, want 3", n)
	}

	// A person of tenant A reads them back, with the run the token named.
	token := f.token(t, personA)
	all := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=ACME%2FUploaded", token, "", nil)
	if all.Code != http.StatusOK {
		t.Fatalf("list: %d: %s", all.Code, all.Body.String())
	}
	verdicts := list(answerOf(t, all), "verdicts")
	if len(verdicts) != 6 {
		t.Fatalf("%d verdicts, want 6: %s", len(verdicts), all.Body.String())
	}
	item := verdicts[0].(map[string]any)
	if item["repo"] != uploadedRepo || item["event"] != "pull_request" || item["sha"] != strings.Repeat("c0", 20) ||
		item["workflow_ref"] != uploadedRepo+"/.github/workflows/ci.yml@refs/pull/5/merge" ||
		item["run_url"] != "https://github.com/acme/uploaded/actions/runs/7001" || item["run_id"] != float64(7001) {
		t.Errorf("the run is not the one the token named: %v", item)
	}
	if item["sarif_sha256"] != strings.Repeat("ef", 32) || item["build_sha256"] != strings.Repeat("ab", 32) {
		t.Errorf("digests: %v", item)
	}

	// Filters: a decision by slug and by id, and a page at a time, newest first.
	for _, target := range []string{"/v1/verdicts?decision=pin-versions&repo=acme%2Fuploaded", "/v1/verdicts?decision=" + decisionPin + "&repo=acme%2Fuploaded"} {
		w := c.exchange(t, handler, http.MethodGet, target, token, "", nil)
		if got := list(answerOf(t, w), "verdicts"); len(got) != 3 {
			t.Errorf("%s: %d verdicts, want 3", target, len(got))
		}
	}
	page := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded&limit=4", token, "", nil)
	first4 := list(answerOf(t, page), "verdicts")
	if len(first4) != 4 {
		t.Fatalf("first page has %d verdicts, want 4", len(first4))
	}
	rest := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded&before="+first4[3].(map[string]any)["id"].(string), token, "", nil)
	if got := list(answerOf(t, rest), "verdicts"); len(got) != 2 {
		t.Errorf("second page has %d verdicts, want 2", len(got))
	}
	for i := 1; i < len(first4); i++ {
		if first4[i-1].(map[string]any)["id"].(string) <= first4[i].(map[string]any)["id"].(string) {
			t.Errorf("the page is not newest first at %d", i)
		}
	}

	// Tenant B sees none of it.
	b := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded", f.token(t, personB), "", nil)
	if got := list(answerOf(t, b), "verdicts"); got == nil || len(got) != 0 {
		t.Errorf("tenant B read tenant A's uploads: %s", b.Body.String())
	}
}

// The tenant is the one the mapping gives, whatever the body says, and the body cannot say.
func TestTheTenantOfAnUploadIsTheMappingsAndNeverTheBodys(t *testing.T) {
	f := newFixture(t)
	handler, runs := f.uploadHandler(t, Limits{})
	runs.maps[502] = Mapping{Tenant: tenantB, Installation: 43}

	if w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 502, 7002, 1), "application/json", uploadBody(t, nil)); w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if f.count(t, tenantB, "verification.upload", uploadedRepo) != 1 || f.count(t, tenantA, "verification.upload", uploadedRepo) != 0 {
		t.Error("the upload was not stored under the tenant of the mapping, and only there")
	}

	// Names a tenant, a repository, or a run: all refused, and nothing is stored.
	for name, mutate := range map[string]func(upload, report map[string]any){
		"a tenant":     func(upload, _ map[string]any) { upload["tenant_id"] = tenantA.String() },
		"a tenant key": func(upload, _ map[string]any) { upload["tenant"] = tenantA.String() },
		"a repository": func(upload, _ map[string]any) { upload["repo"] = "acme/api" },
		"a run":        func(upload, _ map[string]any) { upload["run_id"] = 1 },
		"a report tenant": func(_, report map[string]any) {
			report["tenant_id"] = tenantA.String()
		},
	} {
		w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token("acme/refused", 502, 7003, 1), "application/json", uploadBody(t, mutate))
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("%s: status %d: %s", name, w.Code, w.Body.String())
		}
	}
	if f.count(t, tenantA, "verification.upload", "acme/refused")+f.count(t, tenantB, "verification.upload", "acme/refused") != 0 {
		t.Error("a refused upload was stored")
	}
}

func TestAnUploadOverTheCapIsRefusedWholeAndStoresNothing(t *testing.T) {
	f := newFixture(t)
	handler, runs := f.uploadHandler(t, Limits{})
	runs.maps[503] = Mapping{Tenant: tenantA, Installation: 42}
	big := uploadBody(t, func(_, report map[string]any) { report["env"] = strings.Repeat("e", 2<<20) })
	w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token("acme/big", 503, 7004, 1), "application/json", big)
	if w.Code != http.StatusRequestEntityTooLarge || errorOf(t, w) != errTooLarge {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if f.count(t, tenantA, "verification.upload", "acme/big") != 0 {
		t.Error("an upload over the cap was stored")
	}
	// The refusal left nothing behind, so the same run can still upload.
	if w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token("acme/big", 503, 7004, 1), "application/json", uploadBody(t, nil)); w.Code != http.StatusCreated {
		t.Errorf("a normal upload: status %d: %s", w.Code, w.Body.String())
	}
}

// Every refusal of the upload matches the document where it has an answer for it.
func TestTheUploadRefusesWhatItShouldAndSaysSoInTheDocumentsTerms(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, runs := f.uploadHandler(t, Limits{})
	runs.maps[504] = Mapping{Tenant: tenantA, Installation: 42}
	body := uploadBody(t, nil)
	for _, tc := range []struct {
		name, authorization, contentType string
		status                           int
		code                             string
	}{
		{"no token", "", "application/json", http.StatusUnauthorized, errUnauthorized},
		{"a person's token", f.token(t, personA), "application/json", http.StatusUnauthorized, errUnauthorized},
		{"a repository nobody maps", runs.token("acme/stranger", 999, 1, 1), "application/json", http.StatusForbidden, errForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", tc.authorization, tc.contentType, body)
			if w.Code != tc.status || errorOf(t, w) != tc.code {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
	// A body without a content type is not a request the document allows, so it is sent without the check.
	if w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token("acme/nct", 504, 1, 1), "", body); w.Code != http.StatusUnsupportedMediaType || errorOf(t, w) != errUnsupportedMedia {
		t.Errorf("no content type: status %d: %s", w.Code, w.Body.String())
	}
	// A CI token opens no read, and a person's token opens no upload.
	if w := raw(handler, http.MethodGet, "/v1/verdicts", runs.token("acme/api", 504, 1, 1), "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a CI token on a read: status %d, want 401", w.Code)
	}
	// A failed mapping is 503 and stores nothing.
	runs.status = MappingFailed
	w := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token("acme/down", 998, 1, 1), "application/json", body)
	if w.Code != http.StatusServiceUnavailable || errorOf(t, w) != errUnavailable {
		t.Errorf("a failed mapping: status %d: %s", w.Code, w.Body.String())
	}
	for _, repo := range []string{"acme/stranger", "acme/nct", "acme/down"} {
		if n := f.count(t, tenantA, "verification.upload", repo); n != 0 {
			t.Errorf("%s: %d uploads stored by a refused request", repo, n)
		}
	}
}

// Without uploads the route is an unknown route.
func TestWithoutUploadsTheRouteAnswersLikeAnyUnknownRoute(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{})
	if w := raw(handler, http.MethodPost, "/v1/verdicts", "", "application/json", uploadBody(t, nil)); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", w.Code)
	}
	w := raw(handler, http.MethodPost, "/v1/verdicts", f.token(t, personA), "application/json", uploadBody(t, nil))
	if w.Code != http.StatusNotFound || errorOf(t, w) != errNotFound {
		t.Errorf("a person's token: status %d: %s", w.Code, w.Body.String())
	}
	if n := f.count(t, tenantA, "verification.upload", "acme/api"); n != 1 {
		t.Errorf("%d uploads of acme/api, want only the seeded one", n)
	}
}
