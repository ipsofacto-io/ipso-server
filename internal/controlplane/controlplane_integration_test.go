//go:build integration

package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/login"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

const (
	apiAudience = "ipso-api"
	mcpResource = "https://ipso.example.test/mcp"
	metaLatest  = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
)

var tenant = uuid.MustParse("00000000-0000-4000-8000-00000000000a")

// stack is a migrated database with one tenant, a person bound to the API issuer, and an agent bound
// to the MCP issuer. Every row is synthetic.
type stack struct {
	database *pgtest.Database
	app      *sql.DB
	apiAuth  *authntest.Server
	mcpAuth  *authntest.Server
	person   uuid.UUID
	agent    uuid.UUID
}

func newStack(t *testing.T) *stack {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &stack{database: database, app: database.Open(t, pgtest.App), apiAuth: authntest.NewServer(t), mcpAuth: authntest.NewServer(t)}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pgtest.Exec(t.Context(), s.app, tenant.String(), query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	scan := func(query string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pgtest.Scan(t.Context(), s.app, tenant.String(), query, args, &id); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return id
	}
	exec(`INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, tenant)
	s.person = scan(`INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Ada') RETURNING id`, tenant)
	s.agent = scan(`INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, 'agent', 'Agent', $2) RETURNING id`, tenant, s.person)
	exec(`INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'person-1')`, tenant, s.person, s.apiAuth.Server.URL)
	exec(`INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'agent-1')`, tenant, s.agent, s.mcpAuth.Server.URL)
	return s
}

func (s *stack) config(mcp bool) Config {
	cfg := Config{
		DB:       s.app,
		Tenant:   tenant,
		Issuer:   s.apiAuth.Server.URL,
		Audience: apiAudience,
		Client:   s.apiAuth.Server.Client(),
	}
	if mcp {
		cfg.MCPIssuer, cfg.MCPResourceURL = s.mcpAuth.Server.URL, mcpResource
	}
	return cfg
}

func (s *stack) handler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	handler, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func get(handler http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func mcpCall(handler http.Handler, token, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, mcpResource, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if method == "tools/call" {
		req.Header.Set("Mcp-Name", "decisions.applicable")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func list(handler http.Handler, token string) *httptest.ResponseRecorder {
	return mcpCall(handler, token, "tools/list", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+metaLatest+`}}`)
}

func subject(sub string) authntest.TokenOption {
	return func(b *jwt.Builder) *jwt.Builder { return b.Subject(sub) }
}

func TestTheAPIServesTheTokenOfABoundLoginOnly(t *testing.T) {
	s := newStack(t)
	cfg := s.config(false)
	cfg.Web = fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ipso</title>")}}
	handler := s.handler(t, cfg)

	if rec := get(handler, "/healthz", ""); rec.Code != http.StatusNoContent {
		t.Errorf("health: status %d, want 204", rec.Code)
	}
	if rec := get(handler, "/v1/scopes", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", rec.Code)
	}
	good := s.apiAuth.Token(apiAudience, nil, subject("person-1"))
	if rec := get(handler, "/v1/scopes", good); rec.Code != http.StatusOK {
		t.Errorf("a bound login: status %d, want 200: %s", rec.Code, rec.Body)
	}
	if rec := get(handler, "/v1/scopes?tenant="+uuid.NewString(), good); rec.Code != http.StatusBadRequest {
		t.Errorf("a tenant in the query: status %d, want 400", rec.Code)
	}
	if rec := get(handler, "/v1/scopes", s.apiAuth.Token(apiAudience, nil, subject("stranger"))); rec.Code != http.StatusForbidden {
		t.Errorf("a valid token for an unbound subject: status %d, want 403", rec.Code)
	}
	if rec := get(handler, "/v1/scopes", s.apiAuth.Token("other-app", nil, subject("person-1"))); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token for another client: status %d, want 401", rec.Code)
	}
	// The subject is only unique within its issuer: the MCP issuer's token is not this issuer's.
	if rec := get(handler, "/v1/scopes", s.mcpAuth.Token(apiAudience, nil, subject("person-1"))); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token from another issuer: status %d, want 401", rec.Code)
	}
	// Without an MCP issuer the MCP path is not served: it is a path of the web app, which takes no POST.
	if rec := list(handler, s.mcpAuth.Token(mcpResource, nil, subject("agent-1"))); rec.Code != http.StatusMethodNotAllowed || strings.Contains(rec.Body.String(), "decisions.applicable") {
		t.Errorf("the MCP path without an MCP issuer: status %d, want the web app's 405", rec.Code)
	}
}

func TestEachHandlerRefusesATokenMintedForTheOther(t *testing.T) {
	s := newStack(t)
	handler := s.handler(t, s.config(true))

	apiToken := s.apiAuth.Token(apiAudience, nil, subject("person-1"))
	mcpToken := s.mcpAuth.Token(mcpResource, []string{"ipso.read"}, subject("agent-1"))
	if rec := get(handler, "/v1/scopes", apiToken); rec.Code != http.StatusOK {
		t.Fatalf("the API with its own token: status %d: %s", rec.Code, rec.Body)
	}
	if rec := list(handler, mcpToken); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "decisions.applicable") {
		t.Fatalf("MCP with its own token: status %d: %s", rec.Code, rec.Body)
	}

	if rec := list(handler, apiToken); rec.Code != http.StatusUnauthorized {
		t.Errorf("MCP with the API's token: status %d, want 401", rec.Code)
	}
	if rec := get(handler, "/v1/scopes", mcpToken); rec.Code != http.StatusUnauthorized {
		t.Errorf("the API with MCP's token: status %d, want 401", rec.Code)
	}

	// A token that names both audiences passes either audience check, so each handler refuses it.
	both := func(auth *authntest.Server, sub string) string {
		return auth.Token(apiAudience, []string{"ipso.read"}, subject(sub), func(b *jwt.Builder) *jwt.Builder {
			return b.Audience([]string{apiAudience, mcpResource})
		})
	}
	if rec := get(handler, "/v1/scopes", both(s.apiAuth, "person-1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("the API with a token for both: status %d, want 401", rec.Code)
	}
	if rec := list(handler, both(s.mcpAuth, "agent-1")); rec.Code != http.StatusUnauthorized {
		t.Errorf("MCP with a token for both: status %d, want 401", rec.Code)
	}
}

func TestMCPSpeaksForTheLoginsPrincipalAndNamesItsSponsor(t *testing.T) {
	s := newStack(t)
	handler := s.handler(t, s.config(true))
	token := s.mcpAuth.Token(mcpResource, []string{"ipso.read"}, subject("agent-1"))

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"decisions.applicable","arguments":{"repo":"acme/payments"},` + metaLatest + `}}`
	if rec := mcpCall(handler, token, "tools/call", body); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	actions, err := identity.Actions(t.Context(), s.app, tenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Principal != s.agent || actions[0].Responsible != s.person {
		t.Fatalf("the log = %+v, want one entry by the agent that names its sponsor", actions)
	}
	if rec := mcpCall(handler, s.mcpAuth.Token(mcpResource, []string{"ipso.read"}, subject("stranger")), "tools/call", body); rec.Code != http.StatusForbidden {
		t.Errorf("an unbound subject: status %d, want 403", rec.Code)
	}
}

func TestMCPLimitsACallerPerTenant(t *testing.T) {
	s := newStack(t)
	cfg := s.config(true)
	cfg.Limits = api.Limits{Rate: 0.001, Burst: 2}
	handler := s.handler(t, cfg)
	token := s.mcpAuth.Token(mcpResource, []string{"ipso.read"}, subject("agent-1"))
	for i := range 2 {
		if rec := list(handler, token); rec.Code != http.StatusOK {
			t.Fatalf("call %d: status %d: %s", i, rec.Code, rec.Body)
		}
	}
	rec := list(handler, token)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("third call: status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	// The API keeps its own bucket for the same tenant.
	if rec := get(handler, "/v1/scopes", s.apiAuth.Token(apiAudience, nil, subject("person-1"))); rec.Code != http.StatusOK {
		t.Errorf("the API after MCP was limited: status %d", rec.Code)
	}
}

func TestStartRefusesWhatCouldServeTheWrongTenant(t *testing.T) {
	s := newStack(t)

	t.Run("the migration role", func(t *testing.T) {
		cfg := s.config(false)
		cfg.DB = s.database.Open(t, pgtest.Migrate)
		if _, err := New(t.Context(), cfg); !errors.Is(err, rls.ErrRefused) {
			t.Fatalf("err = %v, want the start refusal", err)
		}
	})
	t.Run("a role that bypasses row-level security", func(t *testing.T) {
		cfg := s.config(false)
		cfg.DB = s.database.Open(t, pgtest.Bypass)
		if _, err := New(t.Context(), cfg); !errors.Is(err, rls.ErrRefused) {
			t.Fatalf("err = %v, want the start refusal", err)
		}
	})
	t.Run("a tenant with no row", func(t *testing.T) {
		cfg := s.config(false)
		cfg.Tenant = uuid.New()
		if _, err := New(t.Context(), cfg); !errors.Is(err, tenancy.ErrUnknownTenant) {
			t.Fatalf("err = %v, want an unknown tenant", err)
		}
	})
	t.Run("the same audience for both handlers", func(t *testing.T) {
		cfg := s.config(true)
		cfg.Audience = mcpResource
		if _, err := New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "distinct audiences") {
			t.Fatalf("err = %v, want distinct audiences", err)
		}
	})
	t.Run("an MCP issuer without Client ID Metadata Documents", func(t *testing.T) {
		s.mcpAuth.Meta["client_id_metadata_document_supported"] = false
		if _, err := New(t.Context(), s.config(true)); err == nil || !strings.Contains(err.Error(), "Client ID Metadata") {
			t.Fatalf("err = %v, want the discovery refusal", err)
		}
		s.mcpAuth.Meta["client_id_metadata_document_supported"] = true
	})
	t.Run("an issuer that is not https", func(t *testing.T) {
		cfg := s.config(false)
		cfg.Issuer = "http://idp.example.test"
		if _, err := New(t.Context(), cfg); err == nil {
			t.Fatal("an http issuer was accepted")
		}
	})
}

const signInOrigin = "https://ipso.example.test"

// signIn is a provider of people, reached the way a browser reaches one: the control plane sends the
// browser to it, and the browser comes back with a code. The provider is the fake authorization server
// with a token endpoint that holds the client to what a real one does.
type signIn struct {
	idp       *authntest.Server
	challenge string
	nonce     string
}

func newSignIn(t *testing.T) *signIn {
	t.Helper()
	s := &signIn{idp: authntest.NewServer(t)}
	s.idp.Meta["authorization_endpoint"] = s.idp.Server.URL + "/authorize"
	s.idp.Meta["token_endpoint"] = s.idp.Server.URL + "/token"
	s.idp.Meta["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
	s.idp.Mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("code") != "good-code" || r.PostForm.Get("client_secret") != "test-only-secret" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != s.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		id := s.idp.Token("ipso-login", nil, subject("person-2"), authntest.Claim("nonce", s.nonce))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": id})
	})
	return s
}

func (s *signIn) config(stack *stack) Config {
	cfg := stack.config(false)
	cfg.PublicURL = signInOrigin
	cfg.Providers = []login.ProviderConfig{{ID: "idp", Kind: login.KindOIDC, Issuer: s.idp.Server.URL, ClientID: "ipso-login", ClientSecretEnv: "IPSO_LOGIN_IDP"}}
	cfg.Secrets = func(name string) string { return map[string]string{"IPSO_LOGIN_IDP": "test-only-secret"}[name] }
	return cfg
}

func request(handler http.Handler, method, target string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func cookieOf(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// begin starts a sign-in and returns the attempt cookie and the state, and teaches the provider the
// challenge and nonce the control plane sent.
func (s *signIn) begin(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	rec := request(handler, http.MethodGet, "/auth/login/idp", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start: status %d: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	s.challenge, s.nonce = loc.Query().Get("code_challenge"), loc.Query().Get("nonce")
	return cookieOf(rec, "__Host-ipso-login"), loc.Query().Get("state")
}

func sessionRows(t *testing.T, admin *sql.DB) int {
	t.Helper()
	var n int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM identity.session`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The whole path on PostgreSQL 18: a person the tenant bound signs in, the cookie is their session on
// the API, another site cannot use it, and logout ends it. A failed sign-in writes no session.
func TestAPersonSignsInAndTheCookieIsTheirSession(t *testing.T) {
	s := newStack(t)
	in := newSignIn(t)
	admin := s.database.Open(t, pgtest.Admin)
	if _, err := pgtest.Exec(t.Context(), s.app, tenant.String(),
		`INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'person-2')`, tenant, s.person, in.idp.Server.URL); err != nil {
		t.Fatal(err)
	}
	handler := s.handler(t, in.config(s))

	// A forged state creates no session, and neither does a callback with no attempt.
	attempt, state := in.begin(t, handler)
	if rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state=forged", nil, attempt); rec.Code != http.StatusBadRequest {
		t.Errorf("a forged state: status %d", rec.Code)
	}
	if rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+state, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no attempt cookie: status %d", rec.Code)
	}
	if n := sessionRows(t, admin); n != 0 {
		t.Fatalf("%d sessions after failed sign-ins, want 0", n)
	}

	attempt, state = in.begin(t, handler)
	rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+state, nil, attempt)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: status %d: %s", rec.Code, rec.Body)
	}
	session := cookieOf(rec, "__Host-ipso-session")
	if session == nil || sessionRows(t, admin) != 1 {
		t.Fatalf("session cookie %v, %d rows", session, sessionRows(t, admin))
	}

	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, session); rec.Code != http.StatusOK {
		t.Errorf("the API with the session: status %d: %s", rec.Code, rec.Body)
	}
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the API with nothing: status %d", rec.Code)
	}
	// A request another site makes with the cookie is refused, and so is one with a made-up cookie.
	if rec := request(handler, http.MethodPost, "/v1/resolve", map[string]string{"Sec-Fetch-Site": "cross-site"}, session); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: status %d", rec.Code)
	}
	forged := &http.Cookie{Name: session.Name, Value: strings.Repeat("A", 43)}
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, forged); rec.Code != http.StatusUnauthorized || cookieOf(rec, session.Name) == nil {
		t.Errorf("a made-up cookie: status %d", rec.Code)
	}
	// Remote MCP and a bearer header never read the cookie.
	if rec := request(handler, http.MethodGet, "/v1/scopes", map[string]string{"Authorization": "Bearer bad"}, session); rec.Code != http.StatusUnauthorized {
		t.Errorf("a bad bearer token and a good cookie: status %d", rec.Code)
	}

	if rec := request(handler, http.MethodPost, "/auth/logout", map[string]string{"Sec-Fetch-Site": "cross-site"}, session); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site logout: status %d", rec.Code)
	}
	if rec := request(handler, http.MethodPost, "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin"}, session); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: status %d", rec.Code)
	}
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, session); rec.Code != http.StatusUnauthorized {
		t.Errorf("the API after logout: status %d, want 401: this process kept the session", rec.Code)
	}
	if n := sessionRows(t, admin); n != 0 {
		t.Errorf("%d sessions after logout", n)
	}
}

func TestASignInOfAPersonTheTenantNeverBoundCreatesNoSession(t *testing.T) {
	s := newStack(t)
	in := newSignIn(t)
	admin := s.database.Open(t, pgtest.Admin)
	handler := s.handler(t, in.config(s))

	attempt, state := in.begin(t, handler)
	rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+state, nil, attempt)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "unknown_login") || !strings.Contains(rec.Body.String(), "person-2") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if cookieOf(rec, "__Host-ipso-session") != nil || sessionRows(t, admin) != 0 {
		t.Error("a session was started")
	}
}

func TestAnAgentsLoginCreatesNoBrowserSession(t *testing.T) {
	s := newStack(t)
	in := newSignIn(t)
	admin := s.database.Open(t, pgtest.Admin)
	if _, err := pgtest.Exec(t.Context(), s.app, tenant.String(),
		`INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'person-2')`, tenant, s.agent, in.idp.Server.URL); err != nil {
		t.Fatal(err)
	}
	handler := s.handler(t, in.config(s))
	attempt, state := in.begin(t, handler)
	rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+state, nil, attempt)
	if rec.Code != http.StatusForbidden || sessionRows(t, admin) != 0 {
		t.Fatalf("status %d: %s, %d sessions", rec.Code, rec.Body, sessionRows(t, admin))
	}
}

// With no provider configured there is no /auth, so the API's own 401 answers, and a cookie is not read.
func TestWithoutProvidersThereIsNoSignInAndNoCookie(t *testing.T) {
	s := newStack(t)
	handler := s.handler(t, s.config(false))
	if rec := request(handler, http.MethodGet, "/auth/login/idp", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("/auth without providers: status %d, want the API's 401", rec.Code)
	}
	cookie := &http.Cookie{Name: "__Host-ipso-session", Value: strings.Repeat("A", 43)}
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, cookie); rec.Code != http.StatusUnauthorized || cookieOf(rec, cookie.Name) != nil {
		t.Errorf("a cookie with sign-in off: status %d", rec.Code)
	}
}

// The API owns /v1, the sign-in owns /auth, and the web app owns the rest (ADR-0106). The page needs no
// session, the API still answers 401 to a caller without one, and a path under /v1 is never the page.
func TestTheWebAppIsServedAtEveryPathButTheAPIsAndTheSignIns(t *testing.T) {
	s := newStack(t)
	in := newSignIn(t)
	page := "<!doctype html><title>ipso</title>"
	files := fstest.MapFS{"index.html": {Data: []byte(page)}, "assets/app-1a2b3c.js": {Data: []byte("1")}}

	cfg := in.config(s)
	cfg.Web = files
	handler := s.handler(t, cfg)
	for _, target := range []string{"/", "/decisions", "/decisions/use-postgresql", "/audit/merges"} {
		if rec := request(handler, http.MethodGet, target, nil); rec.Code != http.StatusOK || rec.Body.String() != page || rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: status %d %q", target, rec.Code, rec.Body)
		}
	}
	if rec := request(handler, http.MethodGet, "/assets/app-1a2b3c.js", nil); rec.Code != http.StatusOK || rec.Body.String() != "1" {
		t.Errorf("an asset: status %d", rec.Code)
	}
	if rec := request(handler, http.MethodGet, "/assets/gone.js", nil); rec.Code != http.StatusNotFound {
		t.Errorf("a missing asset: status %d", rec.Code)
	}
	// The API answers under /v1 and never serves the page: an unknown route is the 401 of a caller with
	// no session, and a made-up one is the 404 of the API once there is a session.
	for _, target := range []string{"/v1/scopes", "/v1/nothing", "/v1/"} {
		rec := request(handler, http.MethodGet, target, nil)
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "<title>") {
			t.Errorf("%s: status %d %q", target, rec.Code, rec.Body)
		}
	}
	if rec := request(handler, http.MethodPost, "/", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: status %d", rec.Code)
	}
	// The sign-in answers under /auth, the list of providers included, and /healthz stays outside both.
	rec := request(handler, http.MethodGet, "/auth/providers", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"id":"idp","kind":"oidc"}`) {
		t.Errorf("/auth/providers: status %d %q", rec.Code, rec.Body)
	}
	if rec := request(handler, http.MethodGet, "/auth/nothing", nil); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<title>") {
		t.Errorf("/auth/nothing: status %d %q", rec.Code, rec.Body)
	}
	if rec := request(handler, http.MethodGet, "/healthz", nil); rec.Code != http.StatusNoContent {
		t.Errorf("/healthz: status %d", rec.Code)
	}

	// With no provider, /auth is the API's 401, as before, and the page is still served.
	cfg = s.config(false)
	cfg.Web = files
	handler = s.handler(t, cfg)
	if rec := request(handler, http.MethodGet, "/auth/providers", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("/auth/providers without providers: status %d, want the API's 401", rec.Code)
	}
	if rec := request(handler, http.MethodGet, "/", nil); rec.Code != http.StatusOK || rec.Body.String() != page {
		t.Errorf("/ without providers: status %d %q", rec.Code, rec.Body)
	}
}

// A binary built without the web app still serves the API, and says why / shows no page.
func TestWithoutAWebAppThePathsOfTheAppAnswerWithASentence(t *testing.T) {
	s := newStack(t)
	handler := s.handler(t, s.config(false))
	rec := request(handler, http.MethodGet, "/decisions", nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not built into this binary") {
		t.Errorf("status %d %q", rec.Code, rec.Body)
	}
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("/v1/scopes: status %d", rec.Code)
	}
}

func TestStartRefusesABuildOfTheWebAppWithoutItsPage(t *testing.T) {
	s := newStack(t)
	cfg := s.config(false)
	cfg.Web = fstest.MapFS{"assets/app.js": {Data: []byte("1")}}
	if _, err := New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "the web app") {
		t.Errorf("err = %v", err)
	}
}

func TestStartRefusesAProviderItCannotReach(t *testing.T) {
	s := newStack(t)
	in := newSignIn(t)
	cfg := in.config(s)
	in.idp.Server.Close()
	if _, err := New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "sign-in") {
		t.Fatalf("err = %v, want a sign-in error", err)
	}
	// A client id equal to the API's audience would let an ID token pass as a bearer token.
	cfg = newSignIn(t).config(s)
	cfg.Providers[0].ClientID = apiAudience
	if _, err := New(t.Context(), cfg); err == nil {
		t.Fatal("a client id equal to the API audience was accepted")
	}
}
