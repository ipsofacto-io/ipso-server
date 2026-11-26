//go:build integration

package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/login"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

type multiTenantOIDC struct {
	idp       *authntest.Server
	mu        sync.Mutex
	subject   string
	challenge string
	nonce     string
}

func newMultiTenantOIDC(t *testing.T) *multiTenantOIDC {
	t.Helper()
	idp := authntest.NewServer(t)
	o := &multiTenantOIDC{idp: idp, subject: "user-a"}
	idp.Meta["authorization_endpoint"] = idp.Server.URL + "/authorize"
	idp.Meta["token_endpoint"] = idp.Server.URL + "/token"
	idp.Meta["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
	idp.Mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		o.mu.Lock()
		challenge, nonce, subject := o.challenge, o.nonce, o.subject
		o.mu.Unlock()
		if r.PostForm.Get("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idp.Token("ipso-login", nil, authntest.Subject(subject), authntest.Claim("nonce", nonce)),
		})
	})
	return o
}

func (o *multiTenantOIDC) setSubject(subject string) {
	o.mu.Lock()
	o.subject = subject
	o.mu.Unlock()
}

func (o *multiTenantOIDC) beginBrowser(t *testing.T, handler http.Handler, cookies ...*http.Cookie) (*http.Cookie, string) {
	t.Helper()
	rec := request(handler, http.MethodGet, "/auth/login/idp", nil, cookies...)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login start: %d %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	o.challenge = loc.Query().Get("code_challenge")
	o.nonce = loc.Query().Get("nonce")
	o.mu.Unlock()
	return cookieOf(rec, "__Host-ipso-login"), loc.Query().Get("state")
}

func (o *multiTenantOIDC) signInCLI(t *testing.T, handler http.Handler, subject string) string {
	t.Helper()
	o.setSubject(subject)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_extra_entropy_" + subject
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := "http://127.0.0.1:54321/callback"
	q := url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {"cli-state-" + subject},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	startRec := request(handler, http.MethodGet, "/auth/cli/start?"+q.Encode(), nil)
	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("cli start: %d %s", startRec.Code, startRec.Body)
	}
	attempt := cookieOf(startRec, "__Host-ipso-login")
	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	o.challenge = loc.Query().Get("code_challenge")
	o.nonce = loc.Query().Get("nonce")
	o.mu.Unlock()

	cbRec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+url.QueryEscape(loc.Query().Get("state")), nil, attempt)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("cli callback: %d %s", cbRec.Code, cbRec.Body)
	}
	cbLoc, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cbLoc.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/cli/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	handler.ServeHTTP(tokRec, req)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("cli token: %d %s", tokRec.Code, tokRec.Body)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.AccessToken
}

func TestMultiTenantAPIIsolatesTwoTenantsAcrossEveryCredentialPath(t *testing.T) {
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	app := database.Open(t, pgtest.App)
	admin := database.Open(t, pgtest.Admin)

	tenantA := uuid.MustParse("00000000-0000-4000-8000-00000000001a")
	tenantB := uuid.MustParse("00000000-0000-4000-8000-00000000001b")

	apiAuth := authntest.NewServer(t)
	mcpAuth := authntest.NewServer(t)
	ciAuth := authntest.NewServer(t)
	oidc := newMultiTenantOIDC(t)
	githubApp := &fakeApp{byRepo: map[string]integrations.Installation{
		"alpha-org/repo-a": {ID: 401, AccountID: 91},
		"beta-org/repo-b":  {ID: 402, AccountID: 92},
	}}

	execIn := func(tid uuid.UUID, query string, args ...any) {
		t.Helper()
		if _, err := pgtest.Exec(t.Context(), app, tid.String(), query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	scanIn := func(tid uuid.UUID, query string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pgtest.Scan(t.Context(), app, tid.String(), query, args, &id); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return id
	}

	// Provision two tenants with distinct scopes, principals, logins, installations, and agent pins.
	execIn(tenantA, `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'Tenant A')`, tenantA)
	execIn(tenantB, `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'Tenant B')`, tenantB)

	scopeA := scanIn(tenantA, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'alpha-org') RETURNING id`, tenantA)
	scopeB := scanIn(tenantB, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'beta-org') RETURNING id`, tenantB)
	repoScopeA := scanIn(tenantA, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, $2, 'repo', 'alpha-org/repo-a') RETURNING id`, tenantA, scopeA)
	repoScopeB := scanIn(tenantB, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, $2, 'repo', 'beta-org/repo-b') RETURNING id`, tenantB, scopeB)
	execIn(tenantA, `INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period) VALUES ($1, 1, $2, '{"slug":"alpha-only","title":"Alpha Only","status":"accepted"}'::jsonb, ARRAY[$3::uuid], '[2020-01-01,)'::tstzrange)`, uuid.New(), tenantA, repoScopeA)
	execIn(tenantB, `INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period) VALUES ($1, 1, $2, '{"slug":"beta-only","title":"Beta Only","status":"accepted"}'::jsonb, ARRAY[$3::uuid], '[2020-01-01,)'::tstzrange)`, uuid.New(), tenantB, repoScopeB)

	personA := scanIn(tenantA, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Alice A') RETURNING id`, tenantA)
	personB := scanIn(tenantB, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Bob B') RETURNING id`, tenantB)
	agentA := scanIn(tenantA, `INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, 'agent', 'Agent A', $2) RETURNING id`, tenantA, personA)
	agentB := scanIn(tenantB, `INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, 'agent', 'Agent B', $2) RETURNING id`, tenantB, personB)

	execIn(tenantA, `INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'admin')`, tenantA, personA)
	execIn(tenantB, `INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'admin')`, tenantB, personB)
	execIn(tenantA, `INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'agent')`, tenantA, agentA)
	execIn(tenantB, `INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'agent')`, tenantB, agentB)

	// API bearer logins.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'alice-api')`, tenantA, personA, apiAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'bob-api')`, tenantB, personB, apiAuth.Server.URL)
	// Ambiguous API bearer subject bound in both A and B.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'both-api')`, tenantA, personA, apiAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'both-api')`, tenantB, personB, apiAuth.Server.URL)

	// Remote MCP bearer logins.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'agent-a')`, tenantA, agentA, mcpAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'agent-b')`, tenantB, agentB, mcpAuth.Server.URL)
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'agent-both')`, tenantA, agentA, mcpAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'agent-both')`, tenantB, agentB, mcpAuth.Server.URL)

	// Browser/CLI OIDC logins.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'user-a')`, tenantA, personA, oidc.idp.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'user-b')`, tenantB, personB, oidc.idp.Server.URL)

	// Bind GitHub installations.
	if _, err := tenancy.BindInstallation(t.Context(), app, tenancy.BindOptions{Tenant: tenantA, Installation: 401}); err != nil {
		t.Fatal(err)
	}
	if _, err := tenancy.BindInstallation(t.Context(), app, tenancy.BindOptions{Tenant: tenantB, Installation: 402}); err != nil {
		t.Fatal(err)
	}

	// Register live agent pins for each tenant.
	registerPin := func(tid uuid.UUID, name, repo string) (ed25519.PrivateKey, string) {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(spki)
		execIn(tid, `INSERT INTO verification.agent_pin (tenant_id, name, repo, env, pin_sha256, public_key_der) VALUES ($1, $2, $3, 'prod', $4, $5)`,
			tid, name, repo, sum[:], spki)
		return priv, hex.EncodeToString(sum[:])
	}
	privA, pinHexA := registerPin(tenantA, "pin-a", "alpha-org/repo-a")
	privB, pinHexB := registerPin(tenantB, "pin-b", "beta-org/repo-b")

	// Start ONE multi-tenant API handler serving both tenants.
	handler, err := New(t.Context(), Config{
		DB:             app,
		MultiTenant:    true,
		Issuer:         apiAuth.Server.URL,
		Audience:       apiAudience,
		MCPIssuer:      mcpAuth.Server.URL,
		MCPResourceURL: mcpResource,
		PublicURL:      "https://ipso.example.test",
		Providers: []login.ProviderConfig{{
			ID: "idp", Kind: login.KindOIDC, Issuer: oidc.idp.Server.URL, ClientID: "ipso-login", ClientSecretEnv: "IPSO_LOGIN_IDP_SECRET",
		}},
		Secrets:      func(string) string { return "client-secret" },
		CIAudience:   ciAudience,
		CIIssuer:     ciAuth.Server.URL,
		Repositories: githubApp,
		Client:       apiAuth.Server.Client(),
	})
	if err != nil {
		t.Fatalf("New multi-tenant: %v", err)
	}

	// 1. API bearer tokens: strict isolation + ambiguous subject fail-closed.
	tokA := apiAuth.Token(apiAudience, nil, authntest.Subject("alice-api"))
	tokB := apiAuth.Token(apiAudience, nil, authntest.Subject("bob-api"))
	tokBoth := apiAuth.Token(apiAudience, nil, authntest.Subject("both-api"))

	recA := get(handler, "/v1/scopes", tokA)
	if recA.Code != http.StatusOK || !strings.Contains(recA.Body.String(), "alpha-org") || strings.Contains(recA.Body.String(), "beta-org") {
		t.Fatalf("API bearer A: %d %s", recA.Code, recA.Body)
	}
	recB := get(handler, "/v1/scopes", tokB)
	if recB.Code != http.StatusOK || !strings.Contains(recB.Body.String(), "beta-org") || strings.Contains(recB.Body.String(), "alpha-org") {
		t.Fatalf("API bearer B: %d %s", recB.Code, recB.Body)
	}
	if recBoth := get(handler, "/v1/scopes", tokBoth); recBoth.Code != http.StatusForbidden {
		t.Fatalf("ambiguous API bearer: %d %s, want 403", recBoth.Code, recBoth.Body)
	}
	// Closing both-api's login in Tenant A unblocks Tenant B unambiguously!
	execIn(tenantA, `UPDATE identity.login SET closed_at = now() WHERE issuer = $1 AND subject = 'both-api'`, apiAuth.Server.URL)
	recBothAfter := get(handler, "/v1/scopes", tokBoth)
	if recBothAfter.Code != http.StatusOK || !strings.Contains(recBothAfter.Body.String(), "beta-org") || strings.Contains(recBothAfter.Body.String(), "alpha-org") {
		t.Fatalf("API bearer after closing A login: %d %s", recBothAfter.Code, recBothAfter.Body)
	}
	// Primed loginCache must not serve a stale tenant when a subject moves from A to B within loginTTL.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'mover-api')`, tenantA, personA, apiAuth.Server.URL)
	tokMover := apiAuth.Token(apiAudience, nil, authntest.Subject("mover-api"))
	if rec := get(handler, "/v1/scopes", tokMover); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("primed mover in A: %d %s", rec.Code, rec.Body)
	}
	execIn(tenantA, `UPDATE identity.login SET closed_at = now() WHERE issuer = $1 AND subject = 'mover-api'`, apiAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'mover-api')`, tenantB, personB, apiAuth.Server.URL)
	if rec := get(handler, "/v1/scopes", tokMover); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "beta-org") || strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("moved mover to B within TTL: %d %s", rec.Code, rec.Body)
	}

	// 2. Remote MCP bearer tokens: isolation + ambiguous subject fail-closed.
	mcpTokA := mcpAuth.Token(mcpResource, []string{"ipso.read"}, authntest.Subject("agent-a"))
	mcpTokB := mcpAuth.Token(mcpResource, []string{"ipso.read"}, authntest.Subject("agent-b"))
	mcpTokBoth := mcpAuth.Token(mcpResource, []string{"ipso.read"}, authntest.Subject("agent-both"))
	callRepoA := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"decisions.applicable","arguments":{"repo":"alpha-org/repo-a"},` + metaLatest + `}}`
	callRepoB := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"decisions.applicable","arguments":{"repo":"beta-org/repo-b"},` + metaLatest + `}}`
	if rec := mcpCall(handler, mcpTokA, "tools/call", callRepoA); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alpha-only") || strings.Contains(rec.Body.String(), "beta-only") {
		t.Fatalf("MCP agent A on repo-a: %d %s", rec.Code, rec.Body)
	}
	// Agent A querying Tenant B's repo sees zero decisions from Tenant B.
	if rec := mcpCall(handler, mcpTokA, "tools/call", callRepoB); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "beta-only") {
		t.Fatalf("MCP agent A on repo-b leaked tenant B: %d %s", rec.Code, rec.Body)
	}
	if rec := mcpCall(handler, mcpTokB, "tools/call", callRepoB); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "beta-only") || strings.Contains(rec.Body.String(), "alpha-only") {
		t.Fatalf("MCP agent B on repo-b: %d %s", rec.Code, rec.Body)
	}
	if rec := mcpCall(handler, mcpTokBoth, "tools/call", callRepoA); rec.Code != http.StatusForbidden {
		t.Fatalf("ambiguous MCP agent: %d %s, want 403", rec.Code, rec.Body)
	}

	// 3. Browser sessions + inviting a subject already bound in Tenant A into Tenant B.
	oidc.setSubject("user-a")
	attemptA, stateA := oidc.beginBrowser(t, handler)
	cbA := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+stateA, nil, attemptA)
	if cbA.Code != http.StatusSeeOther {
		t.Fatalf("browser callback A: %d %s", cbA.Code, cbA.Body)
	}
	cookieA := cookieOf(cbA, "__Host-ipso-session")
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, cookieA); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alpha-org") || strings.Contains(rec.Body.String(), "beta-org") {
		t.Fatalf("browser cookie A: %d %s", rec.Code, rec.Body)
	}

	oidc.setSubject("user-b")
	attemptB, stateB := oidc.beginBrowser(t, handler)
	cbB := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+stateB, nil, attemptB)
	if cbB.Code != http.StatusSeeOther {
		t.Fatalf("browser callback B: %d %s", cbB.Code, cbB.Body)
	}
	cookieB := cookieOf(cbB, "__Host-ipso-session")
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, cookieB); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "beta-org") || strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("browser cookie B: %d %s", rec.Code, rec.Body)
	}

	// Invite user-a (already bound in Tenant A) into Tenant B.
	invTok, invHash, err := identity.NewInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.WithAction(t.Context(), app, tenantB, personB, "api.create_invitation", func(tx *sql.Tx) (string, error) {
		_, err := identity.CreateInvitation(t.Context(), tx, personB, "Alice in B", identity.RoleViewer, invHash)
		return "invitation", err
	}); err != nil {
		t.Fatal(err)
	}
	oidc.setSubject("user-a")
	invStart := postJSON(handler, "/auth/invitation/idp", `{"token":"`+invTok+`"}`, cookieA)
	if invStart.Code != http.StatusOK {
		t.Fatalf("invitation start: %d %s", invStart.Code, invStart.Body)
	}
	var invAns struct {
		Location string `json:"location"`
	}
	if err := json.Unmarshal(invStart.Body.Bytes(), &invAns); err != nil {
		t.Fatal(err)
	}
	invLoc, _ := url.Parse(invAns.Location)
	oidc.mu.Lock()
	oidc.challenge = invLoc.Query().Get("code_challenge")
	oidc.nonce = invLoc.Query().Get("nonce")
	oidc.mu.Unlock()
	invAttempt := cookieOf(invStart, "__Host-ipso-login")
	invCB := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+invLoc.Query().Get("state"), nil, invAttempt)
	if invCB.Code != http.StatusSeeOther {
		t.Fatalf("invited callback for user-a into B: %d %s", invCB.Code, invCB.Body)
	}
	cookieAInB := cookieOf(invCB, "__Host-ipso-session")
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, cookieAInB); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "beta-org") || strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("cookie from invitation into B: %d %s", rec.Code, rec.Body)
	}
	// Previous Tenant A session was ended cross-tenant when replaced!
	if rec := request(handler, http.MethodGet, "/v1/scopes", nil, cookieA); rec.Code != http.StatusUnauthorized {
		t.Fatalf("previous Tenant A cookie after cross-tenant replacement: %d, want 401", rec.Code)
	}
	// Plain non-invitation sign-in for user-a now fails closed with 403 (bound in both A and B).
	attemptAmbig, stateAmbig := oidc.beginBrowser(t, handler)
	if rec := request(handler, http.MethodGet, "/auth/callback/idp?code=good-code&state="+stateAmbig, nil, attemptAmbig); rec.Code != http.StatusForbidden {
		t.Fatalf("plain sign-in for ambiguous user-a: %d %s, want 403", rec.Code, rec.Body)
	}

	// 4. CLI sessions (ipsocli_): Tenant B user signs in, reads Tenant B only, and logs out.
	cliTokB := oidc.signInCLI(t, handler, "user-b")
	if rec := get(handler, "/v1/scopes", cliTokB); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "beta-org") || strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("CLI token B: %d %s", rec.Code, rec.Body)
	}
	if rec := request(handler, http.MethodPost, "/auth/cli/logout", map[string]string{"Authorization": "Bearer " + cliTokB}); rec.Code != http.StatusNoContent {
		t.Fatalf("CLI logout B: %d", rec.Code)
	}
	if rec := get(handler, "/v1/scopes", cliTokB); rec.Code != http.StatusUnauthorized {
		t.Fatalf("CLI token B after logout: %d, want 401", rec.Code)
	}

	// 5. CI verdict uploads: Repo A -> Tenant A, Repo B -> Tenant B.
	mintCI := func(repo string, repoID, ownerID int64) string {
		claims := map[string]any{
			"repository": repo, "repository_id": strconv.FormatInt(repoID, 10), "repository_owner_id": strconv.FormatInt(ownerID, 10),
			"run_id": "9001", "run_attempt": "1", "sha": strings.Repeat("ab", 20), "ref": "refs/heads/main",
			"event_name": "push", "workflow_ref": repo + "/.github/workflows/ci.yml@refs/heads/main",
		}
		var opts []authntest.TokenOption
		for k, v := range claims {
			opts = append(opts, authntest.Claim(k, v))
		}
		return ciAuth.Token(ciAudience, nil, opts...)
	}
	if rec := post(handler, mintCI("alpha-org/repo-a", 701, 91)); rec.Code != http.StatusCreated {
		t.Fatalf("CI upload A: %d %s", rec.Code, rec.Body)
	}
	if rec := post(handler, mintCI("beta-org/repo-b", 702, 92)); rec.Code != http.StatusCreated {
		t.Fatalf("CI upload B: %d %s", rec.Code, rec.Body)
	}
	var countA, countB int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload WHERE tenant_id = $1 AND repo = 'alpha-org/repo-a'`, tenantA).Scan(&countA); err != nil || countA != 1 {
		t.Fatalf("CI upload count in A = %d (%v), want 1", countA, err)
	}
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload WHERE tenant_id = $1 AND repo = 'beta-org/repo-b'`, tenantB).Scan(&countB); err != nil || countB != 1 {
		t.Fatalf("CI upload count in B = %d (%v), want 1", countB, err)
	}

	// 6. Live agent pin uploads: Pin A -> Tenant A, Pin B -> Tenant B, cross-tenant decision -> 403.
	postLive := func(priv ed25519.PrivateKey, pinHex, slug string) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(map[string]any{
			"check": "plan",
			"report": map[string]any{
				"report_version": 1, "ipso_version": "0.5.0", "evaluated_at": time.Now().UTC().Format(time.RFC3339), "env": "prod",
				"build_sha256": strings.Repeat("11", 32), "plan_sha256": strings.Repeat("22", 32),
				"verdicts": []any{map[string]any{"decision_id": "01M5QJ0V9EVXKR4C89XNBNT5GG", "slug": slug, "check_index": 0, "mode": "block", "result": "pass", "violations": 0}},
			},
		})
		ts := time.Now().UTC().Format(time.RFC3339)
		sig, err := verification.SignLivePayload(priv, ts, payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ipso-Agent-Pin", pinHex)
		req.Header.Set("X-Ipso-Timestamp", ts)
		req.Header.Set("X-Ipso-Signature", sig)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := postLive(privA, pinHexA, "alpha-only"); rec.Code != http.StatusCreated {
		t.Fatalf("live upload A: %d %s", rec.Code, rec.Body)
	}
	if rec := postLive(privA, pinHexA, "beta-only"); rec.Code != http.StatusForbidden {
		t.Fatalf("live upload A for tenant B decision: %d %s, want 403", rec.Code, rec.Body)
	}
	if rec := postLive(privB, pinHexB, "beta-only"); rec.Code != http.StatusCreated {
		t.Fatalf("live upload B: %d %s", rec.Code, rec.Body)
	}
	var liveA, liveB int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload WHERE tenant_id = $1 AND repo = 'alpha-org/repo-a' AND source_kind = 'live'`, tenantA).Scan(&liveA); err != nil || liveA != 1 {
		t.Fatalf("live upload count in A = %d (%v), want 1", liveA, err)
	}
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM verification.upload WHERE tenant_id = $1 AND repo = 'beta-org/repo-b' AND source_kind = 'live'`, tenantB).Scan(&liveB); err != nil || liveB != 1 {
		t.Fatalf("live upload count in B = %d (%v), want 1", liveB, err)
	}

	// 7. Single-tenant regression: a subject bound in BOTH Tenant A and Tenant B still works
	// when served by a single-tenant control plane pinned to Tenant A.
	execIn(tenantA, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'shared-single')`, tenantA, personA, apiAuth.Server.URL)
	execIn(tenantB, `INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'shared-single')`, tenantB, personB, apiAuth.Server.URL)
	singleA, err := New(t.Context(), Config{
		DB:       app,
		Tenant:   tenantA,
		Issuer:   apiAuth.Server.URL,
		Audience: apiAudience,
		Client:   apiAuth.Server.Client(),
	})
	if err != nil {
		t.Fatalf("single-tenant A: %v", err)
	}
	sharedTok := apiAuth.Token(apiAudience, nil, authntest.Subject("shared-single"))
	if rec := get(singleA, "/v1/scopes", sharedTok); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alpha-org") {
		t.Fatalf("single-tenant regression for shared subject: %d %s", rec.Code, rec.Body)
	}
}

func TestMultiTenantStartRefusesUnmigratedDatabase(t *testing.T) {
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Drop one required multi-tenant lookup function as migrator to simulate an unmigrated DB.
	migrator := database.Open(t, pgtest.Migrate)
	if _, err := migrator.ExecContext(t.Context(), `DROP FUNCTION identity.login_tenants(text, text)`); err != nil {
		t.Fatal(err)
	}
	app := database.Open(t, pgtest.App)
	apiAuth := authntest.NewServer(t)

	_, err := New(t.Context(), Config{
		DB:          app,
		MultiTenant: true,
		Issuer:      apiAuth.Server.URL,
		Audience:    apiAudience,
		Client:      apiAuth.Server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "run ipso-server migrate") {
		t.Fatalf("err = %v, want startup failure naming ipso-server migrate", err)
	}
	// Sanity check: verification.RequireAgentPinLookup is still present when login_tenants is gone,
	// and dropping verification.agent_pin_tenant is also caught when login_tenants exists.
	_ = verification.RequireAgentPinLookup
}
