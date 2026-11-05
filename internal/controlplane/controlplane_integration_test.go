//go:build integration

package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
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
	handler := s.handler(t, s.config(false))

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
	// Without an MCP issuer the MCP path is not served.
	if rec := list(handler, s.mcpAuth.Token(mcpResource, nil, subject("agent-1"))); rec.Code != http.StatusUnauthorized {
		t.Errorf("the MCP path without an MCP issuer: status %d, want the API's 401", rec.Code)
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
