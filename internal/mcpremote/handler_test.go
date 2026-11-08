package mcpremote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

const (
	testResource = "https://mcp.example.test/mcp"
	metaLatest   = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
)

var (
	testTenant    = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	testPrincipal = uuid.MustParse("00000000-0000-4000-8000-0000000000aa")
)

type recordingBackend struct {
	callers  []Caller
	proposed int
	caller   Caller
}

func (r *recordingBackend) Applicable(context.Context, mcptools.ApplicableInput) (mcptools.ApplicableOutput, error) {
	r.callers = append(r.callers, r.caller)
	return mcptools.ApplicableOutput{Decisions: []mcptools.Decision{}}, nil
}

func (r *recordingBackend) Get(context.Context, mcptools.GetInput) (mcptools.GetOutput, error) {
	return mcptools.GetOutput{}, errors.New("no decision")
}

func (r *recordingBackend) Evaluate(context.Context, mcptools.EvaluateInput) (mcptools.EvaluateOutput, error) {
	return mcptools.EvaluateOutput{}, errors.New("not here")
}

func (r *recordingBackend) Propose(context.Context, mcptools.ProposeInput) (mcptools.ProposeOutput, error) {
	r.proposed++
	return mcptools.ProposeOutput{ProposalID: "p1", Status: "proposed"}, nil
}

// testPolicy is the role policy the server runs, compiled once for the package's tests.
var testPolicy = func() func(t testing.TB) *authz.Policy {
	var once sync.Once
	var policy *authz.Policy
	var err error
	return func(t testing.TB) *authz.Policy {
		t.Helper()
		once.Do(func() { policy, err = authz.New(context.Background()) })
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
}()

// principalAs answers the role policy for a principal of this kind with these bindings, the way
// internal/controlplane does from the database.
func principalAs(t testing.TB, kind string, grants ...identity.Grant) AuthorizeFunc {
	policy := testPolicy(t)
	return func(ctx context.Context, _ Caller, action authz.Action) (bool, error) {
		return policy.Allow(ctx, authz.Input{Kind: kind, Grants: grants, Action: action})
	}
}

// anAgent is the principal the tests call as unless they say otherwise: an agent with its role.
func anAgent(t testing.TB) AuthorizeFunc {
	return principalAs(t, identity.KindAgent, identity.Grant{Role: identity.RoleAgent})
}

type rig struct {
	auth    *authntest.Server
	backend *recordingBackend
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigAs(t, anAgent(t))
}

func newRigAs(t *testing.T, authorize AuthorizeFunc) *rig {
	t.Helper()
	auth := authntest.NewServer(t)
	backend := &recordingBackend{}
	handler, err := NewHandler(Config{ResourceURL: testResource, AuthorizationServers: []string{auth.Server.URL}, Version: "test"},
		verifierFor(t, auth, testResource),
		func(_ context.Context, claims authn.Claims) (Caller, bool) {
			if claims.Subject != "agent-1" {
				return Caller{}, false
			}
			return Caller{Tenant: testTenant, Principal: testPrincipal}, true
		},
		func(caller Caller) mcptools.Backend {
			backend.caller = caller
			return backend
		},
		authorize)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{auth: auth, backend: backend, handler: handler}
}

func (r *rig) post(token, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, testResource, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func toolCall(name string) (string, map[string]string) {
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":{},` + metaLatest + `}}`
	return body, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": name}
}

func TestUnauthenticatedCallsAreRejected(t *testing.T) {
	r := newRig(t)
	good := r.auth.Token(testResource, []string{ScopeRead})
	other := authntest.NewServer(t)
	expired := r.auth.Token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder {
		return b.Expiration(time.Now().Add(-time.Hour))
	})
	wrongIssuer := r.auth.Token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder { return b.Issuer("https://elsewhere.test") })
	for name, token := range map[string]string{
		"no token":          "",
		"garbage":           "not-a-token",
		"another audience":  r.auth.Token("https://other.example.test/mcp", []string{ScopeRead}),
		"another signer":    other.Token(testResource, []string{ScopeRead}),
		"expired":           expired,
		"another issuer":    wrongIssuer,
		"too large":         good + strings.Repeat("a", 16<<10),
		"an unsigned token": unsignedToken(t, r.auth.Server.URL),
		"a token signed by a symmetric key made from the public key": symmetricToken(t, r),
	} {
		t.Run(name, func(t *testing.T) {
			body, headers := toolCall(mcptools.ToolApplicable)
			rec := r.post(token, body, headers)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if !strings.Contains(challenge, `resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp"`) {
				t.Fatalf("challenge: %s", challenge)
			}
			if len(r.backend.callers) != 0 {
				t.Fatal("a tool ran")
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost, testResource+"?access_token="+good, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a token in the URL was accepted: %d", rec.Code)
	}
}

func unsignedToken(t *testing.T, issuer string) string {
	t.Helper()
	token, err := jwt.NewBuilder().Issuer(issuer).Audience([]string{testResource}).Subject("agent-1").Expiration(time.Now().Add(time.Hour)).Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.NewSerializer().Serialize(token)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJub25lIn0." + encodeSegment(signed) + "."
}

// symmetricToken tries the classic confusion: HS256 with the published key as the secret.
func symmetricToken(t *testing.T, r *rig) string {
	t.Helper()
	public, err := r.auth.Signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewBuilder().Issuer(r.auth.Server.URL).Audience([]string{testResource}).Subject("agent-1").Expiration(time.Now().Add(time.Hour)).Claim("scope", ScopeRead).Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), secret))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestAnAuthorizedClientCallsTheTools(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead, ScopePropose})

	body, headers := toolCall(mcptools.ToolApplicable)
	rec := r.post(token, body, headers)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"isError":false`) || !strings.Contains(rec.Body.String(), `"resultType":"complete"`) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(r.backend.callers) != 1 || r.backend.callers[0].Tenant != testTenant {
		t.Fatalf("callers %+v", r.backend.callers)
	}

	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + metaLatest + `}}`
	rec = r.post(token, list, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"})
	for _, tool := range []string{mcptools.ToolApplicable, mcptools.ToolGet, mcptools.ToolEvaluate, mcptools.ToolPropose} {
		if !strings.Contains(rec.Body.String(), tool) {
			t.Errorf("%s is not listed: %s", tool, rec.Body)
		}
	}

	body, headers = toolCall(mcptools.ToolPropose)
	if rec = r.post(token, body, headers); rec.Code != http.StatusOK || r.backend.proposed != 1 {
		t.Fatalf("propose: %d %s", rec.Code, rec.Body)
	}

	legacy := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	if rec = r.post(token, legacy, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("a legacy client: %d %s", rec.Code, rec.Body)
	}
	if rec = r.post(token, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("a notification: %d", rec.Code)
	}
}

func TestScopesAreLeastPrivilege(t *testing.T) {
	r := newRig(t)
	read := r.auth.Token(testResource, []string{ScopeRead})
	body, headers := toolCall(mcptools.ToolPropose)
	rec := r.post(read, body, headers)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="ipso.propose"`) {
		t.Fatalf("status %d: %s %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body)
	}
	if r.backend.proposed != 0 {
		t.Fatal("a read token proposed")
	}
	none := r.auth.Token(testResource, nil)
	body, headers = toolCall(mcptools.ToolApplicable)
	if rec = r.post(none, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("a token with no scope read: %d", rec.Code)
	}
	propose := r.auth.Token(testResource, []string{ScopePropose})
	if rec = r.post(propose, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("a propose token read: %d", rec.Code)
	}
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaLatest + `}}`
	if rec = r.post(none, discover, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}); rec.Code != http.StatusOK {
		t.Fatalf("discovery needs only a valid token: %d %s", rec.Code, rec.Body)
	}
}

func TestATenantInTheRequestChangesNothing(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead})
	body, headers := toolCall(mcptools.ToolApplicable)
	headers["X-Tenant-Id"] = uuid.NewString()
	if rec := r.post(token, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if r.backend.callers[0].Tenant != testTenant {
		t.Fatalf("tenant %s", r.backend.callers[0].Tenant)
	}
}

func TestATokenForNoPrincipalIsRefused(t *testing.T) {
	r := newRig(t)
	stranger := r.auth.Token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder { return b.Subject("nobody") })
	body, headers := toolCall(mcptools.ToolApplicable)
	if rec := r.post(stranger, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTransportRules(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead, ScopePropose})
	body, good := toolCall(mcptools.ToolApplicable)
	with := func(name, value string) map[string]string {
		headers := map[string]string{}
		for k, v := range good {
			headers[k] = v
		}
		headers[name] = value
		return headers
	}
	for name, tc := range map[string]struct {
		headers map[string]string
		status  int
		code    float64
	}{
		"method mismatch":                     {with("Mcp-Method", "tools/list"), 400, codeHeaderMismatch},
		"method case":                         {with("Mcp-Method", "TOOLS/CALL"), 400, codeHeaderMismatch},
		"method missing":                      {with("Mcp-Method", ""), 400, codeHeaderMismatch},
		"name mismatch":                       {with("Mcp-Name", "decisions.propose"), 400, codeHeaderMismatch},
		"name missing":                        {with("Mcp-Name", ""), 400, codeHeaderMismatch},
		"version mismatch":                    {with("MCP-Protocol-Version", "2025-06-18"), 400, codeHeaderMismatch},
		"version missing":                     {with("MCP-Protocol-Version", ""), 400, codeHeaderMismatch},
		"an unknown version against the body": {with("MCP-Protocol-Version", "2099-01-01"), 400, codeHeaderMismatch},
		"whitespace is fine":                  {with("Mcp-Name", "  decisions.applicable  "), 200, 0},
	} {
		t.Run(name, func(t *testing.T) {
			rec := r.post(token, body, tc.headers)
			if rec.Code != tc.status {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			if tc.code == 0 {
				return
			}
			var reply struct {
				ID    int `json:"id"`
				Error struct {
					Code float64 `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Error.Code != tc.code || reply.ID != 7 {
				t.Fatalf("%+v", reply)
			}
		})
	}
	if rec := r.post(token, body, with("Content-Type", "text/plain")); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("content type: %d", rec.Code)
	}
	if rec := r.post(token, strings.Repeat("x", maxBodyBytes+1), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: %d", rec.Code)
	}
	if rec := r.post(token, "{", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, httptest.NewRequest(method, testResource, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: %d", method, rec.Code)
		}
	}
}

func TestStatelessFailuresCarryTheirHTTPStatus(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead})
	latest := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}
	for name, tc := range map[string]struct {
		body    string
		headers map[string]string
		status  int
		code    float64
	}{
		"no _meta":                                 {`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, latest, 400, codeInvalidParams},
		"a discover probe with no _meta":           {`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}`, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}, 400, codeInvalidParams},
		"a body version the header disagrees with": {`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"v999.0.0","io.modelcontextprotocol/clientCapabilities":{}}}}`, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}, 400, codeHeaderMismatch},
		"no capabilities":                          {`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, latest, 400, codeInvalidParams},
		"no version":                               {`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}}`, latest, 400, codeInvalidParams},
		"removed method":                           {`{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + metaLatest + `}}`, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "ping"}, 404, codeMethodNotFound},
		"unknown method":                           {`{"jsonrpc":"2.0","id":1,"method":"nope","params":{` + metaLatest + `}}`, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "nope"}, 404, codeMethodNotFound},
		"older client":                             {`{"jsonrpc":"2.0","id":1,"method":"nope"}`, nil, 200, codeMethodNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			rec := r.post(token, tc.body, tc.headers)
			if rec.Code != tc.status {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			var reply struct {
				ID    int `json:"id"`
				Error struct {
					Code float64 `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Error.Code != tc.code || reply.ID != 1 {
				t.Fatalf("%s", rec.Body)
			}
		})
	}
}

func TestUnsupportedVersionNamesWhatIsSupported(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`
	rec := r.post(token, body, map[string]string{"MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var reply struct {
		Error struct {
			Code float64 `json:"code"`
			Data struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Error.Code != codeUnsupportedVersion || reply.Error.Data.Requested != "2099-01-01" || reply.Error.Data.Supported[0] != mcptools.LatestVersion {
		t.Fatalf("%s", rec.Body)
	}
}

func TestDNSRebindingIsRefused(t *testing.T) {
	r := newRig(t)
	token := r.auth.Token(testResource, []string{ScopeRead})
	body, headers := toolCall(mcptools.ToolApplicable)
	req := httptest.NewRequest(http.MethodPost, testResource, strings.NewReader(body))
	req.Host = "attacker.example"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a foreign Host: %d", rec.Code)
	}
	headers["Origin"] = "https://attacker.example"
	if rec := r.post(token, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("a foreign Origin: %d", rec.Code)
	}
	headers["Origin"] = "https://mcp.example.test"
	if rec := r.post(token, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("its own Origin: %d", rec.Code)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	r := newRig(t)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://mcp.example.test/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var doc struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
		Bearer   []string `json:"bearer_methods_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != testResource || doc.Servers[0] != r.auth.Server.URL || len(doc.Scopes) != 2 || doc.Bearer[0] != "header" {
		t.Fatalf("%+v", doc)
	}
}

func TestDiscoverRefusesAServerClientsCouldNotUse(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*authntest.Server)
		want   string
	}{
		"no client id metadata": {func(a *authntest.Server) { delete(a.Meta, "client_id_metadata_document_supported") }, "Client ID Metadata"},
		"no pkce":               {func(a *authntest.Server) { a.Meta["code_challenge_methods_supported"] = []string{"plain"} }, "S256"},
		"another issuer":        {func(a *authntest.Server) { a.Meta["issuer"] = "https://elsewhere.test" }, "names the issuer"},
	} {
		t.Run(name, func(t *testing.T) {
			auth := authntest.NewServer(t)
			tc.change(auth)
			_, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testResource)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestNewHandlerRefusesABadConfig(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier := verifierFor(t, auth, testResource)
	callers := func(context.Context, authn.Claims) (Caller, bool) { return Caller{}, false }
	backends := func(Caller) mcptools.Backend { return nil }
	authorize := anAgent(t)
	for name, url := range map[string]string{
		"plain http": "http://mcp.example.test/mcp",
		"no path":    "https://mcp.example.test",
		"a fragment": "https://mcp.example.test/mcp#x",
		"a query":    "https://mcp.example.test/mcp?x=1",
		"not a url":  "::",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHandler(Config{ResourceURL: url, AuthorizationServers: []string{"https://a.test"}}, verifier, callers, backends, authorize); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := NewHandler(Config{ResourceURL: "http://127.0.0.1:8080/mcp", AuthorizationServers: []string{"https://a.test"}}, verifier, callers, backends, authorize); err != nil {
		t.Fatalf("loopback http: %v", err)
	}
	if _, err := NewHandler(Config{ResourceURL: testResource}, verifier, callers, backends, authorize); err == nil {
		t.Fatal("no authorization server")
	}
	if _, err := NewHandler(Config{ResourceURL: testResource, AuthorizationServers: []string{"https://a.test"}}, nil, callers, backends, authorize); err == nil {
		t.Fatal("no verifier")
	}
	if _, err := NewHandler(Config{ResourceURL: testResource, AuthorizationServers: []string{"https://a.test"}}, verifier, callers, backends, nil); err == nil {
		t.Fatal("no authorize function")
	}
}

func TestErrorsLeakNothing(t *testing.T) {
	r := newRig(t)
	rec := r.post("not-a-token", "{}", nil)
	raw, _ := io.ReadAll(rec.Body)
	if strings.Contains(string(raw), "jwt") || strings.Contains(string(raw), "signature") {
		t.Fatalf("a verifier error reached the client: %s", raw)
	}
}

// limitedRig serves a handler with a small limit and a short deadline. Subject agent-2 speaks for
// another tenant.
func limitedRig(t *testing.T, cfg Config, backend mcptools.Backend) (*authntest.Server, http.Handler) {
	t.Helper()
	auth := authntest.NewServer(t)
	cfg.ResourceURL, cfg.AuthorizationServers, cfg.Version = testResource, []string{auth.Server.URL}, "test"
	handler, err := NewHandler(cfg, verifierFor(t, auth, testResource),
		func(_ context.Context, claims authn.Claims) (Caller, bool) {
			if claims.Subject == "agent-2" {
				return Caller{Tenant: uuid.MustParse("00000000-0000-4000-8000-00000000000b"), Principal: testPrincipal}, true
			}
			return Caller{Tenant: testTenant, Principal: testPrincipal}, true
		},
		func(Caller) mcptools.Backend { return backend },
		anAgent(t))
	if err != nil {
		t.Fatal(err)
	}
	return auth, handler
}

func callTool(handler http.Handler, token string) *httptest.ResponseRecorder {
	body, headers := toolCall(mcptools.ToolApplicable)
	req := httptest.NewRequest(http.MethodPost, testResource, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestATenantPastItsLimitIsRefused(t *testing.T) {
	backend := &recordingBackend{}
	auth, handler := limitedRig(t, Config{Rate: 0.001, Burst: 2}, backend)
	token := auth.Token(testResource, []string{ScopeRead})
	for i := range 2 {
		if rec := callTool(handler, token); rec.Code != http.StatusOK {
			t.Fatalf("call %d: status %d: %s", i, rec.Code, rec.Body)
		}
	}
	rec := callTool(handler, token)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429: %s", rec.Code, rec.Body)
	}
	if retry, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || retry < 1 {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if len(backend.callers) != 2 {
		t.Errorf("the tool ran %d times, want 2", len(backend.callers))
	}
	// Another tenant has its own bucket.
	other := auth.Token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder { return b.Subject("agent-2") })
	if rec := callTool(handler, other); rec.Code != http.StatusOK {
		t.Errorf("another tenant: status %d: %s", rec.Code, rec.Body)
	}
	// A caller with no valid token is refused before it is charged to any tenant.
	if rec := callTool(handler, "garbage"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a bad token: status %d, want 401", rec.Code)
	}
}

// slowBackend waits until its request ends.
type slowBackend struct{ recordingBackend }

func (b *slowBackend) Applicable(ctx context.Context, _ mcptools.ApplicableInput) (mcptools.ApplicableOutput, error) {
	<-ctx.Done()
	return mcptools.ApplicableOutput{}, ctx.Err()
}

func TestARequestPastItsDeadlineIs503(t *testing.T) {
	auth, handler := limitedRig(t, Config{Timeout: 50 * time.Millisecond}, &slowBackend{})
	rec := callTool(handler, auth.Token(testResource, []string{ScopeRead}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503: %s", rec.Code, rec.Body)
	}
}

func TestConfigPathsNameTheEndpointAndItsMetadata(t *testing.T) {
	got := Config{ResourceURL: testResource}.Paths()
	want := []string{"/mcp", "/.well-known/oauth-protected-resource/mcp"}
	if !slices.Equal(got, want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
}

// Every role on every tool and method: the scope says what the token may ask for, and the role policy
// what the principal may do, so a token with every scope still reaches a tool only through a role that
// grants it. A refused call reaches no tool.
func TestEveryRoleOnEveryToolAndMethod(t *testing.T) {
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + metaLatest + `}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{` + metaLatest + `}}`
	type request struct {
		name    string
		body    string
		headers map[string]string
		action  authz.Action
	}
	requests := []request{
		{"server/discover", discover, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}, authz.Member},
		{"tools/list", list, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}, authz.RegistryRead},
	}
	for _, tool := range []string{mcptools.ToolApplicable, mcptools.ToolGet, mcptools.ToolEvaluate} {
		body, headers := toolCall(tool)
		requests = append(requests, request{tool, body, headers, authz.RegistryRead})
	}
	body, headers := toolCall(mcptools.ToolPropose)
	requests = append(requests, request{mcptools.ToolPropose, body, headers, authz.ProposalCreate})

	// The roles that grant each action, as ADR-0108 states them.
	everyRole := identity.Roles
	grants := map[authz.Action][]string{
		authz.Member:         everyRole,
		authz.RegistryRead:   everyRole,
		authz.ProposalCreate: {identity.RoleContributor, identity.RoleDecisionOwner, identity.RoleApprover, identity.RoleAgent},
	}
	for _, role := range append([]string{""}, identity.Roles...) {
		kind := identity.KindHuman
		if role == identity.RoleAgent {
			kind = identity.KindAgent
		}
		var bindings []identity.Grant
		if role != "" {
			bindings = []identity.Grant{{Role: role}}
		}
		for _, req := range requests {
			name := role
			if name == "" {
				name = "no role"
			}
			t.Run(name+"/"+req.name, func(t *testing.T) {
				r := newRigAs(t, principalAs(t, kind, bindings...))
				token := r.auth.Token(testResource, []string{ScopeRead, ScopePropose})
				rec := r.post(token, req.body, req.headers)
				want := slices.Contains(grants[req.action], role)
				if refused := rec.Code == http.StatusForbidden; refused == want {
					t.Fatalf("status %d, want allowed %v: %s", rec.Code, want, rec.Body)
				}
				if !want && (len(r.backend.callers) != 0 || r.backend.proposed != 0) {
					t.Fatal("a refused call reached a tool")
				}
				if !want && !strings.Contains(rec.Body.String(), "no role of this principal allows this") {
					t.Errorf("body %s", rec.Body)
				}
			})
		}
	}
}

func TestAPolicyThatCannotDecideRefusesTheCall(t *testing.T) {
	r := newRigAs(t, func(context.Context, Caller, authz.Action) (bool, error) {
		return false, errors.New("the store is down")
	})
	token := r.auth.Token(testResource, []string{ScopeRead})
	body, headers := toolCall(mcptools.ToolApplicable)
	rec := r.post(token, body, headers)
	if rec.Code != http.StatusInternalServerError || len(r.backend.callers) != 0 {
		t.Fatalf("status %d, %d calls", rec.Code, len(r.backend.callers))
	}
	if strings.Contains(rec.Body.String(), "store") {
		t.Errorf("the cause reached the client: %s", rec.Body)
	}
}
