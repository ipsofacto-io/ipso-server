package mcpremote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const (
	testResource = "https://mcp.example.test/mcp"
	metaLatest   = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
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

type rig struct {
	auth    *fakeAuthServer
	backend *recordingBackend
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()
	auth := newFakeAuthServer(t)
	backend := &recordingBackend{}
	handler, err := NewHandler(Config{ResourceURL: testResource, AuthorizationServers: []string{auth.server.URL}, Version: "test"},
		auth.verifier(testResource),
		func(_ context.Context, claims Claims) (Caller, bool) {
			if claims.Subject != "agent-1" {
				return Caller{}, false
			}
			return Caller{Tenant: testTenant, Principal: testPrincipal}, true
		},
		func(caller Caller) mcptools.Backend {
			backend.caller = caller
			return backend
		})
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
	good := r.auth.token(testResource, []string{ScopeRead})
	other := newFakeAuthServer(t)
	expired := r.auth.token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder {
		return b.Expiration(time.Now().Add(-time.Hour))
	})
	wrongIssuer := r.auth.token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder { return b.Issuer("https://elsewhere.test") })
	for name, token := range map[string]string{
		"no token":          "",
		"garbage":           "not-a-token",
		"another audience":  r.auth.token("https://other.example.test/mcp", []string{ScopeRead}),
		"another signer":    other.token(testResource, []string{ScopeRead}),
		"expired":           expired,
		"another issuer":    wrongIssuer,
		"too large":         good + strings.Repeat("a", maxTokenBytes),
		"an unsigned token": unsignedToken(t, r.auth.server.URL),
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
	public, err := r.auth.signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewBuilder().Issuer(r.auth.server.URL).Audience([]string{testResource}).Subject("agent-1").Expiration(time.Now().Add(time.Hour)).Claim("scope", ScopeRead).Build()
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
	token := r.auth.token(testResource, []string{ScopeRead, ScopePropose})

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
	read := r.auth.token(testResource, []string{ScopeRead})
	body, headers := toolCall(mcptools.ToolPropose)
	rec := r.post(read, body, headers)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="ipso.propose"`) {
		t.Fatalf("status %d: %s %s", rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body)
	}
	if r.backend.proposed != 0 {
		t.Fatal("a read token proposed")
	}
	none := r.auth.token(testResource, nil)
	body, headers = toolCall(mcptools.ToolApplicable)
	if rec = r.post(none, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("a token with no scope read: %d", rec.Code)
	}
	propose := r.auth.token(testResource, []string{ScopePropose})
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
	token := r.auth.token(testResource, []string{ScopeRead})
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
	stranger := r.auth.token(testResource, []string{ScopeRead}, func(b *jwt.Builder) *jwt.Builder { return b.Subject("nobody") })
	body, headers := toolCall(mcptools.ToolApplicable)
	if rec := r.post(stranger, body, headers); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTransportRules(t *testing.T) {
	r := newRig(t)
	token := r.auth.token(testResource, []string{ScopeRead, ScopePropose})
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
		"method mismatch":    {with("Mcp-Method", "tools/list"), 400, codeHeaderMismatch},
		"method case":        {with("Mcp-Method", "TOOLS/CALL"), 400, codeHeaderMismatch},
		"method missing":     {with("Mcp-Method", ""), 400, codeHeaderMismatch},
		"name mismatch":      {with("Mcp-Name", "decisions.propose"), 400, codeHeaderMismatch},
		"name missing":       {with("Mcp-Name", ""), 400, codeHeaderMismatch},
		"version mismatch":   {with("MCP-Protocol-Version", "2025-06-18"), 400, codeHeaderMismatch},
		"version missing":    {with("MCP-Protocol-Version", ""), 400, codeHeaderMismatch},
		"version unknown":    {with("MCP-Protocol-Version", "2099-01-01"), 400, codeUnsupportedVersion},
		"whitespace is fine": {with("Mcp-Name", "  decisions.applicable  "), 200, 0},
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

func TestDNSRebindingIsRefused(t *testing.T) {
	r := newRig(t)
	token := r.auth.token(testResource, []string{ScopeRead})
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
	if doc.Resource != testResource || doc.Servers[0] != r.auth.server.URL || len(doc.Scopes) != 2 || doc.Bearer[0] != "header" {
		t.Fatalf("%+v", doc)
	}
}

func TestDiscoverRefusesAServerClientsCouldNotUse(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*fakeAuthServer)
		want   string
	}{
		"no client id metadata": {func(a *fakeAuthServer) { delete(a.meta, "client_id_metadata_document_supported") }, "Client ID Metadata"},
		"no pkce":               {func(a *fakeAuthServer) { a.meta["code_challenge_methods_supported"] = []string{"plain"} }, "S256"},
		"another issuer":        {func(a *fakeAuthServer) { a.meta["issuer"] = "https://elsewhere.test" }, "names the issuer"},
		"keys over http":        {func(a *fakeAuthServer) { a.meta["jwks_uri"] = "http://elsewhere.test/jwks" }, "jwks_uri"},
		"no keys":               {func(a *fakeAuthServer) { a.keys = func() any { return map[string]any{"keys": []any{}} } }, "no keys"},
		"a symmetric key": {func(a *fakeAuthServer) {
			key, err := jwk.Import([]byte("a shared secret that anyone could read"))
			if err != nil {
				a.t.Fatal(err)
			}
			a.keys = func() any { return map[string]any{"keys": []any{key}} }
		}, "symmetric"},
	} {
		t.Run(name, func(t *testing.T) {
			auth := newFakeAuthServer(t)
			tc.change(auth)
			_, err := Discover(t.Context(), auth.server.Client(), auth.server.URL, testResource)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
	if _, err := Discover(t.Context(), http.DefaultClient, "http://plain.example.test", testResource); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err %v", err)
	}
	if _, err := Discover(t.Context(), nil, "https://x.test", testResource); err == nil {
		t.Fatal("no client")
	}
}

func TestVerifierPicksUpARotatedKeyOnlyWithinTheLimit(t *testing.T) {
	auth := newFakeAuthServer(t)
	verifier := auth.verifier(testResource)
	calls := 0
	rotated := newFakeAuthServer(t)
	rotated.server.Close()
	public, err := rotated.signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	auth.keys = func() any {
		calls++
		return map[string]any{"keys": []any{public}}
	}
	token := auth.token(testResource, []string{ScopeRead})
	auth.signing = rotated.signing
	newToken := auth.token(testResource, []string{ScopeRead})

	if _, err := verifier.Verify(t.Context(), newToken); err == nil {
		t.Fatal("a key this server has not read yet was accepted")
	}
	if calls != 0 {
		t.Fatalf("a bad token made this server call out %d times", calls)
	}
	verifier.mu.Lock()
	verifier.fetched = time.Now().Add(-2 * keyRefreshInterval)
	verifier.mu.Unlock()
	if _, err := verifier.Verify(t.Context(), newToken); err != nil {
		t.Fatalf("a rotated key: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("the rotated-out key still works")
	}
	if calls != 1 {
		t.Fatalf("a bad token inside the limit called out: %d", calls)
	}
}

func TestNewHandlerRefusesABadConfig(t *testing.T) {
	auth := newFakeAuthServer(t)
	verifier := auth.verifier(testResource)
	callers := func(context.Context, Claims) (Caller, bool) { return Caller{}, false }
	backends := func(Caller) mcptools.Backend { return nil }
	for name, url := range map[string]string{
		"plain http": "http://mcp.example.test/mcp",
		"no path":    "https://mcp.example.test",
		"a fragment": "https://mcp.example.test/mcp#x",
		"a query":    "https://mcp.example.test/mcp?x=1",
		"not a url":  "::",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHandler(Config{ResourceURL: url, AuthorizationServers: []string{"https://a.test"}}, verifier, callers, backends); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := NewHandler(Config{ResourceURL: "http://127.0.0.1:8080/mcp", AuthorizationServers: []string{"https://a.test"}}, verifier, callers, backends); err != nil {
		t.Fatalf("loopback http: %v", err)
	}
	if _, err := NewHandler(Config{ResourceURL: testResource}, verifier, callers, backends); err == nil {
		t.Fatal("no authorization server")
	}
	if _, err := NewHandler(Config{ResourceURL: testResource, AuthorizationServers: []string{"https://a.test"}}, nil, callers, backends); err == nil {
		t.Fatal("no verifier")
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
