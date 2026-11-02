package llmgw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")

// sent is one request the fake provider saw.
type sent struct {
	url    string
	header http.Header
	body   map[string]any
}

// provider answers every request with the next response in line, and records what it was sent.
// It stands in for the network, so the URL it records is the one the gateway chose.
type provider struct {
	mu        sync.Mutex
	requests  []sent
	responses []*http.Response
	fail      error
}

func (p *provider) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, _ := io.ReadAll(req.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	p.requests = append(p.requests, sent{url: req.URL.String(), header: req.Header.Clone(), body: body})
	if p.fail != nil {
		return nil, p.fail
	}
	if len(p.responses) == 0 {
		return reply(http.StatusInternalServerError, `{}`), nil
	}
	resp := p.responses[0]
	p.responses = p.responses[1:]
	resp.Request = req
	return resp, nil
}

func reply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

const (
	chatOK     = `{"model":"served-model","choices":[{"message":{"role":"assistant","content":"{\"candidates\":[]}"}}],"usage":{"prompt_tokens":40,"completion_tokens":10}}`
	converseOK = `{"output":{"message":{"role":"assistant","content":[{"text":"{\"candidates\":"},{"text":"[]}"}]}},"stopReason":"end_turn","usage":{"inputTokens":30,"outputTokens":5}}`
)

// memLedger is an in-memory Ledger.
type memLedger struct {
	mu     sync.Mutex
	tokens map[uuid.UUID]int64
}

func (l *memLedger) Reserve(_ context.Context, tenant uuid.UUID, _ time.Time, tokens, limit int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tokens[tenant]+tokens > limit {
		return ErrBudget
	}
	l.tokens[tenant] += tokens
	return nil
}

func (l *memLedger) Settle(_ context.Context, tenant uuid.UUID, _ time.Time, delta int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens[tenant] = max(l.tokens[tenant]+delta, 0)
	return nil
}

func newGateway(t *testing.T, cfg Config, p *provider) (*Gateway, *memLedger) {
	t.Helper()
	setKeys(t)
	ledger := &memLedger{tokens: map[uuid.UUID]int64{}}
	g, err := New(cfg, ledger, &http.Client{Transport: p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g, ledger
}

func only(names ...string) Config {
	cfg := baseConfig()
	cfg.Default = names
	cfg.MonthlyTokens = 100000
	return cfg
}

func TestRoutesToMistral(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	g, ledger := newGateway(t, only("mistral"), p)
	answer, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "sys", User: "usr", MaxTokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Text != `{"candidates":[]}` || answer.Model != "served-model" || answer.Route != "mistral" {
		t.Fatalf("answer = %+v", answer)
	}
	got := p.requests[0]
	if got.url != "https://api.mistral.ai/v1/chat/completions" || got.header.Get("Authorization") != "Bearer synthetic-ipso_llm_mistral" {
		t.Fatalf("request = %s %v", got.url, got.header)
	}
	messages := got.body["messages"].([]any)
	if got.body["model"] != "mistral-medium-2508" || len(messages) != 2 || got.body["temperature"] != float64(0) || got.body["max_tokens"] != float64(100) ||
		got.body["response_format"].(map[string]any)["type"] != "json_object" {
		t.Fatalf("body = %v", got.body)
	}
	if ledger.tokens[tenantA] != 50 {
		t.Fatalf("charged %d tokens, want the 50 the provider reported", ledger.tokens[tenantA])
	}
}

func TestRoutesToBedrockEU(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, converseOK)}}
	g, ledger := newGateway(t, only("bedrock-eu"), p)
	answer, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "sys", User: "usr"})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Text != `{"candidates":[]}` || answer.Model != bedrockRoute.Model || answer.Route != "bedrock-eu" {
		t.Fatalf("answer = %+v", answer)
	}
	got := p.requests[0]
	if got.url != "https://bedrock-runtime.eu-central-1.amazonaws.com/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/converse" {
		t.Fatalf("url = %s", got.url)
	}
	if got.header.Get("Authorization") != "Bearer synthetic-ipso_llm_bedrock" {
		t.Fatalf("header = %v", got.header)
	}
	if _, ok := got.body["system"].([]any); !ok || got.body["inferenceConfig"].(map[string]any)["maxTokens"] != float64(defaultMaxTokens) {
		t.Fatalf("body = %v", got.body)
	}
	if ledger.tokens[tenantA] != 35 {
		t.Fatalf("charged %d tokens, want 35", ledger.tokens[tenantA])
	}
}

func TestRoutesToAzureEU(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	g, _ := newGateway(t, only("azure-eu"), p)
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "sys", User: "usr"}); err != nil {
		t.Fatal(err)
	}
	got := p.requests[0]
	if got.url != "https://ipso-eu.openai.azure.com/openai/v1/chat/completions" || got.header.Get("api-key") != "synthetic-ipso_llm_azure" || got.header.Get("Authorization") != "" {
		t.Fatalf("request = %s %v", got.url, got.header)
	}
	if got.body["model"] != "gpt-4-1-mini" {
		t.Fatalf("body = %v", got.body)
	}
}

func TestBudgetIsEnforcedBeforeAnythingIsSent(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	cfg := only("mistral")
	cfg.MonthlyTokens = 1000
	g, ledger := newGateway(t, cfg, p)

	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u", MaxTokens: 2000}); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget", err)
	}
	ledger.tokens[tenantA] = 990
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u", MaxTokens: 20}); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget", err)
	}
	if len(p.requests) != 0 {
		t.Fatalf("%d requests left the server over budget", len(p.requests))
	}
}

func TestBudgetIsPerTenant(t *testing.T) {
	tenantB := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	cfg := only("mistral")
	cfg.MonthlyTokens = 1000
	cfg.Tenants = map[string]Tenant{tenantB.String(): {MonthlyTokens: 5000}}
	g, ledger := newGateway(t, cfg, p)
	ledger.tokens[tenantA] = 1000
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u", MaxTokens: 10}); !errors.Is(err, ErrBudget) {
		t.Fatalf("tenant A err = %v, want ErrBudget", err)
	}
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantB, System: "s", User: "u", MaxTokens: 2000}); err != nil {
		t.Fatalf("tenant B err = %v", err)
	}
}

func TestRedactionHappensBeforeAnyProviderCall(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	cfg := only("mistral")
	cfg.Redact = []string{`\bACME-[0-9]{6}\b`}
	g, _ := newGateway(t, cfg, p)
	// Split, so that a secret scanner does not read these fakes as credentials.
	secrets := []string{"AKIA" + "ABCDEFGHIJKLMNOP", "ghp_" + "abcdefghijklmnopqrstuvwxyz0123", "jane.doe@example.com", "ACME-123456", "password=" + "hunter22"}
	_, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "keep " + secrets[3], User: "text " + strings.Join(secrets, " ")})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(p.requests[0].body)
	for _, secret := range secrets {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("%q reached the provider", secret)
		}
	}
	if !strings.Contains(string(encoded), "[REDACTED]") {
		t.Errorf("body = %s, want redaction markers", encoded)
	}
}

func TestFailoverOnAnOutage(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(503, `{"error":"echo of the prompt"}`), reply(200, converseOK)}}
	g, _ := newGateway(t, only("mistral", "bedrock-eu"), p)
	answer, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Route != "bedrock-eu" || len(p.requests) != 2 {
		t.Fatalf("answer %+v after %d requests", answer, len(p.requests))
	}
}

func TestNoFailoverOnARejectedRequest(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(400, `{"error":"echo of the prompt"}`), reply(200, converseOK)}}
	g, ledger := newGateway(t, only("mistral", "bedrock-eu"), p)
	_, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"})
	if err == nil || len(p.requests) != 1 {
		t.Fatalf("err %v after %d requests", err, len(p.requests))
	}
	if strings.Contains(err.Error(), "echo") {
		t.Fatalf("err = %v holds the provider's body", err)
	}
	if ledger.tokens[tenantA] != 0 {
		t.Fatalf("a failed call left %d tokens charged", ledger.tokens[tenantA])
	}
}

func TestEveryRouteDownCostsNothing(t *testing.T) {
	p := &provider{fail: errors.New("connection refused")}
	g, ledger := newGateway(t, only("mistral", "bedrock-eu"), p)
	_, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"})
	if err == nil || ledger.tokens[tenantA] != 0 {
		t.Fatalf("err %v, %d tokens charged", err, ledger.tokens[tenantA])
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	redirect := reply(http.StatusFound, ``)
	redirect.Header.Set("Location", "https://collector.example/steal")
	p := &provider{responses: []*http.Response{redirect, reply(200, chatOK)}}
	g, _ := newGateway(t, only("mistral"), p)
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"}); err == nil {
		t.Fatal("a redirect was accepted as an answer")
	}
	for _, request := range p.requests {
		if strings.Contains(request.url, "collector.example") {
			t.Fatal("the gateway followed the redirect with the key")
		}
	}
}

func TestNoTenantIsRefused(t *testing.T) {
	p := &provider{}
	g, _ := newGateway(t, only("mistral"), p)
	if _, err := g.Complete(t.Context(), Request{System: "s", User: "u"}); err == nil || len(p.requests) != 0 {
		t.Fatalf("err %v after %d requests", err, len(p.requests))
	}
}

func TestForCompletesForOneTenant(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, chatOK)}}
	g, ledger := newGateway(t, only("mistral"), p)
	if _, err := g.For(tenantA)(t.Context(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if ledger.tokens[tenantA] != 50 {
		t.Fatalf("charged %d tokens to tenant A", ledger.tokens[tenantA])
	}
}

func TestRoutesToATenantsOpenAICompatibleEndpoint(t *testing.T) {
	setKeys(t)
	own := Route{Name: "acme-openai", Provider: OpenAI, Endpoint: "https://llm.acme.example/v1/", Model: "gpt-4.1", KeyEnv: "IPSO_LLM_TENANT", AllowNonEU: true}
	cfg := only("mistral")
	cfg.Tenants = map[string]Tenant{tenantA.String(): {BYOK: []Route{own}}}
	p := &provider{responses: []*http.Response{reply(200, strings.Replace(chatOK, "served-model", strings.Repeat("x", 300), 1))}}
	g, _ := newGateway(t, cfg, p)
	answer, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"})
	if err != nil {
		t.Fatal(err)
	}
	got := p.requests[0]
	if got.url != "https://llm.acme.example/v1/chat/completions" || got.header.Get("Authorization") != "Bearer synthetic-ipso_llm_tenant" {
		t.Fatalf("request = %s %v", got.url, got.header)
	}
	if answer.Model != "gpt-4.1" {
		t.Fatalf("model = %q, want the route's model in place of an oversized name", answer.Model)
	}
}

func TestEmptyAnswerIsAnErrorAndIsCharged(t *testing.T) {
	p := &provider{responses: []*http.Response{reply(200, `{"choices":[{"message":{"content":null},"finish_reason":"content_filter"}],"usage":{"prompt_tokens":7,"completion_tokens":0}}`)}}
	g, ledger := newGateway(t, only("mistral"), p)
	if _, err := g.Complete(t.Context(), Request{Tenant: tenantA, System: "s", User: "u"}); err == nil {
		t.Fatal("an empty answer was returned as a success")
	}
	if ledger.tokens[tenantA] != 7 {
		t.Fatalf("charged %d tokens, want the 7 the provider reported", ledger.tokens[tenantA])
	}
}
