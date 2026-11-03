//go:build pact

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/pact-foundation/pact-go/v2/consumer"
	m "github.com/pact-foundation/pact-go/v2/matchers"
)

// pactFile is the contract of the web app (consumer ipso-web, IPSO-62) with this API. This test
// writes it from nothing on every run, ci / pact fails when the committed file differs, and
// pact_provider_integration_test.go verifies it against the handler on PostgreSQL (ADR-0091).
const pactFile = "../../api/pacts/ipso-web-ipso-server.json"

// stateRegistry is the one provider state the pact names. Every row it describes is synthetic.
const stateRegistry = "tenant A holds decisions, scopes, a waiver, and proposals"

// rfc3339 is written out because the Timestamp matcher of pact-go uses a look-ahead, which the
// matching engine of the FFI does not support.
const rfc3339 = `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`

const (
	exampleValid = "2026-06-01T00:00:00Z"
	exampleKnown = "2026-11-01T00:00:00Z"
)

func timestamp(example string) m.Matcher { return m.Regex(example, rfc3339) }

type pair struct{ key, value string }

// webCall is one interaction: what the web app sends and the shape of what it reads back.
type webCall struct {
	description string
	state       string
	method      string
	path        string
	query       []pair
	token       bool
	body        any
	status      int
	headers     []pair
	answer      map[string]any
}

func webCalls() []webCall {
	decision := map[string]any{
		"id":      m.UUID(),
		"version": m.Integer(1),
		"body":    m.Like(map[string]any{"slug": "use-tls", "title": "use-tls"}),
	}
	page := func(key string, item any) map[string]any {
		return map[string]any{"valid": timestamp(exampleValid), "known": timestamp(exampleKnown), key: m.EachLike(item, 1)}
	}
	valid := []pair{{"valid", exampleValid}}
	return []webCall{
		{
			description: "a request without a token",
			method:      http.MethodGet,
			path:        "/v1/decisions",
			status:      http.StatusUnauthorized,
			headers:     []pair{{"WWW-Authenticate", `Bearer realm="ipso"`}},
			answer:      map[string]any{"error": "unauthorized"},
		},
		{
			description: "a request to resolve the decisions for changed paths",
			state:       stateRegistry,
			method:      http.MethodPost,
			path:        "/v1/resolve",
			token:       true,
			body:        map[string]any{"repo": "acme/api", "env": "prod", "paths": []string{"docs/a.md"}, "valid": exampleValid},
			status:      http.StatusOK,
			answer: map[string]any{
				"valid":       timestamp(exampleValid),
				"known":       timestamp(exampleKnown),
				"resolutions": m.EachLike(map[string]any{"path": m.Like("docs/a.md"), "decisions": m.EachLike(decision, 1)}, 1),
			},
		},
		{
			description: "a request for the decisions in force",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/decisions",
			query:       valid,
			token:       true,
			status:      http.StatusOK,
			answer:      page("decisions", decision),
		},
		{
			description: "a request for the decisions a slug names",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/decisions/use-tls",
			query:       valid,
			token:       true,
			status:      http.StatusOK,
			answer:      page("decisions", decision),
		},
		{
			description: "a request for the scope tree",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/scopes",
			token:       true,
			status:      http.StatusOK,
			answer: map[string]any{
				"known": timestamp(exampleKnown),
				"scopes": m.ArrayContaining([]any{
					map[string]any{"id": m.UUID(), "parent_id": nil, "kind": "org", "selector": m.Like("acme")},
					map[string]any{"id": m.UUID(), "parent_id": m.UUID(), "kind": m.Like("repo"), "selector": m.Like("acme/api")},
				}),
			},
		},
		{
			description: "a request for the waivers in force",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/waivers",
			query:       valid,
			token:       true,
			status:      http.StatusOK,
			answer: page("waivers", map[string]any{
				"id":          m.UUID(),
				"decision_id": m.UUID(),
				"scope_id":    m.UUID(),
				"ticket_ref":  m.Like("OPS-1"),
				"valid_from":  timestamp("2026-05-01T00:00:00Z"),
				"expires_at":  timestamp("2026-06-10T00:00:00Z"),
			}),
		},
		{
			description: "a request for the proposals from pull requests",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/proposals",
			token:       true,
			status:      http.StatusOK,
			answer: map[string]any{"proposals": m.EachLike(map[string]any{
				"id":             m.UUID(),
				"kind":           "decision",
				"origin":         "llm",
				"status":         "pending",
				"trust_level":    "untrusted",
				"payload":        m.Like(map[string]any{"title": "Use Postgres"}),
				"confidence":     m.Like(0.8),
				"model_id":       m.Like("m"),
				"prompt_version": m.Like("p"),
				"repo":           m.Like("acme/api"),
				"pr_number":      m.Integer(8),
				"source_url":     m.Regex("https://github.com/acme/api/pull/8", `^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+(#[A-Za-z0-9_-]+)?$`),
				"captured_at":    timestamp(exampleKnown),
			}, 1)},
		},
		{
			description: "a request for the proposals from coding agents",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/agent-proposals",
			token:       true,
			status:      http.StatusOK,
			answer: map[string]any{"agent_proposals": m.EachLike(map[string]any{
				"id":           m.UUID(),
				"principal_id": m.UUID(),
				"status":       "pending",
				"payload":      m.Like(map[string]any{"title": "Pin API versions"}),
				"captured_at":  timestamp(exampleKnown),
			}, 1)},
		},
		{
			description: "a request for the drafted checks",
			state:       stateRegistry,
			method:      http.MethodGet,
			path:        "/v1/check-proposals",
			token:       true,
			status:      http.StatusOK,
			answer: map[string]any{"check_proposals": m.EachLike(map[string]any{
				"id":               m.UUID(),
				"status":           "pending",
				"decision_id":      m.UUID(),
				"decision_version": m.Integer(1),
				"engine":           "opa",
				"target":           "agent-edit",
				"spec":             m.Like(map[string]any{}),
				"rego":             m.Like("package p"),
				"fixtures":         m.EachLike(map[string]any{}, 1),
				"repaired":         m.Like(false),
				"model_id":         m.Like("m"),
				"prompt_version":   m.Like("p"),
				"captured_at":      timestamp(exampleKnown),
			}, 1)},
		},
	}
}

// TestPactConsumerIpsoWeb plays the web app against the Pact mock server, one interaction at a
// time, and writes the pact.
func TestPactConsumerIpsoWeb(t *testing.T) {
	if err := os.Remove(pactFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, call := range webCalls() {
		mock, err := consumer.NewV4Pact(consumer.MockHTTPProviderConfig{
			Consumer: "ipso-web",
			Provider: "ipso-server",
			PactDir:  "../../api/pacts",
			LogDir:   t.TempDir(),
			Host:     "127.0.0.1",
		})
		if err != nil {
			t.Fatal(err)
		}
		interaction := mock.AddInteraction()
		if call.state != "" {
			interaction = interaction.Given(call.state)
		}
		err = interaction.
			UponReceiving(call.description).
			WithRequest(consumer.Method(call.method), call.path, func(b *consumer.V4RequestBuilder) {
				for _, q := range call.query {
					b.Query(q.key, m.String(q.value))
				}
				if call.token {
					b.Header("Authorization", m.Regex("Bearer token", `^Bearer \S+$`))
				}
				if call.body != nil {
					b.Header("Content-Type", m.String("application/json"))
					b.JSONBody(call.body)
				}
			}).
			WillRespondWith(call.status, func(b *consumer.V4ResponseBuilder) {
				b.Header("Content-Type", m.String("application/json"))
				for _, h := range call.headers {
					b.Header(h.key, m.String(h.value))
				}
				b.JSONBody(call.answer)
			}).
			ExecuteTest(t, func(config consumer.MockServerConfig) error {
				return call.send(config)
			})
		if err != nil {
			t.Fatalf("%s: %v", call.description, err)
		}
	}
}

// send is the request the web app makes and the least it reads from the answer.
func (c webCall) send(config consumer.MockServerConfig) error {
	query := url.Values{}
	for _, q := range c.query {
		query.Set(q.key, q.value)
	}
	target := url.URL{Scheme: "http", Host: net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), Path: c.path, RawQuery: query.Encode()}
	var body io.Reader
	if c.body != nil {
		data, err := json.Marshal(c.body)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequest(c.method, target.String(), body)
	if err != nil {
		return err
	}
	if c.token {
		request.Header.Set("Authorization", "Bearer token")
	}
	if c.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != c.status {
		return fmt.Errorf("status %d, want %d", response.StatusCode, c.status)
	}
	var answer map[string]any
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return fmt.Errorf("the answer is not a JSON object: %w", err)
	}
	return nil
}
