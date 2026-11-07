// Package llmgw is the LLM gateway (ADR-0081). Every model call ipso makes goes through it. It
// picks the tenant's routes, which are EU-resident unless the tenant brought its own key and
// accepted otherwise (ADR-0014), charges the tenant's monthly token budget, and redacts secrets
// before a prompt leaves the server. It logs no prompt and no answer. ipso-server webhooks builds it
// when IPSO_GATEWAY_CONFIG names a configuration (ADR-0103).
package llmgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/redact"
)

const (
	defaultMaxTokens = 2048
	maxMaxTokens     = 8192
	maxPromptBytes   = 256 << 10
	maxAnswerBytes   = 1 << 20
	routeTimeout     = 90 * time.Second
	// maxRouteTimeoutSeconds is the longest a route may set, for a model served on CPU.
	maxRouteTimeoutSeconds = 600
	settleTimeout          = 10 * time.Second
)

var (
	// ErrBudget means the call would pass the tenant's monthly token budget. Nothing was sent.
	ErrBudget = errors.New("llm: the tenant's monthly token budget is spent")
	// ErrUnavailable means every route of the tenant failed.
	ErrUnavailable = errors.New("llm: no route answered")
)

// Request is one call. System and User are redacted before any route sees them.
type Request struct {
	Tenant    uuid.UUID
	System    string
	User      string
	MaxTokens int
}

// Completion is one answer.
type Completion struct {
	Text         string
	Model        string
	Route        string
	InputTokens  int64
	OutputTokens int64
}

// Gateway sends requests to the tenant's routes in order until one answers.
type Gateway struct {
	tenants  map[uuid.UUID]policy
	defaults policy
	redact   []*regexp.Regexp
	ledger   Ledger
	client   *http.Client
	logger   *slog.Logger
	now      func() time.Time
}

// New checks the configuration and reads each route's key from the environment. A route that is
// not EU-resident, a missing key, or an invalid pattern stops it. client may be nil. The gateway
// never follows a redirect, so a key is not sent to another host.
func New(cfg Config, ledger Ledger, client *http.Client, logger *slog.Logger) (*Gateway, error) {
	if ledger == nil {
		return nil, errors.New("llm gateway: no ledger")
	}
	tenants, defaults, patterns, err := compile(cfg)
	if err != nil {
		return nil, fmt.Errorf("llm gateway: %w", err)
	}
	c := http.Client{}
	if client != nil {
		c = *client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Gateway{tenants: tenants, defaults: defaults, redact: patterns, ledger: ledger, client: &c, logger: logger, now: time.Now}, nil
}

// For returns a function that completes for one tenant, the shape the LLM pipelines take. Each
// pipeline bounds its own answer with maxTokens, and 0 takes the default.
func (g *Gateway) For(tenant uuid.UUID) func(ctx context.Context, system, user string, maxTokens int) (Completion, error) {
	return func(ctx context.Context, system, user string, maxTokens int) (Completion, error) {
		return g.Complete(ctx, Request{Tenant: tenant, System: system, User: user, MaxTokens: maxTokens})
	}
}

// Complete reserves the most the call can cost, tries each route, and settles the reservation to
// what the provider reports. A call that fails on every route costs nothing.
func (g *Gateway) Complete(ctx context.Context, req Request) (Completion, error) {
	if req.Tenant == uuid.Nil {
		return Completion{}, errors.New("llm: no tenant")
	}
	p, ok := g.tenants[req.Tenant]
	if !ok {
		p = g.defaults
	}
	system, user := g.scrub(req.System), g.scrub(req.User)
	if len(system)+len(user) > maxPromptBytes {
		return Completion{}, errors.New("llm: the prompt is larger than 256 KiB")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	maxTokens = min(maxTokens, maxMaxTokens)

	// A token is at least two bytes of prompt in practice, so this bounds the input from above.
	reserved := int64((len(system)+len(user))/2+1) + int64(maxTokens)
	month := monthOf(g.now())
	if err := g.ledger.Reserve(ctx, req.Tenant, month, reserved, p.limit); err != nil {
		return Completion{}, err
	}
	settle := func(used int64) {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
		defer cancel()
		if err := g.ledger.Settle(settleCtx, req.Tenant, month, used-reserved); err != nil {
			g.logger.Error("llm budget settle failed", "tenant", req.Tenant.String(), "error", err.Error())
		}
	}

	for _, route := range p.routes {
		started := g.now()
		answer, err := g.call(ctx, route, system, user, maxTokens)
		elapsed := g.now().Sub(started).Milliseconds()
		if err == nil {
			used := answer.InputTokens + answer.OutputTokens
			if used == 0 {
				used = reserved
			}
			settle(used)
			if strings.TrimSpace(answer.Text) == "" {
				// A content filter answers with no text. The tokens are spent, and nothing is returned.
				return Completion{}, fmt.Errorf("llm route %s: the answer is empty", route.name)
			}
			g.logger.Info("llm call", "tenant", req.Tenant.String(), "route", route.name, "provider", route.provider,
				"model", answer.Model, "input_tokens", answer.InputTokens, "output_tokens", answer.OutputTokens, "ms", elapsed)
			return answer, nil
		}
		g.logger.Warn("llm route failed", "tenant", req.Tenant.String(), "route", route.name, "provider", route.provider,
			"error", err.Error(), "ms", elapsed)
		if ctx.Err() != nil || !retryable(err) {
			settle(0)
			return Completion{}, fmt.Errorf("llm route %s: %w", route.name, err)
		}
	}
	settle(0)
	return Completion{}, ErrUnavailable
}

// scrub removes the built-in secrets and the operator's patterns.
func (g *Gateway) scrub(text string) string {
	text = redact.Text(text)
	for _, pattern := range g.redact {
		text = pattern.ReplaceAllString(text, redact.Marker)
	}
	return text
}

func monthOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// statusError is a provider answer that was not a success. It holds the status only, because a
// provider can echo the prompt in its error body.
type statusError int

func (s statusError) Error() string { return fmt.Sprintf("provider answered %d", int(s)) }

// retryable reports an error another route may not have: a timeout, a lost connection, rate
// limiting, or a server error. A rejected request would be rejected again.
func retryable(err error) bool {
	var status statusError
	if errors.As(err, &status) {
		return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (g *Gateway) call(ctx context.Context, route endpoint, system, user string, maxTokens int) (Completion, error) {
	ctx, cancel := context.WithTimeout(ctx, route.timeout)
	defer cancel()

	var body any
	if route.provider == Bedrock {
		body = converseRequest(system, user, maxTokens)
	} else {
		body = chatRequest(route.model, system, user, maxTokens)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return Completion{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.url, bytes.NewReader(encoded))
	if err != nil {
		return Completion{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if route.provider == Azure {
		req.Header.Set("api-key", route.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+route.key)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return Completion{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return Completion{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Completion{}, statusError(resp.StatusCode)
	}
	if len(raw) > maxAnswerBytes {
		return Completion{}, errors.New("the answer is larger than 1 MiB")
	}
	var answer Completion
	if route.provider == Bedrock {
		answer, err = converseAnswer(raw)
	} else {
		answer, err = chatAnswer(raw)
	}
	if err != nil {
		return Completion{}, err
	}
	// The model name ends up stored next to a proposal, so a provider's value must look like one.
	if !modelName.MatchString(answer.Model) {
		answer.Model = route.model
	}
	answer.Route = route.name
	return answer, nil
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the OpenAI chat completions shape that Mistral and Azure OpenAI also accept. Every
// prompt asks for one JSON object, so the route is asked to answer with valid JSON (ADR-0087).
// Converse has no such switch, and the callers check every answer either way.
func chatRequest(model, system, user string, maxTokens int) any {
	return map[string]any{
		"model":           model,
		"messages":        []message{{Role: "system", Content: system}, {Role: "user", Content: user}},
		"temperature":     0,
		"max_tokens":      maxTokens,
		"response_format": map[string]string{"type": "json_object"},
	}
}

func chatAnswer(raw []byte) (Completion, error) {
	var answer struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || len(answer.Choices) == 0 {
		return Completion{}, errors.New("the provider's answer is not a chat completion")
	}
	return Completion{
		Text:         answer.Choices[0].Message.Content,
		Model:        answer.Model,
		InputTokens:  max(answer.Usage.PromptTokens, 0),
		OutputTokens: max(answer.Usage.CompletionTokens, 0),
	}, nil
}

type textBlock struct {
	Text string `json:"text"`
}

// converseRequest is the Bedrock Converse shape. The model is in the URL.
func converseRequest(system, user string, maxTokens int) any {
	return map[string]any{
		"system":          []textBlock{{Text: system}},
		"messages":        []map[string]any{{"role": "user", "content": []textBlock{{Text: user}}}},
		"inferenceConfig": map[string]any{"maxTokens": maxTokens, "temperature": 0},
	}
}

func converseAnswer(raw []byte) (Completion, error) {
	var answer struct {
		Output struct {
			Message struct {
				Content []textBlock `json:"content"`
			} `json:"message"`
		} `json:"output"`
		Usage struct {
			InputTokens  int64 `json:"inputTokens"`
			OutputTokens int64 `json:"outputTokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil || len(answer.Output.Message.Content) == 0 {
		return Completion{}, errors.New("the provider's answer is not a Converse answer")
	}
	var text strings.Builder
	for _, block := range answer.Output.Message.Content {
		text.WriteString(block.Text)
	}
	return Completion{
		Text:         text.String(),
		InputTokens:  max(answer.Usage.InputTokens, 0),
		OutputTokens: max(answer.Usage.OutputTokens, 0),
	}, nil
}
