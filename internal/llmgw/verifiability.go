package llmgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const VerifiabilityPromptVersion = "verifiability-v1"

// EvalRequest is the wire input to POST /v1/llm/evaluate (ADR-0158, ADR-0160).
type EvalRequest struct {
	DecisionID    string             `json:"decision_id,omitempty"`
	Slug          string             `json:"slug,omitempty"`
	Target        string             `json:"target"`
	Rubric        string             `json:"rubric"`
	Fixtures      []llmcheck.Fixture `json:"fixtures,omitempty"`
	RedactedInput string             `json:"redacted_input"`
	InputSHA256   string             `json:"input_sha256,omitempty"`
}

// EvalResponse is the grounded wire output of POST /v1/llm/evaluate. Raw excerpt text is never stored.
type EvalResponse struct {
	Verdict       string             `json:"verdict"`
	Summary       string             `json:"summary,omitempty"`
	Findings      []llmcheck.Finding `json:"findings"`
	ModelID       string             `json:"model_id"`
	PromptVersion string             `json:"prompt_version"`
}

// CompleteFunc matches Gateway.For(tenant).
type CompleteFunc func(ctx context.Context, system, user string, maxTokens int) (Completion, error)

// EvaluateCheck executes an engine: llm rubric via CompleteFunc and verifies verbatim quotes locally.
func EvaluateCheck(ctx context.Context, complete CompleteFunc, req EvalRequest) (EvalResponse, error) {
	if complete == nil {
		return EvalResponse{}, ErrUnavailable
	}
	spec := llmcheck.Spec{
		Version:  llmcheck.SpecVersion,
		Target:   req.Target,
		Rubric:   req.Rubric,
		Fixtures: req.Fixtures,
	}
	rawSpec, err := llmcheck.MarshalCanonical(spec)
	if err != nil {
		return EvalResponse{}, fmt.Errorf("invalid spec: %w", err)
	}
	validated, err := llmcheck.ParseAndValidate(rawSpec, "", false)
	if err != nil {
		return EvalResponse{}, fmt.Errorf("invalid spec: %w", err)
	}
	if len(req.RedactedInput) > validated.EffectiveMaxInputBytes() {
		return EvalResponse{}, errors.New("redacted_input exceeds maximum size")
	}
	redacted := llmcheck.Redact(req.RedactedInput)
	title := nonEmpty(req.Slug, nonEmpty(req.DecisionID, "decision"))
	comp, err := complete(ctx, llmcheck.SystemPrompt(), llmcheck.UserPrompt(title, validated, redacted), 1024)
	if err != nil {
		return EvalResponse{}, err
	}
	cleaned := stripMarkdownFence(comp.Text)
	verified, err := llmcheck.VerifyAnswer(redacted, []byte(cleaned))
	if err != nil {
		return EvalResponse{
			Verdict:       "error",
			Summary:       err.Error(),
			Findings:      []llmcheck.Finding{},
			ModelID:       nonEmpty(comp.Model, "unknown"),
			PromptVersion: llmcheck.PromptVersion,
		}, nil
	}
	return EvalResponse{
		Verdict:       verified.Verdict,
		Findings:      verified.Findings,
		ModelID:       nonEmpty(comp.Model, "unknown"),
		PromptVersion: llmcheck.PromptVersion,
	}, nil
}

// AnalyzeVerifiability diagnoses whether a draft decision is verifiable and proposes candidate checks and premises.
// When complete is nil (for example when tenant LLM assist is off or no gateway is configured), a deterministic
// structural analyzer runs locally so assisted authoring stays available without external model calls.
func AnalyzeVerifiability(ctx context.Context, tenant uuid.UUID, complete CompleteFunc, req mcptools.VerifiabilityInput) (mcptools.VerifiabilityOutput, error) {
	title := strings.TrimSpace(req.Title)
	statement := strings.TrimSpace(req.Statement)
	if title == "" || statement == "" {
		return mcptools.VerifiabilityOutput{}, errors.New("title and statement are required")
	}
	if complete != nil && tenant != uuid.Nil {
		if out, err := analyzeWithLLM(ctx, complete, req); err == nil {
			return out, nil
		}
	}
	return analyzeDeterministically(req), nil
}

func analyzeWithLLM(ctx context.Context, complete CompleteFunc, req mcptools.VerifiabilityInput) (mcptools.VerifiabilityOutput, error) {
	sys := strings.Join([]string{
		"You analyze software and infrastructure architecture decisions for verifiability.",
		"Respond ONLY with a JSON object matching:",
		`{"classification":"verifiable|ambiguous|human_attestation_only","summary":"short explanation","suggestions":["sharper wording"],"candidate_premises":[{"id":"regulatory-baseline","statement":"...","every":24}],"candidate_checks":[{"engine":"opa|semgrep|checkov|kyverno|llm","target":"diff|terraform-plan|kubernetes-manifest|json-snapshot|text","mode":"block|warn","max_age_days":7,"rationale":"...","llm_spec":"{...}"}]}`,
		"Never invent URLs or metrics about people.",
	}, "\n")
	payload, _ := json.Marshal(req)
	comp, err := complete(ctx, sys, string(payload), 1536)
	if err != nil {
		return mcptools.VerifiabilityOutput{}, err
	}
	var out mcptools.VerifiabilityOutput
	if err := json.Unmarshal([]byte(stripMarkdownFence(comp.Text)), &out); err != nil {
		return mcptools.VerifiabilityOutput{}, err
	}
	switch out.Classification {
	case "verifiable", "ambiguous", "human_attestation_only":
	default:
		return mcptools.VerifiabilityOutput{}, errors.New("unexpected verifiability classification")
	}
	if strings.TrimSpace(out.Summary) == "" {
		return mcptools.VerifiabilityOutput{}, errors.New("empty summary")
	}
	if out.Suggestions == nil {
		out.Suggestions = []string{}
	}
	if out.CandidateChecks == nil {
		out.CandidateChecks = []mcptools.CandidateCheck{}
	}
	if out.CandidatePremises == nil {
		out.CandidatePremises = []mcptools.CandidatePremise{}
	}
	out.AIGenerated = true
	out.ModelID = nonEmpty(comp.Model, "llm-gw")
	out.PromptVersion = VerifiabilityPromptVersion
	return out, nil
}

func analyzeDeterministically(req mcptools.VerifiabilityInput) mcptools.VerifiabilityOutput {
	return mcptools.AnalyzeVerifiability(req)
}

func stripMarkdownFence(s string) string {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "```") {
		if nl := strings.IndexByte(trimmed, '\n'); nl >= 0 {
			trimmed = trimmed[nl+1:]
		}
		if end := strings.LastIndex(trimmed, "```"); end >= 0 {
			trimmed = trimmed[:end]
		}
	}
	return strings.TrimSpace(trimmed)
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
