package llmgw

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

func TestEvaluateCheckVerifiesGroundedQuote(t *testing.T) {
	fixtures := []llmcheck.Fixture{
		{ID: "restricted", Expect: "allow", Input: `{"cidr":"10.0.0.0/8"}`},
		{ID: "open", Expect: "deny", Input: `{"cidr":"0.0.0.0/0"}`},
	}

	t.Run("grounded quote fails check cleanly", func(t *testing.T) {
		complete := func(_ context.Context, _, _ string, _ int) (Completion, error) {
			return Completion{
				Model: "mistral-large-eu",
				Text:  `{"verdict":"fail","findings":[{"quote":"\"cidr\": \"0.0.0.0/0\"","message":"open egress"}]}`,
			}, nil
		}
		out, err := EvaluateCheck(t.Context(), complete, EvalRequest{
			Slug:          "deny-egress",
			Target:        "json-snapshot",
			Rubric:        "Deny unrestricted egress 0.0.0.0/0 on production firewalls.",
			Fixtures:      fixtures,
			RedactedInput: `{"rule":"egress","cidr": "0.0.0.0/0"}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.Verdict != "fail" || len(out.Findings) != 1 || out.ModelID != "mistral-large-eu" {
			t.Fatalf("unexpected eval response: %+v", out)
		}
	})

	t.Run("hallucinated quote turns into fail-closed error", func(t *testing.T) {
		complete := func(_ context.Context, _, _ string, _ int) (Completion, error) {
			return Completion{
				Model: "mistral-large-eu",
				Text:  `{"verdict":"fail","findings":[{"quote":"not-in-input","message":"bad"}]}`,
			}, nil
		}
		out, err := EvaluateCheck(t.Context(), complete, EvalRequest{
			Slug:          "deny-egress",
			Target:        "json-snapshot",
			Rubric:        "Deny unrestricted egress 0.0.0.0/0 on production firewalls.",
			Fixtures:      fixtures,
			RedactedInput: `{"rule":"egress","cidr": "10.0.0.0/8"}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.Verdict != "error" {
			t.Fatalf("expected fail-closed error on ungrounded quote, got %q", out.Verdict)
		}
	})
}

func TestAnalyzeVerifiabilityDeterministicFallback(t *testing.T) {
	ambiguous, err := AnalyzeVerifiability(t.Context(), uuid.Nil, nil, mcptools.VerifiabilityInput{
		Title:     "Firewall egress hygiene",
		Statement: "Services should try to restrict outbound firewall egress where appropriate.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous.Classification != "ambiguous" || len(ambiguous.Suggestions) == 0 || !strings.Contains(ambiguous.Suggestions[0], "MUST") {
		t.Fatalf("expected ambiguous diagnosis with rewrite suggestion, got %+v", ambiguous)
	}

	verifiable, err := AnalyzeVerifiability(t.Context(), uuid.Nil, nil, mcptools.VerifiabilityInput{
		Title:     "Block unrestricted firewall egress",
		Statement: "Production firewall egress rules must never allow 0.0.0.0/0.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifiable.Classification != "verifiable" || len(verifiable.CandidateChecks) < 2 {
		t.Fatalf("expected verifiable diagnosis with candidate checks, got %+v", verifiable)
	}
}
