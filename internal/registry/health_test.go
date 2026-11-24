package registry

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

func TestComputeValidityAndComplianceSeparatesValidityComplianceAndStaleness(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	did := uuid.MustParse("00000000-0000-4000-8000-000000000099")
	body := []byte(`{
		"id":"01J9Z000000000000000000001",
		"slug":"deny-egress-0-0-0-0",
		"title":"Deny unrestricted egress on production firewalls",
		"statement":"Production firewall rules must never allow 0.0.0.0/0 egress.",
		"status":"verified",
		"criticality":"blocking",
		"checks":[
			{"engine":"llm","target":"json-snapshot","mode":"block","status":"verified","max_age_days":7}
		]
	}`)

	t.Run("fresh passing live verdict yields valid and compliant with AI model metadata", func(t *testing.T) {
		h := ComputeValidityAndCompliance(
			did, body, now.Add(-30*24*time.Hour), nil, "", []string{"acme/net"}, nil,
			[]storedVerdictSnap{{
				CheckIndex:    0,
				SourceKind:    "live",
				Command:       "llm",
				Repo:          "acme/net",
				Env:           "prod",
				Result:        "pass",
				EvaluatedAt:   now.Add(-2 * 24 * time.Hour),
				ModelID:       "mistral-large-eu",
				PromptVersion: "llm-check-v1",
			}},
			false, nil, "prod", now,
		)
		if h.Validity.State != "valid" || h.Compliance.State != "compliant" {
			t.Fatalf("unexpected health: %+v", h)
		}
		if h.Compliance.Scopes[0].LatestLive == nil || h.Compliance.Scopes[0].LatestLive.ModelID != "mistral-large-eu" {
			t.Fatalf("expected model_id preserved on LatestLive, got %+v", h.Compliance.Scopes[0])
		}
	})

	t.Run("verdict older than max_age_days becomes stale even when passing", func(t *testing.T) {
		h := ComputeValidityAndCompliance(
			did, body, now.Add(-30*24*time.Hour), nil, "", []string{"acme/net"}, nil,
			[]storedVerdictSnap{{
				CheckIndex:  0,
				SourceKind:  "live",
				Command:     "llm",
				Repo:        "acme/net",
				Env:         "prod",
				Result:      "pass",
				EvaluatedAt: now.Add(-10 * 24 * time.Hour),
			}},
			false, nil, "prod", now,
		)
		if h.Validity.State != "valid" || h.Compliance.State != "stale" || !h.Compliance.Scopes[0].LatestLive.Stale {
			t.Fatalf("expected stale compliance, got %+v", h)
		}
	})

	t.Run("open premise marks validity needs_review while compliance stays compliant", func(t *testing.T) {
		h := ComputeValidityAndCompliance(
			did, body, now.Add(-30*24*time.Hour), nil, "", []string{"acme/net"},
			[]mcptools.PremiseAlert{{PremiseID: "p1", ReasonCode: "premise_failed"}},
			[]storedVerdictSnap{{
				CheckIndex:  0,
				SourceKind:  "change",
				Command:     "llm",
				Repo:        "acme/net",
				Env:         "prod",
				Result:      "pass",
				EvaluatedAt: now.Add(-1 * time.Hour),
			}},
			false, nil, "prod", now,
		)
		if h.Validity.State != "needs_review" || h.Compliance.State != "compliant" {
			t.Fatalf("expected needs_review validity + compliant compliance, got %+v", h)
		}
	})
}
