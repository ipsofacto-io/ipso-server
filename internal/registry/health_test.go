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
		if h.ID != did.String() {
			t.Fatalf("expected registry UUID id %s for keyset pagination, got %s", did, h.ID)
		}
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

	t.Run("sensitive tag redacts title and sets sensitive flag (ADR-0072)", func(t *testing.T) {
		sensitiveBody := []byte(`{
			"id":"01J9Z000000000000000000002",
			"slug":"vault-host",
			"title":"Internal HSM cluster address",
			"statement":"Confidential internal network address.",
			"status":"verified",
			"criticality":"blocking",
			"tags":["security","sensitive"],
			"checks":[{"engine":"opa","target":"terraform-plan","mode":"block","status":"verified"}]
		}`)
		h := ComputeValidityAndCompliance(
			did, sensitiveBody, now.Add(-10*24*time.Hour), nil, "", []string{"acme/sec"},
			[]mcptools.PremiseAlert{{PremiseID: "vault-probe", ReasonCode: "premise_failed", Detail: "https://internal.vault.acme/v1/sys/health /sealed"}},
			nil, false, nil, "", now,
		)
		if !h.Sensitive || h.Title != "" {
			t.Fatalf("expected sensitive=true and redacted empty title, got sensitive=%v title=%q", h.Sensitive, h.Title)
		}
		if len(h.Validity.OpenPremiseReasons) != 1 || h.Validity.OpenPremiseReasons[0].Detail != "" {
			t.Fatalf("expected sensitive premise detail redacted, got %+v", h.Validity.OpenPremiseReasons)
		}
	})

	t.Run("multiple checks aggregate per scope and passing change never masks failing live drift", func(t *testing.T) {
		multiBody := []byte(`{
			"id":"01J9Z000000000000000000003",
			"slug":"firewall-and-tags",
			"title":"Enforce firewall egress and resource tags",
			"statement":"Deny 0.0.0.0/0 egress and require cost tags.",
			"status":"verified",
			"criticality":"blocking",
			"checks":[
				{"engine":"opa","target":"terraform-plan","mode":"block","status":"verified","max_age_days":7},
				{"engine":"llm","target":"json-snapshot","mode":"block","status":"verified","max_age_days":7}
			]
		}`)
		h := ComputeValidityAndCompliance(
			did, multiBody, now.Add(-30*24*time.Hour), nil, "", []string{"acme/net"}, nil,
			[]storedVerdictSnap{
				{CheckIndex: 0, SourceKind: "change", Command: "plan", Repo: "acme/net", Env: "prod", Result: "pass", EvaluatedAt: now.Add(-1 * time.Hour)},
				{CheckIndex: 1, SourceKind: "live", Command: "llm", Repo: "acme/net", Env: "prod", Result: "fail", Violations: 1, EvaluatedAt: now.Add(-2 * time.Hour)},
				{CheckIndex: 1, SourceKind: "change", Command: "llm", Repo: "acme/net", Env: "prod", Result: "pass", EvaluatedAt: now.Add(-30 * time.Minute)},
			},
			false, nil, "prod", now,
		)
		if len(h.Compliance.Scopes) != 1 {
			t.Fatalf("expected 1 aggregated scope row for (acme/net, prod), got %d: %+v", len(h.Compliance.Scopes), h.Compliance.Scopes)
		}
		if h.Compliance.State != "violated" || h.Compliance.Scopes[0].State != "violated" {
			t.Fatalf("expected failing live verdict to keep compliance violated despite newer passing change, got %+v", h.Compliance)
		}
	})

	t.Run("env-less verdicts do not satisfy an explicit environment filter", func(t *testing.T) {
		h := ComputeValidityAndCompliance(
			did, body, now.Add(-30*24*time.Hour), nil, "", []string{"acme/net"}, nil,
			[]storedVerdictSnap{{
				CheckIndex:  0,
				SourceKind:  "change",
				Command:     "llm",
				Repo:        "acme/net",
				Env:         "",
				Result:      "pass",
				EvaluatedAt: now.Add(-1 * time.Hour),
			}},
			false, nil, "prod", now,
		)
		if h.Compliance.State != "unverified" {
			t.Fatalf("expected unverified when only env-less verdict exists for env=prod, got %+v", h.Compliance)
		}
	})
}
