package proposals

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
)

// HumanInboxItem is one pending human-authored decision proposal (ADR-0161).
type HumanInboxItem struct {
	ID          uuid.UUID       `json:"id"`
	PrincipalID uuid.UUID       `json:"principal_id"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	CapturedAt  time.Time       `json:"captured_at"`
}

func humanInbox(ctx context.Context, db *sql.DB, tenant uuid.UUID, before any, limit int) ([]HumanInboxItem, error) {
	items := []HumanInboxItem{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, principal_id, status, payload, lower(sys_period)
			FROM proposals.human_proposal p
			WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id < $2::uuid)
			  AND NOT EXISTS (SELECT 1 FROM proposals.human_approval a WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			ORDER BY id DESC
			LIMIT $3`, tenant, before, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item HumanInboxItem
			var payload []byte
			if err := rows.Scan(&item.ID, &item.PrincipalID, &item.Status, &payload, &item.CapturedAt); err != nil {
				return err
			}
			item.Payload = payload
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

// InsertHumanProposal writes a pending human proposal inside caller's READ COMMITTED tenant transaction.
func InsertHumanProposal(ctx context.Context, tx *sql.Tx, tenant, author uuid.UUID, payload json.RawMessage) (uuid.UUID, error) {
	if tenant == uuid.Nil || author == uuid.Nil || len(payload) == 0 {
		return uuid.Nil, fmt.Errorf("%w: tenant, author, and payload are required", registry.ErrInvalidQuery)
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil || obj == nil {
		return uuid.Nil, fmt.Errorf("%w: payload must be a JSON object", registry.ErrInvalidQuery)
	}
	delete(obj, "status")
	title, _ := obj["title"].(string)
	statement, _ := obj["statement"].(string)
	if strings.TrimSpace(title) == "" || strings.TrimSpace(statement) == "" {
		return uuid.Nil, fmt.Errorf("%w: title and statement are required", registry.ErrInvalidQuery)
	}
	cleaned, err := json.Marshal(obj)
	if err != nil || len(cleaned) > 65536 {
		return uuid.Nil, fmt.Errorf("%w: payload exceeds maximum size", registry.ErrInvalidQuery)
	}
	var id uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO proposals.human_proposal (tenant_id, principal_id, payload)
		VALUES ($1, $2, $3::jsonb)
		RETURNING id`, tenant, author, string(cleaned)).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("insert human proposal: %w", err)
	}
	return id, nil
}

// LLMCheckProposal describes a drafted engine: llm check proposal for an existing decision version (ADR-0158).
type LLMCheckProposal struct {
	DecisionID    uuid.UUID
	Version       int
	Mode          string
	MaxAgeDays    *int
	Spec          llmcheck.Spec
	ModelID       string
	PromptVersion string
}

// InsertLLMCheckProposal validates an engine: llm spec (including allow+deny fixtures when Mode is "block")
// and records it in proposals.check_proposal inside caller's transaction. If autoApproveBy is non-nil, it also
// records check_approval in the same transaction.
func InsertLLMCheckProposal(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, p LLMCheckProposal, autoApproveBy *uuid.UUID) (uuid.UUID, error) {
	if tenant == uuid.Nil || p.DecisionID == uuid.Nil || p.Version < 1 {
		return uuid.Nil, fmt.Errorf("%w: tenant, decision, and version are required", registry.ErrInvalidQuery)
	}
	if p.MaxAgeDays != nil && (*p.MaxAgeDays < 1 || *p.MaxAgeDays > 365) {
		return uuid.Nil, fmt.Errorf("%w: max_age_days must be between 1 and 365", registry.ErrInvalidQuery)
	}
	raw, err := llmcheck.MarshalCanonical(p.Spec)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", registry.ErrInvalidQuery, err)
	}
	requireBlock := p.Mode == "" || p.Mode == "block"
	validated, err := llmcheck.ParseAndValidate(raw, "", requireBlock)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", registry.ErrInvalidQuery, err)
	}
	canonical, err := llmcheck.MarshalCanonical(validated)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", registry.ErrInvalidQuery, err)
	}
	fixturesJSON, err := json.Marshal(validated.Fixtures)
	if err != nil {
		return uuid.Nil, err
	}
	modelID := strings.TrimSpace(p.ModelID)
	if modelID == "" {
		modelID = "human-authored"
	}
	promptVer := strings.TrimSpace(p.PromptVersion)
	if promptVer == "" {
		promptVer = llmcheck.PromptVersion
	}
	digest := sha256.Sum256(canonical)
	var maxAge any
	if p.MaxAgeDays != nil {
		maxAge = *p.MaxAgeDays
	}
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO proposals.check_proposal
			(tenant_id, decision_id, decision_version, engine, target, spec, rego, rego_sha256,
			 fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version, max_age_days)
		VALUES ($1, $2, $3, 'llm', $4, $5::jsonb, $6, $7, $8::jsonb, $9, $9, false, $10, $11, $12)
		RETURNING id`,
		tenant, p.DecisionID, p.Version, validated.Target, string(canonical), string(canonical), digest[:],
		string(fixturesJSON), len(validated.Fixtures), modelID, promptVer, maxAge).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert llm check proposal: %w", err)
	}
	if autoApproveBy != nil && *autoApproveBy != uuid.Nil {
		if _, err := ApproveCheck(ctx, tx, tenant, *autoApproveBy, p.DecisionID, id, OutcomeApproved); err != nil {
			return uuid.Nil, err
		}
	}
	return id, nil
}
