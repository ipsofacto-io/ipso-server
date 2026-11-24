package llmgw

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrOptInRequired indicates the tenant has not enabled the requested LLM capability in llm.tenant_policy.
var ErrOptInRequired = errors.New("llm: tenant opt-in is required")

// TenantPolicy records per-tenant opt-in switches for authoring assistance and engine: llm evaluation.
type TenantPolicy struct {
	AllowAuthoringAssist bool      `json:"allow_authoring_assist"`
	AllowCheckEval       bool      `json:"allow_check_eval"`
	UpdatedAt            time.Time `json:"updated_at,omitzero"`
}

// GetTenantPolicy reads the tenant's LLM opt-in settings, defaulting to false/false when unset.
func GetTenantPolicy(ctx context.Context, db *sql.DB, tenant uuid.UUID) (TenantPolicy, error) {
	if db == nil || tenant == uuid.Nil {
		return TenantPolicy{}, errors.New("llm policy: database and tenant are required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TenantPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return TenantPolicy{}, err
	}
	var out TenantPolicy
	err = tx.QueryRowContext(ctx, `
		SELECT allow_authoring_assist, allow_check_eval, updated_at
		FROM llm.tenant_policy
		WHERE tenant_id = ipso.current_tenant()`).Scan(&out.AllowAuthoringAssist, &out.AllowCheckEval, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPolicy{}, nil
	}
	return out, err
}

// SetTenantPolicy updates the tenant's LLM opt-in settings inside caller's READ COMMITTED tenant transaction.
func SetTenantPolicy(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, allowAssist, allowEval bool) (TenantPolicy, error) {
	if tenant == uuid.Nil {
		return TenantPolicy{}, errors.New("llm policy: tenant is required")
	}
	var out TenantPolicy
	err := tx.QueryRowContext(ctx, `
		INSERT INTO llm.tenant_policy (tenant_id, allow_authoring_assist, allow_check_eval, updated_at)
		VALUES ($1, $2, $3, clock_timestamp())
		ON CONFLICT (tenant_id) DO UPDATE
		SET allow_authoring_assist = EXCLUDED.allow_authoring_assist,
		    allow_check_eval = EXCLUDED.allow_check_eval,
		    updated_at = clock_timestamp()
		RETURNING allow_authoring_assist, allow_check_eval, updated_at`,
		tenant, allowAssist, allowEval).Scan(&out.AllowAuthoringAssist, &out.AllowCheckEval, &out.UpdatedAt)
	return out, err
}
