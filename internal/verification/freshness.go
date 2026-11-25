package verification

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FreshnessPolicy configures the default max_age_days threshold for an environment ("" for tenant default).
type FreshnessPolicy struct {
	Env        string    `json:"env"`
	MaxAgeDays int       `json:"max_age_days"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ListFreshnessPolicies returns all freshness thresholds configured for the tenant.
func ListFreshnessPolicies(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]FreshnessPolicy, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, errors.New("freshness: database and tenant are required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, reduce("freshness: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return nil, reduce("freshness: set tenant", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT env, max_age_days, updated_at
		FROM verification.freshness_policy
		WHERE tenant_id = ipso.current_tenant()
		ORDER BY env ASC`)
	if err != nil {
		return nil, reduce("freshness: read", err)
	}
	defer func() { _ = rows.Close() }()
	out := []FreshnessPolicy{}
	for rows.Next() {
		var p FreshnessPolicy
		if err := rows.Scan(&p.Env, &p.MaxAgeDays, &p.UpdatedAt); err != nil {
			return nil, reduce("freshness: scan", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetFreshnessPolicy upserts a freshness threshold inside caller's READ COMMITTED tenant transaction.
func SetFreshnessPolicy(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, env string, maxAgeDays int) (FreshnessPolicy, error) {
	env = strings.ToLower(strings.TrimSpace(env))
	if tenant == uuid.Nil || !plain(env, 0, maxEnvBytes) || maxAgeDays < 1 || maxAgeDays > 365 {
		return FreshnessPolicy{}, invalid("env must be short text and max_age_days between 1 and 365")
	}
	var out FreshnessPolicy
	err := tx.QueryRowContext(ctx, `
		INSERT INTO verification.freshness_policy (tenant_id, env, max_age_days, updated_at)
		VALUES ($1, $2, $3, clock_timestamp())
		ON CONFLICT (tenant_id, env) DO UPDATE
		SET max_age_days = EXCLUDED.max_age_days,
		    updated_at = clock_timestamp()
		RETURNING env, max_age_days, updated_at`,
		tenant, env, maxAgeDays).Scan(&out.Env, &out.MaxAgeDays, &out.UpdatedAt)
	if err != nil {
		return FreshnessPolicy{}, reduce("freshness: upsert", err)
	}
	return out, nil
}
