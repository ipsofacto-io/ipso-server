package llmgw

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Ledger holds each tenant's token use per calendar month (UTC).
type Ledger interface {
	// Reserve adds tokens to the month only if the total stays within limit. Otherwise it returns
	// ErrBudget and adds nothing.
	Reserve(ctx context.Context, tenant uuid.UUID, month time.Time, tokens, limit int64) error
	// Settle adds delta, which is negative when a call used less than it reserved. The total never
	// goes below zero.
	Settle(ctx context.Context, tenant uuid.UUID, month time.Time, delta int64) error
}

// PGLedger keeps the ledger in llm.usage. Two servers share one budget, and a reservation is one
// statement, so two calls cannot both take the last tokens.
type PGLedger struct {
	DB *sql.DB
}

// Reserve implements Ledger.
func (l PGLedger) Reserve(ctx context.Context, tenant uuid.UUID, month time.Time, tokens, limit int64) error {
	if tokens > limit {
		return ErrBudget
	}
	return l.tenantTx(ctx, tenant, func(tx *sql.Tx) error {
		var total int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO llm.usage AS u (tenant_id, month, tokens) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, month) DO UPDATE SET tokens = u.tokens + EXCLUDED.tokens
			WHERE u.tokens + EXCLUDED.tokens <= $4
			RETURNING tokens`, tenant, month, tokens, limit).Scan(&total)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrBudget
		}
		return err
	})
}

// Settle implements Ledger.
func (l PGLedger) Settle(ctx context.Context, tenant uuid.UUID, month time.Time, delta int64) error {
	if delta == 0 {
		return nil
	}
	return l.tenantTx(ctx, tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE llm.usage SET tokens = greatest(tokens + $3, 0)
			WHERE tenant_id = $1 AND month = $2`, tenant, month, delta)
		return err
	})
}

func (l PGLedger) tenantTx(ctx context.Context, tenant uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := l.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
