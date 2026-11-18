package identity

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// EnsureOperator inserts the reserved operator principal when the tenant has none (ADR-0129). The
// caller owns the transaction and has already set ipso.tenant. A row with this id and another kind is
// an error, and the command that called writes no entry.
func EnsureOperator(ctx context.Context, tx *sql.Tx, tenant uuid.UUID) error {
	if tx == nil || tenant == uuid.Nil {
		return fmt.Errorf("%w: a tenant is required", ErrInvalidQuery)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO identity.principal (tenant_id, id, kind, name)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, tenant, OperatorPrincipal, KindOperator, OperatorName); err != nil {
		return fmt.Errorf("record the operator: %w", err)
	}
	var kind string
	if err := tx.QueryRowContext(ctx, `
		SELECT kind FROM identity.principal WHERE tenant_id = $1 AND id = $2`,
		tenant, OperatorPrincipal).Scan(&kind); err != nil {
		return fmt.Errorf("record the operator: %w", err)
	}
	if kind != KindOperator {
		return fmt.Errorf("record the operator: %w", ErrOperatorPrincipal)
	}
	return nil
}

// AppendOperator ensures the operator principal and inserts one action log entry in the caller's
// transaction, which must be READ COMMITTED (ADR-0126, ADR-0129). The insert is the last statement of
// a command that logs, so the chain lock is held only until commit.
func AppendOperator(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, action, subject string) error {
	if action == "" || subject == "" {
		return fmt.Errorf("%w: an action and a subject are required", ErrInvalidQuery)
	}
	if err := EnsureOperator(ctx, tx, tenant); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
		VALUES ($1, $2, $2, $3, $4)`, tenant, OperatorPrincipal, action, subject); err != nil {
		return fmt.Errorf("record the action: %w", err)
	}
	return nil
}
