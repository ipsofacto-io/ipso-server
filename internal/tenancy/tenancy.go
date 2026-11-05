// Package tenancy knows which tenants exist. A deployment serves one tenant in single-tenant mode,
// and the process refuses to start for a tenant that has no row (ADR-0093).
package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrUnknownTenant is returned when no row names the tenant.
var ErrUnknownTenant = errors.New("unknown tenant")

// Require returns nil when the tenant has a row. The read runs with ipso.tenant set to that tenant,
// so row-level security shows the row to nobody else.
func Require(ctx context.Context, db *sql.DB, tenant uuid.UUID) error {
	if db == nil || tenant == uuid.Nil {
		return fmt.Errorf("%w: a database and a tenant are required", ErrUnknownTenant)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("read the tenant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return fmt.Errorf("read the tenant: %w", err)
	}
	var found bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.tenant WHERE tenant_id = $1)`, tenant).Scan(&found); err != nil {
		return fmt.Errorf("read the tenant: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: %s has no row in tenancy.tenant", ErrUnknownTenant, tenant)
	}
	return nil
}
