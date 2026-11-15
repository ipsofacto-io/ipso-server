package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrInstallationBound is returned when a GitHub App installation is already bound to another tenant. The
// error never names that tenant (ADR-0101).
var ErrInstallationBound = errors.New("the installation is bound to another tenant")

// BindOptions is one installation and the tenant that owns it.
type BindOptions struct {
	Tenant       uuid.UUID
	Installation int64
}

// BindReport says what a bind changed. A run that changes nothing is a repeat.
type BindReport struct {
	Tenant       uuid.UUID `json:"tenant"`
	Installation int64     `json:"installation"`
	Bound        bool      `json:"bound"`
}

// BindInstallation records that a GitHub App installation belongs to a tenant. It is one transaction as
// the application role with ipso.tenant set to that tenant, so row-level security lets it write the
// tenant's own binding and nothing else. The primary key is the installation id alone, which makes
// "an installation maps to exactly one tenant" a guarantee of the database: a second tenant's bind finds
// the id taken and is refused. Binding the same pair again changes nothing.
//
// The caller proves that the installation is the tenant's to claim. This function trusts its arguments.
func BindInstallation(ctx context.Context, db *sql.DB, o BindOptions) (BindReport, error) {
	report := BindReport{Tenant: o.Tenant, Installation: o.Installation}
	switch {
	case db == nil:
		return report, errors.New("bind: a database is required")
	case o.Tenant == uuid.Nil:
		return report, errors.New("bind: a tenant id is required")
	case o.Installation <= 0:
		return report, errors.New("bind: an installation id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, reduce("bind: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSession(ctx, tx, o.Tenant, false); err != nil {
		return report, err
	}

	var gone bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.offboarding WHERE tenant_id = $1)`, o.Tenant).Scan(&gone); err != nil {
		return report, reduce("bind: read the tombstone", err)
	}
	if gone {
		return report, fmt.Errorf("bind: %s: %w", o.Tenant, ErrOffboarded)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.tenant WHERE tenant_id = $1)`, o.Tenant).Scan(&exists); err != nil {
		return report, reduce("bind: read the tenant", err)
	}
	if !exists {
		return report, fmt.Errorf("bind: %s: %w", o.Tenant, ErrUnknownTenant)
	}

	// ON CONFLICT DO NOTHING needs no SELECT policy, so a binding of another tenant, which this session
	// cannot see, still stops the insert.
	res, err := tx.ExecContext(ctx,
		`INSERT INTO tenancy.installation (installation_id, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		o.Installation, o.Tenant)
	if err != nil {
		return report, reduce("bind: insert the binding", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		report.Bound = true
	} else {
		var ours bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenancy.installation WHERE installation_id = $1 AND tenant_id = $2)`,
			o.Installation, o.Tenant).Scan(&ours); err != nil {
			return report, reduce("bind: read the binding", err)
		}
		if !ours {
			return report, fmt.Errorf("bind: installation %d: %w", o.Installation, ErrInstallationBound)
		}
	}
	if err := tx.Commit(); err != nil {
		return report, reduce("bind: commit", err)
	}
	return report, nil
}

// InstallationTenant returns the tenant an installation is bound to, and false when none is. The tenant
// setting is cleared on purpose, so the lookup runs the way the webhooks process runs it, with no tenant,
// and a setting left on a pooled connection cannot change the answer. The caller names one installation
// and gets one tenant id back. It cannot list the bindings (ADR-0101).
func InstallationTenant(ctx context.Context, db *sql.DB, installation int64) (uuid.UUID, bool, error) {
	if db == nil {
		return uuid.Nil, false, errors.New("installation tenant: a database is required")
	}
	if installation <= 0 {
		return uuid.Nil, false, nil
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return uuid.Nil, false, reduce("installation tenant: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	return installationOwner(ctx, tx, "installation tenant", installation)
}

// UnbindInstallation removes the binding of an installation that GitHub deleted, and returns the tenant that
// held it. It is one transaction as the application role. The tenant comes from the lookup that
// InstallationTenant makes, with no tenant set, and never from the caller. The delete runs with ipso.tenant set
// to that tenant, so row-level security lets it remove that one tenant's binding and nothing else (ADR-0125).
// An installation no tenant holds changes nothing and reports false, and so does a second call.
//
// The caller proves that GitHub deleted the installation. This function trusts its argument.
func UnbindInstallation(ctx context.Context, db *sql.DB, installation int64) (uuid.UUID, bool, error) {
	if db == nil {
		return uuid.Nil, false, errors.New("unbind: a database is required")
	}
	if installation <= 0 {
		return uuid.Nil, false, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, false, reduce("unbind: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	tenant, bound, err := installationOwner(ctx, tx, "unbind", installation)
	if err != nil || !bound {
		return uuid.Nil, false, err
	}
	if err := setSession(ctx, tx, tenant, false); err != nil {
		return uuid.Nil, false, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM tenancy.installation WHERE installation_id = $1`, installation)
	if err != nil {
		return uuid.Nil, false, reduce("unbind: delete the binding", err)
	}
	// Offboarding may have removed the binding since the lookup. Then there is nothing left to remove.
	if n, _ := res.RowsAffected(); n != 1 {
		return uuid.Nil, false, nil
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, false, reduce("unbind: commit", err)
	}
	return tenant, true, nil
}

// installationOwner clears the tenant setting of tx and asks tenancy.installation_tenant for the tenant of one
// installation, the way the webhooks process asks. A setting left on a pooled connection cannot change the
// answer.
func installationOwner(ctx context.Context, tx *sql.Tx, operation string, installation int64) (uuid.UUID, bool, error) {
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return uuid.Nil, false, reduce(operation+": clear the tenant", err)
	}
	var tenant uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT tenancy.installation_tenant($1)`, installation).Scan(&tenant); err != nil {
		return uuid.Nil, false, reduce(operation+": look up", err)
	}
	if !tenant.Valid {
		return uuid.Nil, false, nil
	}
	return tenant.UUID, true, nil
}

// RequireInstallationLookup returns nil when the database has the lookup function. The webhooks process
// calls it at start, so a deployment that was not migrated stops there and not on its first delivery.
func RequireInstallationLookup(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("installation lookup: a database is required")
	}
	// No installation has a negative id, so this asks the function and learns no tenant.
	var tenant uuid.NullUUID
	if err := db.QueryRowContext(ctx, `SELECT tenancy.installation_tenant(-1)`).Scan(&tenant); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "42883" || pgErr.Code == "3F000") {
			return errors.New("installation lookup: the database has no tenancy.installation_tenant, run ipso-server migrate")
		}
		return reduce("installation lookup", err)
	}
	return nil
}
