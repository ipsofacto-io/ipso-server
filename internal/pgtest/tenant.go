//go:build integration

package pgtest

import (
	"context"
	"database/sql"
)

// WithTenant runs fn in one transaction with ipso.tenant set for that transaction
// only. The setting does not survive the commit, and an empty string left on the
// session matches no row.
func WithTenant(ctx context.Context, db *sql.DB, tenant string, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Exec runs one statement with ipso.tenant set for that statement's transaction.
func Exec(ctx context.Context, db *sql.DB, tenant, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := WithTenant(ctx, db, tenant, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query, args...)
		return execErr
	})
	return result, err
}

// Scan runs one query with ipso.tenant set and scans the single row.
func Scan(ctx context.Context, db *sql.DB, tenant, query string, args []any, dest ...any) error {
	return WithTenant(ctx, db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(dest...)
	})
}
