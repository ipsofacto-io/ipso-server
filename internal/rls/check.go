// Package rls is the start gate for a process that reads or writes tenant rows.
// ipso-server migrate does not call it: the migration role owns the tables and must
// still apply files. The API process calls Check before it serves (IPSO-133, ADR-0050).
package rls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrRefused is returned when the connected role must not serve tenant data.
var ErrRefused = errors.New("refusing to start")

// Check refuses a connection that could read every tenant. A superuser and a role
// with BYPASSRLS skip row-level security even when it is forced. The owner of a
// table can switch row-level security off. A table with tenant_id and no forced
// row-level security would let the application role read every tenant through its
// grants. session_user and current_user are both checked, so a login that switches
// role at connect time is refused too.
func Check(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("no database: %w", ErrRefused)
	}
	if err := refusePrivileged(ctx, db); err != nil {
		return err
	}
	if err := refuseTableOwner(ctx, db); err != nil {
		return err
	}
	return refuseUnforced(ctx, db)
}

func refusePrivileged(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT rolname, rolsuper, rolbypassrls
		FROM pg_catalog.pg_roles
		WHERE rolname IN (session_user, current_user)`)
	if err != nil {
		return fmt.Errorf("read role attributes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	checked := 0
	for rows.Next() {
		var (
			name        string
			superuser   bool
			bypassesRLS bool
		)
		if err := rows.Scan(&name, &superuser, &bypassesRLS); err != nil {
			return fmt.Errorf("read role attributes: %w", err)
		}
		checked++
		if superuser || bypassesRLS {
			return fmt.Errorf("role %q is a superuser or has BYPASSRLS: %w", name, ErrRefused)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read role attributes: %w", err)
	}
	if checked == 0 {
		return fmt.Errorf("the connected role is not in pg_roles: %w", ErrRefused)
	}
	return nil
}

func refuseTableOwner(ctx context.Context, db *sql.DB) error {
	var schema, table string
	err := db.QueryRowContext(ctx, `
		SELECT n.nspname, c.relname
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p')
		  AND c.relowner = current_user::regrole
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		LIMIT 1`).Scan(&schema, &table)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read table owners: %w", err)
	}
	return fmt.Errorf("role owns %s.%s: %w", schema, table, ErrRefused)
}

func refuseUnforced(ctx context.Context, db *sql.DB) error {
	var schema, table string
	err := db.QueryRowContext(ctx, `
		SELECT n.nspname, c.relname
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE c.relkind IN ('r', 'p')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND a.attname = 'tenant_id'
		  AND a.attnum > 0
		  AND NOT a.attisdropped
		  AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
		LIMIT 1`).Scan(&schema, &table)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read row-level security: %w", err)
	}
	return fmt.Errorf("table %s.%s has tenant_id without forced row-level security: %w", schema, table, ErrRefused)
}
