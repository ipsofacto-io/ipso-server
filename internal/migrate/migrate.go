// Package migrate applies the embedded PostgreSQL schema migrations with goose (ADR-0050).
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// migrationFiles embeds every file in migrations, hidden files included, so that Validate
// sees a stray file instead of silently skipping it.
//
//go:embed all:migrations
var migrationFiles embed.FS

// ErrPrivilegedRole is returned when the session or current role could bypass the
// protections the migrations set up. A SECURITY DEFINER function owned by such a role
// would run with that power.
var ErrPrivilegedRole = errors.New("refusing to run as a superuser or BYPASSRLS role")

// Run validates the embedded migrations and applies the pending ones with the role in
// databaseURL. It returns the file names it applied, in order. It opens one connection
// to the database and nothing else.
func Run(ctx context.Context, databaseURL string) ([]string, error) {
	fsys, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	return run(ctx, databaseURL, fsys)
}

func run(ctx context.Context, databaseURL string, fsys fs.FS) ([]string, error) {
	if err := Validate(fsys); err != nil {
		return nil, fmt.Errorf("invalid migrations: %w", err)
	}
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		// pgx redacts the password in this error.
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	db := stdlib.OpenDB(*config)
	provider, err := newProvider(db, fsys)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	// Closing the provider closes db and with it the session that holds the advisory lock.
	defer func() { _ = provider.Close() }()

	if err := provider.Ping(ctx); err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := refusePrivilegedRole(ctx, db); err != nil {
		return nil, err
	}
	results, err := provider.Up(ctx)
	applied := make([]string, 0, len(results))
	for _, result := range results {
		applied = append(applied, path.Base(result.Source.Path))
	}
	if err != nil {
		return applied, fmt.Errorf("apply migrations: %w", err)
	}
	return applied, nil
}

// newProvider builds a goose Provider that reads only fsys. It disables the global
// registry so a Go migration registered anywhere cannot run with this role's privileges,
// and it serializes concurrent runs with a session advisory lock. Out-of-order versions
// stay refused, which is goose's default.
func newProvider(db *sql.DB, fsys fs.FS) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(
		goose.DialectPostgres,
		db,
		fsys,
		goose.WithDisableGlobalRegistry(true),
		goose.WithSessionLocker(locker),
	)
}

// refusePrivilegedRole fails before any statement when the session role or the current
// role is a superuser or has BYPASSRLS. The current role differs from the session role
// after SET ROLE, which a connection can request through its options.
func refusePrivilegedRole(ctx context.Context, db *sql.DB) error {
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
			return fmt.Errorf("role %q: %w", name, ErrPrivilegedRole)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read role attributes: %w", err)
	}
	if checked == 0 {
		return errors.New("read role attributes: the connected role is not in pg_roles")
	}
	return nil
}
