//go:build integration

package rls

import (
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

func openDSN(t *testing.T, dsn string) (*sql.DB, error) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, nil
}
