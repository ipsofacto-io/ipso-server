//go:build integration

package tenancy_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

func migrated(t *testing.T) *sql.DB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.Open(t, pgtest.App)
}

func TestRequireFindsOnlyATenantWithARow(t *testing.T) {
	db := migrated(t)
	known := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	if err := tenancy.Require(t.Context(), db, known); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Fatalf("before the row exists: %v", err)
	}
	if _, err := pgtest.Exec(t.Context(), db, known.String(), `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, known); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.Require(t.Context(), db, known); err != nil {
		t.Fatalf("after the row exists: %v", err)
	}
	if err := tenancy.Require(t.Context(), db, uuid.New()); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Fatalf("another tenant: %v", err)
	}
}
