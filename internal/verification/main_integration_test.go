//go:build integration

package verification

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
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

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

// store is a migrated database with two tenants, opened as the application role and as an administrator.
type store struct {
	app, admin *sql.DB
}

func newStore(t *testing.T) *store {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &store{app: database.Open(t, pgtest.App), admin: database.Open(t, pgtest.Admin)}
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		if _, err := pgtest.Exec(t.Context(), s.app, tenant.String(), `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// count reads a table as an administrator, so that row-level security does not hide a row that a test
// expects to find or to be absent.
func (s *store) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.admin.QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}
