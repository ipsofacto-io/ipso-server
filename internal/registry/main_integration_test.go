//go:build integration

package registry

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

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

// Synthetic tenants. No customer data is involved.
var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

// registryDB is a migrated database with a pool for the application role and one for the
// superuser, which the tests use to read the clock and to break rules the application cannot.
type registryDB struct {
	app   *sql.DB
	admin *sql.DB
}

func newRegistryDB(t *testing.T) registryDB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return registryDB{app: db.Open(t, pgtest.App), admin: db.Open(t, pgtest.Admin)}
}

// tryScope inserts a scope as the application role. A nil parent makes a root.
func (r registryDB) tryScope(ctx context.Context, tenant, parent uuid.UUID, kind, selector string) (uuid.UUID, error) {
	var parentArg any
	if parent != uuid.Nil {
		parentArg = parent
	}
	var id uuid.UUID
	err := r.app.QueryRowContext(ctx, `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector)
		VALUES ($1, $2, $3, $4) RETURNING id`, tenant, parentArg, kind, selector).Scan(&id)
	return id, err
}

func (r registryDB) scope(t *testing.T, tenant, parent uuid.UUID, kind, selector string) uuid.UUID {
	t.Helper()
	id, err := r.tryScope(t.Context(), tenant, parent, kind, selector)
	if err != nil {
		t.Fatalf("insert %s scope %q: %v", kind, selector, err)
	}
	return id
}

// decision inserts the first version of a decision as the application role. valid is a
// tstzrange literal such as "[2026-01-01,)".
func (r registryDB) decision(t *testing.T, tenant, id uuid.UUID, valid string, scopes ...uuid.UUID) {
	t.Helper()
	_, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, jsonb_build_object('id', $1::uuid::text), $3::uuid[], $4::text::tstzrange)`,
		id, tenant, scopes, valid)
	if err != nil {
		t.Fatalf("insert decision: %v", err)
	}
}

// mark reads the database clock, which is the clock that sets transaction time, with a pause on
// each side so that no row written before it shares its microsecond.
func mark(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	pause := func() {
		if _, err := db.ExecContext(t.Context(), `SELECT pg_sleep(0.02)`); err != nil {
			t.Fatal(err)
		}
	}
	pause()
	var now time.Time
	if err := db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	pause()
	return now
}
