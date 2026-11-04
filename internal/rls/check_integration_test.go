//go:build integration

package rls

import (
	"errors"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestCheckAcceptsTheApplicationRole(t *testing.T) {
	db := migrated(t)
	if err := Check(t.Context(), db.Open(t, pgtest.App)); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRefusesAPrivilegedRole(t *testing.T) {
	tests := []struct {
		name string
		open func(*pgtest.Database) string
	}{
		{"superuser", func(db *pgtest.Database) string { return db.DSN(pgtest.Admin) }},
		{"BYPASSRLS role", func(db *pgtest.Database) string { return db.DSN(pgtest.Bypass) }},
		{"plain login that switches to a BYPASSRLS role", func(db *pgtest.Database) string {
			return db.DSNSwitchingRole(pgtest.Member, pgtest.Bypass)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := migrated(t)
			conn, err := openDSN(t, tt.open(db))
			if err != nil {
				t.Fatal(err)
			}
			err = Check(t.Context(), conn)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Check = %v, want the start refusal", err)
			}
		})
	}
}

func TestCheckRefusesTheTableOwner(t *testing.T) {
	db := migrated(t)
	err := Check(t.Context(), db.Open(t, pgtest.Migrate))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Check = %v, want the start refusal", err)
	}
}

func TestCheckRefusesATenantTableWithoutForcedRowLevelSecurity(t *testing.T) {
	db := migrated(t)
	admin := db.Open(t, pgtest.Admin)
	if _, err := admin.ExecContext(t.Context(), `CREATE TABLE public.opened (tenant_id uuid)`); err != nil {
		t.Fatal(err)
	}
	err := Check(t.Context(), db.Open(t, pgtest.App))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Check = %v, want the start refusal", err)
	}
}

func migrated(t *testing.T) *pgtest.Database {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
