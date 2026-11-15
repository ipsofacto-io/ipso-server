//go:build integration

package rls

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// installationIDs returns the installation each seeded tenant owns, read as the superuser.
func installationIDs(t *testing.T, admin *sql.DB) map[string]int64 {
	t.Helper()
	rows, err := admin.QueryContext(t.Context(), `SELECT tenant_id::text, installation_id FROM tenancy.installation`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	ids := make(map[string]int64)
	for rows.Next() {
		var tenant string
		var id int64
		if err := rows.Scan(&tenant, &id); err != nil {
			t.Fatal(err)
		}
		ids[tenant] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// lookup asks tenancy.installation_tenant for an installation with ipso.tenant set to session, or with
// no tenant when session is empty. A tenant that is not found comes back as an invalid NullString.
func lookup(t *testing.T, db *sql.DB, session string, installation int64) sql.NullString {
	t.Helper()
	var got sql.NullString
	const query = `SELECT tenancy.installation_tenant($1)::text`
	if session == "" {
		if err := db.QueryRowContext(t.Context(), query, installation).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if err := pgtest.Scan(t.Context(), db, session, query, []any{installation}, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// The lookup crosses tenants, so it is the trust boundary of IPSO-140 (ADR-0101). A caller names one
// installation and gets back one tenant id. It cannot list the bindings, and a caller that has a tenant
// learns nothing about another tenant's installations.
func TestInstallationLookupShowsTheCallerNoOtherTenantsData(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	admin := db.Open(t, pgtest.Admin)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)
	ids := installationIDs(t, admin)
	idA, idB := ids[tenantA], ids[tenantB]
	if idA == 0 || idB == 0 || idA == idB {
		t.Fatalf("the seed bound installations %v, want one for each tenant", ids)
	}

	// With no tenant, which is how the webhooks process asks, the lookup answers for the id it is given.
	for installation, want := range map[int64]string{idA: tenantA, idB: tenantB} {
		if got := lookup(t, app, "", installation); !got.Valid || got.String != want {
			t.Errorf("lookup(%d) with no tenant = %v, want %s", installation, got, want)
		}
	}
	if got := lookup(t, app, "", 1); got.Valid {
		t.Errorf("lookup of an unbound installation = %v, want none", got)
	}

	// The table itself stays closed to a session with no tenant, so the bindings cannot be listed.
	var n int
	if err := app.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.installation`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a session with no tenant lists %d bindings (%v), want 0", n, err)
	}

	// With a tenant set, the lookup answers for that tenant only.
	if got := lookup(t, app, tenantB, idA); got.Valid {
		t.Errorf("tenant B learned the owner of tenant A's installation: %v", got)
	}
	if got := lookup(t, app, tenantB, idB); !got.Valid || got.String != tenantB {
		t.Errorf("tenant B's own installation = %v", got)
	}
	if err := pgtest.Scan(t.Context(), app, tenantB, `SELECT count(*) FROM tenancy.installation`, nil, &n); err != nil || n != 1 {
		t.Errorf("tenant B lists %d bindings (%v), want its own 1", n, err)
	}
}

func TestInstallationLookupIsADefinerFunctionOnlyTheApplicationRoleMayCall(t *testing.T) {
	db := migrated(t)
	admin := db.Open(t, pgtest.Admin)
	var definer, appMay, bypassMay bool
	var owner, config, volatility string
	err := admin.QueryRowContext(t.Context(), `
		SELECT p.prosecdef, pg_get_userbyid(p.proowner), coalesce(array_to_string(p.proconfig, ';'), ''), p.provolatile::text,
		       has_function_privilege('ipso_app', p.oid, 'execute'),
		       has_function_privilege('ipso_bypass', p.oid, 'execute')
		FROM pg_catalog.pg_proc AS p
		WHERE p.oid = 'tenancy.installation_tenant(bigint)'::regprocedure`).
		Scan(&definer, &owner, &config, &volatility, &appMay, &bypassMay)
	if err != nil {
		t.Fatal(err)
	}
	if !definer || owner != pgtest.Migrate {
		t.Errorf("SECURITY DEFINER = %v, owner %s; want a definer function owned by %s", definer, owner, pgtest.Migrate)
	}
	if !strings.Contains(config, "search_path=pg_catalog, pg_temp") {
		t.Errorf("config = %q, want a pinned search_path", config)
	}
	if volatility != "s" {
		t.Errorf("volatility = %q, want stable", volatility)
	}
	if !appMay || bypassMay {
		t.Errorf("EXECUTE: application role %v, other role %v; want true and false", appMay, bypassMay)
	}
}

func TestApplicationRoleCannotChangeOrTakeABinding(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	admin := db.Open(t, pgtest.Admin)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)
	ids := installationIDs(t, admin)

	// A binding never moves to another tenant. There is no UPDATE for the application role at all.
	if _, err := pgtest.Exec(t.Context(), app, tenantA, `UPDATE tenancy.installation SET tenant_id = tenant_id`); sqlState(err) != "42501" {
		t.Errorf("update: sqlstate = %q, want 42501 (%v)", sqlState(err), err)
	}

	// Another tenant's id is taken for good, whoever asks. The refusal is the primary key.
	_, err := pgtest.Exec(t.Context(), app, tenantB,
		`INSERT INTO tenancy.installation (installation_id, tenant_id) VALUES ($1, $2::uuid)`, ids[tenantA], tenantB)
	if sqlState(err) != "23505" {
		t.Errorf("a second binding: sqlstate = %q, want 23505 (%v)", sqlState(err), err)
	}
	if got := lookup(t, app, "", ids[tenantA]); got.String != tenantA {
		t.Errorf("owner after the refused binding = %v, want tenant A", got)
	}
}

// The migration role reads every binding only when no tenant is set, which is what lets the definer
// function work. Its delete has no such arm, so the offboard command still touches one tenant at a time.
func TestMigrationRoleDeletesOneTenantsBindingsAtATime(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	migrator := db.Open(t, pgtest.Migrate)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)

	var n int
	if err := migrator.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.installation`).Scan(&n); err != nil || n != 2 {
		t.Errorf("the migration role with no tenant sees %d bindings (%v), want 2", n, err)
	}
	if err := pgtest.Scan(t.Context(), migrator, tenantA, `SELECT count(*) FROM tenancy.installation`, nil, &n); err != nil || n != 1 {
		t.Errorf("the migration role with tenant A sees %d bindings (%v), want 1", n, err)
	}
	res, err := migrator.ExecContext(t.Context(), `DELETE FROM tenancy.installation`)
	if err != nil {
		t.Fatal(err)
	}
	if deleted, _ := res.RowsAffected(); deleted != 0 {
		t.Errorf("a delete with no tenant removed %d bindings, want 0", deleted)
	}
	res, err = pgtest.Exec(t.Context(), migrator, tenantA, `DELETE FROM tenancy.installation`)
	if err != nil {
		t.Fatal(err)
	}
	if deleted, _ := res.RowsAffected(); deleted != 1 {
		t.Errorf("a delete for tenant A removed %d bindings, want 1", deleted)
	}
}

// The webhooks process removes the binding of a deleted installation as the application role, with ipso.tenant
// set to the tenant the lookup gave (ADR-0125). Its delete reaches that tenant's bindings and no other's, and a
// session with no tenant removes nothing.
func TestApplicationRoleDeletesOnlyItsOwnTenantsBindings(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	admin := db.Open(t, pgtest.Admin)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)
	ids := installationIDs(t, admin)

	res, err := app.ExecContext(t.Context(), `DELETE FROM tenancy.installation`)
	if err != nil {
		t.Fatal(err)
	}
	if deleted, _ := res.RowsAffected(); deleted != 0 {
		t.Errorf("a delete with no tenant removed %d bindings, want 0", deleted)
	}
	res, err = pgtest.Exec(t.Context(), app, tenantB, `DELETE FROM tenancy.installation WHERE installation_id = $1`, ids[tenantA])
	if err != nil {
		t.Fatal(err)
	}
	if deleted, _ := res.RowsAffected(); deleted != 0 {
		t.Errorf("tenant B removed %d of tenant A's bindings, want 0", deleted)
	}
	res, err = pgtest.Exec(t.Context(), app, tenantA, `DELETE FROM tenancy.installation`)
	if err != nil {
		t.Fatal(err)
	}
	if deleted, _ := res.RowsAffected(); deleted != 1 {
		t.Errorf("tenant A removed %d bindings, want its own 1", deleted)
	}
	if got := lookup(t, app, "", ids[tenantA]); got.Valid {
		t.Errorf("tenant A's installation still maps to %v", got)
	}
	if got := lookup(t, app, "", ids[tenantB]); got.String != tenantB {
		t.Errorf("tenant B's installation = %v, want tenant B", got)
	}
}
