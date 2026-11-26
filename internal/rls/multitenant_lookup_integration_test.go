//go:build integration

package rls

import (
	"crypto/sha256"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestMultiTenantLookupsAreDefinerFunctionsOnlyAppMayCall(t *testing.T) {
	db := migrated(t)
	admin := db.Open(t, pgtest.Admin)

	functions := []struct {
		sig        string
		volatility string
	}{
		{"identity.login_tenants(text,text)", "s"},
		{"identity.human_login_tenants(text,text)", "s"},
		{"identity.session_tenant(bytea)", "s"},
		{"identity.cli_session_tenant(bytea)", "s"},
		{"identity.invitation_tenant(bytea)", "s"},
		{"identity.scim_token_tenant(bytea)", "s"},
		{"verification.agent_pin_tenant(bytea)", "s"},
		{"identity.create_login_choice(bytea,text,text,bytea,text,text,text)", "v"},
		{"identity.read_login_choice(bytea)", "s"},
		{"identity.consume_login_choice(bytea)", "v"},
		{"identity.cancel_login_choice(bytea)", "v"},
	}
	for _, fn := range functions {
		var definer, appMay, bypassMay, publicMay bool
		var owner, config, volatility string
		err := admin.QueryRowContext(t.Context(), `
			SELECT p.prosecdef, pg_get_userbyid(p.proowner), coalesce(array_to_string(p.proconfig, ';'), ''), p.provolatile::text,
			       has_function_privilege('ipso_app', p.oid, 'execute'),
			       has_function_privilege('ipso_bypass', p.oid, 'execute'),
			       has_function_privilege('public', p.oid, 'execute')
			FROM pg_catalog.pg_proc AS p
			WHERE p.oid = $1::regprocedure`, fn.sig).
			Scan(&definer, &owner, &config, &volatility, &appMay, &bypassMay, &publicMay)
		if err != nil {
			t.Fatalf("%s: %v", fn.sig, err)
		}
		if !definer || owner != pgtest.Migrate {
			t.Errorf("%s: SECURITY DEFINER = %v, owner %s; want definer owned by %s", fn.sig, definer, owner, pgtest.Migrate)
		}
		if !strings.Contains(config, "search_path=pg_catalog, pg_temp") {
			t.Errorf("%s: config = %q, want pinned search_path", fn.sig, config)
		}
		if volatility != fn.volatility {
			t.Errorf("%s: volatility = %q, want %q", fn.sig, volatility, fn.volatility)
		}
		if !appMay || bypassMay || publicMay {
			t.Errorf("%s: EXECUTE app=%v bypass=%v public=%v; want true, false, false", fn.sig, appMay, bypassMay, publicMay)
		}
	}

	// ipso_app and public have zero direct table privileges on identity.login_choice.
	for _, role := range []string{pgtest.App, pgtest.Bypass, "public"} {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			var allowed bool
			if err := admin.QueryRowContext(t.Context(), `SELECT has_table_privilege($1, 'identity.login_choice', $2)`, role, priv).Scan(&allowed); err != nil {
				t.Fatalf("has_table_privilege(%s, %s): %v", role, priv, err)
			}
			if allowed {
				t.Errorf("role %s has direct %s on identity.login_choice, want false", role, priv)
			}
		}
	}
}

func TestMultiTenantLookupsRespectTenantContextAndNeverLeakListings(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	admin := db.Open(t, pgtest.Admin)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)

	// Read seeded hashes as admin for lookup verification.
	readHash := func(query, tenant string) []byte {
		t.Helper()
		var h []byte
		if err := admin.QueryRowContext(t.Context(), query, tenant).Scan(&h); err != nil {
			t.Fatalf("%s (%s): %v", query, tenant, err)
		}
		return h
	}
	sessA := readHash(`SELECT token_sha256 FROM identity.session WHERE tenant_id = $1::uuid`, tenantA)
	sessB := readHash(`SELECT token_sha256 FROM identity.session WHERE tenant_id = $1::uuid`, tenantB)
	cliA := readHash(`SELECT token_sha256 FROM identity.cli_session WHERE tenant_id = $1::uuid`, tenantA)
	cliB := readHash(`SELECT token_sha256 FROM identity.cli_session WHERE tenant_id = $1::uuid`, tenantB)
	invA := readHash(`SELECT token_sha256 FROM identity.invitation WHERE tenant_id = $1::uuid`, tenantA)
	invB := readHash(`SELECT token_sha256 FROM identity.invitation WHERE tenant_id = $1::uuid`, tenantB)
	scimA := readHash(`SELECT token_sha256 FROM identity.scim_token WHERE tenant_id = $1::uuid`, tenantA)
	scimB := readHash(`SELECT token_sha256 FROM identity.scim_token WHERE tenant_id = $1::uuid`, tenantB)
	pinA := readHash(`SELECT pin_sha256 FROM verification.agent_pin WHERE tenant_id = $1::uuid`, tenantA)
	pinB := readHash(`SELECT pin_sha256 FROM verification.agent_pin WHERE tenant_id = $1::uuid`, tenantB)

	byteaCases := []struct {
		name    string
		query   string
		hashA   []byte
		hashB   []byte
		unknown []byte
	}{
		{"session", `SELECT identity.session_tenant($1)::text`, sessA, sessB, []byte("no-such-session-hash-00000000000")},
		{"cli_session", `SELECT identity.cli_session_tenant($1)::text`, cliA, cliB, []byte("no-such-cli-sess-hash-0000000000")},
		{"invitation", `SELECT identity.invitation_tenant($1)::text`, invA, invB, []byte("no-such-invite-hash-000000000000")},
		{"scim_token", `SELECT identity.scim_token_tenant($1)::text`, scimA, scimB, []byte("no-such-scim-token-hash-00000000")},
		{"agent_pin", `SELECT verification.agent_pin_tenant($1)::text`, pinA, pinB, []byte("no-such-agent-pin-hash-000000000")},
	}
	for _, tc := range byteaCases {
		t.Run(tc.name, func(t *testing.T) {
			var got sql.NullString
			// With no tenant set: returns owning tenant.
			if err := app.QueryRowContext(t.Context(), tc.query, tc.hashA).Scan(&got); err != nil || !got.Valid || got.String != tenantA {
				t.Errorf("no tenant hashA = %v (%v), want %s", got, err, tenantA)
			}
			if err := app.QueryRowContext(t.Context(), tc.query, tc.hashB).Scan(&got); err != nil || !got.Valid || got.String != tenantB {
				t.Errorf("no tenant hashB = %v (%v), want %s", got, err, tenantB)
			}
			if err := app.QueryRowContext(t.Context(), tc.query, tc.unknown).Scan(&got); err != nil || got.Valid {
				t.Errorf("no tenant unknown = %v (%v), want null", got, err)
			}
			// With tenantB set: hashA returns nothing; hashB returns tenantB.
			if err := pgtest.Scan(t.Context(), app, tenantB, tc.query, []any{tc.hashA}, &got); err != nil || got.Valid {
				t.Errorf("tenantB asking for hashA = %v (%v), want null", got, err)
			}
			if err := pgtest.Scan(t.Context(), app, tenantB, tc.query, []any{tc.hashB}, &got); err != nil || !got.Valid || got.String != tenantB {
				t.Errorf("tenantB asking for hashB = %v (%v), want %s", got, err, tenantB)
			}
		})
	}

	// Expired invitations must not resolve. Insert via app, then backdate created_at/expires_at as admin.
	expiredHash := sha256.Sum256([]byte("expired-invitation-token"))
	var principalA uuid.UUID
	if err := admin.QueryRowContext(t.Context(), `SELECT id FROM identity.principal WHERE tenant_id = $1::uuid AND kind = 'human' LIMIT 1`, tenantA).Scan(&principalA); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), app, tenantA,
		`INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by) VALUES ($1::uuid, $2, 'Expired', 'viewer', $3)`,
		tenantA, expiredHash[:], principalA); err != nil {
		t.Fatal(err)
	}
	backdateTx, err := admin.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backdateTx.ExecContext(t.Context(), `SET LOCAL session_replication_role = 'replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := backdateTx.ExecContext(t.Context(),
		`UPDATE identity.invitation SET created_at = now() - interval '8 days', expires_at = now() - interval '1 minute' WHERE token_sha256 = $1`,
		expiredHash[:]); err != nil {
		t.Fatal(err)
	}
	if err := backdateTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var got sql.NullString
	if err := app.QueryRowContext(t.Context(), `SELECT identity.invitation_tenant($1)::text`, expiredHash[:]).Scan(&got); err != nil || got.Valid {
		t.Errorf("expired invitation resolved to %v (%v), want null", got, err)
	}

	// identity.login_tenants: returns both tenants (LIMIT 2) for a subject present in A, B, and C,
	// and drops closed logins.
	const tenantC = "00000000-0000-4000-8000-00000000000c"
	pgtest.SeedEveryTable(t, app, tenantC)
	queryLogins := func(session, issuer, subject string) []string {
		t.Helper()
		tx, err := app.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, true)`, session); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.QueryContext(t.Context(), `SELECT tenant_id::text FROM identity.login_tenants($1, $2)`, issuer, subject)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		return out
	}
	// Seed binds issuer 'https://idp.example.test' subject 'subject-1' in all three tenants.
	gotLogins := queryLogins("", "https://idp.example.test", "subject-1")
	if len(gotLogins) != 2 {
		t.Errorf("login_tenants for subject in 3 tenants returned %d rows (%v), want LIMIT 2", len(gotLogins), gotLogins)
	}
	// With ipso.tenant set to tenantB, only tenantB is returned.
	gotInB := queryLogins(tenantB, "https://idp.example.test", "subject-1")
	if len(gotInB) != 1 || gotInB[0] != tenantB {
		t.Errorf("login_tenants with tenantB = %v, want [%s]", gotInB, tenantB)
	}
	// Closing tenantA's and tenantC's logins leaves only tenantB.
	for _, tid := range []string{tenantA, tenantC} {
		if _, err := pgtest.Exec(t.Context(), app, tid,
			`UPDATE identity.login SET closed_at = now() WHERE issuer = 'https://idp.example.test' AND subject = 'subject-1'`); err != nil {
			t.Fatal(err)
		}
	}
	gotAfterClose := queryLogins("", "https://idp.example.test", "subject-1")
	if len(gotAfterClose) != 1 || gotAfterClose[0] != tenantB {
		t.Errorf("login_tenants after closing A and C = %v, want [%s]", gotAfterClose, tenantB)
	}

	// ipso_app with no tenant still cannot list any of the six tables.
	for _, table := range []string{
		"identity.login",
		"identity.session",
		"identity.cli_session",
		"identity.invitation",
		"identity.scim_token",
		"verification.agent_pin",
	} {
		var n int
		if err := app.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Errorf("ipso_app with no tenant lists %d rows from %s (%v), want 0", n, table, err)
		}
	}

	// Global uniqueness prevents tenantB from inserting tenantA's session hash (23505).
	var loginB uuid.UUID
	if err := admin.QueryRowContext(t.Context(), `SELECT id FROM identity.login WHERE tenant_id = $1::uuid LIMIT 1`, tenantB).Scan(&loginB); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), app, tenantB,
		`INSERT INTO identity.session (tenant_id, login_id, token_sha256, expires_at) VALUES ($1::uuid, $2, $3, now() + interval '1 hour')`,
		tenantB, loginB, sessA); sqlState(err) != "23505" {
		t.Errorf("duplicate session hash across tenants: sqlstate = %q (%v), want 23505", sqlState(err), err)
	}
}

func TestMigrationRoleDeleteStaysSingleTenantOnMultiTenantLookupTables(t *testing.T) {
	db := migrated(t)
	app := db.Open(t, pgtest.App)
	migrator := db.Open(t, pgtest.Migrate)
	pgtest.SeedEveryTable(t, app, tenantA)
	pgtest.SeedEveryTable(t, app, tenantB)

	tables := []string{
		"identity.session",
		"identity.cli_session",
		"identity.invitation",
		"identity.scim_token",
		"verification.agent_pin",
		"identity.login",
	}
	for _, table := range tables {
		var total int
		if err := migrator.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&total); err != nil || total < 2 {
			t.Errorf("%s: migrator with no tenant saw %d rows (%v), want >= 2", table, total, err)
		}
		res, err := migrator.ExecContext(t.Context(), `DELETE FROM `+table)
		if err != nil {
			t.Fatalf("%s delete with no tenant: %v", table, err)
		}
		if deleted, _ := res.RowsAffected(); deleted != 0 {
			t.Errorf("%s: migrator DELETE with no tenant removed %d rows, want 0", table, deleted)
		}
		var inA int
		if err := pgtest.Scan(t.Context(), migrator, tenantA, `SELECT count(*) FROM `+table, nil, &inA); err != nil || inA == 0 {
			t.Fatalf("%s: count in tenantA = %d (%v)", table, inA, err)
		}
		res, err = pgtest.Exec(t.Context(), migrator, tenantA, `DELETE FROM `+table)
		if err != nil {
			t.Fatalf("%s delete in tenantA: %v", table, err)
		}
		if deleted, _ := res.RowsAffected(); int(deleted) != inA {
			t.Errorf("%s: migrator DELETE in tenantA removed %d rows, want %d", table, deleted, inA)
		}
		var remainingB int
		if err := pgtest.Scan(t.Context(), migrator, tenantB, `SELECT count(*) FROM `+table, nil, &remainingB); err != nil || remainingB == 0 {
			t.Errorf("%s: tenantB lost rows after tenantA delete: remaining %d (%v)", table, remainingB, err)
		}
	}

	// tenancy.tenant and identity.principal also allow migrator cross-tenant SELECT for human_login_tenants,
	// while keeping migrator DELETE strictly single-tenant.
	for _, table := range []string{"identity.principal", "tenancy.tenant"} {
		var total int
		if err := migrator.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&total); err != nil || total < 2 {
			t.Errorf("%s: migrator with no tenant saw %d rows (%v), want >= 2", table, total, err)
		}
		res, err := migrator.ExecContext(t.Context(), `DELETE FROM `+table)
		if err != nil {
			t.Fatalf("%s delete with no tenant: %v", table, err)
		}
		if deleted, _ := res.RowsAffected(); deleted != 0 {
			t.Errorf("%s: migrator DELETE with no tenant removed %d rows, want 0", table, deleted)
		}
	}
	const tenantSolo = "00000000-0000-4000-8000-00000000000d"
	if _, err := pgtest.Exec(t.Context(), app, tenantSolo, `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1::uuid, 'Solo')`, tenantSolo); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), app, tenantSolo, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1::uuid, 'human', 'Solo Person')`, tenantSolo); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity.principal", "tenancy.tenant"} {
		res, err := pgtest.Exec(t.Context(), migrator, tenantSolo, `DELETE FROM `+table)
		if err != nil {
			t.Fatalf("%s delete in tenantSolo: %v", table, err)
		}
		if deleted, _ := res.RowsAffected(); deleted != 1 {
			t.Errorf("%s: migrator DELETE in tenantSolo removed %d rows, want 1", table, deleted)
		}
		var remainingB int
		if err := pgtest.Scan(t.Context(), migrator, tenantB, `SELECT count(*) FROM `+table, nil, &remainingB); err != nil || remainingB == 0 {
			t.Errorf("%s: tenantB lost rows after tenantSolo delete: remaining %d (%v)", table, remainingB, err)
		}
	}
}
