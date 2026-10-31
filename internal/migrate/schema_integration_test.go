//go:build integration

package migrate_test

import (
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// Synthetic identifiers. No customer data is involved.
const (
	tenantA  = "00000000-0000-4000-8000-00000000000a"
	tenantB  = "00000000-0000-4000-8000-00000000000b"
	decision = "00000000-0000-4000-8000-0000000000d1"
)

const insertVersion = `
	INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
	VALUES ($1::uuid, $2::int, $3::uuid, '{"statement":"synthetic"}', ARRAY[$5::uuid], $4::text::tstzrange)`

// schema is a migrated database with a pool for each role the tests act as. orgs holds one
// org scope for each tenant, which the decision rows point at.
type schema struct {
	app   *sql.DB
	admin *sql.DB
	orgs  map[string]string
}

// migrated applies the embedded migrations as the migration role to an empty database.
func migrated(t *testing.T) schema {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := schema{app: db.Open(t, pgtest.App), admin: db.Open(t, pgtest.Admin), orgs: make(map[string]string)}
	for _, tenant := range []string{tenantA, tenantB} {
		s.orgs[tenant] = s.addScope(t, tenant, "", "org", "acme")
	}
	return s
}

// addScope inserts a scope as the application role and returns its id. An empty parent means
// a root.
func (s schema) addScope(t *testing.T, tenant, parent, kind, selector string) string {
	t.Helper()
	id, err := s.tryScope(t, tenant, parent, kind, selector)
	if err != nil {
		t.Fatalf("insert %s scope %q: %v", kind, selector, err)
	}
	return id
}

func (s schema) tryScope(t *testing.T, tenant, parent, kind, selector string) (string, error) {
	t.Helper()
	var id string
	err := s.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector)
		VALUES ($1::uuid, nullif($2, '')::uuid, $3, $4)
		RETURNING id`, tenant, parent, kind, selector).Scan(&id)
	return id, err
}

func (s schema) insert(t *testing.T, tenant string, version int, validPeriod string) {
	t.Helper()
	if _, err := s.app.ExecContext(t.Context(), insertVersion, decision, version, tenant, validPeriod, s.orgs[tenant]); err != nil {
		t.Fatalf("insert version %d: %v", version, err)
	}
}

// dbNow reads the database clock, which is the clock that sets transaction time.
func dbNow(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	if err := db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

func sleep(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), `SELECT pg_sleep(0.02)`); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// pgError returns the PostgreSQL error in err, and fails the test when err is not one.
func pgError(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("want a PostgreSQL error, got %v", err)
	}
	return pgErr
}

func requireSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if got := pgError(t, err); got.Code != want {
		t.Fatalf("want SQLSTATE %s, got %s: %v", want, got.Code, got)
	}
}

func TestMigrationsCreateTheObjects(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	if n := count(t, s.admin, `SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'btree_gist'`); n != 1 {
		t.Errorf("btree_gist extensions = %d, want 1", n)
	}
	for _, name := range []string{"decision_version", "decision_version_history", "decision_version_all"} {
		var found bool
		if err := s.admin.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "registry."+name).Scan(&found); err != nil || !found {
			t.Errorf("registry.%s missing (err %v)", name, err)
		}
	}

	var key string
	err := s.admin.QueryRowContext(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_catalog.pg_constraint
		WHERE conrelid = 'registry.decision_version'::regclass AND contype = 'p'`).Scan(&key)
	if err != nil {
		t.Fatal(err)
	}
	if want := "PRIMARY KEY (tenant_id, decision_id, valid_period WITHOUT OVERLAPS)"; key != want {
		t.Errorf("primary key = %q, want %q", key, want)
	}

	// LIKE must not carry the temporal key or the open-period check into the history table.
	if n := count(t, s.admin, `SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid = 'registry.decision_version_history'::regclass AND contype IN ('p', 'c', 'x')`); n != 0 {
		t.Errorf("history table has %d key or check constraints, want 0", n)
	}
}

func TestPrimaryKeyRejectsAnOverlappingPeriod(t *testing.T) {
	s := migrated(t)
	s.insert(t, tenantA, 1, "[2026-01-01,2026-06-01)")

	_, err := s.app.ExecContext(t.Context(), insertVersion, decision, 2, tenantA, "[2026-03-01,2026-09-01)", s.orgs[tenantA])
	requireSQLState(t, err, "23P01")

	s.insert(t, tenantA, 2, "[2026-06-01,2026-09-01)") // adjacent, no overlap
	s.insert(t, tenantB, 1, "[2026-03-01,2026-09-01)") // the same decision id in another tenant
}

func TestUpdateArchivesTheOldRow(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET version = 2, body = '{"statement":"changed"}' WHERE tenant_id = $1 AND decision_id = $2`, tenantA, decision); err != nil {
		t.Fatalf("the application role must be able to update decision_version: %v", err)
	}

	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version WHERE decision_id = $1`, decision); n != 1 {
		t.Fatalf("current rows = %d, want 1", n)
	}
	var (
		currentVersion int
		currentOpen    bool
		currentFrom    time.Time
	)
	err := s.app.QueryRowContext(ctx, `SELECT version, upper(sys_period) IS NULL, lower(sys_period) FROM registry.decision_version WHERE decision_id = $1`, decision).Scan(&currentVersion, &currentOpen, &currentFrom)
	if err != nil {
		t.Fatal(err)
	}
	if currentVersion != 2 || !currentOpen {
		t.Errorf("current row: version %d, open %v, want version 2 and open", currentVersion, currentOpen)
	}

	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version_history WHERE decision_id = $1`, decision); n != 1 {
		t.Fatalf("history rows = %d, want 1", n)
	}
	var (
		archivedVersion int
		archivedTo      time.Time
		archivedBody    string
	)
	err = s.app.QueryRowContext(ctx, `SELECT version, upper(sys_period), body->>'statement' FROM registry.decision_version_history WHERE decision_id = $1`, decision).Scan(&archivedVersion, &archivedTo, &archivedBody)
	if err != nil {
		t.Fatalf("history row must be closed: %v", err)
	}
	if archivedVersion != 1 || archivedBody != "synthetic" {
		t.Errorf("archived row: version %d, body %q, want the old row", archivedVersion, archivedBody)
	}
	if !archivedTo.Equal(currentFrom) {
		t.Errorf("history closes at %v, current row opens at %v, want the same instant", archivedTo, currentFrom)
	}
}

// Transaction time moves when the recorded belief changes, not when a statement runs.
func TestUpdateThatChangesNothingArchivesNothing(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	var openedAt time.Time
	if err := s.app.QueryRowContext(ctx, `SELECT lower(sys_period) FROM registry.decision_version WHERE decision_id = $1`, decision).Scan(&openedAt); err != nil {
		t.Fatal(err)
	}
	sleep(t, s.admin)

	for _, statement := range []string{
		`UPDATE registry.decision_version SET version = version WHERE decision_id = $1`,
		`UPDATE registry.decision_version SET body = '{"statement": "synthetic"}' WHERE decision_id = $1`, // same JSON, other spacing
	} {
		if _, err := s.app.ExecContext(ctx, statement, decision); err != nil {
			t.Fatal(err)
		}
	}

	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version_history`); n != 0 {
		t.Errorf("history rows = %d, want 0", n)
	}
	var from time.Time
	if err := s.app.QueryRowContext(ctx, `SELECT lower(sys_period) FROM registry.decision_version WHERE decision_id = $1`, decision).Scan(&from); err != nil {
		t.Fatal(err)
	}
	if !from.Equal(openedAt) {
		t.Errorf("sys_period opens at %v after a no-op update, want %v", from, openedAt)
	}
}

// Changing only sys_period is a change, so the archive path runs and replaces the supplied value.
func TestUpdateOfOnlySysPeriodStillCannotBackdate(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	before := dbNow(t, s.admin)
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET sys_period = '[2000-01-01,)'::tstzrange WHERE decision_id = $1`, decision); err != nil {
		t.Fatal(err)
	}
	var from time.Time
	if err := s.app.QueryRowContext(ctx, `SELECT lower(sys_period) FROM registry.decision_version WHERE decision_id = $1`, decision).Scan(&from); err != nil {
		t.Fatal(err)
	}
	if from.Before(before) {
		t.Errorf("sys_period opens at %v, before the update ran at %v", from, before)
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version_history`); n != 1 {
		t.Errorf("history rows = %d, want 1", n)
	}
}

func TestUpdateCannotBackdateTransactionTime(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	before := dbNow(t, s.admin)
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET version = 2, sys_period = '[2000-01-01,)'::tstzrange WHERE decision_id = $1`, decision); err != nil {
		t.Fatal(err)
	}
	var from time.Time
	if err := s.app.QueryRowContext(ctx, `SELECT lower(sys_period) FROM registry.decision_version WHERE decision_id = $1`, decision).Scan(&from); err != nil {
		t.Fatal(err)
	}
	if from.Before(before) {
		t.Errorf("sys_period opens at %v, before the update ran at %v", from, before)
	}
}

func TestDeleteArchivesAndLeavesNoCurrentRow(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")

	if _, err := s.app.ExecContext(ctx, `DELETE FROM registry.decision_version WHERE tenant_id = $1 AND decision_id = $2`, tenantA, decision); err != nil {
		t.Fatalf("the application role must be able to delete from decision_version: %v", err)
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version WHERE decision_id = $1`, decision); n != 0 {
		t.Errorf("current rows = %d, want 0", n)
	}
	var (
		version int
		from    time.Time
		to      time.Time
	)
	err := s.app.QueryRowContext(ctx, `SELECT version, lower(sys_period), upper(sys_period) FROM registry.decision_version_history WHERE decision_id = $1`, decision).Scan(&version, &from, &to)
	if err != nil {
		t.Fatalf("want one closed history row: %v", err)
	}
	if version != 1 || to.Before(from) {
		t.Errorf("history row: version %d, sys_period [%v, %v), want version 1 and a closed period", version, from, to)
	}
}

func TestApplicationRoleCannotWriteHistory(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insert(t, tenantA, 1, "[2026-01-01,)")
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET version = 2 WHERE decision_id = $1`, decision); err != nil {
		t.Fatal(err)
	}

	writes := map[string]string{
		"insert": `INSERT INTO registry.decision_version_history SELECT * FROM registry.decision_version_history`,
		"update": `UPDATE registry.decision_version_history SET version = 9`,
		"delete": `DELETE FROM registry.decision_version_history`,
	}
	for name, statement := range writes {
		t.Run(name, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
	if n := count(t, s.app, `SELECT count(*) FROM registry.decision_version_history`); n != 1 {
		t.Errorf("the application role must still read history: rows = %d, want 1", n)
	}
}

func TestInsertSetsTransactionTime(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	// One decision, so the valid periods must not overlap.
	validPeriods := []string{"[2026-01-01,2026-02-01)", "[2026-02-01,2026-03-01)"}

	// Both a backdated open period and a closed period are replaced by the trigger.
	for i, supplied := range []string{"[2000-01-01,)", "[2000-01-01,2000-02-01)"} {
		before := dbNow(t, s.admin)
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
			VALUES ($1::uuid, $2::int, $3::uuid, '{}', ARRAY[$6::uuid], $4::text::tstzrange, $5::text::tstzrange)`,
			decision, i+1, tenantA, validPeriods[i], supplied, s.orgs[tenantA])
		if err != nil {
			t.Fatalf("insert with sys_period %s: %v", supplied, err)
		}
		after := dbNow(t, s.admin)

		var (
			from time.Time
			open bool
		)
		err = s.app.QueryRowContext(ctx, `SELECT lower(sys_period), upper(sys_period) IS NULL FROM registry.decision_version WHERE decision_id = $1 AND version = $2`, decision, i+1).Scan(&from, &open)
		if err != nil {
			t.Fatal(err)
		}
		if !open || from.Before(before) || from.After(after) {
			t.Errorf("supplied %s: stored open %v from %v, want open from a time in [%v, %v]", supplied, open, from, before, after)
		}
	}
}

func TestTableRejectsAClosedPeriodWhenTriggersAreOff(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	// session_replication_role = replica skips the triggers, so the check constraint is the
	// only thing left between a closed sys_period and decision_version. Only a superuser can set it.
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
		VALUES ($1::uuid, 1, $2::uuid, '{}', ARRAY[$3::uuid], '[2026-01-01,)', '[2000-01-01,2000-02-01)')`, decision, tenantA, s.orgs[tenantA])
	requireSQLState(t, err, "23514")
	if pgErr := pgError(t, err); pgErr.ConstraintName != "decision_version_sys_period_open" {
		t.Errorf("constraint = %q, want decision_version_sys_period_open", pgErr.ConstraintName)
	}
}

func TestApplicationRoleCannotSwitchTheTriggersOff(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	statements := map[string]string{
		"disable triggers":        `ALTER TABLE registry.decision_version DISABLE TRIGGER ALL`,
		"replica role":            `SET session_replication_role = replica`,
		"create in the schema":    `CREATE TABLE registry.extra (id int)`,
		"truncate current rows":   `TRUNCATE registry.decision_version`,
		"call a trigger function": `SELECT registry.decision_version_archive()`,
	}
	for name, statement := range statements {
		t.Run(name, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
}

func TestViewUsesSecurityInvoker(t *testing.T) {
	s := migrated(t)
	var options string
	err := s.admin.QueryRowContext(t.Context(), `SELECT coalesce(array_to_string(reloptions, ','), '') FROM pg_catalog.pg_class WHERE oid = 'registry.decision_version_all'::regclass`).Scan(&options)
	if err != nil {
		t.Fatal(err)
	}
	if options != "security_invoker=true" {
		t.Errorf("view options = %q, want security_invoker=true", options)
	}
}

func TestTriggerFunctionsAreDefinerFunctionsOfTheMigrationRole(t *testing.T) {
	s := migrated(t)
	for _, function := range []string{
		"registry.decision_version_open_sys_period()",
		"registry.decision_version_archive()",
		"registry.scope_write_closure()",
	} {
		t.Run(function, func(t *testing.T) {
			var (
				definer bool
				owner   string
				config  string
			)
			err := s.admin.QueryRowContext(t.Context(), `
				SELECT prosecdef, pg_get_userbyid(proowner), coalesce(array_to_string(proconfig, ';'), '')
				FROM pg_catalog.pg_proc WHERE oid = $1::text::regprocedure`, function).Scan(&definer, &owner, &config)
			if err != nil {
				t.Fatal(err)
			}
			if !definer {
				t.Error("function is not SECURITY DEFINER")
			}
			if owner != pgtest.Migrate {
				t.Errorf("owner = %q, want %q", owner, pgtest.Migrate)
			}
			if want := "search_path=pg_catalog, pg_temp"; config != want {
				t.Errorf("function config = %q, want %q", config, want)
			}
		})
	}
}

func TestTriggersRunOnTheCurrentTablesOnly(t *testing.T) {
	s := migrated(t)
	rows, err := s.admin.QueryContext(t.Context(), `
		SELECT tgrelid::regclass::text, tgname, tgtype
		FROM pg_catalog.pg_trigger WHERE NOT tgisinternal ORDER BY tgname`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()

	type trigger struct {
		table string
		name  string
		kind  int
	}
	var got []trigger
	for rows.Next() {
		var tr trigger
		if err := rows.Scan(&tr.table, &tr.name, &tr.kind); err != nil {
			t.Fatal(err)
		}
		got = append(got, tr)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update. An after trigger has no bit 2.
	want := []trigger{
		{"registry.baseline", "baseline_fingerprints", 1 | 2 | 4},
		{"registry.baseline", "baseline_open_sys_period", 1 | 2 | 4},
		{"registry.decision_version", "decision_version_archive", 1 | 2 | 8 | 16},
		{"registry.decision_version", "decision_version_clear_premise", 1 | 16},
		{"registry.decision_version", "decision_version_open_sys_period", 1 | 2 | 4},
		{"registry.decision_version", "decision_version_scope_refs", 1 | 2 | 4 | 16},
		{"registry.grandfather_period", "grandfather_period_open_sys_period", 1 | 2 | 4},
		{"registry.premise_clearance", "premise_clearance_check", 1 | 2 | 4},
		{"registry.premise_clearance", "premise_clearance_open_sys_period", 1 | 2 | 4},
		{"registry.premise_evaluation", "premise_evaluation_check", 1 | 2 | 4},
		{"registry.premise_evaluation", "premise_evaluation_open_sys_period", 1 | 2 | 4},
		{"registry.premise_host_allow", "premise_host_allow_open_sys_period", 1 | 2 | 4},
		{"registry.premise_host_allow", "premise_host_allow_prepare", 1 | 2 | 4},
		{"registry.premise_reason", "premise_reason_check", 1 | 2 | 4},
		{"registry.premise_reason", "premise_reason_open_sys_period", 1 | 2 | 4},
		{"registry.scope", "scope_prepare", 1 | 2 | 4},
		{"registry.scope", "scope_rewrite_closure", 1 | 16},
		{"registry.scope", "scope_version", 1 | 2 | 8 | 16},
		{"registry.scope", "scope_write_closure", 1 | 4},
		{"registry.supersession", "supersession_check", 1 | 2 | 4},
		{"registry.supersession", "supersession_close", 1 | 4},
		{"registry.supersession", "supersession_open_sys_period", 1 | 2 | 4},
		{"registry.waiver", "waiver_check", 1 | 2 | 4},
		{"registry.waiver_notice", "waiver_notice_check", 1 | 2 | 4},
		{"registry.waiver_notice", "waiver_notice_open_sys_period", 1 | 2 | 4},
		{"registry.waiver", "waiver_open_sys_period", 1 | 2 | 4},
	}
	if !slices.Equal(got, want) {
		t.Errorf("triggers = %+v, want %+v", got, want)
	}
}

func TestApplicationRoleHasNoPowerOverTheSchema(t *testing.T) {
	s := migrated(t)

	var superuser, bypassRLS, createRole bool
	err := s.admin.QueryRowContext(t.Context(), `SELECT rolsuper, rolbypassrls, rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = $1`, pgtest.App).Scan(&superuser, &bypassRLS, &createRole)
	if err != nil {
		t.Fatal(err)
	}
	if superuser || bypassRLS || createRole {
		t.Errorf("application role: superuser %v, bypassrls %v, createrole %v, want all false", superuser, bypassRLS, createRole)
	}
	owned := count(t, s.admin, `
		SELECT (SELECT count(*) FROM pg_catalog.pg_class WHERE relowner = $1::text::regrole)
		     + (SELECT count(*) FROM pg_catalog.pg_proc WHERE proowner = $1::text::regrole)
		     + (SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspowner = $1::text::regrole)`, pgtest.App)
	if owned != 0 {
		t.Errorf("application role owns %d objects, want none", owned)
	}
	notOwnedByMigrate := count(t, s.admin, `
		SELECT count(*) FROM pg_catalog.pg_class
		WHERE relnamespace = 'registry'::regnamespace AND relowner <> $1::text::regrole`, pgtest.Migrate)
	if notOwnedByMigrate != 0 {
		t.Errorf("%d registry relations are not owned by the migration role", notOwnedByMigrate)
	}
}

// asOf is the Q1 shape of section 2.3 without the scope join, which IPSO-23 defines.
func asOf(t *testing.T, db *sql.DB, validAt string, knownAt time.Time) []int {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `
		SELECT version FROM registry.decision_version_all
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
		  AND valid_period @> $3::timestamptz
		  AND sys_period @> $4::timestamptz
		ORDER BY version`, tenantA, decision, validAt, knownAt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return versions
}

func TestAsOfQueryReadsBothTables(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	beforeInsert := dbNow(t, s.admin)
	s.insert(t, tenantA, 1, "[2026-04-01,)")
	knownThen := dbNow(t, s.admin)
	sleep(t, s.admin)
	// Retroactive correction: the decision applied from 1 March, and ipso learns that now.
	if _, err := s.app.ExecContext(ctx, `UPDATE registry.decision_version SET version = 2, valid_period = '[2026-03-01,)' WHERE decision_id = $1`, decision); err != nil {
		t.Fatal(err)
	}
	knownNow := dbNow(t, s.admin)

	tests := []struct {
		name    string
		validAt string
		knownAt time.Time
		want    []int
	}{
		{"before ipso knew anything", "2026-05-01", beforeInsert, nil},
		{"as known then, after adoption", "2026-05-01", knownThen, []int{1}},
		{"as known now, after adoption", "2026-05-01", knownNow, []int{2}},
		{"as known then, in the corrected month", "2026-03-15", knownThen, nil},
		{"as known now, in the corrected month", "2026-03-15", knownNow, []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := asOf(t, s.app, tt.validAt, tt.knownAt); !slices.Equal(got, tt.want) {
				t.Errorf("versions = %v, want %v", got, tt.want)
			}
		})
	}
}
