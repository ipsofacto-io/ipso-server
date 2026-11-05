//go:build integration

package migrate_test

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
)

// riverShape lists what a schema of River's tables is made of, with the schema name removed, so that two
// schemas made by different means can be compared line by line. river_migration is left out: goose is the
// one ledger (ADR-0050, ADR-0097).
const riverShape = `
	SELECT replace(line, $1::text || '.', '') FROM (
		SELECT format('relation %s %s %s', c.relname, c.relkind, c.relpersistence) AS line
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = $1::text AND c.relname NOT LIKE 'river_migration%'
		UNION ALL
		SELECT format('column %s.%s %s notnull=%s default=%s', c.relname, a.attname,
		              format_type(a.atttypid, a.atttypmod), a.attnotnull, coalesce(pg_get_expr(d.adbin, d.adrelid), ''))
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = c.oid AND d.adnum = a.attnum
		WHERE n.nspname = $1::text AND c.relkind = 'r' AND c.relname <> 'river_migration'
		UNION ALL
		SELECT format('constraint %s.%s %s', c.relname, con.conname, pg_get_constraintdef(con.oid))
		FROM pg_catalog.pg_constraint AS con
		JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = $1::text AND c.relname <> 'river_migration'
		UNION ALL
		SELECT pg_get_indexdef(i.indexrelid)
		FROM pg_catalog.pg_index AS i
		JOIN pg_catalog.pg_class AS t ON t.oid = i.indrelid
		JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
		WHERE n.nspname = $1::text AND t.relname <> 'river_migration'
		UNION ALL
		SELECT pg_get_triggerdef(tg.oid)
		FROM pg_catalog.pg_trigger AS tg
		JOIN pg_catalog.pg_class AS t ON t.oid = tg.tgrelid
		JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
		WHERE n.nspname = $1::text AND NOT tg.tgisinternal
		UNION ALL
		SELECT pg_get_functiondef(p.oid)
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
		WHERE n.nspname = $1::text
		UNION ALL
		SELECT format('enum %s %s %s', t.typname, e.enumsortorder, e.enumlabel)
		FROM pg_catalog.pg_enum AS e
		JOIN pg_catalog.pg_type AS t ON t.oid = e.enumtypid
		JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
		WHERE n.nspname = $1::text
	) AS shape
	ORDER BY 1`

func shapeOf(t *testing.T, db *sql.DB, schema string) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), riverShape, schema)
	if err != nil {
		t.Fatalf("read the shape of %s: %v", schema, err)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// River's own migrator is the reference for what its client expects. A River release that adds a
// migration makes this test fail until a goose file carries it (ADR-0097).
func TestRiverTablesMatchTheMigrationsOfRiverItself(t *testing.T) {
	db := server.NewDatabase(t)
	ctx := t.Context()
	if _, err := migrate.Run(ctx, db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin := db.Open(t, pgtest.Admin)
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA river_reference`); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, db.DSN(pgtest.Admin))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: "river_reference"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatalf("River's own migrations: %v", err)
	}

	got, want := shapeOf(t, admin, "river"), shapeOf(t, admin, "river_reference")
	// A shape of two empty schemas would match, so require the tables to be there.
	for _, table := range []string{"river_job", "river_leader", "river_queue", "river_notification"} {
		if !slices.ContainsFunc(got, func(line string) bool { return strings.HasPrefix(line, "relation "+table+" r ") }) {
			t.Fatalf("schema river has no table %s:\n%s", table, strings.Join(got, "\n"))
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("schema river differs from River's own migrations.\nonly in river:\n%s\nonly in River's:\n%s",
			strings.Join(difference(got, want), "\n"), strings.Join(difference(want, got), "\n"))
	}
}

func difference(a, b []string) []string {
	var only []string
	for _, line := range a {
		if !slices.Contains(b, line) {
			only = append(only, line)
		}
	}
	return only
}

func TestRiverTablesBelongToTheMigrationRoleAndTheApplicationRoleHoldsWhatRiverNeeds(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()

	if err := rls.Check(ctx, s.app); err != nil {
		t.Errorf("rls.Check refuses the application role once River's tables exist: %v", err)
	}

	if n := count(t, s.admin, `
		SELECT (SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'river'::regnamespace AND relowner <> $1::text::regrole)
		     + (SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace = 'river'::regnamespace AND proowner <> $1::text::regrole)
		     + (SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'river' AND nspowner <> $1::text::regrole)`, pgtest.Migrate); n != 0 {
		t.Errorf("%d objects of schema river are not owned by the migration role", n)
	}

	privileges := func(kind, object string, privileges ...string) map[string]bool {
		t.Helper()
		got := make(map[string]bool, len(privileges))
		for _, privilege := range privileges {
			var held bool
			query := fmt.Sprintf(`SELECT has_%s_privilege($1::text, $2::text, $3::text)`, kind)
			if err := s.admin.QueryRowContext(ctx, query, pgtest.App, object, privilege).Scan(&held); err != nil {
				t.Fatalf("%s %s %s: %v", kind, object, privilege, err)
			}
			got[privilege] = held
		}
		return got
	}
	check := func(kind, object string, want map[string]bool) {
		t.Helper()
		var names []string
		for name := range want {
			names = append(names, name)
		}
		slices.Sort(names)
		got := privileges(kind, object, names...)
		for _, name := range names {
			if got[name] != want[name] {
				t.Errorf("%s %s: %s = %v, want %v", kind, object, name, got[name], want[name])
			}
		}
	}

	check("schema", "river", map[string]bool{"USAGE": true, "CREATE": false})
	readWrite := map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "TRUNCATE": false, "TRIGGER": false, "REFERENCES": false}
	for _, table := range []string{"river.river_job", "river.river_leader", "river.river_queue"} {
		check("table", table, readWrite)
	}
	// River's SQLite driver is the only one that uses this table.
	check("table", "river.river_notification", map[string]bool{"SELECT": false, "INSERT": false, "UPDATE": false, "DELETE": false})
	check("sequence", "river.river_job_id_seq", map[string]bool{"USAGE": true, "SELECT": true, "UPDATE": false})
	check("sequence", "river.river_notification_id_seq", map[string]bool{"USAGE": false, "SELECT": false})

	const function = "river.river_job_state_in_bitmask(bit, river.river_job_state)"
	for role, want := range map[string]bool{pgtest.App: true, pgtest.Bypass: false} {
		var held bool
		if err := s.admin.QueryRowContext(ctx, `SELECT has_function_privilege($1::text, $2::text, 'EXECUTE')`, role, function).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if held != want {
			t.Errorf("EXECUTE on %s for %s = %v, want %v", function, role, held, want)
		}
	}
}
