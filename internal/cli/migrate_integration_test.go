//go:build integration

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3/lock"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var embeddedFiles = []string{"00001_btree_gist.sql", "00002_registry_decision_version.sql"}

func scalar(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// appliedNothing reports whether no migration file has run: no extension and no registry schema.
func appliedNothing(t *testing.T, admin *sql.DB) bool {
	t.Helper()
	return scalar(t, admin, `SELECT count(*) FROM pg_catalog.pg_extension WHERE extname = 'btree_gist'`) == 0 &&
		scalar(t, admin, `SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'registry'`) == 0
}

// untouched reports whether a run left no trace at all, not even goose's version table.
func untouched(t *testing.T, admin *sql.DB) bool {
	t.Helper()
	return appliedNothing(t, admin) &&
		scalar(t, admin, `SELECT count(*) FROM pg_catalog.pg_class WHERE relname = 'goose_db_version'`) == 0
}

func TestMigrateAppliesTheMigrationsAsTheMigrationRole(t *testing.T) {
	db := server.NewDatabase(t)
	t.Setenv(databaseURLEnv, db.DSN(pgtest.Migrate))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"migrate"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, name := range embeddedFiles {
		if !strings.Contains(stdout.String(), "applied "+name+"\n") {
			t.Errorf("stdout = %q, want it to report %s", stdout.String(), name)
		}
	}

	admin := db.Open(t, pgtest.Admin)
	if n := scalar(t, admin, `SELECT count(*) FROM goose_db_version WHERE version_id > 0`); n != len(embeddedFiles) {
		t.Errorf("recorded versions = %d, want %d", n, len(embeddedFiles))
	}
	if n := scalar(t, admin, `SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace = 'registry'::regnamespace AND relname IN ('decision_version', 'decision_version_history', 'decision_version_all')`); n != 3 {
		t.Errorf("registry objects = %d, want 3", n)
	}

	// A second run finds nothing to do.
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"migrate"}, &stdout, &stderr); code != 0 {
		t.Fatalf("second run: exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "no pending migrations\n" {
		t.Errorf("second run: stdout = %q", stdout.String())
	}
}

// Two runs against one empty database apply each version once: the session lock makes one wait.
func TestMigrateSerializesConcurrentRuns(t *testing.T) {
	db := server.NewDatabase(t)
	d := deps{
		getenv:  func(string) string { return db.DSN(pgtest.Migrate) },
		migrate: migrate.Run,
	}

	const runs = 2
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		applied = make(map[string]int)
	)
	for range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"migrate"}, &stdout, &stderr, d)
			mu.Lock()
			defer mu.Unlock()
			if code != 0 {
				t.Errorf("exit code = %d, stderr = %q", code, stderr.String())
			}
			for _, name := range embeddedFiles {
				if strings.Contains(stdout.String(), "applied "+name+"\n") {
					applied[name]++
				}
			}
		}()
	}
	wg.Wait()

	for _, name := range embeddedFiles {
		if applied[name] != 1 {
			t.Errorf("%s was applied %d times, want once", name, applied[name])
		}
	}
	admin := db.Open(t, pgtest.Admin)
	if n := scalar(t, admin, `SELECT count(*) FROM goose_db_version WHERE version_id > 0`); n != len(embeddedFiles) {
		t.Errorf("recorded versions = %d, want %d", n, len(embeddedFiles))
	}
}

// The run takes goose's session advisory lock before it applies any file. The test holds that
// lock itself, so a run that ignores it would apply the files while the lock is held. goose
// creates its version table before it locks, so that table may already exist.
func TestMigrateWaitsForTheAdvisoryLock(t *testing.T) {
	db := server.NewDatabase(t)
	admin := db.Open(t, pgtest.Admin)
	conn, err := admin.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), `SELECT pg_advisory_lock($1)`, lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}

	d := deps{getenv: func(string) string { return db.DSN(pgtest.Migrate) }, migrate: migrate.Run}
	finished := make(chan int, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		finished <- run(context.Background(), []string{"migrate"}, &stdout, &stderr, d)
	}()

	select {
	case code := <-finished:
		t.Fatalf("the run finished with exit code %d while the lock was held", code)
	case <-time.After(2 * time.Second):
	}
	if !appliedNothing(t, admin) {
		t.Fatal("the run applied migrations while the lock was held")
	}

	if _, err := conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock($1)`, lock.DefaultLockID); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-finished:
		if code != 0 {
			t.Fatalf("exit code = %d after the lock was released", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not finish after the lock was released")
	}
	if n := scalar(t, admin, `SELECT count(*) FROM goose_db_version WHERE version_id > 0`); n != len(embeddedFiles) {
		t.Errorf("recorded versions = %d, want %d", n, len(embeddedFiles))
	}
}

func TestMigrateRefusesAPrivilegedRole(t *testing.T) {
	tests := []struct {
		name string
		dsn  func(*pgtest.Database) string
	}{
		{"superuser", func(db *pgtest.Database) string { return db.DSN(pgtest.Admin) }},
		{"BYPASSRLS role", func(db *pgtest.Database) string { return db.DSN(pgtest.Bypass) }},
		{"plain login that switches to a BYPASSRLS role", func(db *pgtest.Database) string {
			return db.DSNSwitchingRole(pgtest.Member, pgtest.Bypass)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := server.NewDatabase(t)
			t.Setenv(databaseURLEnv, tt.dsn(db))

			var stdout, stderr bytes.Buffer
			if code := Run([]string{"migrate"}, &stdout, &stderr); code == 0 {
				t.Fatal("exit code = 0, want non-zero")
			}
			if !strings.Contains(stderr.String(), migrate.ErrPrivilegedRole.Error()) {
				t.Errorf("stderr = %q, want the refusal", stderr.String())
			}
			if !untouched(t, db.Open(t, pgtest.Admin)) {
				t.Error("the refused run left objects behind")
			}
		})
	}
}

// The application role owns nothing and cannot create a schema, so a run as that role fails
// closed instead of applying part of the stream.
func TestMigrateAsTheApplicationRoleFailsClosed(t *testing.T) {
	db := server.NewDatabase(t)
	t.Setenv(databaseURLEnv, db.DSN(pgtest.App))

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"migrate"}, &stdout, &stderr); code == 0 {
		t.Fatal("exit code = 0, want non-zero")
	}
	if !untouched(t, db.Open(t, pgtest.Admin)) {
		t.Error("the failed run left objects behind")
	}
}
