//go:build integration

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// The four commands, run through Run with the environment a deployment sets, against a real database: one
// tenant is created, exported, restored into another, and offboarded.
func TestTenantCommandsMoveATenantAndDeleteIt(t *testing.T) {
	const (
		source = "00000000-0000-4000-8000-0000000000a5"
		target = "00000000-0000-4000-8000-0000000000a6"
		person = "00000000-0000-4000-8000-0000000000a1"
	)
	db := server.NewDatabase(t)
	admin := db.Open(t, pgtest.Admin)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(tenantKEKEnv, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))

	// An application command holds the application credential and not the migration one, and the other
	// way round.
	asApp := func(dsn string, args ...string) (int, string, string) {
		t.Setenv(databaseEnv, dsn)
		t.Setenv(migrateDatabaseEnv, "")
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	asMigrate := func(dsn string, args ...string) (int, string, string) {
		t.Setenv(databaseEnv, "")
		t.Setenv(migrateDatabaseEnv, dsn)
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	count := func(table, tenant string) int {
		t.Helper()
		var n int
		if err := admin.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table+" WHERE tenant_id = $1::uuid", tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// create: the first person is bound and made admin, and a second run says it changed nothing.
	app := db.Open(t, pgtest.App)
	pgtest.SeedEveryTable(t, app, source)
	create := []string{"tenant", "create", "--tenant", target, "--name", "restored"}
	code, stdout, stderr := asApp(db.DSN(pgtest.App), create...)
	if code != 0 || !strings.Contains(stdout, `"created": true`) {
		t.Fatalf("create: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = asApp(db.DSN(pgtest.App), create...)
	if code != 0 || !strings.Contains(stdout, `"created": false`) || !strings.Contains(stdout, `"key_created": false`) {
		t.Fatalf("second create: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, _, stderr = asApp(db.DSN(pgtest.App), "tenant", "create", "--tenant", "00000000-0000-4000-8000-0000000000a7", "--name", "bound",
		"--person", person, "--person-name", "Ada", "--issuer", "https://idp.example.test", "--subject", "s1")
	if code != 0 || count("identity.login", "00000000-0000-4000-8000-0000000000a7") != 1 || count("identity.role_binding", "00000000-0000-4000-8000-0000000000a7") != 1 {
		t.Fatalf("create with a person: code %d, stderr %q", code, stderr)
	}

	// An application command never runs as a superuser or with the migration credential.
	if code, _, stderr := asApp(db.DSN(pgtest.Admin), create...); code != 1 || !strings.Contains(stderr, "refusing") {
		t.Errorf("create as a superuser: code %d, stderr %q", code, stderr)
	}
	t.Setenv(databaseEnv, db.DSN(pgtest.App))
	t.Setenv(migrateDatabaseEnv, db.DSN(pgtest.Migrate))
	var out, errOut bytes.Buffer
	if code := Run(create, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "migration credential") {
		t.Errorf("create holding the migration credential: code %d, stderr %q", code, errOut.String())
	}

	// export
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archive := filepath.Join(dir, "source.age")
	code, stdout, stderr = asApp(db.DSN(pgtest.App), "tenant", "export", "--tenant", source, "--recipient", id.Recipient().String(), "--out", archive)
	if code != 0 {
		t.Fatalf("export: code %d, stderr %q", code, stderr)
	}
	var exported struct{ Total int }
	if err := json.Unmarshal([]byte(stdout), &exported); err != nil || exported.Total == 0 {
		t.Fatalf("export report %q: %v", stdout, err)
	}
	if info, err := os.Stat(archive); err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatalf("archive: %v, %v", info, err)
	}

	// restore: as a superuser it is refused, as the migration role it works.
	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := []string{"tenant", "restore", "--tenant", target, "--identity", identityFile, "--in", archive}
	if code, _, stderr := asMigrate(db.DSN(pgtest.Admin), restore...); code != 1 || !strings.Contains(stderr, migrate.ErrPrivilegedRole.Error()) {
		t.Errorf("restore as a superuser: code %d, stderr %q", code, stderr)
	}
	if code, _, stderr := asMigrate(db.DSN(pgtest.App), restore...); code != 1 {
		t.Errorf("restore as the application role: code %d, stderr %q", code, stderr)
	}
	if count("registry.scope", target) != 0 {
		t.Fatal("a refused restore wrote rows")
	}
	code, _, stderr = asMigrate(db.DSN(pgtest.Migrate), restore...)
	if code != 0 {
		t.Fatalf("restore: code %d, stderr %q", code, stderr)
	}
	if count("registry.scope", target) == 0 || count("registry.scope", target) != count("registry.scope", source) {
		t.Errorf("scopes: target %d, source %d", count("registry.scope", target), count("registry.scope", source))
	}

	// offboard: the name must be the tenant's, and then nothing of the tenant is left.
	if code, _, stderr := asMigrate(db.DSN(pgtest.Migrate), "tenant", "offboard", "--tenant", source, "--confirm", "restored"); code != 1 || !strings.Contains(stderr, "confirmation") {
		t.Errorf("offboard with the wrong name: code %d, stderr %q", code, stderr)
	}
	code, stdout, stderr = asMigrate(db.DSN(pgtest.Migrate), "tenant", "offboard", "--tenant", source, "--confirm", "synthetic tenant")
	if code != 0 || !strings.Contains(stdout, `"verified": true`) || !strings.Contains(stdout, `"key_destroyed": true`) {
		t.Fatalf("offboard: code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, table := range []string{"registry.scope", "registry.decision_version", "identity.principal", "tenancy.tenant", "tenancy.tenant_key"} {
		if n := count(table, source); n != 0 {
			t.Errorf("%d rows of the source remain in %s", n, table)
		}
	}
	if count("tenancy.offboarding", source) != 1 || count("registry.scope", target) == 0 {
		t.Error("the tombstone is missing or the restored tenant lost its rows")
	}
	// The id is gone for good.
	if code, _, stderr := asApp(db.DSN(pgtest.App), "tenant", "create", "--tenant", source, "--name", "synthetic tenant"); code != 1 || !strings.Contains(stderr, "offboarded") {
		t.Errorf("create for an offboarded id: code %d, stderr %q", code, stderr)
	}
}
