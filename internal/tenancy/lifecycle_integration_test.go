//go:build integration

package tenancy_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const (
	tenantA = "00000000-0000-4000-8000-00000000000a"
	tenantB = "00000000-0000-4000-8000-00000000000b"
	tenantC = "00000000-0000-4000-8000-00000000000c"

	tombstone = "tenancy.offboarding"
)

// The tables the application never exports or restores, whatever the schema holds.
var notRestored = map[string]bool{
	"tenancy.tenant":     true,
	"tenancy.tenant_key": true,
	"identity.session":   true,
	// A binding is unique across tenants, so a restore into a fresh tenant would find it taken (ADR-0101).
	"tenancy.installation": true,
	tombstone:              true,
}

type lifecycle struct {
	app, migrator, admin *sql.DB
	kek                  tenancy.KEK
}

func newLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	kek, err := tenancy.ParseKEK(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &lifecycle{app: db.Open(t, pgtest.App), migrator: db.Open(t, pgtest.Migrate), admin: db.Open(t, pgtest.Admin), kek: kek}
}

func (l *lifecycle) provision(t *testing.T, tenant, name string, person *tenancy.Person) tenancy.ProvisionReport {
	t.Helper()
	report, err := tenancy.Provision(t.Context(), l.app, tenancy.ProvisionOptions{Tenant: uuid.MustParse(tenant), Name: name, Person: person, KEK: l.kek})
	if err != nil {
		t.Fatalf("provision %s: %v", tenant, err)
	}
	return report
}

// tables lists every table with a tenant_id column, from the catalog, the way the commands find them.
func (l *lifecycle) tables(t *testing.T) []string {
	t.Helper()
	rows, err := l.admin.QueryContext(t.Context(), `
		SELECT n.nspname || '.' || c.relname
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// count counts the rows of a tenant as the superuser, which row-level security does not bind.
func (l *lifecycle) count(t *testing.T, table, tenant string) int {
	t.Helper()
	var n int
	if err := l.admin.QueryRowContext(t.Context(), fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1::uuid`, table), tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// countAs counts the rows a role sees when ipso.tenant is the tenant.
func (l *lifecycle) countAs(t *testing.T, db *sql.DB, table, tenant string) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), db, tenant, fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1::uuid`, table), []any{tenant}, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// rows returns the rows of a tenant without the tenant id, so two tenants can be compared.
func (l *lifecycle) rows(t *testing.T, table, tenant string) []string {
	t.Helper()
	res, err := l.admin.QueryContext(t.Context(), fmt.Sprintf(`SELECT (to_jsonb(t) - 'tenant_id')::text FROM %s AS t WHERE tenant_id = $1::uuid ORDER BY 1`, table), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Close() }()
	var out []string
	for res.Next() {
		var row string
		if err := res.Scan(&row); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := res.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (l *lifecycle) addJob(t *testing.T, tenant string) {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"tenant": tenant})
	if _, err := l.admin.ExecContext(t.Context(),
		`INSERT INTO river.river_job (max_attempts, args, kind, queue) VALUES (3, $1::jsonb, 'waiver_notices', 'waiver_notices')`, string(args)); err != nil {
		t.Fatal(err)
	}
}

func (l *lifecycle) jobs(t *testing.T, tenant string) int {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"tenant": tenant})
	var n int
	if err := l.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM river.river_job WHERE args @> $1::jsonb`, string(args)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (l *lifecycle) export(t *testing.T, tenant string, id *age.X25519Identity) ([]byte, tenancy.ExportReport) {
	t.Helper()
	var out bytes.Buffer
	report, err := tenancy.Export(t.Context(), l.app, tenancy.ExportOptions{Tenant: uuid.MustParse(tenant), Recipients: []age.Recipient{id.Recipient()}, Out: &out})
	if err != nil {
		t.Fatalf("export %s: %v", tenant, err)
	}
	return out.Bytes(), report
}

func (l *lifecycle) restore(archive []byte, tenant string, id *age.X25519Identity, t *testing.T) (tenancy.RestoreReport, error) {
	t.Helper()
	return tenancy.Restore(t.Context(), l.migrator, tenancy.RestoreOptions{Tenant: uuid.MustParse(tenant), Identities: []age.Identity{id}, In: bytes.NewReader(archive)})
}

func identity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestProvisionCreatesAnIsolatedTenantAndARepeatChangesNothing(t *testing.T) {
	l := newLifecycle(t)
	person := &tenancy.Person{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000a1"), Name: "Ada", Issuer: "https://idp.example.test", Subject: "sub-1"}

	first := l.provision(t, tenantA, "acme", person)
	if !first.Created || !first.KeyCreated || !first.PersonBound {
		t.Fatalf("first run = %+v", first)
	}
	if err := tenancy.Require(t.Context(), l.app, uuid.MustParse(tenantA)); err != nil {
		t.Fatalf("Require: %v", err)
	}
	// The wrapped key opens with the key encryption key for this tenant and no other.
	var wrapped []byte
	if err := pgtest.Scan(t.Context(), l.app, tenantA, `SELECT wrapped_dek FROM tenancy.tenant_key WHERE tenant_id = $1::uuid`, []any{tenantA}, &wrapped); err != nil {
		t.Fatal(err)
	}
	if dek, err := l.kek.Unwrap(uuid.MustParse(tenantA), wrapped); err != nil || len(dek) != 32 {
		t.Fatalf("Unwrap = %x, %v", dek, err)
	}
	if _, err := l.kek.Unwrap(uuid.MustParse(tenantB), wrapped); !errors.Is(err, tenancy.ErrKey) {
		t.Fatalf("another tenant opened the key: %v", err)
	}

	// A second tenant sees nothing of the first, and the first nothing of the second.
	l.provision(t, tenantB, "globex", nil)
	for _, table := range []string{"tenancy.tenant", "tenancy.tenant_key"} {
		if got := l.countAs(t, l.app, table, tenantB); got != 1 {
			t.Errorf("tenant B sees %d rows of %s, want its own 1", got, table)
		}
		var seen int
		if err := pgtest.Scan(t.Context(), l.app, tenantB, fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1::uuid`, table), []any{tenantA}, &seen); err != nil || seen != 0 {
			t.Errorf("tenant B sees %d rows of tenant A in %s (%v)", seen, table, err)
		}
	}
	if l.count(t, "identity.principal", tenantB) != 0 || l.count(t, "identity.principal", tenantA) != 1 {
		t.Error("the person was not bound to tenant A only")
	}
	// The first person is the tenant's admin, over the whole tenant, so someone can grant the other roles.
	var role string
	var scoped bool
	if err := pgtest.Scan(t.Context(), l.app, tenantA, `SELECT role, scope_id IS NOT NULL FROM identity.role_binding WHERE principal_id = $1::uuid`, []any{person.ID.String()}, &role, &scoped); err != nil || role != "admin" || scoped {
		t.Errorf("the first person holds %q (scoped %v), want admin over the tenant (%v)", role, scoped, err)
	}

	before := l.rows(t, "tenancy.tenant_key", tenantA)
	again := l.provision(t, tenantA, "acme", person)
	if again.Created || again.KeyCreated || again.PersonBound {
		t.Fatalf("repeat = %+v, want no change", again)
	}
	if n := l.count(t, "identity.role_binding", tenantA); n != 1 {
		t.Errorf("a repeat left %d bindings, want the one admin binding", n)
	}
	if after := l.rows(t, "tenancy.tenant_key", tenantA); strings.Join(after, "") != strings.Join(before, "") {
		t.Error("a repeat replaced the wrapped key")
	}

	// A revoke is kept while the tenant has another admin, and a tenant left with none gets its first
	// person back as admin from create.
	run := func(query string, args ...any) {
		t.Helper()
		if _, err := pgtest.Exec(t.Context(), l.app, tenantA, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	var other string
	if err := pgtest.Scan(t.Context(), l.app, tenantA, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1::uuid, 'human', 'Bea') RETURNING id::text`, []any{tenantA}, &other); err != nil {
		t.Fatal(err)
	}
	run(`INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1::uuid, $2::uuid, 'admin')`, tenantA, other)
	run(`DELETE FROM identity.role_binding WHERE tenant_id = $1::uuid AND principal_id = $2::uuid`, tenantA, person.ID.String())
	if again := l.provision(t, tenantA, "acme", person); again.PersonBound {
		t.Errorf("create restored a revoked admin while another admin exists: %+v", again)
	}
	if n := l.count(t, "identity.role_binding", tenantA); n != 1 {
		t.Errorf("%d bindings after the revoke, want the other admin's", n)
	}
	run(`DELETE FROM identity.role_binding WHERE tenant_id = $1::uuid AND principal_id = $2::uuid`, tenantA, other)
	if again := l.provision(t, tenantA, "acme", person); !again.PersonBound {
		t.Errorf("create did not restore the admin of a tenant with none: %+v", again)
	}
}

func TestProvisionRefusesOtherAttributesAndAnotherKey(t *testing.T) {
	l := newLifecycle(t)
	person := &tenancy.Person{ID: uuid.MustParse("00000000-0000-4000-8000-0000000000a1"), Name: "Ada", Issuer: "https://idp.example.test", Subject: "sub-1"}
	l.provision(t, tenantA, "acme", person)

	other := *person
	other.Name = "Bea"
	otherLogin := *person
	otherLogin.ID = uuid.MustParse("00000000-0000-4000-8000-0000000000a2")
	otherKEK, _ := tenancy.ParseKEK(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))

	for name, opts := range map[string]tenancy.ProvisionOptions{
		"another name":               {Tenant: uuid.MustParse(tenantA), Name: "globex", Person: person, KEK: l.kek},
		"another person name":        {Tenant: uuid.MustParse(tenantA), Name: "acme", Person: &other, KEK: l.kek},
		"a login of someone else":    {Tenant: uuid.MustParse(tenantA), Name: "acme", Person: &otherLogin, KEK: l.kek},
		"another key encryption key": {Tenant: uuid.MustParse(tenantA), Name: "acme", Person: person, KEK: otherKEK},
	} {
		_, err := tenancy.Provision(t.Context(), l.app, opts)
		switch name {
		case "another key encryption key":
			if !errors.Is(err, tenancy.ErrKey) {
				t.Errorf("%s: %v, want ErrKey", name, err)
			}
		default:
			if !errors.Is(err, tenancy.ErrConflict) {
				t.Errorf("%s: %v, want ErrConflict", name, err)
			}
		}
	}
	if l.count(t, "identity.principal", tenantA) != 1 || l.count(t, "identity.login", tenantA) != 1 {
		t.Error("a refused run left rows behind")
	}
}

func TestExportThenRestoreReproducesTheTenantInAFreshOne(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	pgtest.SeedEveryTable(t, l.app, tenantB)
	l.provision(t, tenantC, "restored", nil)
	id := identity(t)

	archive, exported := l.export(t, tenantA, id)

	// The archive holds this tenant's rows and nobody else's, and is not readable without the key.
	want := 0
	for _, table := range l.tables(t) {
		if !notRestored[table] || table == "tenancy.tenant" {
			want += l.count(t, table, tenantA)
		}
	}
	if exported.Total != int64(want) {
		t.Fatalf("export wrote %d rows, tenant A has %d in the exported tables", exported.Total, want)
	}
	if bytes.Contains(archive, []byte("synthetic tenant")) {
		t.Fatal("the archive holds plaintext")
	}

	report, err := l.restore(archive, tenantC, id, t)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if report.Source.String() != tenantA || report.Total != exported.Total-1 {
		t.Fatalf("report = %+v; want source A and every row but the tenant row (%d)", report, exported.Total-1)
	}

	// Row for row, ids and transaction time included: the triggers did not stamp anything again.
	for _, table := range l.tables(t) {
		if notRestored[table] {
			continue
		}
		got, wantRows := l.rows(t, table, tenantC), l.rows(t, table, tenantA)
		if len(wantRows) == 0 {
			t.Errorf("the seed left %s empty", table)
		}
		if strings.Join(got, "\n") != strings.Join(wantRows, "\n") {
			t.Errorf("%s differs after the restore:\n got  %v\n want %v", table, got, wantRows)
		}
	}
	// What a restore must not carry: sessions, the source's key, the source's name.
	if n := l.count(t, "identity.session", tenantC); n != 0 {
		t.Errorf("%d sessions were restored", n)
	}
	var name string
	if err := pgtest.Scan(t.Context(), l.app, tenantC, `SELECT name FROM tenancy.tenant WHERE tenant_id = $1::uuid`, []any{tenantC}, &name); err != nil || name != "restored" {
		t.Errorf("tenant C is called %q (%v)", name, err)
	}
	if a, c := l.rows(t, "tenancy.tenant_key", tenantA), l.rows(t, "tenancy.tenant_key", tenantC); len(c) != 1 || a[0] == c[0] {
		t.Error("the restored tenant did not keep its own wrapped key")
	}
	// The source and the bystander are untouched, and the restored tenant works.
	for _, table := range l.tables(t) {
		if table != tombstone && l.count(t, table, tenantA) == 0 {
			t.Errorf("the export emptied %s of tenant A", table)
		}
	}
	if err := tenancy.Require(t.Context(), l.app, uuid.MustParse(tenantC)); err != nil {
		t.Fatal(err)
	}
	if got := l.countAs(t, l.app, "registry.scope", tenantC); got != l.count(t, "registry.scope", tenantA) {
		t.Errorf("tenant C sees %d scopes, want %d", got, l.count(t, "registry.scope", tenantA))
	}
	// A tenant that has rows is not a target.
	if _, err := l.restore(archive, tenantC, id, t); !errors.Is(err, tenancy.ErrNotFresh) {
		t.Errorf("second restore = %v, want ErrNotFresh", err)
	}
	if _, err := l.restore(archive, tenantB, id, t); !errors.Is(err, tenancy.ErrNotFresh) {
		t.Errorf("restore into tenant B = %v, want ErrNotFresh", err)
	}
	if _, err := l.restore(archive, "00000000-0000-4000-8000-0000000000ff", id, t); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Errorf("restore into a tenant with no row = %v, want ErrUnknownTenant", err)
	}
}

// parts is an archive taken apart, so a test can break the rules the writer keeps.
type parts struct {
	header map[string]any
	rows   []partRow
}

type partRow struct {
	Table string          `json:"table"`
	Row   json.RawMessage `json:"row"`
}

func open(t *testing.T, archive []byte, id *age.X25519Identity) parts {
	t.Helper()
	dec, err := age.Decrypt(bytes.NewReader(archive), id)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(dec)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(plain), "\n"), "\n")
	var p parts
	if err := json.Unmarshal([]byte(lines[0]), &p.header); err != nil {
		t.Fatal(err)
	}
	for _, line := range lines[1 : len(lines)-1] {
		var r partRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		p.rows = append(p.rows, r)
	}
	return p
}

// line encodes a value as one JSON line. Without SetEscapeHTML(false), json.Marshal would rewrite &, < and >
// inside a raw row as \u0026 and so on.
func line(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// seal writes the parts as an archive with a trailer that matches them.
func seal(t *testing.T, p parts, id *age.X25519Identity) []byte {
	t.Helper()
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(enc)
	_, _ = zw.Write(line(t, p.header))
	type sum struct {
		Rows   int64  `json:"rows"`
		SHA256 string `json:"sha256"`
	}
	tables := p.header["tables"].([]any)
	counts := map[string]int64{}
	hashes := map[string]interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}{}
	for _, name := range tables {
		hashes[name.(string)] = sha256.New()
	}
	for _, r := range p.rows {
		// PostgreSQL prints jsonb with spaces after colons and commas, and the encoder compacts a raw
		// message. Compacting first makes the bytes that are hashed the bytes that are written.
		var compact bytes.Buffer
		if err := json.Compact(&compact, r.Row); err != nil {
			t.Fatal(err)
		}
		r.Row = compact.Bytes()
		_, _ = zw.Write(line(t, r))
		if h, ok := hashes[r.Table]; ok {
			counts[r.Table]++
			_, _ = h.Write(r.Row)
			_, _ = h.Write([]byte{'\n'})
		}
	}
	trailer := map[string]sum{}
	for _, name := range tables {
		trailer[name.(string)] = sum{Rows: counts[name.(string)], SHA256: hex.EncodeToString(hashes[name.(string)].Sum(nil))}
	}
	_, _ = zw.Write(line(t, map[string]any{"end": true, "tables": trailer}))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestRestoreRefusesABadArchiveAndWritesNothing(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	l.provision(t, tenantC, "restored", nil)
	id := identity(t)
	archive, _ := l.export(t, tenantA, id)

	dropPrincipals := func(p *parts) {
		kept := p.rows[:0]
		for _, r := range p.rows {
			if r.Table != "identity.principal" {
				kept = append(kept, r)
			}
		}
		p.rows = kept
	}
	cases := map[string]struct {
		archive []byte
		id      *age.X25519Identity
		want    error
	}{
		"another identity": {archive, identity(t), tenancy.ErrArchive},
		"a truncated file": {archive[:len(archive)-100], id, tenancy.ErrArchive},
		"a changed byte":   {func() []byte { b := bytes.Clone(archive); b[len(b)/2] ^= 1; return b }(), id, tenancy.ErrArchive},
		"another schema": {func() []byte {
			p := open(t, archive, id)
			p.header["schema"] = strings.Repeat("0", 64)
			return seal(t, p, id)
		}(), id, tenancy.ErrSchema},
		"a table the database does not have": {func() []byte {
			p := open(t, archive, id)
			p.header["tables"] = append(p.header["tables"].([]any), "evil.table")
			return seal(t, p, id)
		}(), id, tenancy.ErrSchema},
		"a row for a table the header does not list": {func() []byte {
			p := open(t, archive, id)
			p.rows = append(p.rows, partRow{Table: "pg_catalog.pg_class", Row: json.RawMessage(`{}`)})
			return seal(t, p, id)
		}(), id, tenancy.ErrArchive},
		"rows that name a person the archive lacks": {func() []byte {
			p := open(t, archive, id)
			dropPrincipals(&p)
			return seal(t, p, id)
		}(), id, tenancy.ErrOrphan},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := l.restore(tc.archive, tenantC, tc.id, t)
			if !errors.Is(err, tc.want) {
				t.Fatalf("restore = %v, want %v", err, tc.want)
			}
			for _, table := range l.tables(t) {
				if !notRestored[table] && l.count(t, table, tenantC) != 0 {
					t.Errorf("a refused restore left rows in %s", table)
				}
			}
		})
	}
}

func TestRestoreTakesRowsAsDataAndPinsThemToTheTarget(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	l.provision(t, tenantC, "restored", nil)
	id := identity(t)
	archive, _ := l.export(t, tenantA, id)

	const hostile = `'); DROP SCHEMA registry CASCADE; --`
	p := open(t, archive, id)
	for i, r := range p.rows {
		var row map[string]any
		if err := json.Unmarshal(r.Row, &row); err != nil {
			t.Fatal(err)
		}
		if _, ok := row["tenant_id"]; ok {
			row["tenant_id"] = tenantB // an archive can claim any tenant
		}
		if r.Table == "identity.principal" {
			row["name"] = hostile
		}
		p.rows[i].Row, _ = json.Marshal(row)
	}
	if _, err := l.restore(seal(t, p, id), tenantC, id, t); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if n := l.count(t, "identity.principal", tenantB); n != 0 {
		t.Errorf("%d rows were written for the tenant the archive claimed", n)
	}
	var stored int
	if err := l.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM identity.principal WHERE tenant_id = $1::uuid AND name = $2`, tenantC, hostile).Scan(&stored); err != nil || stored == 0 {
		t.Errorf("the hostile name was not stored as data: %d, %v", stored, err)
	}
	var schemas int
	if err := l.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname = 'registry'`).Scan(&schemas); err != nil || schemas != 1 {
		t.Errorf("the registry schema is gone: %d, %v", schemas, err)
	}
}

func TestOffboardDeletesEverythingAndVerifiesIt(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	pgtest.SeedEveryTable(t, l.app, tenantB)
	l.addJob(t, tenantA)
	l.addJob(t, tenantB)

	tables := l.tables(t)
	beforeA, beforeB := map[string]int{}, map[string]int{}
	var totalA int
	for _, table := range tables {
		if table == tombstone {
			continue
		}
		beforeA[table], beforeB[table] = l.count(t, table, tenantA), l.count(t, table, tenantB)
		if beforeA[table] == 0 {
			t.Errorf("the seed left %s empty, so its deletion would prove nothing", table)
		}
		// The role that deletes must see what it deletes, or a count of zero would prove nothing either.
		if seen := l.countAs(t, l.migrator, table, tenantA); seen != beforeA[table] {
			t.Errorf("the migration role sees %d of %d rows in %s", seen, beforeA[table], table)
		}
		totalA += beforeA[table]
	}

	if _, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "globex"}); !errors.Is(err, tenancy.ErrConfirm) {
		t.Fatalf("a wrong confirmation: %v, want ErrConfirm", err)
	}
	for table, n := range beforeA {
		if l.count(t, table, tenantA) != n {
			t.Fatalf("a refused offboarding changed %s", table)
		}
	}

	report, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "synthetic tenant"})
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if !report.Verified || report.Repeat || !report.KeyDestroyed || report.DeletedRows != int64(totalA) || report.DeletedJobs != 1 {
		t.Fatalf("report = %+v, want %d rows, 1 job, key destroyed, verified", report, totalA)
	}
	for table, n := range beforeA {
		if report.Rows[table] != int64(n) {
			t.Errorf("report says %d rows deleted from %s, there were %d", report.Rows[table], table, n)
		}
		if got := l.count(t, table, tenantA); got != 0 {
			t.Errorf("%d rows of tenant A remain in %s", got, table)
		}
		if got := l.count(t, table, tenantB); got != beforeB[table] {
			t.Errorf("%s of tenant B has %d rows, want %d", table, got, beforeB[table])
		}
	}
	if l.jobs(t, tenantA) != 0 || l.jobs(t, tenantB) != 1 {
		t.Errorf("jobs of A = %d, of B = %d; want 0 and 1", l.jobs(t, tenantA), l.jobs(t, tenantB))
	}

	// The tombstone holds counts and the id, and nothing else.
	var rows, jobs int64
	var destroyed bool
	if err := l.admin.QueryRowContext(t.Context(), `SELECT deleted_rows, deleted_jobs, key_destroyed FROM tenancy.offboarding WHERE tenant_id = $1::uuid`, tenantA).Scan(&rows, &jobs, &destroyed); err != nil {
		t.Fatal(err)
	}
	if rows != int64(totalA) || jobs != 1 || !destroyed {
		t.Errorf("tombstone = %d rows, %d jobs, destroyed %v", rows, jobs, destroyed)
	}
	if l.count(t, tombstone, tenantB) != 0 {
		t.Error("tenant B has a tombstone")
	}

	if err := tenancy.Require(t.Context(), l.app, uuid.MustParse(tenantA)); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Errorf("Require after offboarding = %v", err)
	}
	if err := tenancy.Require(t.Context(), l.app, uuid.MustParse(tenantB)); err != nil {
		t.Errorf("Require for the bystander = %v", err)
	}
	if _, err := tenancy.Provision(t.Context(), l.app, tenancy.ProvisionOptions{Tenant: uuid.MustParse(tenantA), Name: "synthetic tenant", KEK: l.kek}); !errors.Is(err, tenancy.ErrOffboarded) {
		t.Errorf("provisioning an offboarded id = %v, want ErrOffboarded", err)
	}

	// A repeat removes what appeared since, and leaves the tombstone as it was.
	l.addJob(t, tenantA)
	again, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA)})
	if err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if !again.Repeat || !again.Verified || again.DeletedJobs != 1 || again.DeletedRows != 0 || l.jobs(t, tenantA) != 0 {
		t.Errorf("repeat = %+v", again)
	}
	if err := l.admin.QueryRowContext(t.Context(), `SELECT deleted_rows FROM tenancy.offboarding WHERE tenant_id = $1::uuid`, tenantA).Scan(&rows); err != nil || rows != int64(totalA) {
		t.Errorf("tombstone after a repeat = %d, %v", rows, err)
	}

	if _, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantC), Confirm: "x"}); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Errorf("offboarding an unknown tenant = %v", err)
	}
}

func TestTheCommandsNeedTheRoleThatTheInstallGrantedThem(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	l.provision(t, tenantC, "restored", nil)
	id := identity(t)
	archive, _ := l.export(t, tenantA, id)

	// The application role may not skip triggers, so it can neither purge nor restore.
	if _, err := tenancy.Offboard(t.Context(), l.app, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "synthetic tenant"}); err == nil {
		t.Error("the application role offboarded a tenant")
	}
	if l.count(t, "registry.scope", tenantA) == 0 {
		t.Error("a refused offboarding deleted rows")
	}
	if _, err := tenancy.Restore(t.Context(), l.app, tenancy.RestoreOptions{Tenant: uuid.MustParse(tenantC), Identities: []age.Identity{id}, In: bytes.NewReader(archive)}); err == nil {
		t.Error("the application role restored a tenant")
	}
	if l.count(t, "registry.scope", tenantC) != 0 {
		t.Error("a refused restore wrote rows")
	}

	// An export of a tenant that has no row is refused, and an export never leaves another tenant's rows in.
	if _, err := tenancy.Export(t.Context(), l.app, tenancy.ExportOptions{Tenant: uuid.MustParse(tenantB), Recipients: []age.Recipient{id.Recipient()}, Out: io.Discard}); !errors.Is(err, tenancy.ErrUnknownTenant) {
		t.Errorf("export of a tenant with no row = %v", err)
	}
}

// A role sees only the rows its policies allow. Without a policy the delete would remove nothing and the
// count would find nothing, so the command must refuse before it deletes.
func TestOffboardRefusesATableTheMigrationRoleHasNoPolicyFor(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	if _, err := l.admin.ExecContext(t.Context(), `DROP POLICY migrate_delete ON registry.baseline`); err != nil {
		t.Fatal(err)
	}
	_, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "synthetic tenant"})
	if err == nil || !strings.Contains(err.Error(), "DELETE on registry.baseline") {
		t.Fatalf("offboard = %v, want a refusal that names the table", err)
	}
	for _, table := range l.tables(t) {
		if table != tombstone && l.count(t, table, tenantA) == 0 {
			t.Errorf("a refused offboarding emptied %s", table)
		}
	}
	if l.count(t, tombstone, tenantA) != 0 {
		t.Error("a refused offboarding wrote a tombstone")
	}
}
