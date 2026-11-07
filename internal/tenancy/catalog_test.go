package tenancy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func sampleTables() []Table {
	return []Table{
		{Schema: "identity", Name: "principal", Columns: []Column{{"tenant_id", "uuid", false}, {"id", "uuid", false}, {"name", "text", false}}},
		{Schema: "identity", Name: "session", Columns: []Column{{"tenant_id", "uuid", false}}},
		{Schema: "registry", Name: "scope", Columns: []Column{{"tenant_id", "uuid", false}, {"match_repo", "text", false}, {"repo_key", "text", true}}},
		{Schema: "tenancy", Name: "installation", Columns: []Column{{"tenant_id", "uuid", false}, {"installation_id", "int8", false}}},
		{Schema: "tenancy", Name: "offboarding", Columns: []Column{{"tenant_id", "uuid", false}}},
		{Schema: "tenancy", Name: "tenant", Columns: []Column{{"tenant_id", "uuid", false}, {"name", "text", false}}},
		{Schema: "tenancy", Name: "tenant_key", Columns: []Column{{"tenant_id", "uuid", false}}},
	}
}

func TestTheTableSetsKeepWhatMustNotMove(t *testing.T) {
	all := sampleTables()
	if got, want := strings.Join(names(exported(all)), " "), "identity.principal registry.scope tenancy.tenant"; got != want {
		t.Errorf("exported = %q, want %q: the key, the sessions, the installations and the tombstone never leave", got, want)
	}
	if got, want := strings.Join(names(restorable(all)), " "), "identity.principal registry.scope"; got != want {
		t.Errorf("restorable = %q, want %q: the target keeps its own tenant row", got, want)
	}
	purged := strings.Join(names(purgeable(all)), " ")
	if strings.Contains(purged, tombstoneTable) {
		t.Errorf("purgeable = %q includes the tombstone", purged)
	}
	for _, must := range []string{tenantKeyTable, sessionTable, tenantTable, installationTable} {
		if !strings.Contains(purged, must) {
			t.Errorf("purgeable = %q misses %s", purged, must)
		}
	}
}

func TestFingerprintChangesWithTheShapeAndNotWithTheOrder(t *testing.T) {
	base := fingerprint(exported(sampleTables()))

	reordered := sampleTables()
	reordered[0].Columns[0], reordered[0].Columns[2] = reordered[0].Columns[2], reordered[0].Columns[0]
	reordered[0], reordered[2] = reordered[2], reordered[0]
	if got := fingerprint(exported(reordered)); got != base {
		t.Error("the order of tables or columns changed the fingerprint")
	}

	for name, mutate := range map[string]func([]Table){
		"a column type":      func(ts []Table) { ts[0].Columns[2].Type = "varchar" },
		"a column added":     func(ts []Table) { ts[0].Columns = append(ts[0].Columns, Column{"extra", "int4", false}) },
		"a column generated": func(ts []Table) { ts[0].Columns[2].Generated = true },
		"a column renamed":   func(ts []Table) { ts[0].Columns[2].Name = "label" },
		"a table renamed":    func(ts []Table) { ts[0].Name = "people" },
	} {
		changed := sampleTables()
		mutate(changed)
		if fingerprint(exported(changed)) == base {
			t.Errorf("%s did not change the fingerprint", name)
		}
	}
	if len(base) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex digits", base)
	}
}

func TestInsertStatementQuotesNamesLeavesOutGeneratedColumnsAndPinsTheTenant(t *testing.T) {
	tables := sampleTables()
	got := insertStatement(tables[2])
	want := `INSERT INTO "registry"."scope" ("tenant_id", "match_repo") SELECT $2::uuid, r."match_repo" FROM jsonb_populate_recordset(NULL::"registry"."scope", $1::jsonb) AS r`
	if got != want {
		t.Errorf("insertStatement =\n%s\nwant\n%s", got, want)
	}
	odd := Table{Schema: `we"ird`, Name: "from", Columns: []Column{{"tenant_id", "uuid", false}, {`co"l`, "text", false}}}
	if stmt := insertStatement(odd); !strings.Contains(stmt, `"we""ird"."from"`) || !strings.Contains(stmt, `r."co""l"`) {
		t.Errorf("identifiers are not quoted: %s", stmt)
	}
}

func TestOrphanQueryMatchesOnEveryKeyColumnAndSkipsNulls(t *testing.T) {
	byName := map[string]Table{}
	for _, tb := range sampleTables() {
		byName[tb.String()] = tb
	}
	fk := foreignKey{
		name: "login_principal", child: "identity.session", parent: "identity.principal",
		childCols: []string{"tenant_id", "login_id"}, parentCols: []string{"tenant_id", "id"},
	}
	got := fk.orphanQuery(byName)
	for _, part := range []string{
		`FROM "identity"."session" AS c WHERE c.tenant_id = $1`,
		`c."tenant_id" IS NOT NULL AND c."login_id" IS NOT NULL`,
		`FROM "identity"."principal" AS p WHERE p."tenant_id" = c."tenant_id" AND p."id" = c."login_id"`,
	} {
		if !strings.Contains(got, part) {
			t.Errorf("orphan query misses %q:\n%s", part, got)
		}
	}
}

func TestReduceKeepsTheClassAndTheNamesAndDropsTheMessage(t *testing.T) {
	secret := "invalid input syntax for type uuid: \"super-secret-value\""
	err := reduce("restore: write registry.scope", fmt.Errorf("wrapped: %w", &pgconn.PgError{
		Code: "22P02", Message: secret, Detail: "Key (x)=(super-secret-value)", SchemaName: "registry", TableName: "scope", ConstraintName: "scope_check",
	}))
	if got := err.Error(); strings.Contains(got, "secret") || got != "restore: write registry.scope: SQLSTATE 22P02 on registry.scope (scope_check)" {
		t.Errorf("reduce = %q", got)
	}
	if got := reduce("op", context.DeadlineExceeded).Error(); got != "op: timed out" {
		t.Errorf("deadline = %q", got)
	}
	if got := reduce("op", context.Canceled).Error(); got != "op: canceled" {
		t.Errorf("canceled = %q", got)
	}
	if got := reduce("op", errors.New("contains super-secret-value")).Error(); strings.Contains(got, "secret") || got != "op: failed" {
		t.Errorf("other = %q", got)
	}
}
