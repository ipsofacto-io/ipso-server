package tenancy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// queryer is what *sql.DB and *sql.Tx both offer.
type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// The tables the lifecycle commands treat on purpose. Every other table with a tenant_id column is found
// in the catalog, so a table added by a later migration is exported, restored and purged without a code
// change, and the integration tests fail when its policies are missing (ADR-0100).
const (
	tenantTable       = "tenancy.tenant"
	tenantKeyTable    = "tenancy.tenant_key"
	sessionTable      = "identity.session"
	tombstoneTable    = "tenancy.offboarding"
	installationTable = "tenancy.installation"
)

// Table is a table with a tenant_id column.
type Table struct {
	Schema  string
	Name    string
	Columns []Column
}

// Column is a column of a Table.
type Column struct {
	Name string
	Type string
	// Generated columns are computed by the database, so a restore leaves them out.
	Generated bool
}

// String is the qualified name, the form the archive uses.
func (t Table) String() string { return t.Schema + "." + t.Name }

// ident is the quoted, qualified name for use in a statement.
func (t Table) ident() string { return pgx.Identifier{t.Schema, t.Name}.Sanitize() }

// catalog returns every table with a tenant_id column, with its columns, in name order. The names come
// from the database and are quoted before they reach a statement.
func catalog(ctx context.Context, q queryer) ([]Table, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT n.nspname, c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attgenerated <> ''
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE c.relkind IN ('r', 'p') AND c.relpersistence = 'p'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND EXISTS (
		      SELECT 1 FROM pg_catalog.pg_attribute AS t
		      WHERE t.attrelid = c.oid AND t.attname = 'tenant_id' AND t.attnum > 0 AND NOT t.attisdropped)
		ORDER BY n.nspname, c.relname, a.attname`)
	if err != nil {
		return nil, reduce("read the catalog", err)
	}
	defer func() { _ = rows.Close() }()

	var tables []Table
	for rows.Next() {
		var schema, name string
		var col Column
		if err := rows.Scan(&schema, &name, &col.Name, &col.Type, &col.Generated); err != nil {
			return nil, reduce("read the catalog", err)
		}
		if n := len(tables); n == 0 || tables[n-1].Schema != schema || tables[n-1].Name != name {
			tables = append(tables, Table{Schema: schema, Name: name})
		}
		last := &tables[len(tables)-1]
		last.Columns = append(last.Columns, col)
	}
	if err := rows.Err(); err != nil {
		return nil, reduce("read the catalog", err)
	}
	// The archive lists tables in this order on one machine and compares it on another, so the order is
	// bytewise and not the collation of the database.
	sort.Slice(tables, func(i, j int) bool { return tables[i].String() < tables[j].String() })
	return tables, nil
}

// exported is the tables an export carries: every tenant table except the wrapped key, which never leaves
// the database, the sessions, which hold credential hashes and end on their own, the tombstone, and the
// installation bindings. A binding is unique across tenants, so a restore into a fresh tenant would find it
// taken by the tenant it was exported from, and moving a live installation to a copy is the operator's
// choice (ADR-0101).
func exported(all []Table) []Table {
	var out []Table
	for _, t := range all {
		switch t.String() {
		case tenantKeyTable, sessionTable, tombstoneTable, installationTable:
			continue
		}
		out = append(out, t)
	}
	return out
}

// restorable is the exported tables a restore writes. The target already has its tenant row.
func restorable(all []Table) []Table {
	var out []Table
	for _, t := range exported(all) {
		if t.String() != tenantTable {
			out = append(out, t)
		}
	}
	return out
}

// purgeable is the tables an offboarding empties: all of them but the tombstone.
func purgeable(all []Table) []Table {
	var out []Table
	for _, t := range all {
		if t.String() != tombstoneTable {
			out = append(out, t)
		}
	}
	return out
}

func names(tables []Table) []string {
	out := make([]string, len(tables))
	for i, t := range tables {
		out[i] = t.String()
	}
	return out
}

// fingerprint is the SHA-256 of the shape of the exported tables: table, column, type and whether the
// column is generated, in name order. A restore refuses an archive whose shape is not the target's.
func fingerprint(tables []Table) string {
	sorted := append([]Table(nil), tables...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	h := sha256.New()
	for _, t := range sorted {
		cols := append([]Column(nil), t.Columns...)
		sort.Slice(cols, func(i, j int) bool { return cols[i].Name < cols[j].Name })
		for _, c := range cols {
			_, _ = fmt.Fprintf(h, "%s\t%s\t%s\t%t\n", t, c.Name, c.Type, c.Generated)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// foreignKey is a foreign key between two tenant tables.
type foreignKey struct {
	name       string
	child      string
	parent     string
	childCols  []string
	parentCols []string
}

// foreignKeys returns the foreign keys whose two tables both carry a tenant_id column.
func foreignKeys(ctx context.Context, q queryer, tables []Table) ([]foreignKey, error) {
	known := make(map[string]Table, len(tables))
	for _, t := range tables {
		known[t.String()] = t
	}
	rows, err := q.QueryContext(ctx, `
		SELECT con.conname, cn.nspname, c.relname, pn.nspname, p.relname,
		       json_agg(ca.attname ORDER BY k.ord)::text, json_agg(pa.attname ORDER BY k.ord)::text
		FROM pg_catalog.pg_constraint AS con
		JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid
		JOIN pg_catalog.pg_namespace AS cn ON cn.oid = c.relnamespace
		JOIN pg_catalog.pg_class AS p ON p.oid = con.confrelid
		JOIN pg_catalog.pg_namespace AS pn ON pn.oid = p.relnamespace
		CROSS JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(child, parent, ord)
		JOIN pg_catalog.pg_attribute AS ca ON ca.attrelid = c.oid AND ca.attnum = k.child
		JOIN pg_catalog.pg_attribute AS pa ON pa.attrelid = p.oid AND pa.attnum = k.parent
		WHERE con.contype = 'f'
		GROUP BY con.oid, con.conname, cn.nspname, c.relname, pn.nspname, p.relname
		ORDER BY cn.nspname, c.relname, con.conname`)
	if err != nil {
		return nil, reduce("read the foreign keys", err)
	}
	defer func() { _ = rows.Close() }()

	var keys []foreignKey
	for rows.Next() {
		var (
			fk                         foreignKey
			childSchema, childName     string
			parentSchema, parentName   string
			childColsJSON, parentColsJ string
		)
		if err := rows.Scan(&fk.name, &childSchema, &childName, &parentSchema, &parentName, &childColsJSON, &parentColsJ); err != nil {
			return nil, reduce("read the foreign keys", err)
		}
		fk.child = childSchema + "." + childName
		fk.parent = parentSchema + "." + parentName
		if _, ok := known[fk.child]; !ok {
			continue
		}
		if _, ok := known[fk.parent]; !ok {
			continue
		}
		if err := json.Unmarshal([]byte(childColsJSON), &fk.childCols); err != nil {
			return nil, errors.New("read the foreign keys: unreadable column list")
		}
		if err := json.Unmarshal([]byte(parentColsJ), &fk.parentCols); err != nil {
			return nil, errors.New("read the foreign keys: unreadable column list")
		}
		keys = append(keys, fk)
	}
	if err := rows.Err(); err != nil {
		return nil, reduce("read the foreign keys", err)
	}
	return keys, nil
}

// orphanQuery counts the rows of a tenant in the child table that name no row in the parent table. A
// null in any key column matches nothing, the rule of MATCH SIMPLE that every foreign key here uses.
func (fk foreignKey) orphanQuery(tables map[string]Table) string {
	child, parent := tables[fk.child], tables[fk.parent]
	var notNull, match []string
	for i, col := range fk.childCols {
		c := pgx.Identifier{col}.Sanitize()
		p := pgx.Identifier{fk.parentCols[i]}.Sanitize()
		notNull = append(notNull, "c."+c+" IS NOT NULL")
		match = append(match, "p."+p+" = c."+c)
	}
	return fmt.Sprintf(
		`SELECT count(*) FROM %s AS c WHERE c.tenant_id = $1 AND %s AND NOT EXISTS (SELECT 1 FROM %s AS p WHERE %s)`,
		child.ident(), strings.Join(notNull, " AND "), parent.ident(), strings.Join(match, " AND "))
}

// setSession applies the settings every lifecycle transaction needs. The tenant is what row-level
// security reads. The rest make the text form of dates, ranges, floats and byte strings the same on the
// machine that exports and the one that restores. replica turns off triggers and the triggers behind
// foreign keys for this transaction only, which needs the grant of the install (ADR-0100).
func setSession(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, replica bool) error {
	settings := [][2]string{
		{"ipso.tenant", tenant.String()},
		{"TimeZone", "UTC"},
		{"DateStyle", "ISO, MDY"},
		{"extra_float_digits", "1"},
		{"bytea_output", "hex"},
	}
	if replica {
		settings = append(settings, [2]string{"session_replication_role", "replica"})
	}
	for _, s := range settings {
		if _, err := tx.ExecContext(ctx, `SELECT set_config($1, $2, true)`, s[0], s[1]); err != nil {
			return reduce("set "+s[0], err)
		}
	}
	return nil
}

// reduce keeps the operation and the class of the cause and drops the rest of err's text. A database
// message can quote the value that failed it, and what a lifecycle command handles is tenant content.
// The table and the constraint are names of the schema and are kept.
func reduce(operation string, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		out := fmt.Sprintf("%s: SQLSTATE %s", operation, pgErr.Code)
		if pgErr.TableName != "" {
			out += " on " + pgErr.SchemaName + "." + pgErr.TableName
		}
		if pgErr.ConstraintName != "" {
			out += " (" + pgErr.ConstraintName + ")"
		}
		return errors.New(out)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: timed out", operation)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: canceled", operation)
	default:
		return fmt.Errorf("%s: failed", operation)
	}
}
