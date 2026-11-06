package tenancy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"filippo.io/age"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrNotFresh is returned when the target tenant already has rows.
	ErrNotFresh = errors.New("the tenant is not empty")
	// ErrSchema is returned when an archive was made for tables other than this database's.
	ErrSchema = errors.New("the archive was made for another schema")
	// ErrOrphan is returned when restored rows name a row that the archive did not carry.
	ErrOrphan = errors.New("restored rows break a foreign key")
)

const (
	// batchRows and batchBytes bound one INSERT. A statement holds at most this many rows of an archive.
	batchRows  = 500
	batchBytes = 4 << 20
)

// RestoreOptions is what a restore needs. Tenant is the target, made by Provision without a first person.
type RestoreOptions struct {
	Tenant     uuid.UUID
	Identities []age.Identity
	In         io.Reader
}

// RestoreReport counts the rows inserted for each table. It holds no row content.
type RestoreReport struct {
	Tenant uuid.UUID        `json:"tenant"`
	Source uuid.UUID        `json:"source"`
	Rows   map[string]int64 `json:"rows"`
	Total  int64            `json:"total"`
}

// Restore reads an archive that Export wrote into a fresh tenant (ADR-0100). It runs as the migration
// role, which the install allows to skip triggers for one transaction: a trigger would stamp the
// transaction time of every row again and the foreign key triggers would need the rows in an order. Ids
// and transaction time are kept, so "as known then" survives.
//
// The archive is treated as untrusted input. Table names are used only when the catalog lists them, row
// content only as one bound parameter, every row is written with the target's tenant id, and the
// transaction commits only when the archive matches its trailer and no foreign key is left open. Anyone
// with a recipient's public key can write an archive for it, so the caller restores only an archive it
// has reason to trust.
func Restore(ctx context.Context, db *sql.DB, o RestoreOptions) (RestoreReport, error) {
	report := RestoreReport{Tenant: o.Tenant, Rows: make(map[string]int64)}
	switch {
	case db == nil:
		return report, errors.New("restore: a database is required")
	case o.Tenant == uuid.Nil:
		return report, errors.New("restore: a tenant id is required")
	case o.In == nil:
		return report, errors.New("restore: an archive is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, reduce("restore: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSession(ctx, tx, o.Tenant, true); err != nil {
		return report, err
	}

	all, err := catalog(ctx, tx)
	if err != nil {
		return report, err
	}
	exp, targets := exported(all), restorable(all)

	var found bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.tenant WHERE tenant_id = $1)`, o.Tenant).Scan(&found); err != nil {
		return report, reduce("restore: read the tenant", err)
	}
	if !found {
		return report, fmt.Errorf("restore: %w: %s has no row in tenancy.tenant", ErrUnknownTenant, o.Tenant)
	}
	for _, t := range targets {
		var present bool
		if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE tenant_id = $1)`, t.ident()), o.Tenant).Scan(&present); err != nil {
			return report, reduce("restore: read "+t.String(), err)
		}
		if present {
			return report, fmt.Errorf("restore: %w: %s has rows in %s", ErrNotFresh, o.Tenant, t)
		}
	}

	ar, err := openArchive(o.In, o.Identities)
	if err != nil {
		return report, err
	}
	report.Source = ar.hdr.Tenant
	if ar.hdr.Schema != fingerprint(exp) || !slices.Equal(ar.hdr.Tables, names(exp)) {
		return report, fmt.Errorf("restore: %w", ErrSchema)
	}

	byName := make(map[string]Table, len(all))
	statements := make(map[string]string, len(targets))
	for _, t := range all {
		byName[t.String()] = t
	}
	for _, t := range targets {
		statements[t.String()] = insertStatement(t)
	}
	b := &batch{ctx: ctx, tx: tx, tenant: o.Tenant, statements: statements, report: &report}
	for {
		table, row, err := ar.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return report, err
		}
		if table == tenantTable {
			// The target has its row already. The archive's row only says what the tenant was called.
			continue
		}
		if err := b.add(table, row); err != nil {
			return report, err
		}
	}
	if err := b.flush(); err != nil {
		return report, err
	}

	keys, err := foreignKeys(ctx, tx, all)
	if err != nil {
		return report, err
	}
	for _, fk := range keys {
		if _, restored := statements[fk.child]; !restored {
			continue
		}
		var orphans int64
		if err := tx.QueryRowContext(ctx, fk.orphanQuery(byName), o.Tenant).Scan(&orphans); err != nil {
			return report, reduce("restore: check "+fk.name, err)
		}
		if orphans > 0 {
			return report, fmt.Errorf("restore: %w: %s on %s", ErrOrphan, fk.name, fk.child)
		}
	}
	if err := tx.Commit(); err != nil {
		return report, reduce("restore: commit", err)
	}
	return report, nil
}

// insertStatement writes the rows of a JSON array into a table. The table name is quoted, the rows are
// the first parameter and the target tenant the second, which replaces the tenant id of every row.
// Generated columns are left out, since the database computes them.
func insertStatement(t Table) string {
	var cols, values []string
	for _, c := range t.Columns {
		if c.Generated {
			continue
		}
		id := pgx.Identifier{c.Name}.Sanitize()
		cols = append(cols, id)
		if c.Name == "tenant_id" {
			values = append(values, "$2::uuid")
		} else {
			values = append(values, "r."+id)
		}
	}
	return fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb) AS r`,
		t.ident(), strings.Join(cols, ", "), strings.Join(values, ", "), t.ident())
}

// batch collects the rows of one table into a JSON array and writes them in one statement.
type batch struct {
	ctx        context.Context
	tx         *sql.Tx
	tenant     uuid.UUID
	statements map[string]string
	report     *RestoreReport

	table string
	buf   bytes.Buffer
	n     int
}

// add appends a row, and writes the batch first when the table changes or the batch is full. The row is
// copied, since the reader reuses its buffer.
func (b *batch) add(table string, row []byte) error {
	if table != b.table {
		if err := b.flush(); err != nil {
			return err
		}
		if _, ok := b.statements[table]; !ok {
			return fmt.Errorf("%w: a row names a table that is not restored", ErrArchive)
		}
		b.table = table
	}
	if b.n == 0 {
		b.buf.WriteByte('[')
	} else {
		b.buf.WriteByte(',')
	}
	b.buf.Write(row)
	b.n++
	if b.n >= batchRows || b.buf.Len() >= batchBytes {
		return b.flush()
	}
	return nil
}

func (b *batch) flush() error {
	if b.n == 0 {
		return nil
	}
	b.buf.WriteByte(']')
	_, err := b.tx.ExecContext(b.ctx, b.statements[b.table], b.buf.String(), b.tenant.String())
	if err != nil {
		return reduce("restore: write "+b.table, err)
	}
	b.report.Rows[b.table] += int64(b.n)
	b.report.Total += int64(b.n)
	b.buf.Reset()
	b.n = 0
	return nil
}
