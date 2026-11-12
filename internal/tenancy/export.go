package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
)

// ExportOptions is what an export needs. The archive is encrypted to the recipients, and only their
// private keys open it.
type ExportOptions struct {
	Tenant     uuid.UUID
	Recipients []age.Recipient
	Out        io.Writer
}

// ExportReport counts the rows written for each table and the EDR files. It holds no row content.
type ExportReport struct {
	Tenant uuid.UUID        `json:"tenant"`
	Rows   map[string]int64 `json:"rows"`
	Total  int64            `json:"total"`
	Files  int64            `json:"files"`
}

// Export writes every row of a tenant to an encrypted archive that Restore reads (ADR-0100), and after the rows
// one EDR Markdown file for each version of each decision (ADR-0112). It runs as the
// application role in one read-only transaction at REPEATABLE READ, so the archive is one consistent
// snapshot and row-level security limits it to the tenant. The export is complete only when it returns nil,
// and a caller that gets an error discards what was written.
func Export(ctx context.Context, db *sql.DB, o ExportOptions) (ExportReport, error) {
	report := ExportReport{Tenant: o.Tenant, Rows: make(map[string]int64)}
	switch {
	case db == nil:
		return report, errors.New("export: a database is required")
	case o.Tenant == uuid.Nil:
		return report, errors.New("export: a tenant id is required")
	case o.Out == nil:
		return report, errors.New("export: an output is required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return report, reduce("export: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSession(ctx, tx, o.Tenant, false); err != nil {
		return report, err
	}

	var name string
	switch err := tx.QueryRowContext(ctx, `SELECT name FROM tenancy.tenant WHERE tenant_id = $1`, o.Tenant).Scan(&name); {
	case errors.Is(err, sql.ErrNoRows):
		return report, fmt.Errorf("export: %w: %s has no row in tenancy.tenant", ErrUnknownTenant, o.Tenant)
	case err != nil:
		return report, reduce("export: read the tenant", err)
	}
	all, err := catalog(ctx, tx)
	if err != nil {
		return report, err
	}
	tables := exported(all)

	w, err := newArchiveWriter(o.Out, o.Recipients, header{
		Format:     Format,
		Tenant:     o.Tenant,
		Name:       name,
		ExportedAt: time.Now().UTC(),
		Schema:     fingerprint(tables),
		Tables:     names(tables),
	})
	if err != nil {
		return report, err
	}
	for _, t := range tables {
		err := w.table(t.String(), func(emit func([]byte) error) error {
			rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT to_jsonb(t)::text FROM %s AS t WHERE t.tenant_id = $1`, t.ident()), o.Tenant)
			if err != nil {
				return reduce("export: read "+t.String(), err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var row []byte
				if err := rows.Scan(&row); err != nil {
					return reduce("export: read "+t.String(), err)
				}
				if err := emit(row); err != nil {
					return err
				}
				report.Rows[t.String()]++
				report.Total++
			}
			if err := rows.Err(); err != nil {
				return reduce("export: read "+t.String(), err)
			}
			return nil
		})
		if err != nil {
			return report, err
		}
	}
	if report.Files, err = writeEDRFiles(ctx, tx, w, o.Tenant); err != nil {
		return report, err
	}
	if err := w.finish(); err != nil {
		return report, err
	}
	return report, nil
}
