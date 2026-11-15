package tenancy

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

var (
	// ErrConfirm is returned when the confirmation is not the name of the tenant.
	ErrConfirm = errors.New("the confirmation is not the name of the tenant")
	// ErrNotVerified is returned when rows of the tenant remain after the purge.
	ErrNotVerified = errors.New("rows of the tenant remain")
)

// OffboardOptions names the tenant to delete. Confirm must be its name, so a pasted id alone deletes
// nothing.
type OffboardOptions struct {
	Tenant  uuid.UUID
	Confirm string
}

// OffboardReport says what was deleted and whether a second look found anything left. It holds counts and
// table names only, and the head of the hash chain of the action log, which is a position and a hash.
type OffboardReport struct {
	Tenant       uuid.UUID        `json:"tenant"`
	Rows         map[string]int64 `json:"rows"`
	DeletedRows  int64            `json:"deleted_rows"`
	DeletedJobs  int64            `json:"deleted_jobs"`
	KeyDestroyed bool             `json:"key_destroyed"`
	// LogSeq and LogHash are the last entry of the action log, which the tombstone keeps so that a copy of
	// the log held elsewhere can still be checked after the tenant is gone (ADR-0126). They are empty when
	// the log was empty and for a tombstone written before the chain.
	LogSeq  int64  `json:"log_seq,omitempty"`
	LogHash string `json:"log_hash,omitempty"`
	// Repeat is true when the tenant had no row and a tombstone already existed: the run only removed
	// what had appeared since.
	Repeat   bool `json:"repeat"`
	Verified bool `json:"verified"`
}

// Offboard deletes a tenant and proves it (ADR-0100). It runs as the migration role in one transaction
// that skips triggers: every row of the tenant in every table with a tenant_id column except the
// tombstone, the wrapped data key included, and the River jobs that name the tenant. It counts again
// before it commits, writes the tombstone with triggers back on, and after the commit looks a second time
// in a new transaction. Anything left makes it return ErrNotVerified, and a repeat removes it.
//
// The caller stops the api and worker of the tenant first. A job inserted between the purge and the
// commit survives it and is found by the second look.
func Offboard(ctx context.Context, db *sql.DB, o OffboardOptions) (OffboardReport, error) {
	report := OffboardReport{Tenant: o.Tenant, Rows: make(map[string]int64)}
	switch {
	case db == nil:
		return report, errors.New("offboard: a database is required")
	case o.Tenant == uuid.Nil:
		return report, errors.New("offboard: a tenant id is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, reduce("offboard: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSession(ctx, tx, o.Tenant, true); err != nil {
		return report, err
	}

	var name string
	hasRow := true
	switch err := tx.QueryRowContext(ctx, `SELECT name FROM tenancy.tenant WHERE tenant_id = $1`, o.Tenant).Scan(&name); {
	case errors.Is(err, sql.ErrNoRows):
		hasRow = false
	case err != nil:
		return report, reduce("offboard: read the tenant", err)
	}
	var tombstone bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.offboarding WHERE tenant_id = $1)`, o.Tenant).Scan(&tombstone); err != nil {
		return report, reduce("offboard: read the tombstone", err)
	}
	switch {
	case !hasRow && !tombstone:
		return report, fmt.Errorf("offboard: %w: %s has no row in tenancy.tenant", ErrUnknownTenant, o.Tenant)
	case hasRow && o.Confirm != name:
		return report, fmt.Errorf("offboard: %w", ErrConfirm)
	}
	report.Repeat = !hasRow

	all, err := catalog(ctx, tx)
	if err != nil {
		return report, err
	}
	tables := purgeable(all)
	if err := requirePolicies(ctx, tx, tables); err != nil {
		return report, err
	}
	// The head is read before the delete, because the delete removes the log. The caller has stopped the api
	// and the worker, so nothing is appended between this read and the delete.
	head, err := logHead(ctx, tx, o.Tenant)
	if err != nil {
		return report, err
	}
	report.LogSeq, report.LogHash = head.seq, head.hash
	for _, t := range tables {
		res, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $1`, t.ident()), o.Tenant)
		if err != nil {
			return report, reduce("offboard: delete from "+t.String(), err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			report.Rows[t.String()] = n
			report.DeletedRows += n
		}
		if t.String() == tenantKeyTable {
			report.KeyDestroyed = n > 0
		}
	}
	jobs, err := jobArgs(o.Tenant)
	if err != nil {
		return report, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM river.river_job WHERE args @> $1::jsonb`, jobs)
	if err != nil {
		return report, reduce("offboard: delete the jobs", err)
	}
	report.DeletedJobs, _ = res.RowsAffected()

	left, err := remaining(ctx, tx, tables, o.Tenant)
	if err != nil {
		return report, err
	}
	if len(left) > 0 {
		return report, fmt.Errorf("offboard: %w: %s", ErrNotVerified, strings.Join(left, ", "))
	}

	if !tombstone {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('session_replication_role', 'origin', true)`); err != nil {
			return report, reduce("offboard: restore triggers", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tenancy.offboarding (tenant_id, deleted_rows, deleted_jobs, key_destroyed, log_seq, log_hash) VALUES ($1, $2, $3, $4, $5, $6)`,
			o.Tenant, report.DeletedRows, report.DeletedJobs, report.KeyDestroyed, head.seqArg(), head.hashArg()); err != nil {
			return report, reduce("offboard: write the tombstone", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return report, reduce("offboard: commit", err)
	}

	// The second look runs in a new transaction, so it sees what other sessions committed meanwhile.
	look, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return report, reduce("offboard: verify", err)
	}
	defer func() { _ = look.Rollback() }()
	if err := setSession(ctx, look, o.Tenant, false); err != nil {
		return report, err
	}
	left, err = remaining(ctx, look, tables, o.Tenant)
	if err != nil {
		return report, err
	}
	if len(left) > 0 {
		return report, fmt.Errorf("offboard: %w: %s", ErrNotVerified, strings.Join(left, ", "))
	}
	var recorded bool
	if err := look.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.offboarding WHERE tenant_id = $1)`, o.Tenant).Scan(&recorded); err != nil {
		return report, reduce("offboard: verify", err)
	}
	if !recorded {
		return report, fmt.Errorf("offboard: %w: the tombstone is missing", ErrNotVerified)
	}
	report.Verified = true
	return report, nil
}

// chainHead is the last entry of the action log of a tenant, or the zero value when it has none.
type chainHead struct {
	seq  int64
	hash string
}

func (h chainHead) seqArg() any {
	if h.seq == 0 {
		return nil
	}
	return h.seq
}

func (h chainHead) hashArg() any {
	if h.hash == "" {
		return nil
	}
	raw, _ := hex.DecodeString(h.hash)
	return raw
}

// logHead reads the head of the chain of the tenant's action log. It repeats the query of identity's chain
// reader on purpose: offboarding runs as the migration role in one replica-mode transaction, which the
// application-role reader of internal/identity does not use. A repeat has no log left, so it reads the
// head the first run put in the tombstone.
func logHead(ctx context.Context, q queryer, tenant uuid.UUID) (chainHead, error) {
	var seq sql.NullInt64
	var hash []byte
	err := q.QueryRowContext(ctx,
		`SELECT seq, hash FROM identity.action_log WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenant).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		err = q.QueryRowContext(ctx,
			`SELECT log_seq, log_hash FROM tenancy.offboarding WHERE tenant_id = $1`, tenant).Scan(&seq, &hash)
		if errors.Is(err, sql.ErrNoRows) {
			return chainHead{}, nil
		}
	}
	if err != nil {
		return chainHead{}, reduce("offboard: read the head of the action log", err)
	}
	if !seq.Valid {
		return chainHead{}, nil
	}
	return chainHead{seq: seq.Int64, hash: hex.EncodeToString(hash)}, nil
}

// requirePolicies refuses to purge when the current role has no SELECT or no DELETE policy on a table. Row-level
// security hides the rows a role has no policy for, so the delete would remove nothing and the count after it
// would find nothing, and the tombstone would claim a clean tenant. A table added by a later migration without
// its policies is caught here, and by the isolation suite before it ships.
func requirePolicies(ctx context.Context, q queryer, tables []Table) error {
	rows, err := q.QueryContext(ctx, `
		SELECT n.nspname || '.' || c.relname, cmd.name
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		CROSS JOIN (VALUES ('r', 'SELECT'), ('d', 'DELETE')) AS cmd(code, name)
		WHERE c.relkind IN ('r', 'p') AND c.relpersistence = 'p'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND EXISTS (
		      SELECT 1 FROM pg_catalog.pg_attribute AS a
		      WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped)
		  AND NOT EXISTS (
		      SELECT 1 FROM pg_catalog.pg_policy AS p
		      WHERE p.polrelid = c.oid AND p.polcmd IN (cmd.code::"char", '*')
		        AND (p.polroles = '{0}'::oid[] OR pg_catalog.to_regrole(current_user)::oid = ANY (p.polroles)))`)
	if err != nil {
		return reduce("offboard: read the policies", err)
	}
	defer func() { _ = rows.Close() }()
	wanted := make(map[string]bool, len(tables))
	for _, t := range tables {
		wanted[t.String()] = true
	}
	var missing []string
	for rows.Next() {
		var table, cmd string
		if err := rows.Scan(&table, &cmd); err != nil {
			return reduce("offboard: read the policies", err)
		}
		if wanted[table] {
			missing = append(missing, cmd+" on "+table)
		}
	}
	if err := rows.Err(); err != nil {
		return reduce("offboard: read the policies", err)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("offboard: the role has no policy for %s, so the deletion could not be verified", strings.Join(missing, ", "))
	}
	return nil
}

// jobArgs is the JSON a River job of the tenant contains: its arguments hold the tenant id (ADR-0096).
func jobArgs(tenant uuid.UUID) (string, error) {
	b, err := json.Marshal(map[string]string{"tenant": tenant.String()})
	if err != nil {
		return "", fmt.Errorf("offboard: %w", err)
	}
	return string(b), nil
}

// remaining names every table, and the job table, that still holds a row of the tenant.
func remaining(ctx context.Context, q queryer, tables []Table, tenant uuid.UUID) ([]string, error) {
	var left []string
	for _, t := range tables {
		var present bool
		if err := q.QueryRowContext(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE tenant_id = $1)`, t.ident()), tenant).Scan(&present); err != nil {
			return nil, reduce("offboard: verify "+t.String(), err)
		}
		if present {
			left = append(left, t.String())
		}
	}
	jobs, err := jobArgs(tenant)
	if err != nil {
		return nil, err
	}
	var present bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM river.river_job WHERE args @> $1::jsonb)`, jobs).Scan(&present); err != nil {
		return nil, reduce("offboard: verify the jobs", err)
	}
	if present {
		left = append(left, "river.river_job")
	}
	sort.Strings(left)
	return left, nil
}
