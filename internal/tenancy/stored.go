package tenancy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
)

// The exports a tenant admin asks for through the API (ADR-0111). The archive is the one Export writes for
// the operator command, so Restore reads it. It waits in tenancy.export_part, encrypted to the one age public
// key the admin gave, until it is downloaded or expires. A tenant holds at most one export.

const (
	// ExportKept is how long a finished export can be downloaded. A pending or running export expires after
	// the same time, so one whose job died leaves nothing behind.
	ExportKept = 24 * time.Hour
	// ExportGrace is how long after an export expires the sweep waits before it deletes the parts, so that a
	// download that began before the expiry can end. Nothing reads an expired export, whether or not the
	// sweep has deleted it yet.
	ExportGrace = 30 * time.Minute
	// ExportCooldown is how long after an export finished, or failed, the tenant must wait to ask for another, so
	// that a token that asks again and again cannot keep the worker reading the whole tenant and writing a
	// gigabyte of parts back to back.
	ExportCooldown = 10 * time.Minute
	// ExportStuck is how long after a job first claimed an export the sweep gives up on it while it is still
	// running. Three attempts of 30 minutes with their backoff fit inside it, so an export still running after it
	// lost its job to a kill that no attempt survived to mark.
	ExportStuck = 2 * time.Hour
	// ExportPartSize is the size of one stored part but the last.
	ExportPartSize = 1 << 20
	// MaxStoredExport bounds an archive kept in the database. A tenant with more uses the operator command.
	MaxStoredExport = 1 << 30
	// maxRecipient bounds the text of a public key. A hybrid key is about 1950 characters.
	maxRecipient = 4096
)

// The states of an export a caller can see. A finished export that a newer request replaced is in the state
// replaced: it is no longer served, and its parts stay until the sweep deletes them.
const (
	ExportPending = "pending"
	ExportRunning = "running"
	ExportReady   = "ready"
	ExportFailed  = "failed"
)

var (
	// ErrNoExport is returned for an export the tenant does not have, one that has expired, and one a job
	// can no longer work on. The three are one answer, so a caller learns nothing about the others.
	ErrNoExport = errors.New("no such export")
	// ErrExportNotReady is returned when an archive is asked for before the job has finished it, or after it
	// failed.
	ErrExportNotReady = errors.New("the export is not ready")
	// ErrBadRecipient is returned for a recipient that is not one native or hybrid age public key. The text
	// never quotes what was given, which might be a private key pasted by mistake.
	ErrBadRecipient = errors.New("a recipient is not an age public key")
	// ErrExportTooLarge is returned when the archive would pass MaxStoredExport.
	ErrExportTooLarge = errors.New("the export is larger than the API keeps")
)

// TooSoonError is returned when the last export of the tenant finished less than ExportCooldown ago. The API
// answers 429 with Wait as the Retry-After.
type TooSoonError struct{ Wait time.Duration }

func (*TooSoonError) Error() string {
	return "the last export finished too recently to ask for another"
}

// recipientText is the bech32 text of a native (age1...) or hybrid (age1pq1...) recipient, so a value that
// cannot be one, a comment, a second line or a private key, is refused before it is parsed.
var recipientText = regexp.MustCompile(`^age1[0-9a-z]+$`)

// ParseRecipient reads exactly one native or hybrid age public key. The command line and the API use it, so
// both accept the same keys.
func ParseRecipient(s string) (age.Recipient, error) {
	if len(s) > maxRecipient || !recipientText.MatchString(s) {
		return nil, ErrBadRecipient
	}
	var (
		recipient age.Recipient
		err       error
	)
	if strings.HasPrefix(s, "age1pq1") {
		recipient, err = age.ParseHybridRecipient(s)
	} else {
		recipient, err = age.ParseX25519Recipient(s)
	}
	if err != nil {
		return nil, ErrBadRecipient
	}
	return recipient, nil
}

// StoredExport is a row of tenancy.export, without the key it is encrypted to.
type StoredExport struct {
	ID          uuid.UUID
	RequestedBy uuid.UUID
	State       string
	CreatedAt   time.Time
	FinishedAt  *time.Time
	ExpiresAt   time.Time
	// Bytes, Parts and SHA256 are set once the export is ready: the size of the ciphertext, the number of
	// parts it is stored in, and its SHA-256.
	Bytes  int64
	Parts  int
	SHA256 []byte
}

const exportColumns = `id, requested_by, state, created_at, finished_at, expires_at, bytes, parts, sha256`

type rowScanner interface{ Scan(dest ...any) error }

func scanExport(row rowScanner) (StoredExport, error) {
	var (
		e        StoredExport
		finished sql.NullTime
		size     sql.NullInt64
		parts    sql.NullInt32
	)
	if err := row.Scan(&e.ID, &e.RequestedBy, &e.State, &e.CreatedAt, &finished, &e.ExpiresAt, &size, &parts, &e.SHA256); err != nil {
		return StoredExport{}, err
	}
	if finished.Valid {
		e.FinishedAt = &finished.Time
	}
	e.Bytes = size.Int64
	e.Parts = int(parts.Int32)
	return e, nil
}

// inTenantTx runs fn in one transaction with ipso.tenant set, so row-level security limits every statement
// to the tenant, and commits when fn returns nil.
func inTenantTx(ctx context.Context, db *sql.DB, tenant uuid.UUID, readOnly bool, fn func(tx *sql.Tx) error) error {
	if db == nil || tenant == uuid.Nil {
		return errors.New("a database and a tenant are required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return fmt.Errorf("tenant transaction: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return fmt.Errorf("tenant transaction: set the tenant: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return reduce("tenant transaction: commit", err)
	}
	return nil
}

// StartExport records a request for an export in the transaction the caller opened for the tenant. It is a
// TooSoonError when the last export finished less than ExportCooldown ago. Then it deletes a failed export and
// marks a ready one, and a pending or running one that expired, replaced, which stops it being served while its
// parts stay for a download in flight, and inserts the new one. A pending or running export that is still
// current makes the insert fail on export_one_at_a_time, which the API answers with 409. The error of that
// insert is returned with its cause, because the API reads the SQLSTATE to answer.
func StartExport(ctx context.Context, tx *sql.Tx, tenant, principal uuid.UUID, recipient string) (StoredExport, error) {
	if _, err := ParseRecipient(recipient); err != nil {
		return StoredExport{}, err
	}
	var wait sql.NullFloat64
	if err := tx.QueryRowContext(ctx, `
		SELECT extract(epoch FROM max(finished_at) + make_interval(secs => $2) - now())
		FROM tenancy.export
		WHERE tenant_id = $1 AND state IN ('ready', 'failed') AND finished_at > now() - make_interval(secs => $2)`,
		tenant, ExportCooldown.Seconds()).Scan(&wait); err != nil {
		return StoredExport{}, reduce("export: read the last export", err)
	}
	if wait.Valid && wait.Float64 > 0 {
		return StoredExport{}, &TooSoonError{Wait: time.Duration(wait.Float64 * float64(time.Second))}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenancy.export WHERE tenant_id = $1 AND state = 'failed'`, tenant); err != nil {
		return StoredExport{}, reduce("export: clear the last export", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE tenancy.export
		SET state = 'replaced', finished_at = coalesce(finished_at, now()), expires_at = least(expires_at, now())
		WHERE tenant_id = $1 AND (state = 'ready' OR (state IN ('pending', 'running') AND expires_at <= now()))`, tenant); err != nil {
		return StoredExport{}, reduce("export: replace the last export", err)
	}
	e, err := scanExport(tx.QueryRowContext(ctx, `
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))
		RETURNING `+exportColumns, tenant, principal, recipient, ExportKept.Seconds()))
	if err != nil {
		return StoredExport{}, fmt.Errorf("export: record the request: %w", err)
	}
	return e, nil
}

// GetExport returns an export of the tenant that has not expired.
func GetExport(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (StoredExport, error) {
	var e StoredExport
	err := inTenantTx(ctx, db, tenant, true, func(tx *sql.Tx) (err error) {
		e, err = GetExportTx(ctx, tx, tenant, id)
		return err
	})
	return e, err
}

// GetExportTx is GetExport in a transaction the caller opened for the tenant.
func GetExportTx(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (StoredExport, error) {
	e, err := scanExport(tx.QueryRowContext(ctx, `
		SELECT `+exportColumns+` FROM tenancy.export
		WHERE tenant_id = $1 AND id = $2 AND expires_at > now()`, tenant, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return StoredExport{}, ErrNoExport
	case err != nil:
		return StoredExport{}, reduce("export: read the export", err)
	}
	return e, nil
}

// ExportPart returns one stored part of a finished export.
func ExportPart(ctx context.Context, db *sql.DB, tenant, id uuid.UUID, seq int) ([]byte, error) {
	var data []byte
	err := inTenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT data FROM tenancy.export_part
			WHERE tenant_id = $1 AND export_id = $2 AND seq = $3`, tenant, id, seq).Scan(&data)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNoExport
		case err != nil:
			return reduce("export: read a part", err)
		}
		return nil
	})
	return data, err
}

// claimExport marks the export running, clears the parts an earlier attempt left, and returns the key to
// encrypt to. It is ErrNoExport when the export is gone, expired, or no longer pending or running.
func claimExport(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (string, error) {
	var recipient string
	err := inTenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			UPDATE tenancy.export SET state = 'running', started_at = coalesce(started_at, now())
			WHERE tenant_id = $1 AND id = $2 AND state IN ('pending', 'running') AND expires_at > now()
			RETURNING recipient`, tenant, id).Scan(&recipient)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return ErrNoExport
		case err != nil:
			return reduce("export: claim", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenancy.export_part WHERE tenant_id = $1 AND export_id = $2`, tenant, id); err != nil {
			return reduce("export: clear the parts", err)
		}
		return nil
	})
	return recipient, err
}

// RunStoredExport makes the archive of a pending or running export and stores it in parts. It runs as the
// application role, and Export holds one read-only snapshot while the parts are written in transactions of
// their own, so no transaction is open for longer than a part takes. The export is ready only when it
// returns nil. A failure leaves the parts for the next attempt to clear, and FailExport removes them.
func RunStoredExport(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (ExportReport, error) {
	recipient, err := claimExport(ctx, db, tenant, id)
	if err != nil {
		return ExportReport{Tenant: tenant}, err
	}
	key, err := ParseRecipient(recipient)
	if err != nil {
		return ExportReport{Tenant: tenant}, err
	}
	out := newPartWriter(func(seq int, data []byte) error {
		return inTenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data) VALUES ($1, $2, $3, $4)`,
				tenant, id, seq, data); err != nil {
				return reduce("export: store a part", err)
			}
			return nil
		})
	})
	report, err := Export(ctx, db, ExportOptions{Tenant: tenant, Recipients: []age.Recipient{key}, Out: out})
	if err != nil {
		return report, err
	}
	if err := out.flush(); err != nil {
		return report, err
	}
	err = inTenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE tenancy.export
			SET state = 'ready', finished_at = now(), expires_at = now() + make_interval(secs => $3),
			    bytes = $4, parts = $5, sha256 = $6
			WHERE tenant_id = $1 AND id = $2 AND state = 'running'`,
			tenant, id, ExportKept.Seconds(), out.total, out.seq, out.hash.Sum(nil))
		if err != nil {
			return reduce("export: finish", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrNoExport
		}
		return nil
	})
	return report, err
}

// FailExport marks a pending or running export failed and removes its parts. It does nothing to an export
// that is ready or gone.
func FailExport(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) error {
	return inTenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE tenancy.export
			SET state = 'failed', finished_at = now(), expires_at = now() + make_interval(secs => $3)
			WHERE tenant_id = $1 AND id = $2 AND state IN ('pending', 'running')`, tenant, id, ExportKept.Seconds())
		if err != nil {
			return reduce("export: fail", err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenancy.export_part WHERE tenant_id = $1 AND export_id = $2`, tenant, id); err != nil {
			return reduce("export: clear the parts", err)
		}
		return nil
	})
}

// ExportSweep is what one sweep did and found: the exports it deleted for having expired, the running exports it
// marked failed for being stuck, and the ids of the exports that still wait for a job.
type ExportSweep struct {
	Deleted, Failed int64
	Open            []uuid.UUID
}

// SweepExports deletes the exports that expired more than ExportGrace ago, with their parts, marks failed the
// running exports that a job claimed more than ExportStuck ago, and names the exports that still wait for a
// job: pending, or running and not yet finished. A running export is named too, because the job that was making
// it may have died, and a job already queued for it is skipped by its unique options.
func SweepExports(ctx context.Context, db *sql.DB, tenant uuid.UUID) (ExportSweep, error) {
	var out ExportSweep
	err := inTenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			DELETE FROM tenancy.export WHERE tenant_id = $1 AND expires_at <= now() - make_interval(secs => $2)`,
			tenant, ExportGrace.Seconds())
		if err != nil {
			return reduce("export: delete the expired", err)
		}
		if out.Deleted, err = res.RowsAffected(); err != nil {
			return reduce("export: delete the expired", err)
		}
		// A running export that no job finishes would be queued again by every sweep. After ExportStuck it
		// fails, with its parts, so the admin can ask again.
		if err := tx.QueryRowContext(ctx, `
			WITH stuck AS (
				UPDATE tenancy.export
				SET state = 'failed', finished_at = now(), expires_at = now() + make_interval(secs => $3)
				WHERE tenant_id = $1 AND state = 'running' AND started_at <= now() - make_interval(secs => $2)
				RETURNING id),
			gone AS (
				DELETE FROM tenancy.export_part WHERE tenant_id = $1 AND export_id IN (SELECT id FROM stuck))
			SELECT count(*) FROM stuck`,
			tenant, ExportStuck.Seconds(), ExportKept.Seconds()).Scan(&out.Failed); err != nil {
			return reduce("export: fail the stuck", err)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM tenancy.export
			WHERE tenant_id = $1 AND state IN ('pending', 'running') AND expires_at > now()
			ORDER BY id`, tenant)
		if err != nil {
			return reduce("export: read the open exports", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return reduce("export: read the open exports", err)
			}
			out.Open = append(out.Open, id)
		}
		if err := rows.Err(); err != nil {
			return reduce("export: read the open exports", err)
		}
		return nil
	})
	return out, err
}

// partWriter cuts what is written to it into parts of ExportPartSize, hands each to put, and keeps the size and
// SHA-256 of the whole. It refuses an archive over MaxStoredExport. put is called with the number of the part
// and its bytes, which it must not keep.
type partWriter struct {
	put   func(seq int, data []byte) error
	buf   []byte
	seq   int
	total int64
	hash  hash.Hash
}

func newPartWriter(put func(seq int, data []byte) error) *partWriter {
	return &partWriter{put: put, buf: make([]byte, 0, ExportPartSize), hash: sha256.New()}
}

func (w *partWriter) Write(p []byte) (int, error) {
	if w.total+int64(len(w.buf))+int64(len(p)) > MaxStoredExport {
		return 0, ErrExportTooLarge
	}
	written := len(p)
	for len(p) > 0 {
		take := min(ExportPartSize-len(w.buf), len(p))
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		if len(w.buf) == ExportPartSize {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return written, nil
}

// flush stores the buffer as the next part. An empty buffer stores nothing.
func (w *partWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	if err := w.put(w.seq, w.buf); err != nil {
		return err
	}
	w.hash.Write(w.buf)
	w.total += int64(len(w.buf))
	w.seq++
	w.buf = w.buf[:0]
	return nil
}
