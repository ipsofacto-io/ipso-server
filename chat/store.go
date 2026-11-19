package chat

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// Destination is one configured webhook. URL is unsealed and must not be logged or returned by HTTP.
type Destination struct {
	Connector string
	URL       string
}

// Store reads and writes chat rows for one tenant.
type Store struct {
	db     *sql.DB
	tenant uuid.UUID
	key    []byte
}

// NewStore returns a store bound to one tenant and one connector key.
func NewStore(db *sql.DB, tenant uuid.UUID, key []byte) Store {
	return Store{db: db, tenant: tenant, key: key}
}

// Put seals webhookURL and replaces the destination for connector.
// The action log names the connector, not the URL.
func (s Store) Put(ctx context.Context, actor uuid.UUID, connector, webhookURL string) (uuid.UUID, error) {
	if s.db == nil || s.tenant == uuid.Nil || len(s.key) != 32 || actor == uuid.Nil || !KnownConnector(connector) {
		return uuid.Nil, ErrInvalid
	}
	sealed, err := Seal(s.key, s.tenant, connector, webhookURL)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = identity.WithAction(ctx, s.db, s.tenant, actor, "api.put_chat", func(tx *sql.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM integrations.chat_destination
			WHERE tenant_id = $1 AND connector = $2`, s.tenant, connector); err != nil {
			return "", err
		}
		err := tx.QueryRowContext(ctx, `
			INSERT INTO integrations.chat_destination (tenant_id, connector, url_sealed)
			VALUES ($1, $2, $3)
			RETURNING id`, s.tenant, connector, sealed).Scan(&id)
		if err != nil {
			return "", err
		}
		return "chat " + connector, nil
	})
	if err != nil {
		if sqlState(err) == "23505" {
			return uuid.Nil, ErrConflict
		}
		if sqlState(err) == "23514" {
			return uuid.Nil, ErrInvalid
		}
		return uuid.Nil, err
	}
	return id, nil
}

// Delete removes the destination for connector. Delivery rows stay, so a later bind does not resend them.
func (s Store) Delete(ctx context.Context, actor uuid.UUID, connector string) error {
	if s.db == nil || s.tenant == uuid.Nil || actor == uuid.Nil || !KnownConnector(connector) {
		return ErrInvalid
	}
	err := identity.WithAction(ctx, s.db, s.tenant, actor, "api.delete_chat", func(tx *sql.Tx) (string, error) {
		res, err := tx.ExecContext(ctx, `
			DELETE FROM integrations.chat_destination
			WHERE tenant_id = $1 AND connector = $2`, s.tenant, connector)
		if err != nil {
			return "", err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", ErrNotFound
		}
		return "chat " + connector, nil
	})
	return err
}

// List returns each destination. The caller must not log or echo URL.
// A row that does not open is returned with an empty URL, and List also returns ErrInvalid.
// The other connector is still in the result, so one bad binding does not hide it.
func (s Store) List(ctx context.Context) ([]Destination, error) {
	if s.db == nil || s.tenant == uuid.Nil || len(s.key) != 32 {
		return nil, ErrInvalid
	}
	var out []Destination
	var blocked bool
	err := tenantTx(ctx, s.db, s.tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT connector, url_sealed
			FROM integrations.chat_destination
			WHERE tenant_id = $1
			ORDER BY connector`, s.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var connector string
			var sealed []byte
			if err := rows.Scan(&connector, &sealed); err != nil {
				return err
			}
			plain, err := Open(s.key, sealed, s.tenant, connector)
			if err != nil {
				blocked = true
				out = append(out, Destination{Connector: connector})
				continue
			}
			out = append(out, Destination{Connector: connector, URL: plain})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if blocked {
		return out, ErrInvalid
	}
	return out, nil
}

// PendingWaivers returns the digest of undelivered waiver notices and the ids that digest includes.
func (s Store) PendingWaivers(ctx context.Context, connector string) (string, []uuid.UUID, error) {
	if !ready(s) || !KnownConnector(connector) {
		return "", nil, ErrInvalid
	}
	var lines []WaiverNotice
	err := tenantTx(ctx, s.db, s.tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT n.id, w.decision_id, n.days_before, n.ticket_ref
			FROM registry.waiver_notice AS n
			JOIN registry.waiver AS w ON w.tenant_id = n.tenant_id AND w.id = n.waiver_id
			WHERE n.tenant_id = $1
			  AND NOT EXISTS (
			    SELECT 1 FROM integrations.chat_delivery AS d
			    WHERE d.tenant_id = n.tenant_id AND d.connector = $2
			      AND d.kind = 'waiver' AND d.subject_id = n.id)
			ORDER BY n.id
			LIMIT $3`, s.tenant, connector, LineLimit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var line WaiverNotice
			if err := rows.Scan(&line.ID, &line.Decision, &line.Days, &line.Ticket); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		return rows.Err()
	})
	if err != nil {
		return "", nil, err
	}
	text, ids := WaiverDigest(lines)
	return text, ids, nil
}

// PendingPremises returns the digest of open premise reasons and the ids that digest includes.
func (s Store) PendingPremises(ctx context.Context, connector string) (string, []uuid.UUID, error) {
	if !ready(s) || !KnownConnector(connector) {
		return "", nil, ErrInvalid
	}
	var lines []PremiseNotice
	err := tenantTx(ctx, s.db, s.tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT r.id, r.decision_id, r.premise_id
			FROM registry.premise_reason AS r
			WHERE r.tenant_id = $1
			  AND NOT EXISTS (
			    SELECT 1 FROM registry.premise_clearance AS c
			    WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id)
			  AND NOT EXISTS (
			    SELECT 1 FROM integrations.chat_delivery AS d
			    WHERE d.tenant_id = r.tenant_id AND d.connector = $2
			      AND d.kind = 'premise' AND d.subject_id = r.id)
			ORDER BY r.id
			LIMIT $3`, s.tenant, connector, LineLimit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var line PremiseNotice
			if err := rows.Scan(&line.ID, &line.Decision, &line.Premise); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		return rows.Err()
	})
	if err != nil {
		return "", nil, err
	}
	text, ids := PremiseDigest(lines)
	return text, ids, nil
}

// Record inserts one delivery row per id after a successful post. A row that already exists is left as it is.
func (s Store) Record(ctx context.Context, connector, kind string, ids []uuid.UUID) error {
	if !ready(s) || !KnownConnector(connector) || !KnownKind(kind) {
		return ErrInvalid
	}
	if len(ids) == 0 {
		return nil
	}
	return tenantTx(ctx, s.db, s.tenant, false, func(tx *sql.Tx) error {
		for _, id := range ids {
			if id == uuid.Nil {
				return ErrInvalid
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO integrations.chat_delivery (tenant_id, connector, kind, subject_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (tenant_id, connector, kind, subject_id) DO NOTHING`,
				s.tenant, connector, kind, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func ready(s Store) bool {
	return s.db != nil && s.tenant != uuid.Nil
}

func tenantTx(ctx context.Context, db *sql.DB, tenant uuid.UUID, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: readOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
