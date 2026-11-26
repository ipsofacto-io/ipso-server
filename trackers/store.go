package trackers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// Admin replaces one connector binding for a tenant. When fixedTenant is non-nil (single-tenant
// mode), Put refuses any other tenant as defense in depth.
type Admin struct {
	db          *sql.DB
	fixedTenant uuid.UUID
	key         []byte
}

// NewAdmin returns an admin for connector bindings. Pass uuid.Nil as tenant in multi-tenant mode.
func NewAdmin(db *sql.DB, tenant uuid.UUID, key []byte) Admin {
	return Admin{db: db, fixedTenant: tenant, key: key}
}

// Put seals the token and the webhook secret and replaces the binding for connector in tenant.
// The subject of the action log is the connector, not the secret.
func (a Admin) Put(ctx context.Context, tenant, actor uuid.UUID, connector, account, label, token, webhook string) (uuid.UUID, error) {
	if a.db == nil || tenant == uuid.Nil || (a.fixedTenant != uuid.Nil && tenant != a.fixedTenant) || len(a.key) != 32 || actor == uuid.Nil || !KnownConnector(connector) {
		return uuid.Nil, ErrInvalid
	}
	if !plainText(account, 200) || !plainText(token, 4000) || !plainText(webhook, 4000) {
		return uuid.Nil, ErrInvalid
	}
	if label == "" {
		label = defaultLabel
	}
	if !labelPattern.MatchString(label) {
		return uuid.Nil, ErrInvalid
	}
	tokenSealed, err := Seal(a.key, tenant, connector, token)
	if err != nil {
		return uuid.Nil, err
	}
	webhookSealed, err := Seal(a.key, tenant, connector, webhook)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = identity.WithAction(ctx, a.db, tenant, actor, "api.put_tracker", func(tx *sql.Tx) (string, error) {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM integrations.tracker_binding
			WHERE tenant_id = $1 AND connector = $2`, tenant, connector); err != nil {
			return "", err
		}
		err := tx.QueryRowContext(ctx, `
			INSERT INTO integrations.tracker_binding
				(tenant_id, connector, external_account, label, token_sealed, webhook_sealed)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id`, tenant, connector, account, label, tokenSealed, webhookSealed).Scan(&id)
		if err != nil {
			return "", err
		}
		return "tracker " + connector, nil
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

// Secret is one binding as the webhook lookup returns it. Token and Webhook are still sealed.
type Secret struct {
	ID        uuid.UUID
	Tenant    uuid.UUID
	Connector string
	Account   string
	Label     string
	Token     []byte
	Webhook   []byte
}

// Lookup reads the binding named by the webhook path. The transaction clears ipso.tenant first so
// any setting left on a pooled connection cannot hide the row. The row is the one binding, not a list.
func Lookup(ctx context.Context, db *sql.DB, id uuid.UUID) (Secret, error) {
	if db == nil || id == uuid.Nil {
		return Secret{}, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return Secret{}, err
	}
	var secret Secret
	err = tx.QueryRowContext(ctx, `
		SELECT tenant_id, connector, external_account, label, token_sealed, webhook_sealed
		FROM integrations.tracker_binding_for_webhook($1)`, id).Scan(
		&secret.Tenant, &secret.Connector, &secret.Account, &secret.Label, &secret.Token, &secret.Webhook)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, err
	}
	secret.ID = id
	return secret, nil
}

// WaiverBinding is the binding that opens a waiver ticket, in the order Jira, Linear, GitHub Issues.
type WaiverBinding struct {
	Connector string
	Account   string
	Token     []byte
}

// BindingForWaiver returns the binding that opens a waiver ticket, or false when the tenant has none.
func BindingForWaiver(ctx context.Context, db *sql.DB, tenant uuid.UUID) (WaiverBinding, bool, error) {
	if db == nil || tenant == uuid.Nil {
		return WaiverBinding{}, false, ErrInvalid
	}
	var binding WaiverBinding
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT connector, external_account, token_sealed
			FROM integrations.tracker_binding
			WHERE tenant_id = $1
			ORDER BY CASE connector WHEN 'jira' THEN 1 WHEN 'linear' THEN 2 WHEN 'github_issues' THEN 3 ELSE 4 END
			LIMIT 1`, tenant).Scan(&binding.Connector, &binding.Account, &binding.Token)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return WaiverBinding{}, false, nil
	}
	if err != nil {
		return WaiverBinding{}, false, err
	}
	return binding, true, nil
}

// DueWaiver is a waiver ticket this server created whose 0-day notice is stored and whose link is still open.
type DueWaiver struct {
	Connector  string
	Account    string
	ExternalID string
	Token      []byte
}

// DueWaivers lists waiver links that the 0-day notice may close. At most 50, so one sweep stays bounded.
func DueWaivers(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]DueWaiver, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, ErrInvalid
	}
	var due []DueWaiver
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT l.connector, b.external_account, l.external_id, b.token_sealed
			FROM integrations.tracker_link AS l
			JOIN integrations.tracker_binding AS b
			  ON b.tenant_id = l.tenant_id AND b.connector = l.connector
			JOIN registry.waiver_notice AS n
			  ON n.tenant_id = l.tenant_id AND n.waiver_id = l.waiver_id AND n.days_before = 0
			WHERE l.tenant_id = $1 AND l.kind = 'waiver' AND l.status = 'open'
			LIMIT 50`, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item DueWaiver
			if err := rows.Scan(&item.Connector, &item.Account, &item.ExternalID, &item.Token); err != nil {
				return err
			}
			due = append(due, item)
		}
		return rows.Err()
	})
	return due, err
}

// LinkWaiver inserts the link for a waiver ticket this server just created. The transaction is the
// waiver's, with ipso.tenant already set.
func LinkWaiver(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, connector, externalID, url string, waiver uuid.UUID) error {
	if tx == nil || tenant == uuid.Nil || waiver == uuid.Nil || !KnownConnector(connector) || !plainText(externalID, 200) || !AllowedURL(connector, url) {
		return ErrInvalid
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO integrations.tracker_link
			(tenant_id, connector, external_id, url, kind, waiver_id, status)
		VALUES ($1, $2, $3, $4, 'waiver', $5, 'open')`, tenant, connector, externalID, url, waiver)
	if sqlState(err) == "23505" {
		return ErrConflict
	}
	return err
}

// SetStatus sets the link status and no other column.
func SetStatus(ctx context.Context, db *sql.DB, tenant uuid.UUID, connector, externalID, status string) error {
	if db == nil || !KnownStatus(status) {
		return ErrInvalid
	}
	return tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		return setStatus(ctx, tx, tenant, connector, externalID, status)
	})
}

// InboxItem is one tracker proposal a person has not answered. The ticket body is not in it.
type InboxItem struct {
	ID            uuid.UUID       `json:"id"`
	Connector     string          `json:"connector"`
	Status        string          `json:"status"`
	TrustLevel    string          `json:"trust_level"`
	Payload       json.RawMessage `json:"payload"`
	Confidence    float64         `json:"confidence"`
	ModelID       string          `json:"model_id"`
	PromptVersion string          `json:"prompt_version"`
	ExternalID    string          `json:"external_id"`
	SourceURL     string          `json:"source_url"`
	CapturedAt    time.Time       `json:"captured_at"`
}

// Inbox lists tracker proposals with no approval, newest first.
// before is the last id of the previous page, or uuid.Nil for the first page.
func Inbox(ctx context.Context, db *sql.DB, tenant, before uuid.UUID, limit int) ([]InboxItem, error) {
	if db == nil || tenant == uuid.Nil || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	var cursor any
	if before != uuid.Nil {
		cursor = before
	}
	items := []InboxItem{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT p.id, p.connector, p.status, p.trust_level, p.payload, p.confidence, p.model_id, p.prompt_version,
			       p.external_id, p.source_url, lower(p.sys_period)
			FROM proposals.tracker_proposal p
			WHERE p.tenant_id = $1 AND ($2::uuid IS NULL OR p.id < $2::uuid)
			  AND NOT EXISTS (
			    SELECT 1 FROM proposals.tracker_approval a
			    WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			ORDER BY p.id DESC
			LIMIT $3`, tenant, cursor, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item InboxItem
			var payload []byte
			if err := rows.Scan(&item.ID, &item.Connector, &item.Status, &item.TrustLevel, &payload, &item.Confidence,
				&item.ModelID, &item.PromptVersion, &item.ExternalID, &item.SourceURL, &item.CapturedAt); err != nil {
				return err
			}
			item.Payload = payload
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func setStatus(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, connector, externalID, status string) error {
	if !KnownStatus(status) {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE integrations.tracker_link
		SET status = $4
		WHERE tenant_id = $1 AND connector = $2 AND external_id = $3`, tenant, connector, externalID, status)
	return err
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

// AccountHost is the host half of a Jira account, which is host/project.
func AccountHost(account string) (host, project string, ok bool) {
	host, project, ok = strings.Cut(account, "/")
	if !ok || host == "" || project == "" || strings.Contains(project, "/") {
		return "", "", false
	}
	return host, project, true
}
