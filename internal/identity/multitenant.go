package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrAmbiguousLogin is returned in multi-tenant mode when an issuer and subject hold open logins in
// two or more tenants (ADR-0170). Callers fail closed with 403 rather than picking a tenant.
var ErrAmbiguousLogin = errors.New("ambiguous login across tenants")

// LoginTenant resolves an issuer and subject to its single open tenant in multi-tenant mode using
// identity.login_tenants. Zero rows returns ErrUnknownLogin; two rows returns ErrAmbiguousLogin.
// The transaction clears ipso.tenant before invoking the definer lookup so any setting left on a
// pooled connection cannot alter the answer.
func LoginTenant(ctx context.Context, db *sql.DB, issuer, subject string) (uuid.UUID, error) {
	if db == nil || issuer == "" || subject == "" {
		return uuid.Nil, fmt.Errorf("%w: a database, an issuer, and a subject are required", ErrInvalidQuery)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve login tenant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return uuid.Nil, fmt.Errorf("resolve login tenant: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id FROM identity.login_tenants($1, $2)`, issuer, subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve login tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			return uuid.Nil, fmt.Errorf("resolve login tenant: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, fmt.Errorf("resolve login tenant: %w", err)
	}
	switch len(tenants) {
	case 0:
		return uuid.Nil, ErrUnknownLogin
	case 1:
		return tenants[0], nil
	default:
		return uuid.Nil, ErrAmbiguousLogin
	}
}

// SessionTenant resolves a browser session token hash to its owning tenant in multi-tenant mode.
func SessionTenant(ctx context.Context, db *sql.DB, hash []byte) (uuid.UUID, bool, error) {
	return hashTenant(ctx, db, "session tenant", `SELECT identity.session_tenant($1)`, hash)
}

// CLISessionTenant resolves a CLI session token hash to its owning tenant in multi-tenant mode.
func CLISessionTenant(ctx context.Context, db *sql.DB, hash []byte) (uuid.UUID, bool, error) {
	return hashTenant(ctx, db, "cli session tenant", `SELECT identity.cli_session_tenant($1)`, hash)
}

// InvitationTenant resolves an unexpired invitation token hash to its owning tenant in multi-tenant mode.
func InvitationTenant(ctx context.Context, db *sql.DB, hash []byte) (uuid.UUID, bool, error) {
	return hashTenant(ctx, db, "invitation tenant", `SELECT identity.invitation_tenant($1)`, hash)
}

// SCIMTokenTenant resolves a SCIM bearer token hash to its owning tenant in multi-tenant mode.
func SCIMTokenTenant(ctx context.Context, db *sql.DB, hash []byte) (uuid.UUID, bool, error) {
	return hashTenant(ctx, db, "scim token tenant", `SELECT identity.scim_token_tenant($1)`, hash)
}

// AuthenticateSCIMToken resolves a raw SCIM bearer token to its owning tenant in multi-tenant mode
// and verifies it under forced row-level security with a constant-time hash comparison.
func AuthenticateSCIMToken(ctx context.Context, db *sql.DB, token []byte) (uuid.UUID, bool, error) {
	if db == nil || len(token) == 0 {
		return uuid.Nil, false, nil
	}
	sum := sha256.Sum256(token)
	tenant, ok, err := SCIMTokenTenant(ctx, db, sum[:])
	if err != nil {
		return uuid.Nil, false, err
	}
	if !ok {
		_ = subtle.ConstantTimeCompare(absentTokenHash[:], sum[:])
		return uuid.Nil, false, nil
	}
	verified, err := SCIMTokenOK(ctx, db, tenant, token)
	if err != nil || !verified {
		return uuid.Nil, false, err
	}
	return tenant, true, nil
}

func hashTenant(ctx context.Context, db *sql.DB, operation, query string, hash []byte) (uuid.UUID, bool, error) {
	if db == nil || len(hash) != TokenHashSize {
		return uuid.Nil, false, fmt.Errorf("%w: a database and a %d-byte hash are required", ErrInvalidQuery, TokenHashSize)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("%s: %w", operation, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return uuid.Nil, false, fmt.Errorf("%s: %w", operation, err)
	}
	var tenant uuid.NullUUID
	if err := tx.QueryRowContext(ctx, query, hash).Scan(&tenant); err != nil {
		return uuid.Nil, false, fmt.Errorf("%s: %w", operation, err)
	}
	if !tenant.Valid {
		return uuid.Nil, false, nil
	}
	return tenant.UUID, true, nil
}

// RequireMultiTenantLookups probes the five identity definer lookup functions at start in multi-tenant
// mode using inert inputs that cannot match any valid row (check constraints require non-empty HTTPS
// issuers and 32-byte hashes), so an unmigrated database stops at start without revealing any tenant.
func RequireMultiTenantLookups(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("multi-tenant lookups: a database is required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("multi-tenant lookups: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return fmt.Errorf("multi-tenant lookups: clear tenant: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id FROM identity.login_tenants('', '')`)
	if err != nil {
		return missingLookupError("identity.login_tenants", err)
	}
	_ = rows.Close()

	inert := []byte{}
	for _, probe := range []struct {
		name  string
		query string
	}{
		{"identity.session_tenant", `SELECT identity.session_tenant($1)`},
		{"identity.cli_session_tenant", `SELECT identity.cli_session_tenant($1)`},
		{"identity.invitation_tenant", `SELECT identity.invitation_tenant($1)`},
		{"identity.scim_token_tenant", `SELECT identity.scim_token_tenant($1)`},
	} {
		var tenant uuid.NullUUID
		if err := tx.QueryRowContext(ctx, probe.query, inert).Scan(&tenant); err != nil {
			return missingLookupError(probe.name, err)
		}
	}
	return nil
}

func missingLookupError(name string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "42883" || pgErr.Code == "3F000") {
		return fmt.Errorf("multi-tenant lookups: the database has no %s, run ipso-server migrate", name)
	}
	return fmt.Errorf("multi-tenant lookups: probe %s: %w", name, err)
}
