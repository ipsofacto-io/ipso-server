package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotHuman is returned when the login belongs to an agent. An agent keeps its bearer login and has
// no browser session (ADR-0099).
var ErrNotHuman = errors.New("a session needs the login of a person")

// ErrUnknownSession is returned for a session the tenant has no unexpired row for.
var ErrUnknownSession = errors.New("unknown session")

// TokenHashSize is the size of the SHA-256 the table keeps of a session token.
const TokenHashSize = 32

// StartSession opens a session for the principal the tenant bound to the issuer and subject, and
// returns when it ends. hash is the SHA-256 of the new session token, and previous is the hash of the
// session the browser held, or nil. The old session ends and the tenant's expired
// rows go in the same transaction, so a sign-in leaves one session for that browser. The login is
// read in the INSERT itself: an issuer and a subject the tenant never bound are ErrUnknownLogin, and
// nothing is written. The tenant must be the one this process serves, because StartSession trusts it.
func StartSession(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string, hash, previous []byte) (time.Time, error) {
	if tenant == uuid.Nil || issuer == "" || subject == "" || len(hash) != TokenHashSize || (previous != nil && len(previous) != TokenHashSize) {
		return time.Time{}, fmt.Errorf("%w: a tenant, an issuer, a subject, and a token hash are required", ErrInvalidQuery)
	}
	var expires time.Time
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM identity.session
			WHERE tenant_id = ipso.current_tenant() AND expires_at <= clock_timestamp()`); err != nil {
			return err
		}
		if previous != nil {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM identity.session
				WHERE tenant_id = ipso.current_tenant() AND token_sha256 = $1`, previous); err != nil {
				return err
			}
		}
		return tx.QueryRowContext(ctx, `
			INSERT INTO identity.session (tenant_id, login_id, token_sha256)
			SELECT tenant_id, id, $3::bytea
			FROM identity.login
			WHERE tenant_id = ipso.current_tenant() AND issuer = $1 AND subject = $2
			RETURNING expires_at`, issuer, subject, hash).Scan(&expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrUnknownLogin
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23514" {
		return time.Time{}, ErrNotHuman
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("start the session: %w", err)
	}
	return expires, nil
}

// SessionPrincipal returns the principal of the unexpired session with this token hash, and when the
// session ends. The principal is read through the session's login. The tenant must be the one this
// process serves, because SessionPrincipal trusts it.
func SessionPrincipal(ctx context.Context, db *sql.DB, tenant uuid.UUID, hash []byte) (uuid.UUID, time.Time, error) {
	if tenant == uuid.Nil || len(hash) != TokenHashSize {
		return uuid.Nil, time.Time{}, fmt.Errorf("%w: a tenant and a token hash are required", ErrInvalidQuery)
	}
	var principal uuid.UUID
	var expires time.Time
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT l.principal_id, s.expires_at
			FROM identity.session s
			JOIN identity.login l ON l.tenant_id = s.tenant_id AND l.id = s.login_id
			WHERE s.tenant_id = ipso.current_tenant()
			  AND s.token_sha256 = $1
			  AND s.expires_at > clock_timestamp()`, hash).Scan(&principal, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, time.Time{}, ErrUnknownSession
	}
	if err != nil {
		return uuid.Nil, time.Time{}, fmt.Errorf("read the session: %w", err)
	}
	return principal, expires, nil
}

// EndSession deletes the session with this token hash. A session that is not there is not an error:
// signing out twice is the same as signing out once. The tenant must be the one this process serves.
func EndSession(ctx context.Context, db *sql.DB, tenant uuid.UUID, hash []byte) error {
	if tenant == uuid.Nil || len(hash) != TokenHashSize {
		return fmt.Errorf("%w: a tenant and a token hash are required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			DELETE FROM identity.session
			WHERE tenant_id = ipso.current_tenant() AND token_sha256 = $1`, hash)
		return err
	})
	if err != nil {
		return fmt.Errorf("end the session: %w", err)
	}
	return nil
}
