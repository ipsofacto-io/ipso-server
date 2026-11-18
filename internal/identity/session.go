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
		if err := dropSessions(ctx, tx, previous); err != nil {
			return err
		}
		var err error
		expires, err = insertSession(ctx, tx, issuer, subject, hash)
		return err
	})
	return expires, sessionError(err)
}

// AcceptInvitation is StartSession for a sign-in that carries an invitation (ADR-0127). A login the tenant
// already bound signs in as it always did, and the invitation stays open for the person it was made for.
// Otherwise it uses the invitation, and in the same transaction it writes the person the invitation names,
// the login of this issuer and subject, the one role binding, the session, and last the entry of the action
// log, so a sign-in that cannot be logged writes nothing. invitation is the hash of the token. A token the
// tenant holds no open invitation for is ErrUnknownInvitation, and nothing is written. The tenant must be the
// one this process serves, because AcceptInvitation trusts it.
func AcceptInvitation(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string, invitation, hash, previous []byte) (time.Time, error) {
	if tenant == uuid.Nil || issuer == "" || subject == "" || len(invitation) != TokenHashSize || len(hash) != TokenHashSize || (previous != nil && len(previous) != TokenHashSize) {
		return time.Time{}, fmt.Errorf("%w: a tenant, an issuer, a subject, and two token hashes are required", ErrInvalidQuery)
	}
	expires, err := acceptInvitation(ctx, db, tenant, issuer, subject, invitation, hash, previous)
	if !errors.Is(err, ErrUnknownInvitation) && !errors.Is(err, errLoginBound) {
		return expires, err
	}
	// Another sign-in of this person was first: it used this invitation, or bound the same issuer and subject
	// with another one, and its transaction has committed. Nothing of this one was written, so the person signs
	// in as the login they now have. A person with no login is still one who came with an invitation that is not
	// open, whichever way it went.
	expires, err = StartSession(ctx, db, tenant, issuer, subject, hash, previous)
	if errors.Is(err, ErrUnknownLogin) {
		return time.Time{}, ErrUnknownInvitation
	}
	return expires, err
}

// errLoginBound is what acceptInvitation returns when the login it would write was bound by a sign-in that
// committed first. The transaction is rolled back, so the invitation is not used.
var errLoginBound = errors.New("the login was bound by another sign-in")

func acceptInvitation(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string, invitation, hash, previous []byte) (time.Time, error) {
	var expires time.Time
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		if err := dropSessions(ctx, tx, previous); err != nil {
			return err
		}
		var err error
		if expires, err = insertSession(ctx, tx, issuer, subject, hash); !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// Not bound yet. The delete is the use: a second sign-in with the same token finds no row, and two at
		// once serialise on it, so the one that waits finds it gone.
		var id uuid.UUID
		var name, role string
		err = tx.QueryRowContext(ctx, `
			DELETE FROM identity.invitation
			WHERE tenant_id = ipso.current_tenant() AND token_sha256 = $1 AND expires_at > clock_timestamp()
			RETURNING id, name, role`, invitation).Scan(&id, &name, &role)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownInvitation
		}
		if err != nil {
			return fmt.Errorf("use the invitation: %w", err)
		}
		var person uuid.UUID
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO identity.principal (tenant_id, kind, name)
			VALUES (ipso.current_tenant(), 'human', $1)
			RETURNING id`, name).Scan(&person); err != nil {
			return fmt.Errorf("write the person: %w", err)
		}
		bound, err := tx.ExecContext(ctx, `
			INSERT INTO identity.login (tenant_id, principal_id, issuer, subject)
			VALUES (ipso.current_tenant(), $1, $2, $3)
			ON CONFLICT ON CONSTRAINT login_once DO NOTHING`, person, issuer, subject)
		if err != nil {
			return fmt.Errorf("write the login: %w", err)
		}
		if n, err := bound.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return fmt.Errorf("write the login: %w", err)
			}
			return errLoginBound
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO identity.role_binding (tenant_id, principal_id, role)
			VALUES (ipso.current_tenant(), $1, $2)`, person, role); err != nil {
			return fmt.Errorf("write the role binding: %w", err)
		}
		if expires, err = insertSession(ctx, tx, issuer, subject, hash); err != nil {
			return err
		}
		// The entry is the last statement, because the chain holds a lock until the transaction ends (ADR-0126).
		// It names the person who accepted and carries the invitation's id and role, never the token or the name.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
			VALUES (ipso.current_tenant(), $1, $1, $2, $3)`, person, acceptAction, "invitation "+id.String()+" role "+role); err != nil {
			return fmt.Errorf("record the action: %w", err)
		}
		return nil
	})
	return expires, sessionError(err)
}

// dropSessions deletes the tenant's expired sessions and the one the browser held, so a sign-in leaves one
// session for that browser.
func dropSessions(ctx context.Context, tx *sql.Tx, previous []byte) error {
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
	return nil
}

// insertSession reads the login in the INSERT itself and returns when the session ends. A login the tenant
// never bound is sql.ErrNoRows, and nothing is written.
func insertSession(ctx context.Context, tx *sql.Tx, issuer, subject string, hash []byte) (time.Time, error) {
	var expires time.Time
	err := tx.QueryRowContext(ctx, `
		INSERT INTO identity.session (tenant_id, login_id, token_sha256)
		SELECT tenant_id, id, $3::bytea
		FROM identity.login
			WHERE tenant_id = ipso.current_tenant() AND issuer = $1 AND subject = $2 AND closed_at IS NULL
			RETURNING expires_at`, issuer, subject, hash).Scan(&expires)
	return expires, err
}

// sessionError turns what a session writer met into the errors callers know.
func sessionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownLogin
	}
	if errors.Is(err, ErrUnknownInvitation) {
		return err
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23514" && pg.ConstraintName == "" {
		return ErrNotHuman
	}
	return fmt.Errorf("start the session: %w", err)
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
			  AND s.expires_at > clock_timestamp()
			  AND l.closed_at IS NULL`, hash).Scan(&principal, &expires)
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
