package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// CLITokenPrefix identifies an opaque CLI session bearer token issued by /auth/cli/token.
	CLITokenPrefix = "ipsocli_"
	cliTokenBytes  = 32
	cliTokenBody   = 43 // base64.RawURLEncoding.EncodedLen(32)

	cliStartAction = "auth.cli.start"
	cliEndAction   = "auth.cli.end"
)

// ErrUnknownCLISession is returned for a CLI token the tenant holds no unexpired row for.
var ErrUnknownCLISession = errors.New("unknown CLI session")

// NewCLIToken mints an opaque CLI session token and its SHA-256 digest.
func NewCLIToken() (string, []byte, error) {
	raw := make([]byte, cliTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := CLITokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// CLITokenHash parses and hashes a bearer token carrying CLITokenPrefix.
func CLITokenHash(token string) ([]byte, bool) {
	body, ok := strings.CutPrefix(token, CLITokenPrefix)
	if !ok || len(body) != cliTokenBody {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(decoded) != cliTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}

// CheckHumanLogin verifies that the tenant holds an open login of a human principal for issuer and subject.
func CheckHumanLogin(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string) error {
	if tenant == uuid.Nil || issuer == "" || subject == "" {
		return fmt.Errorf("%w: a tenant, an issuer, and a subject are required", ErrInvalidQuery)
	}
	var kind string
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT p.kind
			FROM identity.login l
			JOIN identity.principal p ON p.tenant_id = l.tenant_id AND p.id = l.principal_id
			WHERE l.tenant_id = ipso.current_tenant()
			  AND l.issuer = $1
			  AND l.subject = $2
			  AND l.closed_at IS NULL`, issuer, subject).Scan(&kind)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownLogin
	}
	if err != nil {
		return fmt.Errorf("read the login: %w", err)
	}
	if kind != KindHuman {
		return ErrNotHuman
	}
	return nil
}

// StartCLISession opens a revocable CLI session for a human login and records the action in identity.action_log.
func StartCLISession(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string, hash []byte) (time.Time, error) {
	if tenant == uuid.Nil || issuer == "" || subject == "" || len(hash) != TokenHashSize {
		return time.Time{}, fmt.Errorf("%w: a tenant, an issuer, a subject, and a token hash are required", ErrInvalidQuery)
	}
	var expires time.Time
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM identity.cli_session
			WHERE tenant_id = ipso.current_tenant() AND expires_at <= clock_timestamp()`); err != nil {
			return err
		}
		var sessionID, person uuid.UUID
		err := tx.QueryRowContext(ctx, `
			WITH target AS (
				SELECT id, principal_id
				FROM identity.login
				WHERE tenant_id = ipso.current_tenant()
				  AND issuer = $1
				  AND subject = $2
				  AND closed_at IS NULL
			),
			inserted AS (
				INSERT INTO identity.cli_session (tenant_id, login_id, token_sha256)
				SELECT ipso.current_tenant(), id, $3::bytea
				FROM target
				RETURNING id, expires_at
			)
			SELECT inserted.id, inserted.expires_at, target.principal_id
			FROM inserted, target`, issuer, subject, hash).Scan(&sessionID, &expires, &person)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
			VALUES (ipso.current_tenant(), $1, $1, $2, $3)`,
			person, cliStartAction, "cli_session "+sessionID.String())
		return err
	})
	return expires, sessionError(err)
}

// CLISessionPrincipal returns the principal of an unexpired CLI session and when it expires.
func CLISessionPrincipal(ctx context.Context, db *sql.DB, tenant uuid.UUID, hash []byte) (uuid.UUID, time.Time, error) {
	if tenant == uuid.Nil || len(hash) != TokenHashSize {
		return uuid.Nil, time.Time{}, fmt.Errorf("%w: a tenant and a token hash are required", ErrInvalidQuery)
	}
	var principal uuid.UUID
	var expires time.Time
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT l.principal_id, s.expires_at
			FROM identity.cli_session s
			JOIN identity.login l ON l.tenant_id = s.tenant_id AND l.id = s.login_id
			WHERE s.tenant_id = ipso.current_tenant()
			  AND s.token_sha256 = $1
			  AND s.expires_at > clock_timestamp()
			  AND l.closed_at IS NULL`, hash).Scan(&principal, &expires)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, time.Time{}, ErrUnknownCLISession
	}
	if err != nil {
		return uuid.Nil, time.Time{}, fmt.Errorf("read the CLI session: %w", err)
	}
	return principal, expires, nil
}

// EndCLISession revokes a CLI session by token hash and appends an audit log entry when a live session is removed.
func EndCLISession(ctx context.Context, db *sql.DB, tenant uuid.UUID, hash []byte) error {
	if tenant == uuid.Nil || len(hash) != TokenHashSize {
		return fmt.Errorf("%w: a tenant and a token hash are required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var sessionID, person uuid.UUID
		err := tx.QueryRowContext(ctx, `
			DELETE FROM identity.cli_session s
			USING identity.login l
			WHERE s.tenant_id = ipso.current_tenant()
			  AND s.token_sha256 = $1
			  AND l.tenant_id = s.tenant_id
			  AND l.id = s.login_id
			RETURNING s.id, l.principal_id`, hash).Scan(&sessionID, &person)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
			VALUES (ipso.current_tenant(), $1, $1, $2, $3)`,
			person, cliEndAction, "cli_session "+sessionID.String())
		return err
	})
	if err != nil {
		return fmt.Errorf("end the CLI session: %w", err)
	}
	return nil
}
