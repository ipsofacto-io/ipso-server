package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// ChoiceTokenSize is the number of random bytes in a pending tenant-choice cookie token (ADR-0171).
	ChoiceTokenSize = 32
	choiceTokenText = 43 // base64.RawURLEncoding.EncodedLen(32)
	// LoginChoiceTTL is how long a pending tenant choice lasts in PostgreSQL.
	LoginChoiceTTL = 5 * time.Minute
)

// ErrAmbiguousLogin is returned in multi-tenant mode when an issuer and subject hold open logins in
// two or more tenants (ADR-0170). Callers fail closed with 403 rather than picking a tenant.
var ErrAmbiguousLogin = errors.New("ambiguous login across tenants")

// ErrUnknownChoice is returned when a pending tenant-choice token is absent, already consumed, or expired (ADR-0171).
var ErrUnknownChoice = errors.New("unknown login choice")

// TenantOption is one tenant a verified person may choose at sign-in (ADR-0171).
type TenantOption struct {
	ID   uuid.UUID
	Name string
}

// LoginChoice is the server-side state held between an IdP callback and the person's tenant choice (ADR-0171).
type LoginChoice struct {
	Issuer       string
	Subject      string
	Previous     []byte
	CLIRedirect  string
	CLIState     string
	CLIChallenge string
	IsCLI        bool
	ExpiresAt    time.Time
}

// NewChoiceToken mints a 32-byte unpadded base64url choice token and its SHA-256 digest.
func NewChoiceToken() (string, []byte, error) {
	raw := make([]byte, ChoiceTokenSize)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	return token, sum[:], nil
}

// ChoiceTokenHash validates and hashes a choice token from the __Host-ipso-choice cookie.
func ChoiceTokenHash(token string) ([]byte, bool) {
	if len(token) != choiceTokenText {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != ChoiceTokenSize {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

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

// HumanLoginTenants returns every tenant (up to 100, ordered by name then tenant_id) in which the
// verified issuer and subject hold an open login bound to a human principal (ADR-0171). When zero
// human tenants match, it checks identity.login_tenants so callers still distinguish an unbound
// subject (ErrUnknownLogin) from an agent-only subject (ErrNotHuman).
func HumanLoginTenants(ctx context.Context, db *sql.DB, issuer, subject string) ([]TenantOption, error) {
	if db == nil || issuer == "" || subject == "" {
		return nil, fmt.Errorf("%w: a database, an issuer, and a subject are required", ErrInvalidQuery)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("list human login tenants: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return nil, fmt.Errorf("list human login tenants: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT tenant_id, tenant_name FROM identity.human_login_tenants($1, $2)`, issuer, subject)
	if err != nil {
		return nil, fmt.Errorf("list human login tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []TenantOption
	for rows.Next() {
		var opt TenantOption
		if err := rows.Scan(&opt.ID, &opt.Name); err != nil {
			return nil, fmt.Errorf("list human login tenants: %w", err)
		}
		out = append(out, opt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list human login tenants: %w", err)
	}
	if len(out) > 0 {
		return out, nil
	}
	var anyTenant uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT tenant_id FROM identity.login_tenants($1, $2) LIMIT 1`, issuer, subject).Scan(&anyTenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownLogin
	}
	if err != nil {
		return nil, fmt.Errorf("list human login tenants: %w", err)
	}
	return nil, ErrNotHuman
}

// CreateLoginChoice stores a 5-minute single-use pending tenant choice keyed by token hash (ADR-0171).
func CreateLoginChoice(ctx context.Context, db *sql.DB, hash []byte, choice LoginChoice) (time.Time, error) {
	if db == nil || len(hash) != TokenHashSize || choice.Issuer == "" || choice.Subject == "" ||
		(choice.Previous != nil && len(choice.Previous) != TokenHashSize) {
		return time.Time{}, fmt.Errorf("%w: a database, hash, issuer, and subject are required", ErrInvalidQuery)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return time.Time{}, fmt.Errorf("create login choice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return time.Time{}, fmt.Errorf("create login choice: %w", err)
	}
	var prev any
	if choice.Previous != nil {
		prev = choice.Previous
	}
	var expires time.Time
	if err := tx.QueryRowContext(
		ctx,
		`SELECT identity.create_login_choice($1, $2, $3, $4, $5, $6, $7)`,
		hash, choice.Issuer, choice.Subject, prev, choice.CLIRedirect, choice.CLIState, choice.CLIChallenge,
	).Scan(&expires); err != nil {
		return time.Time{}, fmt.Errorf("create login choice: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("create login choice: %w", err)
	}
	return expires, nil
}

// ReadLoginChoice reads an unexpired pending tenant choice without consuming it (ADR-0171).
func ReadLoginChoice(ctx context.Context, db *sql.DB, hash []byte) (LoginChoice, error) {
	if db == nil || len(hash) != TokenHashSize {
		return LoginChoice{}, fmt.Errorf("%w: a database and a %d-byte hash are required", ErrInvalidQuery, TokenHashSize)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return LoginChoice{}, fmt.Errorf("read login choice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return LoginChoice{}, fmt.Errorf("read login choice: %w", err)
	}
	var out LoginChoice
	err = tx.QueryRowContext(ctx, `SELECT issuer, subject, is_cli, expires_at FROM identity.read_login_choice($1)`, hash).
		Scan(&out.Issuer, &out.Subject, &out.IsCLI, &out.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginChoice{}, ErrUnknownChoice
	}
	if err != nil {
		return LoginChoice{}, fmt.Errorf("read login choice: %w", err)
	}
	return out, nil
}

// ConsumeLoginChoice atomically deletes and returns an unexpired pending tenant choice (ADR-0171).
func ConsumeLoginChoice(ctx context.Context, db *sql.DB, hash []byte) (LoginChoice, error) {
	if db == nil || len(hash) != TokenHashSize {
		return LoginChoice{}, fmt.Errorf("%w: a database and a %d-byte hash are required", ErrInvalidQuery, TokenHashSize)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return LoginChoice{}, fmt.Errorf("consume login choice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return LoginChoice{}, fmt.Errorf("consume login choice: %w", err)
	}
	var out LoginChoice
	err = tx.QueryRowContext(
		ctx,
		`SELECT issuer, subject, previous_session_sha256, cli_redirect_uri, cli_state, cli_challenge FROM identity.consume_login_choice($1)`,
		hash,
	).Scan(&out.Issuer, &out.Subject, &out.Previous, &out.CLIRedirect, &out.CLIState, &out.CLIChallenge)
	if errors.Is(err, sql.ErrNoRows) {
		if cerr := tx.Commit(); cerr != nil {
			return LoginChoice{}, fmt.Errorf("consume login choice: %w", cerr)
		}
		return LoginChoice{}, ErrUnknownChoice
	}
	if err != nil {
		return LoginChoice{}, fmt.Errorf("consume login choice: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return LoginChoice{}, fmt.Errorf("consume login choice: %w", err)
	}
	out.IsCLI = out.CLIRedirect != ""
	return out, nil
}

// CancelLoginChoice deletes a pending tenant choice if present and prunes expired rows (ADR-0171).
func CancelLoginChoice(ctx context.Context, db *sql.DB, hash []byte) error {
	if db == nil || len(hash) != TokenHashSize {
		return fmt.Errorf("%w: a database and a %d-byte hash are required", ErrInvalidQuery, TokenHashSize)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("cancel login choice: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', '', true)`); err != nil {
		return fmt.Errorf("cancel login choice: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT identity.cancel_login_choice($1)`, hash); err != nil {
		return fmt.Errorf("cancel login choice: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cancel login choice: %w", err)
	}
	return nil
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

// RequireMultiTenantLookups probes the identity definer lookup and login-choice functions at start
// in multi-tenant mode using inert inputs that cannot match any valid row (check constraints require
// non-empty HTTPS issuers and 32-byte hashes), so an unmigrated database stops at start without
// revealing any tenant.
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

	hRows, err := tx.QueryContext(ctx, `SELECT tenant_id, tenant_name FROM identity.human_login_tenants('', '')`)
	if err != nil {
		return missingLookupError("identity.human_login_tenants", err)
	}
	_ = hRows.Close()

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

	cRows, err := tx.QueryContext(ctx, `SELECT issuer, subject, is_cli, expires_at FROM identity.read_login_choice($1)`, inert)
	if err != nil {
		return missingLookupError("identity.read_login_choice", err)
	}
	_ = cRows.Close()

	for _, fn := range []struct {
		name string
		sig  string
	}{
		{"identity.create_login_choice", "identity.create_login_choice(bytea,text,text,bytea,text,text,text)"},
		{"identity.consume_login_choice", "identity.consume_login_choice(bytea)"},
		{"identity.cancel_login_choice", "identity.cancel_login_choice(bytea)"},
	} {
		var allowed bool
		if err := tx.QueryRowContext(ctx, `SELECT has_function_privilege(current_user, $1::regprocedure, 'execute')`, fn.sig).Scan(&allowed); err != nil {
			return missingLookupError(fn.name, err)
		}
		if !allowed {
			return fmt.Errorf("multi-tenant lookups: the current role cannot execute %s", fn.name)
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
