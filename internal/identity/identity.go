// Package identity reads who acts and records what they did. An agent is a principal with a human
// sponsor, and the action log always names a person (ADR-0076). The rules live in the database, so
// this package cannot be the one place that forgets them.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Kinds of principal.
const (
	KindHuman = "human"
	KindAgent = "agent"
)

// Roles a binding can give, section 13.2 of the specification and ADR-0108.
const (
	RoleViewer        = "viewer"
	RoleContributor   = "contributor"
	RoleDecisionOwner = "decision-owner"
	RoleApprover      = "approver"
	RoleAdmin         = "admin"
	RoleAuditor       = "auditor"
	RoleAgent         = "agent"
)

// Roles is every role, in the order section 13.2 lists them.
var Roles = []string{RoleViewer, RoleContributor, RoleDecisionOwner, RoleApprover, RoleAdmin, RoleAuditor, RoleAgent}

// ErrInvalidQuery is returned for a nil tenant or principal, or a bound that is not usable.
var ErrInvalidQuery = errors.New("invalid query")

// ErrUnknownPrincipal is returned when the tenant has no such principal.
var ErrUnknownPrincipal = errors.New("unknown principal")

// ErrUnknownLogin is returned when the tenant has no login for the issuer and subject.
var ErrUnknownLogin = errors.New("unknown login")

// maxActions bounds one read of the log.
const maxActions = 1000

// maxGrants bounds the role bindings one principal reads. A principal with more is refused rather than
// judged on part of its bindings.
const maxGrants = 1000

// Principal is one person or agent. Sponsor is uuid.Nil for a person. Grants are its role bindings, in
// no particular order (ADR-0108).
type Principal struct {
	ID      uuid.UUID
	Kind    string
	Name    string
	Sponsor uuid.UUID
	Grants  []Grant
}

// Grant is one role binding. Scope is uuid.Nil for a binding that covers the whole tenant, and otherwise
// the scope whose subtree it covers.
type Grant struct {
	Role  string
	Scope uuid.UUID
}

// Action is one entry in the log, with the person answerable for it.
type Action struct {
	ID              uuid.UUID
	Principal       uuid.UUID
	PrincipalKind   string
	PrincipalName   string
	Responsible     uuid.UUID
	ResponsibleName string
	Action          string
	Subject         string
	At              time.Time
}

// PrincipalFor returns the principal that a verified token speaks for: the one the tenant bound to the
// token's issuer and subject. Nothing else maps a token to a principal, so a subject the tenant never
// bound is ErrUnknownLogin, whatever else the token says (ADR-0093). The tenant must be the one this
// process serves, because PrincipalFor trusts it.
func PrincipalFor(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, subject string) (uuid.UUID, error) {
	if tenant == uuid.Nil || issuer == "" || subject == "" {
		return uuid.Nil, fmt.Errorf("%w: a tenant, an issuer, and a subject are required", ErrInvalidQuery)
	}
	var principal uuid.UUID
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT principal_id
			FROM identity.login
			WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`, tenant, issuer, subject).Scan(&principal)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrUnknownLogin
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("read the login: %w", err)
	}
	return principal, nil
}

// Get reads one principal and its role bindings in one transaction, so a binding removed before the
// call is not seen. Nothing caches them. The tenant must be the authenticated one, because Get trusts it.
func Get(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (Principal, error) {
	if tenant == uuid.Nil || id == uuid.Nil {
		return Principal{}, fmt.Errorf("%w: a tenant and a principal are required", ErrInvalidQuery)
	}
	var principal Principal
	var sponsor uuid.NullUUID
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT id, kind, name, sponsor_id
			FROM identity.principal
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, id).
			Scan(&principal.ID, &principal.Kind, &principal.Name, &sponsor)
		if err != nil {
			return err
		}
		principal.Grants, err = grants(ctx, tx, id)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrUnknownPrincipal
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read the principal: %w", err)
	}
	principal.Sponsor = sponsor.UUID
	return principal, nil
}

// grants reads the role bindings of one principal, at most maxGrants of them.
func grants(ctx context.Context, tx *sql.Tx, principal uuid.UUID) ([]Grant, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT role, scope_id
		FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
		LIMIT $2`, principal, maxGrants+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Grant
	for rows.Next() {
		var g Grant
		var scope uuid.NullUUID
		if err := rows.Scan(&g.Role, &scope); err != nil {
			return nil, err
		}
		g.Scope = scope.UUID
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > maxGrants {
		return nil, fmt.Errorf("the principal has more than %d role bindings", maxGrants)
	}
	return out, nil
}

// RecordAction logs one action and returns the person answerable for it, which the database decides
// from the principal. The tenant must be the authenticated one, because RecordAction trusts it.
func RecordAction(ctx context.Context, db *sql.DB, tenant, principal uuid.UUID, action, subject string) (uuid.UUID, error) {
	if tenant == uuid.Nil || principal == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: a tenant and a principal are required", ErrInvalidQuery)
	}
	var responsible uuid.UUID
	err := inTenant(ctx, db, tenant, false, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
			VALUES ($1, $2, $2, $3, $4)
			RETURNING responsible_id`, tenant, principal, action, subject).Scan(&responsible)
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("record the action: %w", err)
	}
	return responsible, nil
}

// Actions reads the newest entries of the log, newest first, with both names. The tenant must be the
// authenticated one, because Actions trusts it.
func Actions(ctx context.Context, db *sql.DB, tenant uuid.UUID, limit int) ([]Action, error) {
	if tenant == uuid.Nil || limit < 1 || limit > maxActions {
		return nil, fmt.Errorf("%w: a tenant and a limit from 1 to %d are required", ErrInvalidQuery, maxActions)
	}
	var actions []Action
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id, a.principal_id, p.kind, p.name, a.responsible_id, r.name, a.action, a.subject, lower(a.sys_period)
			FROM identity.action_log a
			JOIN identity.principal p ON p.tenant_id = a.tenant_id AND p.id = a.principal_id
			JOIN identity.principal r ON r.tenant_id = a.tenant_id AND r.id = a.responsible_id
			WHERE a.tenant_id = ipso.current_tenant()
			ORDER BY a.id DESC
			LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item Action
			if err := rows.Scan(&item.ID, &item.Principal, &item.PrincipalKind, &item.PrincipalName, &item.Responsible, &item.ResponsibleName, &item.Action, &item.Subject, &item.At); err != nil {
				return err
			}
			actions = append(actions, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read the action log: %w", err)
	}
	return actions, nil
}

// inTenant runs fn in one REPEATABLE READ transaction with ipso.tenant set for that transaction
// only, the way internal/registry does. A pooled connection does not keep the setting.
func inTenant(ctx context.Context, db *sql.DB, tenant uuid.UUID, readOnly bool, fn func(*sql.Tx) error) error {
	return inTenantAt(ctx, db, tenant, sql.LevelRepeatableRead, readOnly, fn)
}

// inTenantAt is inTenant at the isolation level given. A session writer asks for READ COMMITTED,
// because two sign-ins that delete the same expired row must not abort one of them.
func inTenantAt(ctx context.Context, db *sql.DB, tenant uuid.UUID, level sql.IsolationLevel, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: level, ReadOnly: readOnly})
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
