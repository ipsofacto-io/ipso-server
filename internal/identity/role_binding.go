package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// The role bindings of ADR-0128. A binding is a row of identity.role_binding. The application role
// inserts and deletes one and never updates one (ADR-0108), so a change of role is a grant of the new
// binding and a revoke of the old one. These run in the transaction of the caller, which logs the grant
// and the revoke (WithAction). The tenant is the one that transaction set.

// ErrUnknownBinding is returned when this tenant has no role binding with that id.
var ErrUnknownBinding = errors.New("unknown role binding")

// ErrUnknownScope is returned when this tenant has no scope with that id.
var ErrUnknownScope = errors.New("unknown scope")

// ErrLastAdmin is returned when revoking the binding would leave the tenant with no admin.
var ErrLastAdmin = errors.New("last admin")

// RoleBinding is one role binding. ScopeID is uuid.Nil when the binding covers the whole tenant.
type RoleBinding struct {
	ID          uuid.UUID
	PrincipalID uuid.UUID
	Role        string
	ScopeID     uuid.UUID
}

// GrantRoleBinding inserts one binding and returns it. A principal or a scope this tenant does not
// have is ErrUnknownPrincipal or ErrUnknownScope. The database still refuses a role the principal's
// kind cannot hold, a scope on a role that is tenant-wide, an unknown role and a duplicate, and those
// errors are returned as the database raised them.
func GrantRoleBinding(ctx context.Context, tx *sql.Tx, principal uuid.UUID, role string, scope uuid.UUID) (RoleBinding, error) {
	if principal == uuid.Nil || role == "" {
		return RoleBinding{}, fmt.Errorf("%w: a principal and a role are required", ErrInvalidQuery)
	}
	var one int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM identity.principal
		WHERE tenant_id = ipso.current_tenant() AND id = $1`, principal).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleBinding{}, ErrUnknownPrincipal
	}
	if err != nil {
		return RoleBinding{}, fmt.Errorf("read the principal: %w", err)
	}
	var scopeArg any
	if scope != uuid.Nil {
		err = tx.QueryRowContext(ctx, `
			SELECT 1 FROM registry.scope
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, scope).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return RoleBinding{}, ErrUnknownScope
		}
		if err != nil {
			return RoleBinding{}, fmt.Errorf("read the scope: %w", err)
		}
		scopeArg = scope
	}
	binding := RoleBinding{PrincipalID: principal, Role: role, ScopeID: scope}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id)
		VALUES (ipso.current_tenant(), $1, $2, $3)
		RETURNING id`, principal, role, scopeArg).Scan(&binding.ID)
	if err != nil {
		return RoleBinding{}, fmt.Errorf("grant the role: %w", err)
	}
	return binding, nil
}

// RevokeRoleBinding deletes one binding and returns it. It takes an advisory lock on the tenant first,
// so two revokes of the two remaining admins cannot both commit. Revoking the only admin is ErrLastAdmin
// and deletes nothing. An id this tenant does not have is ErrUnknownBinding.
func RevokeRoleBinding(ctx context.Context, tx *sql.Tx, id uuid.UUID) (RoleBinding, error) {
	if id == uuid.Nil {
		return RoleBinding{}, fmt.Errorf("%w: a binding is required", ErrInvalidQuery)
	}
	admins, err := lockTenantAdmins(ctx, tx)
	if err != nil {
		return RoleBinding{}, err
	}
	var binding RoleBinding
	var scope uuid.NullUUID
	err = tx.QueryRowContext(ctx, `
		SELECT id, principal_id, role, scope_id
		FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND id = $1`, id).Scan(&binding.ID, &binding.PrincipalID, &binding.Role, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleBinding{}, ErrUnknownBinding
	}
	if err != nil {
		return RoleBinding{}, fmt.Errorf("read the role binding: %w", err)
	}
	binding.ScopeID = scope.UUID
	if binding.Role == RoleAdmin && !scope.Valid && admins < 2 {
		return RoleBinding{}, ErrLastAdmin
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND id = $1`, id)
	if err != nil {
		return RoleBinding{}, fmt.Errorf("revoke the role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return RoleBinding{}, fmt.Errorf("revoke the role: %w", err)
	}
	if n == 0 {
		return RoleBinding{}, ErrUnknownBinding
	}
	return binding, nil
}

// lockTenantAdmins serializes revokes of this tenant and returns how many tenant-wide admins there are.
// The application role may insert and delete a binding and may not update one, so SELECT FOR UPDATE is
// refused. The advisory lock is held until the transaction ends, and every revoke takes it, so two
// revokes cannot both pass the count and they cannot deadlock on each other. The seed is 147, so the
// key is not one of the other tenant locks (the action log uses 68).
func lockTenantAdmins(ctx context.Context, tx *sql.Tx) (int, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(ipso.current_tenant()::text, 147))`); err != nil {
		return 0, fmt.Errorf("lock the admins: %w", err)
	}
	var n int
	err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND role = 'admin' AND scope_id IS NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("lock the admins: %w", err)
	}
	return n, nil
}

// ListRoleBindings reads one page of the tenant's role bindings, by id from the highest. A nil before
// starts at the top. The tenant must be the authenticated one, because ListRoleBindings trusts it.
func ListRoleBindings(ctx context.Context, db *sql.DB, tenant, before uuid.UUID, limit int) ([]RoleBinding, error) {
	if tenant == uuid.Nil || limit < 1 || limit > registry.MaxPage {
		return nil, fmt.Errorf("%w: a tenant and a limit from 1 to %d are required", ErrInvalidQuery, registry.MaxPage)
	}
	var bound any
	if before != uuid.Nil {
		bound = before
	}
	var out []RoleBinding
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, principal_id, role, scope_id
			FROM identity.role_binding
			WHERE tenant_id = ipso.current_tenant()
			  AND ($1::uuid IS NULL OR id < $1::uuid)
			ORDER BY id DESC
			LIMIT $2`, bound, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var binding RoleBinding
			var scope uuid.NullUUID
			if err := rows.Scan(&binding.ID, &binding.PrincipalID, &binding.Role, &scope); err != nil {
				return err
			}
			binding.ScopeID = scope.UUID
			out = append(out, binding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read the role bindings: %w", err)
	}
	return out, nil
}
