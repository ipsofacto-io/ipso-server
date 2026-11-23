package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErasePrincipalName replaces one person's stored name with the placeholder and closes that person's
// open logins (ADR-0156). The principal id and the role bindings stay. The action log records the
// actor and the person's id, and never the name. A person whose name is already erased is left as
// they are and writes no second entry. The tenant must be the authenticated one, because
// ErasePrincipalName trusts it.
func ErasePrincipalName(ctx context.Context, db *sql.DB, tenant, actor, principal uuid.UUID) error {
	if tenant == uuid.Nil || actor == uuid.Nil || principal == uuid.Nil {
		return fmt.Errorf("%w: a tenant, an actor and a principal are required", ErrInvalidQuery)
	}
	return inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var kind, name string
		var erased bool
		err := tx.QueryRowContext(ctx, `
			SELECT kind, name, name_erased
			FROM identity.principal
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, principal).Scan(&kind, &name, &erased)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownPrincipal
		}
		if err != nil {
			return err
		}
		if kind != KindHuman {
			return ErrNotPerson
		}
		if erased {
			return nil
		}
		if err := refuseLastAdmin(ctx, tx, []uuid.UUID{principal}); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE registry.waiver SET approver = $2
			WHERE tenant_id = ipso.current_tenant() AND approver_id = $1`, principal, ErasedName); err != nil {
			return fmt.Errorf("erase the waiver approver: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.invitation SET name = $2
			WHERE tenant_id = ipso.current_tenant() AND name = $1`, name, ErasedName); err != nil {
			return fmt.Errorf("erase the invitation name: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.scim_user SET user_name = $2
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, principal, ErasedUserName(principal)); err != nil {
			return fmt.Errorf("erase the scim filter key: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE identity.principal SET name = $2, name_erased = true
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, principal, ErasedName)
		if err != nil {
			return fmt.Errorf("erase the principal name: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrUnknownPrincipal
		}
		if err := closeLogin(ctx, tx, principal); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
			VALUES ($1, $2, $2, $3, $4)`, tenant, actor, ActionErasePrincipalName, principal.String()); err != nil {
			return fmt.Errorf("record the action: %w", err)
		}
		return nil
	})
}

// closeLogin ends the open sessions and logins of one person and marks a SCIM row inactive. It does
// not delete role bindings or owner-team membership, which stay as the history of the person.
func closeLogin(ctx context.Context, tx *sql.Tx, principal uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM identity.session
		WHERE tenant_id = ipso.current_tenant()
		  AND login_id IN (
		      SELECT id FROM identity.login
		      WHERE tenant_id = ipso.current_tenant() AND principal_id = $1)`, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE identity.login SET closed_at = clock_timestamp()
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1 AND closed_at IS NULL`, principal); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE identity.scim_user SET active = false
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, principal)
	return err
}
