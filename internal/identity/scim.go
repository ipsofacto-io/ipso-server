package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// SCIM is the enterprise exception that creates a person, assigns IdP roles, and records owner
// teams (ADR-0131, ADR-0132). A SAML sign-in still does not. These functions run as the application
// role in the process tenant.

// ErrSCIMConflict is returned when user_name or external_id is already in use.
var ErrSCIMConflict = errors.New("scim conflict")

// SCIMUser is one provisioned person. ID is the principal id.
type SCIMUser struct {
	ID         uuid.UUID
	ExternalID string
	UserName   string
	Name       string
	Active     bool
}

// SCIMGroup is one group. Ref is fixed at create and is what a group-role row matches.
type SCIMGroup struct {
	ID  uuid.UUID
	Ref string
}

// IDPGroupOwner is one mapping from a group ref to an owner team.
type IDPGroupOwner struct {
	ID       uuid.UUID
	GroupRef string
	OwnerRef string
}

// IDPGroupRole is one mapping from a group ref to a role.
type IDPGroupRole struct {
	ID       uuid.UUID
	GroupRef string
	Role     string
	ScopeID  uuid.UUID
}

const maxSCIMMembers = 1000

var absentTokenHash = sha256.Sum256([]byte("ipso-scim-absent-token"))

// ProvisionSCIMUser creates a human principal and a login for issuer and externalID, or reopens
// that login when it already exists. created is true when a principal was inserted or a closed
// login was opened. The login subject is externalID.
func ProvisionSCIMUser(ctx context.Context, db *sql.DB, tenant uuid.UUID, issuer, externalID, userName, name string) (SCIMUser, bool, error) {
	if err := validSCIMIdentity(issuer, externalID, userName, name); err != nil {
		return SCIMUser{}, false, err
	}
	var user SCIMUser
	var created bool
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var principal uuid.UUID
		var closed bool
		err := tx.QueryRowContext(ctx, `
			SELECT principal_id, closed_at IS NOT NULL
			FROM identity.login
			WHERE tenant_id = ipso.current_tenant() AND issuer = $1 AND subject = $2`,
			issuer, externalID).Scan(&principal, &closed)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if err := tx.QueryRowContext(ctx, `
				INSERT INTO identity.principal (tenant_id, kind, name)
				VALUES (ipso.current_tenant(), 'human', $1)
				RETURNING id`, name).Scan(&principal); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.login (tenant_id, principal_id, issuer, subject)
				VALUES (ipso.current_tenant(), $1, $2, $3)`, principal, issuer, externalID); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		default:
			if _, err := tx.ExecContext(ctx, `
				UPDATE identity.login SET closed_at = NULL
				WHERE tenant_id = ipso.current_tenant() AND principal_id = $1 AND closed_at IS NOT NULL`,
				principal); err != nil {
				return err
			}
			created = closed
		}
		var erased bool
		if err := tx.QueryRowContext(ctx, `
			SELECT name_erased FROM identity.principal
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, principal).Scan(&erased); err != nil {
			return err
		}
		if erased {
			// The filter key of a new row is the placeholder. An existing row keeps the one erasure wrote.
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name, active)
				VALUES (ipso.current_tenant(), $1, $2, $3, true)
				ON CONFLICT (tenant_id, principal_id) DO UPDATE SET active = true`,
				principal, externalID, ErasedUserName(principal)); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
				UPDATE identity.principal SET name = $1
				WHERE tenant_id = ipso.current_tenant() AND id = $2`, name, principal); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name, active)
				VALUES (ipso.current_tenant(), $1, $2, $3, true)
				ON CONFLICT (tenant_id, principal_id) DO UPDATE
				SET user_name = EXCLUDED.user_name, active = true`,
				principal, externalID, userName); err != nil {
				return err
			}
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT p.name, u.user_name
			FROM identity.scim_user u
			JOIN identity.principal p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
			WHERE u.tenant_id = ipso.current_tenant() AND u.principal_id = $1`, principal).Scan(&name, &userName); err != nil {
			return err
		}
		user = SCIMUser{ID: principal, ExternalID: externalID, UserName: userName, Name: name, Active: true}
		if !created {
			return nil
		}
		return insertAction(ctx, tx, principal, "scim.provision", principal.String())
	})
	if err != nil {
		return SCIMUser{}, false, scimErr(err)
	}
	return user, created, nil
}

// SetSCIMActive closes or reopens the login of one SCIM user. Closing deletes every role binding
// and every session of that person. The last tenant-wide admin cannot be closed.
func SetSCIMActive(ctx context.Context, db *sql.DB, tenant uuid.UUID, externalID string, active bool) error {
	if tenant == uuid.Nil || !validText(externalID, 255) {
		return fmt.Errorf("%w: an external id is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		user, err := scimUser(ctx, tx, `external_id = $1`, externalID)
		if err != nil {
			return err
		}
		if user.Active == active {
			return nil
		}
		if !active {
			if err := refuseLastAdmin(ctx, tx, []uuid.UUID{user.ID}); err != nil {
				return err
			}
			if err := closePrincipal(ctx, tx, user.ID); err != nil {
				return err
			}
			return insertAction(ctx, tx, user.ID, "scim.deprovision", user.ID.String())
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.login SET closed_at = NULL
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, user.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.scim_user SET active = true
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, user.ID); err != nil {
			return err
		}
		return insertAction(ctx, tx, user.ID, "scim.provision", user.ID.String())
	})
	if err != nil {
		return scimErr(err)
	}
	return nil
}

// UpdateSCIMUserName changes the filter key. It is not a login subject.
func UpdateSCIMUserName(ctx context.Context, db *sql.DB, tenant uuid.UUID, externalID, userName string) error {
	if tenant == uuid.Nil || !validText(externalID, 255) || !validText(userName, 200) {
		return fmt.Errorf("%w: a user name is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		erased, err := scimNameErased(ctx, tx, externalID)
		if err != nil || erased {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE identity.scim_user SET user_name = $2
			WHERE tenant_id = ipso.current_tenant() AND external_id = $1`, externalID, userName)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUnknownPrincipal
		}
		return nil
	})
	return scimErr(err)
}

// SetSCIMName sets the principal name. It does not change the login.
func SetSCIMName(ctx context.Context, db *sql.DB, tenant uuid.UUID, externalID, name string) error {
	if tenant == uuid.Nil || !validText(externalID, 255) || !validText(name, 200) {
		return fmt.Errorf("%w: a name is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		erased, err := scimNameErased(ctx, tx, externalID)
		if err != nil || erased {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE identity.principal AS p SET name = $2
			FROM identity.scim_user AS u
			WHERE u.tenant_id = ipso.current_tenant() AND u.external_id = $1
			  AND p.tenant_id = u.tenant_id AND p.id = u.principal_id`, externalID, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUnknownPrincipal
		}
		return nil
	})
	return scimErr(err)
}

// ReplaceSCIMUser applies a new filter key, a new principal name, and an active flag in one
// transaction. An empty userName or name is left as it is. A nil active flag is left as it is.
// Deprovision of the last tenant-wide admin writes nothing.
func ReplaceSCIMUser(ctx context.Context, db *sql.DB, tenant uuid.UUID, externalID, userName, name string, active *bool) error {
	if tenant == uuid.Nil || !validText(externalID, 255) {
		return fmt.Errorf("%w: an external id is required", ErrInvalidQuery)
	}
	if userName != "" && !validText(userName, 200) || name != "" && !validText(name, 200) {
		return fmt.Errorf("%w: a user name and a name must be usable", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		user, err := scimUser(ctx, tx, `external_id = $1`, externalID)
		if err != nil {
			return err
		}
		if active != nil && !*active && user.Active {
			if err := refuseLastAdmin(ctx, tx, []uuid.UUID{user.ID}); err != nil {
				return err
			}
		}
		erased, err := scimNameErased(ctx, tx, externalID)
		if err != nil {
			return err
		}
		if userName != "" && userName != user.UserName && !erased {
			if _, err := tx.ExecContext(ctx, `
				UPDATE identity.scim_user SET user_name = $2
				WHERE tenant_id = ipso.current_tenant() AND external_id = $1`, externalID, userName); err != nil {
				return err
			}
		}
		if name != "" && name != user.Name && !erased {
			if _, err := tx.ExecContext(ctx, `
				UPDATE identity.principal SET name = $1
				WHERE tenant_id = ipso.current_tenant() AND id = $2`, name, user.ID); err != nil {
				return err
			}
		}
		if active == nil || *active == user.Active {
			return nil
		}
		if !*active {
			if err := closePrincipal(ctx, tx, user.ID); err != nil {
				return err
			}
			return insertAction(ctx, tx, user.ID, "scim.deprovision", user.ID.String())
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.login SET closed_at = NULL
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, user.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE identity.scim_user SET active = true
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, user.ID); err != nil {
			return err
		}
		return insertAction(ctx, tx, user.ID, "scim.provision", user.ID.String())
	})
	return scimErr(err)
}

// SCIMUserByID reads one user.
func SCIMUserByID(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (SCIMUser, error) {
	return oneSCIMUser(ctx, db, tenant, `u.principal_id = $1`, id)
}

// SCIMUserByExternalID reads one user.
func SCIMUserByExternalID(ctx context.Context, db *sql.DB, tenant uuid.UUID, externalID string) (SCIMUser, error) {
	return oneSCIMUser(ctx, db, tenant, `u.external_id = $1`, externalID)
}

// SCIMUserByUserName reads one user by the filter key.
func SCIMUserByUserName(ctx context.Context, db *sql.DB, tenant uuid.UUID, userName string) (SCIMUser, error) {
	return oneSCIMUser(ctx, db, tenant, `u.user_name = $1`, userName)
}

func oneSCIMUser(ctx context.Context, db *sql.DB, tenant uuid.UUID, where string, arg any) (SCIMUser, error) {
	if tenant == uuid.Nil {
		return SCIMUser{}, fmt.Errorf("%w: a tenant is required", ErrInvalidQuery)
	}
	var user SCIMUser
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		found, err := scimUser(ctx, tx, where, arg)
		user = found
		return err
	})
	if err != nil {
		return SCIMUser{}, scimErr(err)
	}
	return user, nil
}

// scimNameErased reports whether the person of this SCIM external id has had their name erased.
// A missing row is ErrUnknownPrincipal.
func scimNameErased(ctx context.Context, tx *sql.Tx, externalID string) (bool, error) {
	var erased bool
	err := tx.QueryRowContext(ctx, `
		SELECT p.name_erased
		FROM identity.scim_user u
		JOIN identity.principal p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = ipso.current_tenant() AND u.external_id = $1`, externalID).Scan(&erased)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrUnknownPrincipal
	}
	return erased, err
}

func scimUser(ctx context.Context, tx *sql.Tx, where string, arg any) (SCIMUser, error) {
	var user SCIMUser
	err := tx.QueryRowContext(ctx, `
		SELECT u.principal_id, u.external_id, u.user_name, p.name, u.active
		FROM identity.scim_user u
		JOIN identity.principal p ON p.tenant_id = u.tenant_id AND p.id = u.principal_id
		WHERE u.tenant_id = ipso.current_tenant() AND `+where, arg).Scan(
		&user.ID, &user.ExternalID, &user.UserName, &user.Name, &user.Active)
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMUser{}, ErrUnknownPrincipal
	}
	return user, err
}

// CreateSCIMGroup inserts a group. ref is stored as given and is not changed later.
func CreateSCIMGroup(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref string) (SCIMGroup, error) {
	if tenant == uuid.Nil || !validText(ref, 200) {
		return SCIMGroup{}, fmt.Errorf("%w: a group ref is required", ErrInvalidQuery)
	}
	var group SCIMGroup
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO identity.scim_group (tenant_id, group_ref)
			VALUES (ipso.current_tenant(), $1)
			RETURNING id, group_ref`, ref).Scan(&group.ID, &group.Ref)
	})
	if err != nil {
		return SCIMGroup{}, scimErr(err)
	}
	return group, nil
}

// SCIMGroupByID reads one group.
func SCIMGroupByID(ctx context.Context, db *sql.DB, tenant, id uuid.UUID) (SCIMGroup, error) {
	if tenant == uuid.Nil || id == uuid.Nil {
		return SCIMGroup{}, fmt.Errorf("%w: a group is required", ErrInvalidQuery)
	}
	var group SCIMGroup
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT id, group_ref FROM identity.scim_group
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, id).Scan(&group.ID, &group.Ref)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownPrincipal
		}
		return err
	})
	if err != nil {
		return SCIMGroup{}, scimErr(err)
	}
	return group, nil
}

// SCIMGroupByRef returns the group whose ref was fixed at create.
func SCIMGroupByRef(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref string) (SCIMGroup, error) {
	if tenant == uuid.Nil || !validText(ref, 200) {
		return SCIMGroup{}, fmt.Errorf("%w: a group ref is required", ErrInvalidQuery)
	}
	var group SCIMGroup
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT id, group_ref FROM identity.scim_group
			WHERE tenant_id = ipso.current_tenant() AND group_ref = $1`, ref).Scan(&group.ID, &group.Ref)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownPrincipal
		}
		return err
	})
	if err != nil {
		return SCIMGroup{}, scimErr(err)
	}
	return group, nil
}

// SCIMGroupMembers returns the people in one group.
func SCIMGroupMembers(ctx context.Context, db *sql.DB, tenant, groupID uuid.UUID) ([]uuid.UUID, error) {
	if tenant == uuid.Nil || groupID == uuid.Nil {
		return nil, fmt.Errorf("%w: a group is required", ErrInvalidQuery)
	}
	var ids []uuid.UUID
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		var err error
		ids, err = memberIDs(ctx, tx, groupID)
		return err
	})
	if err != nil {
		return nil, scimErr(err)
	}
	return ids, nil
}

// ReplaceSCIMGroupMembers replaces the members of one group and recomputes IdP role bindings and
// owner teams for everyone who was a member or is one now. Hand bindings and hand owner teams stay.
// The last tenant-wide admin is not removed, and then nothing is written.
func ReplaceSCIMGroupMembers(ctx context.Context, db *sql.DB, tenant, groupID uuid.UUID, members []uuid.UUID) error {
	if tenant == uuid.Nil || groupID == uuid.Nil || len(members) > maxSCIMMembers {
		return fmt.Errorf("%w: a group and at most %d members are required", ErrInvalidQuery, maxSCIMMembers)
	}
	seen := map[uuid.UUID]struct{}{}
	for _, id := range members {
		if id == uuid.Nil {
			return fmt.Errorf("%w: a member is required", ErrInvalidQuery)
		}
		seen[id] = struct{}{}
	}
	unique := make([]uuid.UUID, 0, len(seen))
	for id := range seen {
		unique = append(unique, id)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var ref string
		err := tx.QueryRowContext(ctx, `
			SELECT group_ref FROM identity.scim_group
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, groupID).Scan(&ref)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownPrincipal
		}
		if err != nil {
			return err
		}
		if len(unique) > 0 {
			var humans int
			if err := tx.QueryRowContext(ctx, `
				SELECT count(*) FROM identity.principal
				WHERE tenant_id = ipso.current_tenant() AND id = ANY($1::uuid[]) AND kind = 'human'`,
				unique).Scan(&humans); err != nil {
				return err
			}
			if humans != len(unique) {
				return fmt.Errorf("%w: a group member must be a person", ErrInvalidQuery)
			}
		}
		old, err := memberIDs(ctx, tx, groupID)
		if err != nil {
			return err
		}
		affected := map[uuid.UUID]struct{}{}
		for _, id := range old {
			affected[id] = struct{}{}
		}
		for _, id := range unique {
			affected[id] = struct{}{}
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM identity.scim_membership
			WHERE tenant_id = ipso.current_tenant() AND group_id = $1`, groupID); err != nil {
			return err
		}
		for _, id := range unique {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.scim_membership (tenant_id, group_id, principal_id)
				VALUES (ipso.current_tenant(), $1, $2)`, groupID, id); err != nil {
				return err
			}
		}
		people := make([]uuid.UUID, 0, len(affected))
		for id := range affected {
			people = append(people, id)
		}
		if err := syncIDPRoles(ctx, tx, people); err != nil {
			return err
		}
		if err := syncIDPOwners(ctx, tx, people); err != nil {
			return err
		}
		for _, id := range people {
			if err := insertAction(ctx, tx, id, "scim.groups", id.String()); err != nil {
				return err
			}
		}
		return nil
	})
	return scimErr(err)
}

// DeleteSCIMGroup removes a group, its membership, and recomputes the people who were in it.
func DeleteSCIMGroup(ctx context.Context, db *sql.DB, tenant, groupID uuid.UUID) error {
	if tenant == uuid.Nil || groupID == uuid.Nil {
		return fmt.Errorf("%w: a group is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		old, err := memberIDs(ctx, tx, groupID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			DELETE FROM identity.scim_membership
			WHERE tenant_id = ipso.current_tenant() AND group_id = $1`, groupID)
		if err != nil {
			return err
		}
		_ = res
		res, err = tx.ExecContext(ctx, `
			DELETE FROM identity.scim_group
			WHERE tenant_id = ipso.current_tenant() AND id = $1`, groupID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUnknownPrincipal
		}
		if err := syncIDPRoles(ctx, tx, old); err != nil {
			return err
		}
		if err := syncIDPOwners(ctx, tx, old); err != nil {
			return err
		}
		for _, id := range old {
			if err := insertAction(ctx, tx, id, "scim.groups", id.String()); err != nil {
				return err
			}
		}
		return nil
	})
	return scimErr(err)
}

// PutSCIMToken stores the SHA-256 of a token. The plaintext is not stored. actor is the admin.
func PutSCIMToken(ctx context.Context, db *sql.DB, tenant, actor uuid.UUID, hash []byte) error {
	if tenant == uuid.Nil || actor == uuid.Nil || len(hash) != 32 {
		return fmt.Errorf("%w: a token hash is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM identity.scim_token WHERE tenant_id = ipso.current_tenant()`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO identity.scim_token (tenant_id, token_sha256)
			VALUES (ipso.current_tenant(), $1)`, hash); err != nil {
			return err
		}
		return insertAction(ctx, tx, actor, "scim.token", "rotated")
	})
	return scimErr(err)
}

// SCIMTokenOK reports whether token hashes to the stored bearer. A missing row still runs a compare.
func SCIMTokenOK(ctx context.Context, db *sql.DB, tenant uuid.UUID, token []byte) (bool, error) {
	if tenant == uuid.Nil || len(token) == 0 {
		return false, nil
	}
	stored := absentTokenHash[:]
	found := false
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		var hash []byte
		err := tx.QueryRowContext(ctx, `
			SELECT token_sha256 FROM identity.scim_token
			WHERE tenant_id = ipso.current_tenant()`).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		stored = hash
		found = true
		return nil
	})
	sum := sha256.Sum256(token)
	match := subtle.ConstantTimeCompare(stored, sum[:]) == 1
	if err != nil {
		return false, fmt.Errorf("read the scim token: %w", err)
	}
	return found && match, nil
}

// PutIDPGroupRole inserts a mapping and recomputes the members of that group.
func PutIDPGroupRole(ctx context.Context, db *sql.DB, tenant, actor uuid.UUID, groupRef, role string, scope uuid.UUID) (IDPGroupRole, error) {
	if tenant == uuid.Nil || actor == uuid.Nil || !validText(groupRef, 200) || !humanRole(role) {
		return IDPGroupRole{}, fmt.Errorf("%w: a group and a role are required", ErrInvalidQuery)
	}
	if scope != uuid.Nil && role != RoleContributor && role != RoleDecisionOwner && role != RoleApprover {
		return IDPGroupRole{}, fmt.Errorf("%w: this role is not scoped", ErrInvalidQuery)
	}
	var row IDPGroupRole
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var scopeArg any
		if scope != uuid.Nil {
			scopeArg = scope
		}
		var scope uuid.NullUUID
		err := tx.QueryRowContext(ctx, `
			INSERT INTO identity.idp_group_role (tenant_id, group_ref, role, scope_id)
			VALUES (ipso.current_tenant(), $1, $2, $3)
			RETURNING id, group_ref, role, scope_id`, groupRef, role, scopeArg).Scan(
			&row.ID, &row.GroupRef, &row.Role, &scope)
		row.ScopeID = scope.UUID
		if err != nil {
			return err
		}
		people, err := membersOfRef(ctx, tx, groupRef)
		if err != nil {
			return err
		}
		if err := syncIDPRoles(ctx, tx, people); err != nil {
			return err
		}
		for _, id := range people {
			if err := insertAction(ctx, tx, id, "scim.group_role", id.String()); err != nil {
				return err
			}
		}
		return insertAction(ctx, tx, actor, "scim.group_role", row.ID.String())
	})
	if err != nil {
		return IDPGroupRole{}, scimErr(err)
	}
	return row, nil
}

// ListIDPGroupRoles returns every mapping in the tenant.
func ListIDPGroupRoles(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]IDPGroupRole, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: a tenant is required", ErrInvalidQuery)
	}
	var rowsOut []IDPGroupRole
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, group_ref, role, scope_id
			FROM identity.idp_group_role
			WHERE tenant_id = ipso.current_tenant()
			ORDER BY group_ref, role, scope_id`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var row IDPGroupRole
			var scope uuid.NullUUID
			if err := rows.Scan(&row.ID, &row.GroupRef, &row.Role, &scope); err != nil {
				return err
			}
			row.ScopeID = scope.UUID
			rowsOut = append(rowsOut, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, scimErr(err)
	}
	return rowsOut, nil
}

// DeleteIDPGroupRole removes one mapping and recomputes the members of that group.
func DeleteIDPGroupRole(ctx context.Context, db *sql.DB, tenant, actor, id uuid.UUID) error {
	if tenant == uuid.Nil || actor == uuid.Nil || id == uuid.Nil {
		return fmt.Errorf("%w: a mapping is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var ref string
		err := tx.QueryRowContext(ctx, `
			DELETE FROM identity.idp_group_role
			WHERE tenant_id = ipso.current_tenant() AND id = $1
			RETURNING group_ref`, id).Scan(&ref)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownBinding
		}
		if err != nil {
			return err
		}
		people, err := membersOfRef(ctx, tx, ref)
		if err != nil {
			return err
		}
		if err := syncIDPRoles(ctx, tx, people); err != nil {
			return err
		}
		for _, principal := range people {
			if err := insertAction(ctx, tx, principal, "scim.group_role", principal.String()); err != nil {
				return err
			}
		}
		return insertAction(ctx, tx, actor, "scim.group_role", id.String())
	})
	return scimErr(err)
}

// PutIDPGroupOwner inserts a mapping and recomputes the members of that group.
func PutIDPGroupOwner(ctx context.Context, db *sql.DB, tenant, actor uuid.UUID, groupRef, ownerRef string) (IDPGroupOwner, error) {
	if tenant == uuid.Nil || actor == uuid.Nil || !validText(groupRef, 200) || !ownerTeamOK(ownerRef) {
		return IDPGroupOwner{}, fmt.Errorf("%w: a group and an owner team are required", ErrInvalidQuery)
	}
	var row IDPGroupOwner
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO identity.idp_group_owner (tenant_id, group_ref, owner_ref)
			VALUES (ipso.current_tenant(), $1, $2)
			RETURNING id, group_ref, owner_ref`, groupRef, ownerRef).Scan(
			&row.ID, &row.GroupRef, &row.OwnerRef)
		if err != nil {
			return err
		}
		people, err := membersOfRef(ctx, tx, groupRef)
		if err != nil {
			return err
		}
		if err := syncIDPOwners(ctx, tx, people); err != nil {
			return err
		}
		for _, id := range people {
			if err := insertAction(ctx, tx, id, "scim.group_owner", id.String()); err != nil {
				return err
			}
		}
		return insertAction(ctx, tx, actor, "scim.group_owner", row.ID.String())
	})
	if err != nil {
		return IDPGroupOwner{}, scimErr(err)
	}
	return row, nil
}

// ListIDPGroupOwners returns every owner-team mapping in the tenant.
func ListIDPGroupOwners(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]IDPGroupOwner, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: a tenant is required", ErrInvalidQuery)
	}
	var rowsOut []IDPGroupOwner
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, group_ref, owner_ref
			FROM identity.idp_group_owner
			WHERE tenant_id = ipso.current_tenant()
			ORDER BY group_ref, owner_ref`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var row IDPGroupOwner
			if err := rows.Scan(&row.ID, &row.GroupRef, &row.OwnerRef); err != nil {
				return err
			}
			rowsOut = append(rowsOut, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, scimErr(err)
	}
	return rowsOut, nil
}

// DeleteIDPGroupOwner removes one mapping and recomputes the members of that group.
func DeleteIDPGroupOwner(ctx context.Context, db *sql.DB, tenant, actor, id uuid.UUID) error {
	if tenant == uuid.Nil || actor == uuid.Nil || id == uuid.Nil {
		return fmt.Errorf("%w: a mapping is required", ErrInvalidQuery)
	}
	err := inTenantAt(ctx, db, tenant, sql.LevelReadCommitted, false, func(tx *sql.Tx) error {
		var ref string
		err := tx.QueryRowContext(ctx, `
			DELETE FROM identity.idp_group_owner
			WHERE tenant_id = ipso.current_tenant() AND id = $1
			RETURNING group_ref`, id).Scan(&ref)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownBinding
		}
		if err != nil {
			return err
		}
		people, err := membersOfRef(ctx, tx, ref)
		if err != nil {
			return err
		}
		if err := syncIDPOwners(ctx, tx, people); err != nil {
			return err
		}
		for _, principal := range people {
			if err := insertAction(ctx, tx, principal, "scim.group_owner", principal.String()); err != nil {
				return err
			}
		}
		return insertAction(ctx, tx, actor, "scim.group_owner", id.String())
	})
	return scimErr(err)
}

func closePrincipal(ctx context.Context, tx *sql.Tx, principal uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM identity.session
		WHERE tenant_id = ipso.current_tenant()
		  AND login_id IN (
		      SELECT id FROM identity.login
		      WHERE tenant_id = ipso.current_tenant() AND principal_id = $1)`, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM identity.principal_owner
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1`, principal); err != nil {
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

func refuseLastAdmin(ctx context.Context, tx *sql.Tx, losing []uuid.UUID) error {
	if len(losing) == 0 {
		return nil
	}
	if _, err := lockTenantAdmins(ctx, tx); err != nil {
		return err
	}
	holders := map[uuid.UUID]struct{}{}
	rows, err := tx.QueryContext(ctx, `
		SELECT principal_id FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND role = $1 AND scope_id IS NULL`, RoleAdmin)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		holders[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range losing {
		delete(holders, id)
	}
	// Losing a binding matters only when the person is an admin today. A person who is not an
	// admin does not shrink the set, so an empty result with no admin in losing is fine.
	lostAdmin := false
	for _, id := range losing {
		var n int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FROM identity.role_binding
			WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
			  AND role = $2 AND scope_id IS NULL`, id, RoleAdmin).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			lostAdmin = true
		}
	}
	if lostAdmin && len(holders) == 0 {
		return ErrLastAdmin
	}
	return nil
}

type grantKey struct {
	role  string
	scope uuid.UUID
}

func syncIDPRoles(ctx context.Context, tx *sql.Tx, people []uuid.UUID) error {
	if len(people) == 0 {
		return nil
	}
	losing := []uuid.UUID{}
	desired := map[uuid.UUID]map[grantKey]struct{}{}
	for _, id := range people {
		want, err := desiredRoles(ctx, tx, id)
		if err != nil {
			return err
		}
		desired[id] = want
		current, err := idpRoles(ctx, tx, id)
		if err != nil {
			return err
		}
		for key := range current {
			if _, keep := want[key]; !keep && key.role == RoleAdmin && key.scope == uuid.Nil {
				losing = append(losing, id)
				break
			}
		}
	}
	if err := refuseLastAdmin(ctx, tx, losing); err != nil {
		return err
	}
	for _, id := range people {
		current, err := idpRoles(ctx, tx, id)
		if err != nil {
			return err
		}
		want := desired[id]
		for key := range current {
			if _, keep := want[key]; keep {
				continue
			}
			var scope any
			if key.scope != uuid.Nil {
				scope = key.scope
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM identity.role_binding
				WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
				  AND role = $2 AND scope_id IS NOT DISTINCT FROM $3 AND source = 'idp'`,
				id, key.role, scope); err != nil {
				return err
			}
		}
		for key := range want {
			if _, have := current[key]; have {
				continue
			}
			var scope any
			if key.scope != uuid.Nil {
				scope = key.scope
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id, source)
				SELECT ipso.current_tenant(), $1, $2, $3, 'idp'
				WHERE NOT EXISTS (
				    SELECT 1 FROM identity.role_binding
				    WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
				      AND role = $2 AND scope_id IS NOT DISTINCT FROM $3)`,
				id, key.role, scope); err != nil {
				return err
			}
		}
	}
	return nil
}

func desiredRoles(ctx context.Context, tx *sql.Tx, principal uuid.UUID) (map[grantKey]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.role, r.scope_id
		FROM identity.scim_membership m
		JOIN identity.scim_group g ON g.tenant_id = m.tenant_id AND g.id = m.group_id
		JOIN identity.idp_group_role r ON r.tenant_id = m.tenant_id AND r.group_ref = g.group_ref
		WHERE m.tenant_id = ipso.current_tenant() AND m.principal_id = $1`, principal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[grantKey]struct{}{}
	for rows.Next() {
		var key grantKey
		var scope uuid.NullUUID
		if err := rows.Scan(&key.role, &scope); err != nil {
			return nil, err
		}
		key.scope = scope.UUID
		out[key] = struct{}{}
	}
	return out, rows.Err()
}

func idpRoles(ctx context.Context, tx *sql.Tx, principal uuid.UUID) (map[grantKey]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT role, scope_id FROM identity.role_binding
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1 AND source = 'idp'`, principal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[grantKey]struct{}{}
	for rows.Next() {
		var key grantKey
		var scope uuid.NullUUID
		if err := rows.Scan(&key.role, &scope); err != nil {
			return nil, err
		}
		key.scope = scope.UUID
		out[key] = struct{}{}
	}
	return out, rows.Err()
}

func syncIDPOwners(ctx context.Context, tx *sql.Tx, people []uuid.UUID) error {
	if len(people) == 0 {
		return nil
	}
	for _, id := range people {
		want, err := desiredOwners(ctx, tx, id)
		if err != nil {
			return err
		}
		current, err := idpOwners(ctx, tx, id)
		if err != nil {
			return err
		}
		for team := range current {
			if _, keep := want[team]; keep {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM identity.principal_owner
				WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
				  AND owner_ref = $2 AND source = 'idp'`, id, team); err != nil {
				return err
			}
		}
		for team := range want {
			if _, have := current[team]; have {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO identity.principal_owner (tenant_id, principal_id, owner_ref, source)
				SELECT ipso.current_tenant(), $1, $2, 'idp'
				WHERE NOT EXISTS (
				    SELECT 1 FROM identity.principal_owner
				    WHERE tenant_id = ipso.current_tenant() AND principal_id = $1
				      AND owner_ref = $2)`, id, team); err != nil {
				return err
			}
		}
	}
	return nil
}

func desiredOwners(ctx context.Context, tx *sql.Tx, principal uuid.UUID) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.owner_ref
		FROM identity.scim_membership m
		JOIN identity.scim_group g ON g.tenant_id = m.tenant_id AND g.id = m.group_id
		JOIN identity.idp_group_owner r ON r.tenant_id = m.tenant_id AND r.group_ref = g.group_ref
		WHERE m.tenant_id = ipso.current_tenant() AND m.principal_id = $1`, principal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]struct{}{}
	for rows.Next() {
		var team string
		if err := rows.Scan(&team); err != nil {
			return nil, err
		}
		out[team] = struct{}{}
	}
	return out, rows.Err()
}

func idpOwners(ctx context.Context, tx *sql.Tx, principal uuid.UUID) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT owner_ref FROM identity.principal_owner
		WHERE tenant_id = ipso.current_tenant() AND principal_id = $1 AND source = 'idp'`, principal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]struct{}{}
	for rows.Next() {
		var team string
		if err := rows.Scan(&team); err != nil {
			return nil, err
		}
		out[team] = struct{}{}
	}
	return out, rows.Err()
}

func memberIDs(ctx context.Context, tx *sql.Tx, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT principal_id FROM identity.scim_membership
		WHERE tenant_id = ipso.current_tenant() AND group_id = $1`, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func membersOfRef(ctx context.Context, tx *sql.Tx, ref string) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT m.principal_id
		FROM identity.scim_membership m
		JOIN identity.scim_group g ON g.tenant_id = m.tenant_id AND g.id = m.group_id
		WHERE m.tenant_id = ipso.current_tenant() AND g.group_ref = $1`, ref)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func insertAction(ctx context.Context, tx *sql.Tx, principal uuid.UUID, action, subject string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO identity.action_log (tenant_id, principal_id, action, subject)
		VALUES (ipso.current_tenant(), $1, $2, $3)`, principal, action, subject)
	return err
}

func validSCIMIdentity(issuer, externalID, userName, name string) error {
	if !validText(issuer, 2048) || !validText(externalID, 255) || !validText(userName, 200) || !validText(name, 200) {
		return fmt.Errorf("%w: an issuer, an external id, a user name, and a name are required", ErrInvalidQuery)
	}
	return nil
}

var ownerTeam = regexp.MustCompile(`^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

func ownerTeamOK(value string) bool {
	return validText(value, 200) && ownerTeam.MatchString(value)
}

func validText(value string, max int) bool {
	if strings.TrimSpace(value) != value || value == "" || len([]rune(value)) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func humanRole(role string) bool {
	switch role {
	case RoleViewer, RoleContributor, RoleDecisionOwner, RoleApprover, RoleAdmin, RoleAuditor:
		return true
	default:
		return false
	}
}

func scimErr(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505") {
		return fmt.Errorf("%w: %s", ErrSCIMConflict, pg.ConstraintName)
	}
	if errors.As(err, &pg) && pg.Code == "23503" {
		return fmt.Errorf("%w: a member must be a person in this tenant", ErrInvalidQuery)
	}
	if errors.Is(err, ErrLastAdmin) || errors.Is(err, ErrUnknownPrincipal) || errors.Is(err, ErrUnknownBinding) || errors.Is(err, ErrInvalidQuery) {
		return err
	}
	return fmt.Errorf("scim: %w", err)
}
