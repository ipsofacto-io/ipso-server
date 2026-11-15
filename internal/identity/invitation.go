package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// The invitations of ADR-0127. An admin invites a person by name and role, and the first sign-in that
// carries the invitation binds that person's issuer and subject to a new principal, a login and the role.
// The link holds a token of 32 random bytes and the database keeps only their SHA-256, like a session, so
// a read of the table is not an invitation.
const (
	// InvitationTokenSize is the number of random bytes in an invitation token.
	InvitationTokenSize = 32
	// invitationTokenText is the length of a token as unpadded base64url.
	invitationTokenText = 43
	// InvitationTTL is how long an invitation lasts. The trigger of migration 00035 stamps it, so no writer
	// can lengthen it, and this is the same number for the documents that say it.
	InvitationTTL = 7 * 24 * time.Hour
	// MaxOpenInvitations bounds the invitations a tenant holds at once. Expired ones go whenever an invitation
	// is made or used, so the table only grows by what an admin makes in a week. Two admins that create one at
	// the same instant may pass it by one each, which is no harm.
	MaxOpenInvitations = 1000

	// acceptAction is the entry the action log keeps of an invitation that was used. The person is the one it
	// created, so the entry names them.
	acceptAction = "auth.accept_invitation"
)

// ErrUnknownInvitation is returned for a token the tenant holds no open invitation for: one it never made,
// one that was used, revoked or has expired, and one of another tenant. They are all the same answer, so
// nothing says which.
var ErrUnknownInvitation = errors.New("unknown invitation")

// ErrTooManyInvitations is returned when the tenant already holds MaxOpenInvitations.
var ErrTooManyInvitations = errors.New("too many open invitations")

// ErrInvalidInvitation is returned for a role an invitation may not give, which is any but the six a person may
// hold. The database refuses the other things a request can get wrong, as a CHECK violation.
var ErrInvalidInvitation = errors.New("invalid invitation")

// invitationRoles are the roles an invitation may give: the six a person may hold. An agent is never invited.
var invitationRoles = slices.DeleteFunc(slices.Clone(Roles), func(role string) bool { return role == RoleAgent })

// Invitation is one open invitation. The token and its hash are never in it.
type Invitation struct {
	ID        uuid.UUID
	Name      string
	Role      string
	CreatedBy uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewInvitationToken returns a new token as the text of a link and the hash the database keeps of it.
func NewInvitationToken() (string, []byte, error) {
	raw := make([]byte, InvitationTokenSize)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), sum[:], nil
}

// InvitationHash is the hash the database keeps of a token given as text. A token that is not exactly 32
// bytes of unpadded base64url is false, and nothing has to ask the database about it.
func InvitationHash(token string) ([]byte, bool) {
	if len(token) != invitationTokenText {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != InvitationTokenSize {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

// CreateInvitation stores an invitation made by a person, in the transaction of the caller, which logs it
// (WithAction). The tenant's expired invitations go first. The database refuses a name that a principal
// could not have and an inviter who is not a person, as a CHECK violation.
func CreateInvitation(ctx context.Context, tx *sql.Tx, creator uuid.UUID, name, role string, hash []byte) (Invitation, error) {
	if creator == uuid.Nil || len(hash) != sha256.Size {
		return Invitation{}, fmt.Errorf("%w: an inviter and a token hash are required", ErrInvalidQuery)
	}
	if !slices.Contains(invitationRoles, role) {
		return Invitation{}, fmt.Errorf("%w: a role a person may hold is required", ErrInvalidInvitation)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM identity.invitation
		WHERE tenant_id = ipso.current_tenant() AND expires_at <= clock_timestamp()`); err != nil {
		return Invitation{}, fmt.Errorf("drop the expired invitations: %w", err)
	}
	inv := Invitation{Name: name, Role: role, CreatedBy: creator}
	err := tx.QueryRowContext(ctx, `
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by)
		SELECT ipso.current_tenant(), $1::bytea, $2, $3, $4::uuid
		WHERE (SELECT count(*) FROM identity.invitation WHERE tenant_id = ipso.current_tenant()) < $5
		RETURNING id, created_at, expires_at`, hash, name, role, creator, MaxOpenInvitations).
		Scan(&inv.ID, &inv.CreatedAt, &inv.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrTooManyInvitations
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("store the invitation: %w", err)
	}
	return inv, nil
}

// RevokeInvitation deletes an open invitation, in the transaction of the caller. One that is not there,
// because it was used, revoked or has expired, is ErrUnknownInvitation.
func RevokeInvitation(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("%w: an invitation is required", ErrInvalidQuery)
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM identity.invitation
		WHERE tenant_id = ipso.current_tenant() AND id = $1 AND expires_at > clock_timestamp()`, id)
	if err != nil {
		return fmt.Errorf("revoke the invitation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke the invitation: %w", err)
	}
	if n == 0 {
		return ErrUnknownInvitation
	}
	return nil
}

// ListInvitations reads one page of the open invitations, by id from the highest. A nil before starts at the
// top. The tenant must be the authenticated one, because ListInvitations trusts it.
func ListInvitations(ctx context.Context, db *sql.DB, tenant, before uuid.UUID, limit int) ([]Invitation, error) {
	if tenant == uuid.Nil || limit < 1 || limit > registry.MaxPage {
		return nil, fmt.Errorf("%w: a tenant and a limit from 1 to %d are required", ErrInvalidQuery, registry.MaxPage)
	}
	var bound any
	if before != uuid.Nil {
		bound = before
	}
	var out []Invitation
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, name, role, created_by, created_at, expires_at
			FROM identity.invitation
			WHERE tenant_id = ipso.current_tenant()
			  AND expires_at > clock_timestamp()
			  AND ($1::uuid IS NULL OR id < $1::uuid)
			ORDER BY id DESC
			LIMIT $2`, bound, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var inv Invitation
			if err := rows.Scan(&inv.ID, &inv.Name, &inv.Role, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
				return err
			}
			out = append(out, inv)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read the invitations: %w", err)
	}
	return out, nil
}

// CheckInvitation says whether the tenant holds an open invitation with this token hash, and changes
// nothing. The sign-in asks it before it sends the person to the provider, so a link that is used or has
// expired fails at once and not after a round trip. The tenant must be the one this process serves.
func CheckInvitation(ctx context.Context, db *sql.DB, tenant uuid.UUID, hash []byte) error {
	if tenant == uuid.Nil || len(hash) != sha256.Size {
		return fmt.Errorf("%w: a tenant and a token hash are required", ErrInvalidQuery)
	}
	err := inTenant(ctx, db, tenant, true, func(tx *sql.Tx) error {
		var one int
		return tx.QueryRowContext(ctx, `
			SELECT 1
			FROM identity.invitation
			WHERE tenant_id = ipso.current_tenant() AND token_sha256 = $1 AND expires_at > clock_timestamp()`, hash).Scan(&one)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknownInvitation
	}
	if err != nil {
		return fmt.Errorf("read the invitation: %w", err)
	}
	return nil
}
