package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/eehooks"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/login"
)

// installDirectory binds SCIM to the process tenant and the one SAML issuer. Anything else clears
// it, so a denied key or a second provider leaves the routes unmounted (ADR-0131).
func installDirectory(cfg Config, signIn *login.Service) {
	if signIn == nil || !eehooks.Allow(eehooks.FeatureSAML) {
		eehooks.SetDirectory(nil)
		return
	}
	issuer, ok := signIn.EnterpriseIssuer()
	if !ok {
		cfg.Log.Warn("sso.saml is granted but there is not exactly one SAML provider, so SCIM is not mounted")
		eehooks.SetDirectory(nil)
		return
	}
	eehooks.SetDirectory(scimDirectory{db: cfg.DB, tenant: cfg.Tenant, issuer: issuer, log: cfg.Log})
}

type scimDirectory struct {
	db     *sql.DB
	tenant uuid.UUID
	issuer string
	log    *slog.Logger
}

func (d scimDirectory) Provision(ctx context.Context, externalID, userName, name string) (eehooks.User, bool, error) {
	user, created, err := identity.ProvisionSCIMUser(ctx, d.db, d.tenant, d.issuer, externalID, userName, name)
	return toUser(user), created, mapSCIM(err)
}

func (d scimDirectory) SetActive(ctx context.Context, externalID string, active bool) error {
	return mapSCIM(identity.SetSCIMActive(ctx, d.db, d.tenant, externalID, active))
}

func (d scimDirectory) UpdateUserName(ctx context.Context, externalID, userName string) error {
	return mapSCIM(identity.UpdateSCIMUserName(ctx, d.db, d.tenant, externalID, userName))
}

func (d scimDirectory) SetName(ctx context.Context, externalID, name string) error {
	return mapSCIM(identity.SetSCIMName(ctx, d.db, d.tenant, externalID, name))
}

func (d scimDirectory) ReplaceUser(ctx context.Context, externalID, userName, name string, active *bool) error {
	return mapSCIM(identity.ReplaceSCIMUser(ctx, d.db, d.tenant, externalID, userName, name, active))
}

func (d scimDirectory) UserByID(ctx context.Context, id uuid.UUID) (eehooks.User, error) {
	user, err := identity.SCIMUserByID(ctx, d.db, d.tenant, id)
	return toUser(user), mapSCIM(err)
}

func (d scimDirectory) UserByExternalID(ctx context.Context, externalID string) (eehooks.User, error) {
	user, err := identity.SCIMUserByExternalID(ctx, d.db, d.tenant, externalID)
	return toUser(user), mapSCIM(err)
}

func (d scimDirectory) UserByUserName(ctx context.Context, userName string) (eehooks.User, error) {
	user, err := identity.SCIMUserByUserName(ctx, d.db, d.tenant, userName)
	return toUser(user), mapSCIM(err)
}

func (d scimDirectory) CreateGroup(ctx context.Context, ref string) (eehooks.Group, error) {
	group, err := identity.CreateSCIMGroup(ctx, d.db, d.tenant, ref)
	return eehooks.Group{ID: group.ID, Ref: group.Ref}, mapSCIM(err)
}

func (d scimDirectory) GroupByRef(ctx context.Context, ref string) (eehooks.Group, error) {
	group, err := identity.SCIMGroupByRef(ctx, d.db, d.tenant, ref)
	return eehooks.Group{ID: group.ID, Ref: group.Ref}, mapSCIM(err)
}

func (d scimDirectory) Group(ctx context.Context, id uuid.UUID) (eehooks.Group, error) {
	group, err := identity.SCIMGroupByID(ctx, d.db, d.tenant, id)
	return eehooks.Group{ID: group.ID, Ref: group.Ref}, mapSCIM(err)
}

func (d scimDirectory) ReplaceGroupMembers(ctx context.Context, id uuid.UUID, members []uuid.UUID) error {
	return mapSCIM(identity.ReplaceSCIMGroupMembers(ctx, d.db, d.tenant, id, members))
}

func (d scimDirectory) Members(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	ids, err := identity.SCIMGroupMembers(ctx, d.db, d.tenant, id)
	return ids, mapSCIM(err)
}

func (d scimDirectory) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	return mapSCIM(identity.DeleteSCIMGroup(ctx, d.db, d.tenant, id))
}

func (d scimDirectory) PutToken(ctx context.Context, actor uuid.UUID, hash []byte) error {
	return mapSCIM(identity.PutSCIMToken(ctx, d.db, d.tenant, actor, hash))
}

func (d scimDirectory) TokenOK(ctx context.Context, token []byte) (bool, error) {
	ok, err := identity.SCIMTokenOK(ctx, d.db, d.tenant, token)
	if err != nil {
		d.log.Warn("the scim token could not be read", "tenant", d.tenant)
	}
	return ok, err
}

func (d scimDirectory) PutGroupRole(ctx context.Context, actor uuid.UUID, groupRef, role string, scope uuid.UUID) (eehooks.GroupRole, error) {
	row, err := identity.PutIDPGroupRole(ctx, d.db, d.tenant, actor, groupRef, role, scope)
	return eehooks.GroupRole{ID: row.ID, GroupRef: row.GroupRef, Role: row.Role, ScopeID: row.ScopeID}, mapSCIM(err)
}

func (d scimDirectory) ListGroupRoles(ctx context.Context) ([]eehooks.GroupRole, error) {
	rows, err := identity.ListIDPGroupRoles(ctx, d.db, d.tenant)
	if err != nil {
		return nil, mapSCIM(err)
	}
	out := make([]eehooks.GroupRole, 0, len(rows))
	for _, row := range rows {
		out = append(out, eehooks.GroupRole{ID: row.ID, GroupRef: row.GroupRef, Role: row.Role, ScopeID: row.ScopeID})
	}
	return out, nil
}

func (d scimDirectory) DeleteGroupRole(ctx context.Context, actor, id uuid.UUID) error {
	return mapSCIM(identity.DeleteIDPGroupRole(ctx, d.db, d.tenant, actor, id))
}

func toUser(user identity.SCIMUser) eehooks.User {
	return eehooks.User{ID: user.ID, ExternalID: user.ExternalID, UserName: user.UserName, Name: user.Name, Active: user.Active}
}

func mapSCIM(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identity.ErrLastAdmin):
		return eehooks.ErrLastAdmin
	case errors.Is(err, identity.ErrUnknownPrincipal), errors.Is(err, identity.ErrUnknownBinding):
		return eehooks.ErrNotFound
	case errors.Is(err, identity.ErrSCIMConflict):
		return eehooks.ErrConflict
	case errors.Is(err, identity.ErrInvalidQuery):
		return eehooks.ErrInvalid
	default:
		return err
	}
}
