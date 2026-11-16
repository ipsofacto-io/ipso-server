package api

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The role binding routes of ADR-0128. An admin who is a person lists, grants and revokes the bindings
// of the tenant. A binding is never updated: a change of role is a grant and a revoke. Every route asks
// for principal.manage, which only an admin who is a person holds (ADR-0108), so none reads a scope.
// Granting and revoking are logged with the admin's id. The subject names the principal, the binding,
// the role and, when there is one, the scope, and never a name.

type roleBindingHandlers struct {
	db     *sql.DB
	log    *slog.Logger
	writes *writeHandlers
}

// roleBindingRoutes are the operations of ADR-0128.
func roleBindingRoutes(db *sql.DB, log *slog.Logger) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &roleBindingHandlers{db: db, log: log, writes: &writeHandlers{db: db, log: log}}
	return []route{
		{"POST /v1/role-bindings", "grant_role_binding", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.grant)},
		{"GET /v1/role-bindings", "list_role_bindings", authz.PrincipalManage, []string{"limit", "before"}, nil, http.HandlerFunc(h.list)},
		{"DELETE /v1/role-bindings/{id}", "revoke_role_binding", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.revoke)},
	}
}

type grantRoleBindingRequest struct {
	PrincipalID uuid.UUID  `json:"principal_id"`
	Role        string     `json:"role"`
	ScopeID     *uuid.UUID `json:"scope_id"`
}

type roleBindingJSON struct {
	ID          uuid.UUID  `json:"id"`
	PrincipalID uuid.UUID  `json:"principal_id"`
	Role        string     `json:"role"`
	ScopeID     *uuid.UUID `json:"scope_id"`
}

func roleBindingBody(binding identity.RoleBinding) roleBindingJSON {
	body := roleBindingJSON{ID: binding.ID, PrincipalID: binding.PrincipalID, Role: binding.Role}
	if binding.ScopeID != uuid.Nil {
		body.ScopeID = &binding.ScopeID
	}
	return body
}

// bindingSubject is the action-log subject of a grant or a revoke. It names ids and the role, never a name.
func bindingSubject(binding identity.RoleBinding) string {
	subject := "principal " + binding.PrincipalID.String() + " binding " + binding.ID.String() + " role " + binding.Role
	if binding.ScopeID != uuid.Nil {
		subject += " scope " + binding.ScopeID.String()
	}
	return subject
}

// grant stores one binding. A principal or a scope this tenant does not have is 404. The database
// answers a role the principal cannot hold, a scope on a tenant-wide role, an unknown role and a
// duplicate, and those are client errors.
func (h *roleBindingHandlers) grant(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[grantRoleBindingRequest](w, r)
	if !ok {
		return
	}
	if req.PrincipalID == uuid.Nil || req.Role == "" || (req.ScopeID != nil && *req.ScopeID == uuid.Nil) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	scope := uuid.Nil
	if req.ScopeID != nil {
		scope = *req.ScopeID
	}
	h.writes.write(w, r, "grant_role_binding", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, _ Caller) (string, any, error) {
		binding, err := identity.GrantRoleBinding(ctx, tx, req.PrincipalID, req.Role, scope)
		if err != nil {
			return "", nil, err
		}
		return bindingSubject(binding), roleBindingBody(binding), nil
	})
}

// list reads one page of the tenant's bindings, newest first.
func (h *roleBindingHandlers) list(w http.ResponseWriter, r *http.Request) {
	tenant, page, ok := listOf(w, r)
	if !ok {
		return
	}
	found, err := identity.ListRoleBindings(r.Context(), h.db, tenant, page.Before, page.Limit)
	if err != nil {
		writeStoreError(w, h.log, "list_role_bindings", err)
		return
	}
	out := make([]roleBindingJSON, 0, len(found))
	for _, binding := range found {
		out = append(out, roleBindingBody(binding))
	}
	writeJSON(w, http.StatusOK, map[string]any{"role_bindings": out})
}

// revoke deletes one binding. The only admin of the tenant is 409, and the binding stays.
func (h *roleBindingHandlers) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	h.writes.write(w, r, "revoke_role_binding", http.StatusNoContent, func(ctx context.Context, tx *sql.Tx, _ Caller) (string, any, error) {
		binding, err := identity.RevokeRoleBinding(ctx, tx, id)
		if err != nil {
			return "", nil, err
		}
		return bindingSubject(binding), nil, nil
	})
}
