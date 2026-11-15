package api

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The invitation routes of ADR-0127. An admin who is a person invites someone by name and role, and the answer
// holds a link to hand to them. The first sign-in that carries the link binds that person's issuer and subject to a
// new principal, a login and the role, which is done by the sign-in itself (internal/login) and not by a route.
//
// Every route asks for principal.manage, which only an admin who is a person holds (ADR-0108), so none reads
// a scope. Creating and revoking are logged with the person's id in identity.action_log, with the id of the
// invitation and the role as the subject, and never the name or the token.

type invitationHandlers struct {
	db     *sql.DB
	log    *slog.Logger
	writes *writeHandlers
	// origin is the public origin the link points at. It is empty when browser sign-in is off, and then no
	// one could use a link, so no invitation is made.
	origin string
}

// invitationRoutes are the operations of ADR-0127. origin is the origin of browser sign-in, or empty.
func invitationRoutes(db *sql.DB, log *slog.Logger, origin string) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &invitationHandlers{db: db, log: log, writes: &writeHandlers{db: db, log: log}, origin: origin}
	return []route{
		{"POST /v1/invitations", "create_invitation", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.create)},
		{"GET /v1/invitations", "list_invitations", authz.PrincipalManage, []string{"limit", "before"}, nil, http.HandlerFunc(h.list)},
		{"DELETE /v1/invitations/{id}", "revoke_invitation", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.revoke)},
	}
}

type createInvitationRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type invitationJSON struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedBy uuid.UUID `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// createdInvitationJSON is the one answer that holds the token, and the only place it ever leaves the server.
type createdInvitationJSON struct {
	invitationJSON
	Token string `json:"token"`
	URL   string `json:"url"`
}

func invitationBody(inv identity.Invitation) invitationJSON {
	return invitationJSON{
		ID: inv.ID, Name: inv.Name, Role: inv.Role, CreatedBy: inv.CreatedBy,
		CreatedAt: inv.CreatedAt.UTC(), ExpiresAt: inv.ExpiresAt.UTC(),
	}
}

// create stores an invitation and answers with the link. The token is in the fragment of the link, so no
// server or proxy that carries the link sees it, and the answer is the only time it is shown: the database
// keeps its SHA-256. Without browser sign-in there is nowhere the link could be used, so it is 409 and nothing
// is stored.
func (h *invitationHandlers) create(w http.ResponseWriter, r *http.Request) {
	if h.origin == "" {
		writeError(w, http.StatusConflict, errConflict)
		return
	}
	req, ok := decodeBody[createInvitationRequest](w, r)
	if !ok {
		return
	}
	token, hash, err := identity.NewInvitationToken()
	if err != nil {
		h.log.Error("an invitation token could not be made")
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	h.writes.write(w, r, "create_invitation", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		inv, err := identity.CreateInvitation(ctx, tx, caller.Principal, req.Name, req.Role, hash)
		if err != nil {
			return "", nil, err
		}
		return "invitation " + inv.ID.String() + " role " + inv.Role, createdInvitationJSON{
			invitationJSON: invitationBody(inv),
			Token:          token,
			URL:            h.origin + "/invitation#" + token,
		}, nil
	})
}

// list reads the invitations that are still open. The answer never holds a token or a hash.
func (h *invitationHandlers) list(w http.ResponseWriter, r *http.Request) {
	tenant, page, ok := listOf(w, r)
	if !ok {
		return
	}
	found, err := identity.ListInvitations(r.Context(), h.db, tenant, page.Before, page.Limit)
	if err != nil {
		writeStoreError(w, h.log, "list_invitations", err)
		return
	}
	out := make([]invitationJSON, 0, len(found))
	for _, inv := range found {
		out = append(out, invitationBody(inv))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": out})
}

// revoke deletes an open invitation, so a link that was handed to the wrong person stops working. One that was
// used, was revoked or has expired is 404.
func (h *invitationHandlers) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	h.writes.write(w, r, "revoke_invitation", http.StatusNoContent, func(ctx context.Context, tx *sql.Tx, _ Caller) (string, any, error) {
		if err := identity.RevokeInvitation(ctx, tx, id); err != nil {
			return "", nil, err
		}
		return "invitation " + id.String(), nil, nil
	})
}
