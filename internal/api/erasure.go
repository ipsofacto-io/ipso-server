package api

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The name erasure of ADR-0156. An admin who is a person replaces one person's stored name with the
// placeholder. The route asks for principal.manage, which only that admin holds (ADR-0108), so it
// reads no scope. The body is empty: the old name is not a field, and it is not logged.

type erasureHandlers struct {
	db  *sql.DB
	log *slog.Logger
}

// erasureRoutes is the operation of ADR-0156.
func erasureRoutes(db *sql.DB, log *slog.Logger) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &erasureHandlers{db: db, log: log}
	return []route{
		{"POST /v1/principals/{id}/erasure", "erase_principal_name", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.erase)},
	}
}

// erase replaces the name of the person named by the path. A body is refused, and it is not logged.
func (h *erasureHandlers) erase(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	buf := make([]byte, 1)
	n, err := r.Body.Read(buf)
	if n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	caller, ok := personOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	if err := identity.ErasePrincipalName(r.Context(), h.db, caller.Tenant, caller.Principal, id); err != nil {
		writeStoreError(w, h.log, "erase_principal_name", err)
		return
	}
	setJSONHeaders(w.Header())
	w.WriteHeader(http.StatusNoContent)
}
