package api

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// verdictRoutes serves the stored verdicts of CI runs (ADR-0102).
type verdictRoutes struct {
	db *sql.DB
	// log receives the reason an upload could not be stored. Store reduces a database error to a state code
	// and a constraint, so it holds no content from the runner.
	log *slog.Logger
}

type uploadAnswer struct {
	ID       uuid.UUID `json:"id"`
	Verdicts int       `json:"verdicts"`
}

// upload stores the verdicts of one CI run. wrapUpload has verified the token and mapped its repository, so
// the tenant and the run are the ones in the request context, and nothing in the body can name either. The
// body is read whole before anything is stored, and one over the cap is 413 with nothing stored. A repeat of
// the same run and content is 200 with the first upload's id and adds nothing.
func (h *verdictRoutes) upload(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	run, hasRun := runOf(r)
	if !ok || !hasRun {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, errUnsupportedMedia)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, errTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	upload, err := verification.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	stored, err := verification.Store(r.Context(), h.db, tenant, run, upload)
	if err != nil {
		if h.log != nil {
			h.log.Warn("an upload could not be stored", "repository_id", run.RepositoryID, "run_id", run.RunID, "error", err.Error())
		}
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	status := http.StatusOK
	if stored.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, uploadAnswer{ID: stored.ID, Verdicts: stored.Verdicts})
}

// list reads the tenant's stored verdicts, newest first, for one repository or decision or all.
func (h *verdictRoutes) list(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	q := query{values: r.URL.Query()}
	page, ok := q.page()
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	items, err := verification.List(r.Context(), h.db, tenant,
		verification.Filter{Repo: q.values.Get("repo"), Decision: q.values.Get("decision")}, page.Limit, page.Before)
	if errors.Is(err, verification.ErrInvalid) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdicts": items})
}
