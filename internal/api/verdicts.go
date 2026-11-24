package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

var liveScopeEnvExpr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// verdictRoutes serves the stored verdicts of CI runs (ADR-0102).
type verdictRoutes struct {
	db *sql.DB
	// now is the transaction time of a list that names none (ADR-0122).
	now func() time.Time
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
	// Scheduled and manual workflow_dispatch CI runs may report live drift snapshots (ADR-0162);
	// pull-request and commit-push CI runs may only report change verdicts.
	if upload.Live && run.Event != "schedule" && run.Event != "workflow_dispatch" {
		writeError(w, http.StatusForbidden, errForbidden)
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

// uploadLive stores a live/drift verdict report signed by a pinned ipso-agent key (ADR-0162).
func (h *verdictRoutes) uploadLive(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	agent, hasAgent := liveAgentOf(r)
	if !ok || !hasAgent {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	upload, err := verification.Parse(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	pinEnv := strings.ToLower(strings.TrimSpace(agent.Pin.Env))
	reportEnv := strings.ToLower(strings.TrimSpace(upload.Env))
	if reportEnv == "" {
		reportEnv = pinEnv
	}
	if reportEnv != pinEnv {
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	upload.Env = reportEnv
	if len(upload.Verdicts) > 0 {
		now := time.Now().UTC()
		if h.now != nil {
			now = h.now()
		}
		subj := registry.Subject{Repo: strings.ToLower(agent.Pin.Repo)}
		if foldedEnv := strings.ToLower(strings.TrimSpace(upload.Env)); liveScopeEnvExpr.MatchString(foldedEnv) {
			subj.Env = foldedEnv
		}
		applicable, err := registry.Resolve(r.Context(), h.db, tenant, subj, now, now)
		if err != nil {
			if h.log != nil {
				h.log.Warn("a live upload could not resolve pin scopes", "pin", agent.Pin.Name, "error", err.Error())
			}
			writeError(w, http.StatusInternalServerError, errInternal)
			return
		}
		allowedIDs := make(map[string]bool, len(applicable))
		allowedSlugs := make(map[string]bool, len(applicable))
		for _, dec := range applicable {
			var meta struct {
				ID   string `json:"id"`
				Slug string `json:"slug"`
			}
			if json.Unmarshal(dec.Body, &meta) == nil {
				if meta.ID != "" {
					allowedIDs[meta.ID] = true
				}
				if meta.Slug != "" {
					allowedSlugs[meta.Slug] = true
				}
			}
		}
		for _, v := range upload.Verdicts {
			if !allowedIDs[v.DecisionID] && !allowedSlugs[v.Slug] {
				writeError(w, http.StatusForbidden, errForbidden)
				return
			}
		}
	}
	upload.Live = true
	upload.SourceKind = "live"
	run := verification.LiveAgentRun(agent.Pin, agent.Timestamp, upload.Digest)
	stored, err := verification.Store(r.Context(), h.db, tenant, run, upload)
	if err != nil {
		if h.log != nil {
			h.log.Warn("a live upload could not be stored", "pin", agent.Pin.Name, "error", err.Error())
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
	now := h.now()
	known, ok := q.time("known", now)
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	items, err := verification.List(r.Context(), h.db, tenant,
		verification.Filter{Repo: q.values.Get("repo"), Decision: q.values.Get("decision")}, page.Limit, page.Before, known)
	if errors.Is(err, verification.ErrInvalid) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"known": known, "verdicts": items})
}
