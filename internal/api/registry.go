package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// registryRoutes serves the registry reads. valid and known default to now and are always echoed,
// so an answer can be asked for again and read the same.
type registryRoutes struct {
	db  *sql.DB
	now func() time.Time
}

type decisionJSON struct {
	ID      uuid.UUID       `json:"id"`
	Version int             `json:"version"`
	Body    json.RawMessage `json:"body"`
}

type resolveRequest struct {
	Repo  string     `json:"repo"`
	Env   string     `json:"env"`
	Paths []string   `json:"paths"`
	Valid *time.Time `json:"valid"`
	Known *time.Time `json:"known"`
}

type resolutionJSON struct {
	Path        string      `json:"path"`
	DecisionIDs []uuid.UUID `json:"decision_ids"`
}

type resolveAnswer struct {
	Valid       time.Time        `json:"valid"`
	Known       time.Time        `json:"known"`
	Decisions   []decisionJSON   `json:"decisions"`
	Resolutions []resolutionJSON `json:"resolutions"`
}

type scopeJSON struct {
	ID       uuid.UUID  `json:"id"`
	ParentID *uuid.UUID `json:"parent_id"`
	Kind     string     `json:"kind"`
	Selector string     `json:"selector"`
}

type waiverJSON struct {
	ID         uuid.UUID `json:"id"`
	DecisionID uuid.UUID `json:"decision_id"`
	ScopeID    uuid.UUID `json:"scope_id"`
	TicketRef  string    `json:"ticket_ref"`
	ValidFrom  time.Time `json:"valid_from"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// resolve answers a check request (ADR-0051, ADR-0092): the repo, the env, and every changed path,
// one resolution for each path. Each decision is returned once. A path names it by id. It reads and
// writes nothing else, so it is POST only because a list of paths does not fit a URL.
func (h *registryRoutes) resolve(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, errUnsupportedMedia)
		return
	}
	var req resolveRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, errTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	now := h.now()
	validAt, knownAt := now, now
	if req.Valid != nil {
		validAt = *req.Valid
	}
	if req.Known != nil {
		knownAt = *req.Known
	}
	resolved, err := registry.ResolvePaths(r.Context(), h.db, tenant, req.Repo, req.Env, req.Paths, validAt, knownAt)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	resolutions := make([]resolutionJSON, 0, len(resolved.Resolutions))
	for _, resolution := range resolved.Resolutions {
		ids := resolution.DecisionIDs
		if ids == nil {
			ids = []uuid.UUID{}
		}
		resolutions = append(resolutions, resolutionJSON{Path: resolution.Path, DecisionIDs: ids})
	}
	writeJSON(w, http.StatusOK, resolveAnswer{
		Valid:       validAt,
		Known:       knownAt,
		Decisions:   decisionList(resolved.Decisions),
		Resolutions: resolutions,
	})
}

func (h *registryRoutes) decisions(w http.ResponseWriter, r *http.Request) {
	tenant, q, validAt, knownAt, ok := h.read(w, r, true)
	if !ok {
		return
	}
	page, ok := q.page()
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	decisions, err := registry.Decisions(r.Context(), h.db, tenant, validAt, knownAt, page)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": validAt, "known": knownAt, "decisions": decisionList(decisions)})
}

// decision reads the decisions an id or a slug names. Another tenant's id answers the same empty
// list as an id no one has.
func (h *registryRoutes) decision(w http.ResponseWriter, r *http.Request) {
	tenant, _, validAt, knownAt, ok := h.read(w, r, true)
	if !ok {
		return
	}
	decisions, err := registry.Lookup(r.Context(), h.db, tenant, r.PathValue("ref"), validAt, knownAt)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": validAt, "known": knownAt, "decisions": decisionList(decisions)})
}

func (h *registryRoutes) scopes(w http.ResponseWriter, r *http.Request) {
	tenant, q, _, knownAt, ok := h.read(w, r, false)
	if !ok {
		return
	}
	page, ok := q.page()
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	scopes, err := registry.Scopes(r.Context(), h.db, tenant, knownAt, page)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	out := make([]scopeJSON, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, scopeJSON{ID: s.ID, ParentID: s.ParentID, Kind: s.Kind, Selector: s.Selector})
	}
	writeJSON(w, http.StatusOK, map[string]any{"known": knownAt, "scopes": out})
}

func (h *registryRoutes) waivers(w http.ResponseWriter, r *http.Request) {
	tenant, q, validAt, knownAt, ok := h.read(w, r, true)
	if !ok {
		return
	}
	page, ok := q.page()
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	waivers, err := registry.Waivers(r.Context(), h.db, tenant, validAt, knownAt, page)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	out := make([]waiverJSON, 0, len(waivers))
	for _, waiver := range waivers {
		out = append(out, waiverJSON{
			ID:         waiver.ID,
			DecisionID: waiver.DecisionID,
			ScopeID:    waiver.ScopeID,
			TicketRef:  waiver.TicketRef,
			ValidFrom:  waiver.ValidFrom,
			ExpiresAt:  waiver.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": validAt, "known": knownAt, "waivers": out})
}

// listOf checks the tenant and reads the page of a list route that takes no time (ADR-0117).
func listOf(w http.ResponseWriter, r *http.Request) (uuid.UUID, registry.Page, bool) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return uuid.Nil, registry.Page{}, false
	}
	page, ok := query{values: r.URL.Query()}.page()
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return uuid.Nil, registry.Page{}, false
	}
	return tenant, page, true
}

type premiseReasonJSON struct {
	ID         uuid.UUID       `json:"id"`
	DecisionID uuid.UUID       `json:"decision_id"`
	PremiseID  string          `json:"premise_id"`
	OpenedAt   time.Time       `json:"opened_at"`
	URL        string          `json:"url"`
	Pointer    string          `json:"pointer"`
	Expected   json.RawMessage `json:"expected"`
	Observed   json.RawMessage `json:"observed"`
}

// premiseReasons lists the review reasons no clearance has closed, with the fail that opened each (ADR-0117).
// It reads the present and takes no time. The answer holds what the evaluation stored and never the body of the
// probe response.
func (h *registryRoutes) premiseReasons(w http.ResponseWriter, r *http.Request) {
	tenant, page, ok := listOf(w, r)
	if !ok {
		return
	}
	reasons, err := registry.OpenPremiseReasons(r.Context(), h.db, tenant, page)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	out := make([]premiseReasonJSON, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, premiseReasonJSON{
			ID: reason.ID, DecisionID: reason.DecisionID, PremiseID: reason.PremiseID, OpenedAt: reason.OpenedAt,
			URL: reason.URL, Pointer: reason.Pointer, Expected: reason.Expected, Observed: reason.Observed,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"premise_reasons": out})
}

// premiseHosts lists the allowlist as the probe reads it: the latest row of each host (ADR-0117).
func (h *registryRoutes) premiseHosts(w http.ResponseWriter, r *http.Request) {
	tenant, page, ok := listOf(w, r)
	if !ok {
		return
	}
	hosts, err := registry.PremiseHosts(r.Context(), h.db, tenant, page)
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	out := make([]hostJSON, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, hostJSON{ID: host.ID, Host: host.Host, Allowed: host.Allowed})
	}
	writeJSON(w, http.StatusOK, map[string]any{"premise_hosts": out})
}

// read checks the tenant of a GET route and reads its times. A route with no valid time leaves it
// zero.
func (h *registryRoutes) read(w http.ResponseWriter, r *http.Request, hasValid bool) (uuid.UUID, query, time.Time, time.Time, bool) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return uuid.Nil, query{}, time.Time{}, time.Time{}, false
	}
	q := query{values: r.URL.Query()}
	now := h.now()
	var validAt time.Time
	if hasValid {
		if validAt, ok = q.time("valid", now); !ok {
			writeError(w, http.StatusBadRequest, errInvalidQuery)
			return uuid.Nil, query{}, time.Time{}, time.Time{}, false
		}
	}
	knownAt, ok := q.time("known", now)
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return uuid.Nil, query{}, time.Time{}, time.Time{}, false
	}
	return tenant, q, validAt, knownAt, true
}

func decisionList(decisions []registry.Decision) []decisionJSON {
	out := make([]decisionJSON, 0, len(decisions))
	for _, d := range decisions {
		out = append(out, decisionJSON{ID: d.ID, Version: d.Version, Body: json.RawMessage(d.Body)})
	}
	return out
}

func writeRegistryError(w http.ResponseWriter, err error) {
	if errors.Is(err, registry.ErrInvalidQuery) || errors.Is(err, registry.ErrInvalidSubject) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	writeError(w, http.StatusInternalServerError, errInternal)
}
