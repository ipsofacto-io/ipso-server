// Package audit serves the five read-only audit routes of ADR-0055.
// The binary does not listen. The control plane mounts Handler once it can pass the
// tenant from the authenticated token.
package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// TenantFunc returns the tenant for this request. The tenant must be the authenticated
// one. Handler does not read a tenant from the query, a header, or the body.
type TenantFunc func(*http.Request) (uuid.UUID, bool)

// Handler returns the audit routes. A nil tenantFrom, a false result, or a nil tenant
// is 401 and runs no query. A query key tenant or tenant_id is 400 and runs no query.
func Handler(db *sql.DB, tenantFrom TenantFunc) http.Handler {
	h := &handler{db: db, tenantFrom: tenantFrom}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/audit/decisions", h.decisions)
	mux.HandleFunc("GET /v1/audit/beliefs", h.beliefs)
	mux.HandleFunc("GET /v1/audit/merges", h.merges)
	mux.HandleFunc("GET /v1/audit/supersessions/{decisionID}", h.supersessions)
	mux.HandleFunc("GET /v1/audit/waivers", h.waivers)
	return mux
}

type handler struct {
	db         *sql.DB
	tenantFrom TenantFunc
}

type errorBody struct {
	Error string `json:"error"`
}

type decisionJSON struct {
	ID      uuid.UUID       `json:"id"`
	Version int             `json:"version"`
	Body    json.RawMessage `json:"body"`
}

type decisionsJSON struct {
	Decisions []decisionJSON `json:"decisions"`
}

type changeJSON struct {
	ID   uuid.UUID    `json:"id"`
	Then decisionJSON `json:"then"`
	Now  decisionJSON `json:"now"`
}

type beliefsJSON struct {
	Added   []decisionJSON `json:"added"`
	Removed []decisionJSON `json:"removed"`
	Changed []changeJSON   `json:"changed"`
}

type linkJSON struct {
	ID          uuid.UUID `json:"id"`
	From        uuid.UUID `json:"from"`
	To          uuid.UUID `json:"to"`
	EffectiveAt time.Time `json:"effective_at"`
}

type versionJSON struct {
	DecisionID uuid.UUID  `json:"decision_id"`
	Version    int        `json:"version"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidTo    *time.Time `json:"valid_to"`
}

type chainJSON struct {
	Links    []linkJSON    `json:"links"`
	Versions []versionJSON `json:"versions"`
}

type waiverJSON struct {
	ID         uuid.UUID `json:"id"`
	DecisionID uuid.UUID `json:"decision_id"`
	ScopeID    uuid.UUID `json:"scope_id"`
	TicketRef  string    `json:"ticket_ref"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type waiversJSON struct {
	Waivers []waiverJSON `json:"waivers"`
}

func (h *handler) decisions(w http.ResponseWriter, r *http.Request) {
	tenant, subject, validAt, knownAt, ok := h.q1(w, r)
	if !ok {
		return
	}
	decisions, err := registry.Resolve(r.Context(), h.db, tenant, subject, validAt, knownAt)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decisionsJSON{Decisions: decisionList(decisions)})
}

func (h *handler) beliefs(w http.ResponseWriter, r *http.Request) {
	tenant, subject, ok := h.subject(w, r)
	if !ok {
		return
	}
	validAt, ok := requiredTime(w, r, "valid")
	if !ok {
		return
	}
	then, ok := requiredTime(w, r, "then")
	if !ok {
		return
	}
	now, ok := requiredTime(w, r, "now")
	if !ok {
		return
	}
	diff, err := registry.Beliefs(r.Context(), h.db, tenant, subject, validAt, then, now)
	if err != nil {
		writeErr(w, err)
		return
	}
	changed := make([]changeJSON, 0, len(diff.Changed))
	for _, c := range diff.Changed {
		changed = append(changed, changeJSON{ID: c.ID, Then: oneDecision(c.Then), Now: oneDecision(c.Now)})
	}
	writeJSON(w, http.StatusOK, beliefsJSON{
		Added:   decisionList(diff.Added),
		Removed: decisionList(diff.Removed),
		Changed: changed,
	})
}

func (h *handler) merges(w http.ResponseWriter, r *http.Request) {
	tenant, subject, ok := h.subject(w, r)
	if !ok {
		return
	}
	at, ok := requiredTime(w, r, "at")
	if !ok {
		return
	}
	knownAt := at
	if r.URL.Query().Has("known") {
		knownAt, ok = requiredTime(w, r, "known")
		if !ok {
			return
		}
	}
	decisions, err := registry.Resolve(r.Context(), h.db, tenant, subject, at, knownAt)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decisionsJSON{Decisions: decisionList(decisions)})
}

func (h *handler) supersessions(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	decision, err := uuid.Parse(r.PathValue("decisionID"))
	if err != nil || decision == uuid.Nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return
	}
	knownAt, ok := requiredTime(w, r, "known")
	if !ok {
		return
	}
	chain, err := registry.SupersessionChain(r.Context(), h.db, tenant, decision, knownAt)
	if err != nil {
		writeErr(w, err)
		return
	}
	links := make([]linkJSON, 0, len(chain.Links))
	for _, link := range chain.Links {
		links = append(links, linkJSON{
			ID: link.ID, From: link.From, To: link.To, EffectiveAt: link.EffectiveAt,
		})
	}
	versions := make([]versionJSON, 0, len(chain.Versions))
	for _, span := range chain.Versions {
		versions = append(versions, versionJSON{
			DecisionID: span.DecisionID,
			Version:    span.Version,
			ValidFrom:  span.ValidFrom,
			ValidTo:    span.ValidTo,
		})
	}
	writeJSON(w, http.StatusOK, chainJSON{Links: links, Versions: versions})
}

func (h *handler) waivers(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	knownAt, ok := requiredTime(w, r, "known")
	if !ok {
		return
	}
	now, ok := requiredTime(w, r, "now")
	if !ok {
		return
	}
	waivers, err := registry.ExpiringWaivers(r.Context(), h.db, tenant, knownAt, now)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]waiverJSON, 0, len(waivers))
	for _, waiver := range waivers {
		out = append(out, waiverJSON{
			ID:         waiver.ID,
			DecisionID: waiver.DecisionID,
			ScopeID:    waiver.ScopeID,
			TicketRef:  waiver.TicketRef,
			ExpiresAt:  waiver.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, waiversJSON{Waivers: out})
}

// q1 reads the Q1 parameters. known does not default: a missing transaction time would
// silently answer "as known now".
func (h *handler) q1(w http.ResponseWriter, r *http.Request) (uuid.UUID, registry.Subject, time.Time, time.Time, bool) {
	tenant, subject, ok := h.subject(w, r)
	if !ok {
		return uuid.Nil, registry.Subject{}, time.Time{}, time.Time{}, false
	}
	validAt, ok := requiredTime(w, r, "valid")
	if !ok {
		return uuid.Nil, registry.Subject{}, time.Time{}, time.Time{}, false
	}
	knownAt, ok := requiredTime(w, r, "known")
	if !ok {
		return uuid.Nil, registry.Subject{}, time.Time{}, time.Time{}, false
	}
	return tenant, subject, validAt, knownAt, true
}

func (h *handler) subject(w http.ResponseWriter, r *http.Request) (uuid.UUID, registry.Subject, bool) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return uuid.Nil, registry.Subject{}, false
	}
	q := r.URL.Query()
	repo, ok := sole(w, q, "repo")
	if !ok {
		return uuid.Nil, registry.Subject{}, false
	}
	if repo == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return uuid.Nil, registry.Subject{}, false
	}
	path, ok := sole(w, q, "path")
	if !ok {
		return uuid.Nil, registry.Subject{}, false
	}
	env, ok := sole(w, q, "env")
	if !ok {
		return uuid.Nil, registry.Subject{}, false
	}
	return tenant, registry.Subject{Repo: repo, Path: path, Env: env}, true
}

// tenant rejects a smuggled tenant key before it asks tenantFrom, so a request that
// names a tenant never reaches the database and never calls the authenticator.
func (h *handler) tenant(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	if hasTenantKey(r.URL.Query()) {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return uuid.Nil, false
	}
	if h.tenantFrom == nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return uuid.Nil, false
	}
	id, ok := h.tenantFrom(r)
	if !ok || id == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return uuid.Nil, false
	}
	return id, true
}

func hasTenantKey(q url.Values) bool {
	for key := range q {
		if strings.EqualFold(key, "tenant") || strings.EqualFold(key, "tenant_id") {
			return true
		}
	}
	return false
}

// sole returns the one value of key. A repeated key is rejected so a second value
// cannot hide behind the first. A missing key is an empty string.
func sole(w http.ResponseWriter, q url.Values, key string) (string, bool) {
	values := q[key]
	switch len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return "", false
	}
}

func requiredTime(w http.ResponseWriter, r *http.Request, key string) (time.Time, bool) {
	raw, ok := sole(w, r.URL.Query(), key)
	if !ok {
		return time.Time{}, false
	}
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return time.Time{}, false
	}
	return parsed, true
}

func decisionList(decisions []registry.Decision) []decisionJSON {
	out := make([]decisionJSON, 0, len(decisions))
	for _, d := range decisions {
		out = append(out, oneDecision(d))
	}
	return out
}

func oneDecision(d registry.Decision) decisionJSON {
	return decisionJSON{ID: d.ID, Version: d.Version, Body: json.RawMessage(d.Body)}
}

func writeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, registry.ErrInvalidQuery) || errors.Is(err, registry.ErrInvalidSubject) {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid query"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}
