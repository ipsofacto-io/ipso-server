package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// The error codes of the API. A body never carries SQL, row text, or a waiver's reason, approver, or
// ticket (ADR-0054, ADR-0055). The audit and proposal routes answer with the same shape.
const (
	errInvalidQuery     = "invalid query"
	errUnauthorized     = "unauthorized"
	errForbidden        = "forbidden"
	errNotFound         = "not found"
	errTooLarge         = "too large"
	errUnsupportedMedia = "unsupported media type"
	errRateLimited      = "rate limited"
	errTimeout          = "timeout"
	errUnavailable      = "unavailable"
	errResponseTooLarge = "response too large"
	errInternal         = "internal"
)

const defaultPage = 50

type errorBody struct {
	Error string `json:"error"`
}

func errorJSON(code string) string {
	data, _ := json.Marshal(errorBody{Error: code})
	return string(data) + "\n"
}

func setJSONHeaders(h http.Header) {
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: code})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	setJSONHeaders(w.Header())
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

// query is a request's query string. guard has refused a repeated key and every key the route does
// not read, so each key here has one value.
type query struct {
	values url.Values
}

// time reads an RFC 3339 time, or fallback when the key is absent.
func (q query) time(key string, fallback time.Time) (time.Time, bool) {
	raw := q.values.Get(key)
	if raw == "" {
		return fallback, !q.values.Has(key)
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	return parsed, err == nil
}

// page reads limit and before.
func (q query) page() (registry.Page, bool) {
	page := registry.Page{Limit: defaultPage}
	if raw := q.values.Get("limit"); raw != "" || q.values.Has("limit") {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > registry.MaxPage {
			return registry.Page{}, false
		}
		page.Limit = limit
	}
	if raw := q.values.Get("before"); raw != "" || q.values.Has("before") {
		before, err := uuid.Parse(raw)
		if err != nil || before == uuid.Nil {
			return registry.Page{}, false
		}
		page.Before = before
	}
	return page, true
}
