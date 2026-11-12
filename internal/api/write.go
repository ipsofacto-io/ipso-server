package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

var errTrailingData = errors.New("data after the body")

// decodeBytes reads a JSON body whole, with no field the type does not name and nothing after it. The guard
// reads the targets of a scoped call from the same bytes with the same function the handler uses, so what the
// role policy covers is what the handler writes.
func decodeBytes[T any](body []byte) (T, error) {
	var v T
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		return v, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return v, errTrailingData
	}
	return v, nil
}

// decodeBody reads the JSON body of a request into T, or writes the refusal: 415 for another content type,
// 413 for a body over the cap, and 400 for one that is not JSON, names a field the type does not have, or
// has anything after it. A tenant or a principal in the body is such a field (ADR-0090).
func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var zero T
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, errUnsupportedMedia)
		return zero, false
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, errTooLarge)
		} else {
			writeError(w, http.StatusBadRequest, errInvalidQuery)
		}
		return zero, false
	}
	v, err := decodeBytes[T](data)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return zero, false
	}
	return v, true
}

// personOf is the authenticated person a write acts for. The guard put it in the request context after it
// confirmed the principal, and a CI run, which has no principal, is not one.
func personOf(r *http.Request) (Caller, bool) {
	caller, ok := r.Context().Value(callerKey{}).(Caller)
	return caller, ok && caller.Tenant != uuid.Nil && caller.Principal != uuid.Nil
}

// pathID reads a wildcard of the route as a UUID, or writes the 400.
func pathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return uuid.Nil, false
	}
	return id, true
}

// writeStoreError answers for a write that failed (ADR-0109). A message that names a value is never sent
// and never logged, only the SQLSTATE, the table and the constraint:
//
//   - a value the domain refused, and a data exception (class 22), or a value a CHECK constraint refused, is
//     400;
//   - a request for an export too soon after the last one is 429 with the wait;
//   - an id the tenant does not have is 404;
//   - a decision body over 1 MiB in text form is 413, and the database error behind it is never reached;
//   - every other refusal of what the registry holds (a unique, foreign key, exclusion or trigger check), such as a repeat, a scope that still has a child or a role
//     binding, a supersession the decisions do not span, or a waiver outside its decision, is 409;
//   - anything else is 500.
func writeStoreError(w http.ResponseWriter, log *slog.Logger, op string, err error) {
	var soon *tenancy.TooSoonError
	if errors.As(err, &soon) {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(soon.Wait))
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	switch {
	case errors.Is(err, registry.ErrInvalidQuery):
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, errNotFound)
		return
	case errors.Is(err, registry.ErrBodyTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, errTooLarge)
		return
	case errors.Is(err, tenancy.ErrBadRecipient):
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	case errors.Is(err, tenancy.ErrNoExport):
		writeError(w, http.StatusNotFound, errNotFound)
		return
	case errors.Is(err, tenancy.ErrExportNotReady):
		writeError(w, http.StatusConflict, errConflict)
		return
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		log.Info("a write was refused by the store", "op", op, "sqlstate", pg.Code, "table", pg.TableName, "constraint", pg.ConstraintName)
		switch {
		case strings.HasPrefix(pg.Code, "22"), pg.Code == "23514" && pg.ConstraintName != "":
			writeError(w, http.StatusBadRequest, errInvalidQuery)
		case conflicts(pg.Code):
			writeError(w, http.StatusConflict, errConflict)
		default:
			writeError(w, http.StatusInternalServerError, errInternal)
		}
		return
	}
	log.Error("a write failed", "op", op)
	writeError(w, http.StatusInternalServerError, errInternal)
}

// conflicts reports the SQLSTATEs that say the registry refuses a change because of what it already holds:
// a unique key, a foreign key, an exclusion, and a check raised by a trigger. Any other integrity error, a
// NOT NULL for one, is a defect of the server and is a 500 that an operator sees.
func conflicts(code string) bool {
	switch code {
	case "23505", "23503", "23P01", "23514":
		return true
	}
	return false
}
