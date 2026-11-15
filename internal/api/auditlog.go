package api

import (
	"bytes"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The audit log route of ADR-0126. An auditor or an admin reads the hash chain of the tenant's action log
// as JSONL, a page at a time, in the order of the chain. A SIEM polls it with the position of the last line
// it kept. Each line holds exactly the fields the hash covers, so the reader can check every hash and that
// a page continues the one before it.
//
// Reading the log is not an entry of the log. A person's reads are not logged (ADR-0117), and a poller
// would otherwise write an entry for every poll and read it on the next one.

const (
	// auditLogContentType is JSON lines, one entry per line, each ending in a newline.
	auditLogContentType = "application/jsonl"
	// auditLogBytes stops a page before the response cap, which refuses an answer whole, so a page of long
	// subjects ends early instead of failing. A page holds at least one line.
	auditLogBytes = 1 << 20
)

type auditLogHandlers struct {
	db  *sql.DB
	log *slog.Logger
}

// auditLogRoutes is the operation of ADR-0126. It asks for the audit.read action, which the auditor and
// the admin hold and an agent never does (ADR-0108). The one query key is the position to continue from.
func auditLogRoutes(db *sql.DB, log *slog.Logger) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &auditLogHandlers{db: db, log: log}
	return []route{
		{"GET /v1/audit-log", "read_audit_log", authz.AuditRead, []string{"after"}, nil, http.HandlerFunc(h.read)},
	}
}

// read answers with the entries of the tenant's chain whose position is above after, oldest first, at most
// identity.LogPageSize of them and about auditLogBytes. An empty body means nothing is new.
func (h *auditLogHandlers) read(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	after, ok := position(query{values: r.URL.Query()}, "after")
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	entries, err := identity.LogPage(r.Context(), h.db, tenant, after, identity.LogPageSize)
	if err != nil {
		h.log.Error("the audit log could not be read", "tenant", tenant)
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	var body bytes.Buffer
	for _, e := range entries {
		line, err := e.Line()
		if err != nil {
			h.log.Error("an entry of the audit log could not be written", "tenant", tenant, "seq", e.Seq)
			writeError(w, http.StatusInternalServerError, errInternal)
			return
		}
		if body.Len() > 0 && body.Len()+len(line) > auditLogBytes {
			break
		}
		body.Write(line)
	}
	header := w.Header()
	header.Set("Content-Type", auditLogContentType)
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, bytes.NewReader(body.Bytes()))
}

// position reads a position in a chain: a whole number of 0 or more, or 0 when the key is absent.
func position(q query, key string) (int64, bool) {
	if !q.values.Has(key) {
		return 0, true
	}
	n, err := strconv.ParseInt(q.values.Get(key), 10, 64)
	return n, err == nil && n >= 0
}
