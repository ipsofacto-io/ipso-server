package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// The export routes of ADR-0111. An admin who is a person starts an export of their own tenant, encrypted to
// the age public key they give, and downloads the archive when the worker has finished it. The archive is the
// one `ipso-server tenant export` writes, and it waits in the database for 24 hours (tenancy.ExportKept).
//
// Starting an export and downloading one are logged with the person's id in identity.action_log, the entry the
// audit log of IPSO-68 builds on, and the key and the archive are never in a log line.

const (
	// archivePattern is the one route that does not pass through bounded: an archive is far over the response
	// cap and takes far longer than a request deadline, so it is streamed and held to limits of its own.
	archivePattern = "GET /v1/exports/{id}/archive"
	// maxDownloads is how many archives one process sends at once. Another download is 429.
	maxDownloads = 2
	// downloadTimeout bounds one download as a whole.
	downloadTimeout = 30 * time.Minute
	// downloadProgress is how long one part may take to reach the client. A client that stalls is dropped, so
	// it cannot hold one of the slots until downloadTimeout.
	downloadProgress = 2 * time.Minute
	// downloadRetry is what a refused download is told to wait.
	downloadRetry = time.Minute
)

type exportHandlers struct {
	db     *sql.DB
	log    *slog.Logger
	writes *writeHandlers
	// slots holds one token for each download in flight.
	slots chan struct{}
}

// exportRoutes are the operations of ADR-0111. Every one asks for the tenant.export action, which only an
// admin who is a person holds (ADR-0108), so no route here reads a query key or a scope.
func exportRoutes(db *sql.DB, log *slog.Logger) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &exportHandlers{db: db, log: log, writes: &writeHandlers{db: db, log: log}, slots: make(chan struct{}, maxDownloads)}
	return []route{
		{"POST /v1/exports", "start_export", authz.TenantExport, nil, nil, http.HandlerFunc(h.start)},
		{"GET /v1/exports/{id}", "get_export", authz.TenantExport, nil, nil, http.HandlerFunc(h.get)},
		{archivePattern, "download_export", authz.TenantExport, nil, nil, http.HandlerFunc(h.download)},
	}
}

type startExportRequest struct {
	Recipient string `json:"recipient"`
}

type exportJSON struct {
	ID          uuid.UUID  `json:"id"`
	State       string     `json:"state"`
	RequestedBy uuid.UUID  `json:"requested_by"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Bytes       *int64     `json:"bytes"`
	SHA256      *string    `json:"sha256"`
}

func exportBody(e tenancy.StoredExport) exportJSON {
	out := exportJSON{
		ID: e.ID, State: e.State, RequestedBy: e.RequestedBy, CreatedAt: e.CreatedAt.UTC(), ExpiresAt: e.ExpiresAt.UTC(),
	}
	if e.FinishedAt != nil {
		finished := e.FinishedAt.UTC()
		out.FinishedAt = &finished
	}
	if e.State == tenancy.ExportReady {
		out.Bytes = &e.Bytes
		sum := hex.EncodeToString(e.SHA256)
		out.SHA256 = &sum
	}
	return out
}

// start records the request. The worker makes the archive, so the answer is 202 and the admin reads the
// export until it is ready. A tenant holds one export: while one is pending or running this is 409, and a
// finished one is replaced.
func (h *exportHandlers) start(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[startExportRequest](w, r)
	if !ok {
		return
	}
	h.writes.write(w, r, "start_export", http.StatusAccepted, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		e, err := tenancy.StartExport(ctx, tx, caller.Tenant, caller.Principal, req.Recipient)
		if err != nil {
			return "", nil, err
		}
		return "export " + e.ID.String(), exportBody(e), nil
	})
}

// get reads an export of the tenant that has not expired. An id the tenant does not have, one that expired,
// and one of another tenant are the same 404.
func (h *exportHandlers) get(w http.ResponseWriter, r *http.Request) {
	caller, ok := personOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	e, err := tenancy.GetExport(r.Context(), h.db, caller.Tenant, id)
	if err != nil {
		writeStoreError(w, h.log, "get_export", err)
		return
	}
	writeJSON(w, http.StatusOK, exportBody(e))
}

// download sends the finished archive. Its entry in the action log and the check that the export is ready
// are one transaction that ends before the first byte, so a download that is refused is not logged and one
// that is logged is one that began. After the first byte the status is sent, so a failure cannot change it:
// the connection is closed with fewer bytes than Content-Length declared, and age authenticates the file, so
// a client never takes a cut archive for a complete one.
func (h *exportHandlers) download(w http.ResponseWriter, r *http.Request) {
	caller, ok := personOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	// The mux hands a HEAD request to a GET route. There is nothing to send for it, and it must not be logged
	// as a download.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, errInvalidQuery)
		return
	}
	// The guard ran under the request deadline. From here the download has its own.
	if take, ok := r.Context().Value(takeOverKey{}).(func() bool); ok && !take() {
		writeError(w, http.StatusServiceUnavailable, errTimeout)
		return
	}
	// The server's own read deadline would end the request context of a long handler, so it moves with the
	// download, from here on and before any query. A writer that cannot set a deadline, such as a test's, is
	// left as it is.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(downloadTimeout))
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", ratelimit.RetryAfter(downloadRetry))
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), downloadTimeout)
	defer cancel()

	var e tenancy.StoredExport
	err := identity.WithAction(ctx, h.db, caller.Tenant, caller.Principal, "api.download_export", func(tx *sql.Tx) (string, error) {
		var err error
		if e, err = tenancy.GetExportTx(ctx, tx, caller.Tenant, id); err != nil {
			return "", err
		}
		if e.State != tenancy.ExportReady {
			return "", tenancy.ErrExportNotReady
		}
		return "export " + id.String(), nil
	})
	if err != nil {
		writeStoreError(w, h.log, "download_export", err)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/octet-stream")
	header.Set("Content-Length", strconv.FormatInt(e.Bytes, 10))
	header.Set("Content-Disposition", `attachment; filename="ipso-export-`+e.ID.String()+`.age"`)
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")

	sum := sha256.New()
	var sent int64
	for seq := 0; seq < e.Parts; seq++ {
		part, err := tenancy.ExportPart(ctx, h.db, caller.Tenant, id, seq)
		if err != nil {
			h.log.Error("an export part could not be read, so the download was cut", "tenant", caller.Tenant, "export", id, "part", seq)
			return
		}
		_ = rc.SetWriteDeadline(time.Now().Add(downloadProgress))
		if _, err := io.Copy(w, bytes.NewReader(part)); err != nil {
			h.log.Info("a download ended before its last byte", "tenant", caller.Tenant, "export", id, "part", seq)
			return
		}
		sum.Write(part)
		sent += int64(len(part))
	}
	if sent != e.Bytes || !bytes.Equal(sum.Sum(nil), e.SHA256) {
		// The bytes are sent. This line is the only sign that the stored archive is not what the job wrote.
		h.log.Error("a downloaded export did not match its checksum", "tenant", caller.Tenant, "export", id)
	}
}

// takeOverKey carries the function with which the download ends the deadline of the guard.
type takeOverKey struct{}

// streamed runs the guard of a streamed route under the request deadline, as bounded does for every other
// route, and lets the handler take over once the guard has passed: the handler calls the function in the
// context, which stops the deadline and says whether it had not already ended. An answer is never held back
// or capped here, because the handler streams it.
func streamed(next http.Handler, limits Limits) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		timer := time.AfterFunc(limits.Timeout, cancel)
		defer timer.Stop()
		ctx = context.WithValue(ctx, takeOverKey{}, func() bool { return timer.Stop() })
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
