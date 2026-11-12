package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// Only the archive of an export skips the response cap and the request deadline. A route added later is in the
// bounded chain unless it is added here on purpose.
func TestOnlyTheArchiveRouteSkipsTheBoundedChain(t *testing.T) {
	mux, _ := mount(routes(nil, time.Now, nil), ciRoutes(nil, nil))
	var via string
	mark := func(name string) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { via = name })
	}
	handler := split(mux, mark("capped"), mark("stream"))
	for _, rt := range allRoutes() {
		method, path, _ := strings.Cut(rt.pattern, " ")
		via = ""
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, targetOf(path), nil))
		want := "capped"
		if rt.pattern == archivePattern {
			want = "stream"
		}
		if via != want {
			t.Errorf("%s went through the %q chain, want %q", rt.pattern, via, want)
		}
	}
	for name, r := range map[string]*http.Request{
		"a path no route has":             httptest.NewRequest(http.MethodGet, "/v1/exports/"+someone.String()+"/archive/more", nil),
		"the export itself":               httptest.NewRequest(http.MethodGet, "/v1/exports/"+someone.String(), nil),
		"another method on the archive":   httptest.NewRequest(http.MethodPost, "/v1/exports/"+someone.String()+"/archive", nil),
		"the list of exports, if any one": httptest.NewRequest(http.MethodGet, "/v1/exports", nil),
	} {
		via = ""
		handler.ServeHTTP(httptest.NewRecorder(), r)
		if via != "capped" {
			t.Errorf("%s went through the %q chain, want capped", name, via)
		}
	}
}

func TestEveryExportRouteAsksForTheExportActionAndReadsNothingFromTheQuery(t *testing.T) {
	routes := exportRoutes(nil, nil)
	want := map[string]string{"POST /v1/exports": "start_export", "GET /v1/exports/{id}": "get_export", archivePattern: "download_export"}
	if len(routes) != len(want) {
		t.Fatalf("%d export routes, want %d", len(routes), len(want))
	}
	for _, rt := range routes {
		if want[rt.pattern] != rt.op || rt.action != authz.TenantExport || len(rt.keys) != 0 || rt.targets != nil {
			t.Errorf("%s: op %q, action %q, keys %v, targets set %v", rt.pattern, rt.op, rt.action, rt.keys, rt.targets != nil)
		}
	}
}

func TestTheStreamedChainHoldsTheGuardToTheRequestDeadlineAndLetsTheHandlerTakeOver(t *testing.T) {
	limits := Limits{Timeout: 40 * time.Millisecond}
	run := func(guardTakes time.Duration) (tookOver bool, afterwards error) {
		handler := streamed(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			time.Sleep(guardTakes)
			take, ok := r.Context().Value(takeOverKey{}).(func() bool)
			if !ok {
				t.Error("the handler has no way to take over")
				return
			}
			tookOver = take()
			// Once the handler has taken over, the deadline of the guard no longer ends the request.
			time.Sleep(2 * limits.Timeout)
			afterwards = r.Context().Err()
		}), limits)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		return tookOver, afterwards
	}
	if tookOver, afterwards := run(0); !tookOver || afterwards != nil {
		t.Errorf("a guard that is quick: took over %v, the request ended with %v", tookOver, afterwards)
	}
	if tookOver, _ := run(3 * limits.Timeout); tookOver {
		t.Error("a guard that took longer than the deadline let the handler take over")
	}
}

func personRequest(method, target string, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r = r.WithContext(context.WithValue(r.Context(), callerKey{}, Caller{Tenant: tenantFor, Principal: someone}))
	return r
}

var tenantFor = uuid.MustParse("00000000-0000-4000-8000-0000000000c1")

func TestTheDownloadRefusesWhatItCanBeforeTheDatabaseIsAsked(t *testing.T) {
	h := &exportHandlers{log: slog.New(slog.DiscardHandler), slots: make(chan struct{}, maxDownloads)}
	target := "/v1/exports/" + someone.String() + "/archive"
	call := func(r *http.Request, id string) *httptest.ResponseRecorder {
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		h.download(w, r)
		return w
	}

	if w := call(httptest.NewRequest(http.MethodGet, target, nil), someone.String()); w.Code != http.StatusUnauthorized {
		t.Errorf("no caller: %d, want 401", w.Code)
	}
	if w := call(personRequest(http.MethodGet, target, ""), "not-an-id"); w.Code != http.StatusBadRequest {
		t.Errorf("a bad id: %d, want 400", w.Code)
	}
	if w := call(personRequest(http.MethodHead, target, ""), someone.String()); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Errorf("HEAD: %d with Allow %q, want 405 and GET", w.Code, w.Header().Get("Allow"))
	}

	// With every slot taken, another download is 429 with a wait, and the slots stay as they were.
	for range maxDownloads {
		h.slots <- struct{}{}
	}
	w := call(personRequest(http.MethodGet, target, ""), someone.String())
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" || !strings.Contains(w.Body.String(), errRateLimited) {
		t.Errorf("no slot: %d, Retry-After %q, body %s, want 429 and 60", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if len(h.slots) != maxDownloads {
		t.Errorf("%d slots are taken, want %d", len(h.slots), maxDownloads)
	}

	// A guard that ran out of time before the handler began leaves nothing to stream: 503, and no slot is taken.
	h = &exportHandlers{log: slog.New(slog.DiscardHandler), slots: make(chan struct{}, maxDownloads)}
	r := personRequest(http.MethodGet, target, "")
	r = r.WithContext(context.WithValue(r.Context(), takeOverKey{}, func() bool { return false }))
	if w := call(r, someone.String()); w.Code != http.StatusServiceUnavailable || len(h.slots) != 0 {
		t.Errorf("a late guard: %d with %d slots taken, want 503 and none", w.Code, len(h.slots))
	}
}

func TestStartingAnExportRefusesABodyThatIsNotOneRecipientBeforeTheDatabaseIsAsked(t *testing.T) {
	h := &exportHandlers{log: slog.New(slog.DiscardHandler), writes: &writeHandlers{log: slog.New(slog.DiscardHandler)}}
	for name, c := range map[string]struct {
		contentType string
		body        string
		want        int
	}{
		"not JSON":              {"application/json", `recipient`, http.StatusBadRequest},
		"a field it has not":    {"application/json", `{"recipient":"` + aRecipient + `","tenant":"` + tenantFor.String() + `"}`, http.StatusBadRequest},
		"a list of recipients":  {"application/json", `{"recipients":["` + aRecipient + `"]}`, http.StatusBadRequest},
		"data after the body":   {"application/json", `{"recipient":"` + aRecipient + `"} {}`, http.StatusBadRequest},
		"another content type":  {"text/plain", `{"recipient":"` + aRecipient + `"}`, http.StatusUnsupportedMediaType},
		"no content type":       {"", `{"recipient":"` + aRecipient + `"}`, http.StatusUnsupportedMediaType},
		"a recipient as a list": {"application/json", `{"recipient":["` + aRecipient + `"]}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			r := personRequest(http.MethodPost, "/v1/exports", c.body)
			r.Header.Set("Content-Type", c.contentType)
			w := httptest.NewRecorder()
			h.start(w, r)
			if w.Code != c.want {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, c.want)
			}
			if strings.Contains(w.Body.String(), aRecipient) {
				t.Errorf("the answer quotes the key: %s", w.Body)
			}
		})
	}
}

func TestAnExportIsAnswerWithoutTheSizeAndTheSumUntilItIsReady(t *testing.T) {
	created := time.Date(2026, 11, 12, 10, 0, 0, 0, time.FixedZone("CET", 3600))
	finished := created.Add(time.Minute)
	pending := exportBody(tenancy.StoredExport{ID: someone, State: tenancy.ExportPending, RequestedBy: tenantFor, CreatedAt: created, ExpiresAt: created.Add(tenancy.ExportKept)})
	text, _ := json.Marshal(pending)
	for _, want := range []string{`"state":"pending"`, `"finished_at":null`, `"bytes":null`, `"sha256":null`, `"created_at":"2026-11-12T09:00:00Z"`} {
		if !strings.Contains(string(text), want) {
			t.Errorf("a pending export is %s, want %s", text, want)
		}
	}
	sum := make([]byte, 32)
	sum[31] = 0xab
	ready := exportBody(tenancy.StoredExport{ID: someone, State: tenancy.ExportReady, RequestedBy: tenantFor, CreatedAt: created, FinishedAt: &finished,
		ExpiresAt: finished.Add(tenancy.ExportKept), Bytes: 4096, Parts: 1, SHA256: sum})
	text, _ = json.Marshal(ready)
	for _, want := range []string{`"state":"ready"`, `"finished_at":"2026-11-12T09:01:00Z"`, `"bytes":4096`, `"sha256":"` + strings.Repeat("00", 31) + `ab"`} {
		if !strings.Contains(string(text), want) {
			t.Errorf("a ready export is %s, want %s", text, want)
		}
	}
	failed := exportBody(tenancy.StoredExport{ID: someone, State: tenancy.ExportFailed, FinishedAt: &finished, Bytes: 7, SHA256: sum})
	if failed.Bytes != nil || failed.SHA256 != nil {
		t.Errorf("a failed export shows a size and a sum: %+v", failed)
	}
}

func TestTheExportErrorsAreTheStatusesTheDocumentLists(t *testing.T) {
	for err, want := range map[error]int{
		tenancy.ErrBadRecipient:                          http.StatusBadRequest,
		fmt.Errorf("start: %w", tenancy.ErrBadRecipient): http.StatusBadRequest,
		tenancy.ErrNoExport:                              http.StatusNotFound,
		tenancy.ErrExportNotReady:                        http.StatusConflict,
		errors.New("anything else"):                      http.StatusInternalServerError,
	} {
		w := httptest.NewRecorder()
		writeStoreError(w, slog.New(slog.DiscardHandler), "start_export", err)
		var body map[string]string
		if w.Code != want || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 || strings.Contains(w.Body.String(), "anything else") {
			t.Errorf("%v: %d %s, want %d and the code alone", err, w.Code, w.Body, want)
		}
	}
}

// The three operations are the write start_export and the two reads of exportOps, and the matrix says that only
// an admin takes each one.
func TestTheMatrixHoldsEveryExportOperationForTheAdminAlone(t *testing.T) {
	var mounted []string
	for _, rt := range exportRoutes(nil, nil) {
		mounted = append(mounted, rt.op)
	}
	want := slices.Concat([]string{"start_export"}, exportOps)
	slices.Sort(mounted)
	slices.Sort(want)
	if !slices.Equal(mounted, want) {
		t.Fatalf("the routes are %v, the matrix names %v", mounted, want)
	}
	for _, op := range mounted {
		if !slices.Equal(mayCall[op], []string{identity.RoleAdmin}) {
			t.Errorf("%s may be taken by %v, want the admin alone", op, mayCall[op])
		}
	}
	if !slices.Contains(writeOps, "start_export") || slices.Contains(writeOps, "get_export") || slices.Contains(writeOps, "download_export") {
		t.Errorf("writeOps = %v: only start_export writes", writeOps)
	}
}

func TestAnExportAskedForTooSoonIsA429WithTheWait(t *testing.T) {
	w := httptest.NewRecorder()
	writeStoreError(w, slog.New(slog.DiscardHandler), "start_export", fmt.Errorf("start: %w", &tenancy.TooSoonError{Wait: 90*time.Second + time.Millisecond}))
	var body map[string]string
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "91" || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] != errRateLimited {
		t.Errorf("%d with Retry-After %q and %s, want 429, 91 and the rate limit code", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}
