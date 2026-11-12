//go:build integration

package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// newRecipient is a key pair: the identity that opens an archive and the public key an admin gives.
func newRecipient(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity, identity.Recipient().String()
}

func (s scribe) exportRows() int {
	s.t.Helper()
	var n int
	if err := s.f.admin.QueryRowContext(s.t.Context(), `SELECT count(*) FROM tenancy.export`).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s scribe) partsOf(id uuid.UUID) int {
	s.t.Helper()
	var n int
	if err := s.f.admin.QueryRowContext(s.t.Context(), `SELECT count(*) FROM tenancy.export_part WHERE export_id = $1`, id).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

// loggedAs counts the entries of the action log with this action.
func (s scribe) loggedAs(action string) int {
	s.t.Helper()
	n := 0
	for _, a := range s.logged() {
		if a.Action == action {
			n++
		}
	}
	return n
}

// asked starts an export as the admin of tenant A and has the worker make it.
func (s scribe) asked(recipient string) uuid.UUID {
	s.t.Helper()
	id := idOf(s.t, s.expect(http.StatusAccepted, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient}), "id")
	if _, err := tenancy.RunStoredExport(s.t.Context(), s.f.db, tenantA, id); err != nil {
		s.t.Fatalf("make the export: %v", err)
	}
	return id
}

func archiveOf(id uuid.UUID) string { return "/v1/exports/" + id.String() + "/archive" }

// age moves every export back in time by an hour, as if it had been made that long ago, so the cooldown is over.
func (s scribe) age() {
	s.t.Helper()
	if _, err := s.f.admin.ExecContext(s.t.Context(), `
		UPDATE tenancy.export
		SET created_at = created_at - interval '1 hour', finished_at = finished_at - interval '1 hour', expires_at = expires_at - interval '1 hour'`); err != nil {
		s.t.Fatal(err)
	}
}

// An admin asks for the export of the tenant, the worker makes it, and the archive that comes down is the one
// the operator command writes: only the holder of the key opens it, and it names the tenant of the token.
func TestAnAdminAsksForAnExportAndDownloadsTheArchiveOfTheTenant(t *testing.T) {
	s := newScribe(t)
	f := s.f
	identity, recipient := newRecipient(t)

	requested := s.expect(http.StatusAccepted, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient})
	id := idOf(t, requested, "id")
	if requested["state"] != "pending" || requested["finished_at"] != nil || requested["bytes"] != nil || requested["sha256"] != nil ||
		requested["requested_by"] != f.callers[personA].Principal.String() {
		t.Fatalf("the request answered %v", requested)
	}
	created, _ := time.Parse(time.RFC3339Nano, requested["created_at"].(string))
	expires, _ := time.Parse(time.RFC3339Nano, requested["expires_at"].(string))
	if d := expires.Sub(created); d != 24*time.Hour {
		t.Errorf("a request expires after %s, want 24 hours", d)
	}
	if status := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/exports/"+id.String(), nil); status["state"] != "pending" {
		t.Fatalf("the export is %v, want pending", status)
	}
	// Nothing can be downloaded yet, and a second request is refused while this one is under way. Neither is logged.
	s.expect(http.StatusConflict, personA, http.MethodGet, archiveOf(id), nil)
	s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient})
	if s.loggedAs("api.download_export") != 0 || s.loggedAs("api.start_export") != 1 || s.exportRows() != 1 {
		t.Fatalf("%d downloads and %d starts logged, %d exports stored", s.loggedAs("api.download_export"), s.loggedAs("api.start_export"), s.exportRows())
	}

	if _, err := tenancy.RunStoredExport(t.Context(), f.db, tenantA, id); err != nil {
		t.Fatal(err)
	}
	ready := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
	size, _ := ready["bytes"].(float64)
	sum, _ := ready["sha256"].(string)
	if ready["state"] != "ready" || size <= 0 || len(sum) != 64 || ready["finished_at"] == nil {
		t.Fatalf("the export is %v, want ready with a size and a sum", ready)
	}

	w := s.c.exchange(t, s.h, http.MethodGet, archiveOf(id), f.token(t, personA), "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the download answered %d %s", w.Code, w.Body)
	}
	for header, want := range map[string]string{
		"Content-Type":           "application/octet-stream",
		"Content-Length":         strconv.Itoa(int(size)),
		"Content-Disposition":    `attachment; filename="ipso-export-` + id.String() + `.age"`,
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s is %q, want %q", header, got, want)
		}
	}
	archive := w.Body.Bytes()
	if got := sha256.Sum256(archive); float64(len(archive)) != size || hex.EncodeToString(got[:]) != sum {
		t.Fatalf("the body is %d bytes and the sum differs, the export says %v bytes and %s", len(archive), size, sum)
	}
	if s.loggedAs("api.download_export") != 1 {
		t.Errorf("%d downloads were logged, want 1", s.loggedAs("api.download_export"))
	}

	// Only the holder of the key opens it, and what is inside is tenant A and nobody else.
	stranger, _ := newRecipient(t)
	if _, err := age.Decrypt(bytes.NewReader(archive), stranger); err == nil {
		t.Fatal("the archive opened with a key it was not encrypted to")
	}
	plain, err := age.Decrypt(bytes.NewReader(archive), identity)
	if err != nil {
		t.Fatalf("the holder of the key cannot open the archive: %v", err)
	}
	zr, err := gzip.NewReader(plain)
	if err != nil {
		t.Fatal(err)
	}
	header, err := bufio.NewReader(zr).ReadString('\n')
	if err != nil || !strings.Contains(header, `"format":"ipso-tenant-export/1"`) || !strings.Contains(header, tenantA.String()) || strings.Contains(header, tenantB.String()) {
		t.Fatalf("the header is %q (%v)", header, err)
	}

	// Tenant B's admin sees nothing of it.
	s.expect(http.StatusNotFound, personB, http.MethodGet, "/v1/exports/"+id.String(), nil)
	s.expect(http.StatusNotFound, personB, http.MethodGet, archiveOf(id), nil)
	// A request right after it is too soon, with the wait, and the export is untouched.
	soon := s.raw(personA, http.MethodPost, "/v1/exports", "application/json", `{"recipient":"`+recipient+`"}`)
	wait, _ := strconv.Atoi(soon.Header().Get("Retry-After"))
	if soon.Code != http.StatusTooManyRequests || wait < 1 || wait > int(tenancy.ExportCooldown.Seconds()) {
		t.Fatalf("a request right after it: %d with Retry-After %q, want 429 and a wait within the cooldown", soon.Code, soon.Header().Get("Retry-After"))
	}
	s.expect(http.StatusOK, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
	// After the cooldown a request replaces it. The old id is no longer served, and its parts stay for a download in flight.
	s.age()
	next := idOf(t, s.expect(http.StatusAccepted, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient}), "id")
	if next == id || s.exportRows() != 2 || s.partsOf(id) == 0 {
		t.Fatalf("the next export is %s (the old one %s), %d stored, %d old parts", next, id, s.exportRows(), s.partsOf(id))
	}
	s.expect(http.StatusNotFound, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
	s.expect(http.StatusNotFound, personA, http.MethodGet, archiveOf(id), nil)
}

// Every role but the admin is refused all three routes with the plain 403, and a refusal stores nothing and
// logs nothing. Tenant B's admin takes the routes for tenant B and can start its own export.
func TestOnlyAnAdminWhoIsAPersonTakesTheExportRoutes(t *testing.T) {
	s := newScribe(t)
	_, recipient := newRecipient(t)
	id := s.asked(recipient)
	rows, logged := s.exportRows(), len(s.logged())

	for _, op := range append([]string{"start_export"}, exportOps...) {
		for subject, role := range map[string]string{agentA: "agent", viewerA: "viewer", auditorA: "auditor", contributorA: "contributor", approverA: "approver", ownerA: "decision-owner", nobodyA: ""} {
			for _, allowed := range mayCall[op] {
				if allowed == role {
					t.Fatalf("the matrix lets %q take %s", role, op)
				}
			}
			method, target, body := http.MethodPost, "/v1/exports", `{"recipient":"`+recipient+`"}`
			switch op {
			case "get_export":
				method, target, body = http.MethodGet, "/v1/exports/"+id.String(), ""
			case "download_export":
				method, target, body = http.MethodGet, archiveOf(id), ""
			}
			contentType := ""
			if body != "" {
				contentType = "application/json"
			}
			if w := s.raw(subject, method, target, contentType, body); !refusedPlainly(t, w) {
				t.Errorf("%s as %s: %d %s, want a plain 403", op, subject, w.Code, w.Body)
			}
		}
	}
	if s.exportRows() != rows || len(s.logged()) != logged {
		t.Errorf("a refusal changed %d exports and %d log entries", s.exportRows()-rows, len(s.logged())-logged)
	}

	// The admin of tenant B asks for its own, which tenant A's admin cannot read.
	other := idOf(t, s.expect(http.StatusAccepted, personB, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient}), "id")
	s.expect(http.StatusNotFound, personA, http.MethodGet, "/v1/exports/"+other.String(), nil)
	s.expect(http.StatusOK, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
}

// A key the route cannot read is 400, the answer never quotes it, and nothing is stored or logged.
func TestAnExportIsRefusedForARecipientThatIsNotOnePublicKey(t *testing.T) {
	s := newScribe(t)
	keyIdentity, key := newRecipient(t)
	_, other := newRecipient(t)
	corrupted := key[:len(key)-1] + "q"
	if strings.HasSuffix(key, "q") {
		corrupted = key[:len(key)-1] + "p"
	}
	for name, recipient := range map[string]string{
		"empty":             "",
		"a word":            "hunter2",
		"a private key":     keyIdentity.String(),
		"two keys":          key + "\n" + other,
		"a comment":         "# " + key,
		"a space":           key + " ",
		"a bad checksum":    corrupted,
		"a plugin":          "age1yubikey1qdoesnotexist",
		"too long":          "age1" + strings.Repeat("q", 5000),
		"upper case":        strings.ToUpper(key),
		"a list of a key":   `["` + key + `"]`,
		"a hybrid prefix":   "age1pq1",
		"an ssh public key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ",
	} {
		before := len(s.logged())
		body := mustJSON(t, map[string]any{"recipient": recipient})
		if strings.HasPrefix(recipient, "[") {
			body = `{"recipient":` + recipient + `}`
		}
		w := s.raw(personA, http.MethodPost, "/v1/exports", "application/json", body)
		if w.Code != http.StatusBadRequest || (recipient != "" && strings.Contains(w.Body.String(), recipient)) {
			t.Errorf("%s: %d %s, want 400 that does not quote it", name, w.Code, w.Body)
		}
		if s.exportRows() != 0 || len(s.logged()) != before {
			t.Fatalf("%s stored %d exports and logged %d entries", name, s.exportRows(), len(s.logged())-before)
		}
	}
	for name, body := range map[string]string{
		"a tenant in the body":  `{"recipient":"` + key + `","tenant":"` + tenantB.String() + `"}`,
		"no recipient":          `{}`,
		"a second recipient":    `{"recipient":"` + key + `","recipients":["` + other + `"]}`,
		"a body that is a list": `["` + key + `"]`,
	} {
		if w := s.raw(personA, http.MethodPost, "/v1/exports", "application/json", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, w.Code, w.Body)
		}
	}
	if w := s.raw(personA, http.MethodPost, "/v1/exports", "text/plain", key); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a key as plain text: %d, want 415", w.Code)
	}
	if s.exportRows() != 0 {
		t.Fatalf("%d exports were stored", s.exportRows())
	}
}

func TestAnExportThatExpiredIsGoneAndAHeadRequestIsNotADownload(t *testing.T) {
	s := newScribe(t)
	_, recipient := newRecipient(t)
	id := s.asked(recipient)
	// A HEAD request reaches the route of the GET and must not be logged as a download or send a body.
	logged := s.loggedAs("api.download_export")
	w := s.raw(personA, http.MethodHead, archiveOf(id), "", "")
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet || s.loggedAs("api.download_export") != logged {
		t.Errorf("HEAD: %d with Allow %q, %d logged", w.Code, w.Header().Get("Allow"), s.loggedAs("api.download_export")-logged)
	}
	if _, err := s.f.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET created_at = now() - interval '3 days', finished_at = now() - interval '2 days', expires_at = now() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	s.expect(http.StatusNotFound, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
	s.expect(http.StatusNotFound, personA, http.MethodGet, archiveOf(id), nil)
	// The next request is not held back by an export that is over and has not been swept yet.
	s.expect(http.StatusAccepted, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient})
	if s.exportRows() != 2 || s.partsOf(id) == 0 {
		t.Errorf("%d exports stored, %d parts of the expired one, want the new request and the old one until the sweep", s.exportRows(), s.partsOf(id))
	}
}

// bigExport stores a ready export of a given number of random parts for tenant A, without the worker, and
// returns its id, size and sum. It is far over the response cap of every other route.
func (s scribe) bigExport(parts int) (id uuid.UUID, size int64, sum string) {
	s.t.Helper()
	admin := s.f.admin
	data := make([][]byte, parts)
	hash := sha256.New()
	for i := range data {
		data[i] = make([]byte, tenancy.ExportPartSize)
		if _, err := rand.Read(data[i]); err != nil {
			s.t.Fatal(err)
		}
		hash.Write(data[i])
		size += int64(len(data[i]))
	}
	if err := admin.QueryRowContext(s.t.Context(), `
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, state, finished_at, expires_at, bytes, parts, sha256)
		VALUES ($1, $2, $3, 'ready', now(), now() + interval '1 day', $4, $5, $6) RETURNING id`,
		tenantA, s.f.callers[personA].Principal, "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p", size, parts, hash.Sum(nil)).Scan(&id); err != nil {
		s.t.Fatal(err)
	}
	for i, part := range data {
		if _, err := admin.ExecContext(s.t.Context(), `INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data) VALUES ($1, $2, $3, $4)`, tenantA, id, i, part); err != nil {
			s.t.Fatal(err)
		}
	}
	return id, size, hex.EncodeToString(hash.Sum(nil))
}

// serve runs the API on a real server, with the read and write timeouts the binary has but shorter, so a
// download that outlasts them proves that the handler moves them.
func (s scribe) serve(timeout time.Duration) *httptest.Server {
	s.t.Helper()
	srv := httptest.NewUnstartedServer(s.h)
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = timeout, timeout
	srv.Start()
	s.t.Cleanup(srv.Close)
	return srv
}

func (s scribe) get(srv *httptest.Server, subject, target string) *http.Response {
	s.t.Helper()
	req, err := http.NewRequestWithContext(s.t.Context(), http.MethodGet, srv.URL+target, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", s.f.token(s.t, subject))
	resp, err := srv.Client().Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

// A download that takes far longer than the timeouts of the server arrives whole: the handler moves the
// deadlines with every part, and the slow reader is the only thing that makes it slow.
func TestADownloadThatOutlastsTheServerTimeoutsArrivesWhole(t *testing.T) {
	s := newScribe(t)
	id, size, sum := s.bigExport(24)
	srv := s.serve(400 * time.Millisecond)
	resp := s.get(srv, personA, archiveOf(id))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.ContentLength != size {
		t.Fatalf("status %d, length %d, want 200 and %d", resp.StatusCode, resp.ContentLength, size)
	}
	hash := sha256.New()
	buf := make([]byte, tenancy.ExportPartSize)
	var total int64
	started := time.Now()
	for {
		n, err := io.ReadFull(resp.Body, buf)
		hash.Write(buf[:n])
		total += int64(n)
		if err != nil {
			if err != io.ErrUnexpectedEOF && err != io.EOF {
				t.Fatalf("read after %d bytes: %v", total, err)
			}
			break
		}
		time.Sleep(60 * time.Millisecond)
	}
	if elapsed := time.Since(started); elapsed < time.Second {
		t.Fatalf("the download took %s, so it never outlasted the timeouts of the server", elapsed)
	}
	if total != size || hex.EncodeToString(hash.Sum(nil)) != sum {
		t.Fatalf("got %d of %d bytes, or the sum differs", total, size)
	}
}

// When a part cannot be read the status is already sent. The connection ends short of the length it declared, so
// the client sees a failed download and never a short archive.
func TestADownloadThatCannotFinishEndsShortOfItsLength(t *testing.T) {
	s := newScribe(t)
	id, size, _ := s.bigExport(3)
	if _, err := s.f.admin.ExecContext(t.Context(), `DELETE FROM tenancy.export_part WHERE export_id = $1 AND seq = 2`, id); err != nil {
		t.Fatal(err)
	}
	srv := s.serve(5 * time.Second)
	resp := s.get(srv, personA, archiveOf(id))
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || err != io.ErrUnexpectedEOF || int64(len(got)) >= size || int64(len(got)) != 2*tenancy.ExportPartSize {
		t.Fatalf("status %d, %d of %d bytes, error %v, want a cut download", resp.StatusCode, len(got), size, err)
	}
	if s.loggedAs("api.download_export") != 1 {
		t.Errorf("%d downloads were logged, want the one that began", s.loggedAs("api.download_export"))
	}
}

// A process sends two archives at once. A third request is 429 with a wait, and it is served as soon as one of the
// two has ended, even when that one was abandoned by its client.
func TestAtMostTwoDownloadsRunAtOnceAndAnAbandonedOneFreesItsSlot(t *testing.T) {
	s := newScribe(t)
	id, _, _ := s.bigExport(32)
	srv := s.serve(5 * time.Second)

	var held []*http.Response
	for range maxDownloads {
		resp := s.get(srv, personA, archiveOf(id))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a download answered %d", resp.StatusCode)
		}
		// One byte, and then the client stops reading, so the handler blocks on a full connection.
		if _, err := io.ReadFull(resp.Body, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		held = append(held, resp)
	}
	refused := s.get(srv, personA, archiveOf(id))
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests || refused.Header.Get("Retry-After") != "60" {
		t.Fatalf("a third download answered %d with Retry-After %q, want 429 and 60", refused.StatusCode, refused.Header.Get("Retry-After"))
	}
	for _, resp := range held {
		_ = resp.Body.Close()
	}
	eventually := time.Now().Add(20 * time.Second)
	for {
		resp := s.get(srv, personA, archiveOf(id))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(eventually) {
			t.Fatalf("no slot was freed, the last answer was %d", resp.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// A request that replaces an export does not end a download of it that is in flight: the parts stay, and the
// download arrives whole, while the old id is no longer served to anyone else.
func TestAReplacedExportStillFinishesADownloadInFlight(t *testing.T) {
	s := newScribe(t)
	_, recipient := newRecipient(t)
	id, size, sum := s.bigExport(24)
	srv := s.serve(5 * time.Second)

	resp := s.get(srv, personA, archiveOf(id))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the download answered %d", resp.StatusCode)
	}
	hash := sha256.New()
	buf := make([]byte, tenancy.ExportPartSize)
	n, err := io.ReadFull(resp.Body, buf)
	if err != nil {
		t.Fatal(err)
	}
	hash.Write(buf[:n])
	total := int64(n)

	s.age()
	s.expect(http.StatusAccepted, personA, http.MethodPost, "/v1/exports", map[string]any{"recipient": recipient})
	s.expect(http.StatusNotFound, personA, http.MethodGet, "/v1/exports/"+id.String(), nil)
	s.expect(http.StatusNotFound, personA, http.MethodGet, archiveOf(id), nil)

	rest, err := io.Copy(hash, resp.Body)
	if err != nil || total+rest != size || hex.EncodeToString(hash.Sum(nil)) != sum {
		t.Fatalf("the download got %d of %d bytes (%v), or the sum differs", total+rest, size, err)
	}
}
