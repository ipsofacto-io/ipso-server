//go:build integration

package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// auditLine is a line of the audit log route as a SIEM reads it.
type auditLine struct {
	Format      string `json:"format"`
	Seq         int64  `json:"seq"`
	ID          string `json:"id"`
	At          string `json:"at"`
	Principal   string `json:"principal"`
	Responsible string `json:"responsible"`
	Action      string `json:"action"`
	Subject     string `json:"subject"`
	Prev        string `json:"prev"`
	Hash        string `json:"hash"`
}

// readLines parses a JSONL body and refuses a line with a key the document does not have.
func readLines(t *testing.T, body []byte) []auditLine {
	t.Helper()
	var lines []auditLine
	if len(body) > 0 && !bytes.HasSuffix(body, []byte("\n")) {
		t.Fatalf("the body does not end in a newline: %q", body[max(0, len(body)-20):])
	}
	for _, raw := range bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var line auditLine
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&line); err != nil {
			t.Fatalf("a line is not an audit log line: %v: %s", err, raw)
		}
		lines = append(lines, line)
	}
	return lines
}

// holds checks a run of lines the way a reader does with nothing but the lines: each hash is the hash of
// its fields, each line continues the one before it, and the first continues from the hash given.
func holds(t *testing.T, lines []auditLine, prev string, seq int64) {
	t.Helper()
	for _, l := range lines {
		at, err := time.Parse("2006-01-02T15:04:05.000000Z", l.At)
		if err != nil {
			t.Fatalf("seq %d: %v", l.Seq, err)
		}
		e := identity.LogEntry{Seq: l.Seq, ID: uuid.MustParse(l.ID), At: at, Principal: uuid.MustParse(l.Principal), Responsible: uuid.MustParse(l.Responsible), Action: l.Action, Subject: l.Subject}
		raw, err := hex.DecodeString(l.Prev)
		if err != nil || len(raw) != 32 {
			t.Fatalf("seq %d: prev %q", l.Seq, l.Prev)
		}
		copy(e.Prev[:], raw)
		sum := e.Sum()
		switch {
		case l.Format != identity.LogFormat:
			t.Fatalf("seq %d: format %q", l.Seq, l.Format)
		case l.Seq != seq+1:
			t.Fatalf("seq %d after %d", l.Seq, seq)
		case l.Prev != prev:
			t.Fatalf("seq %d continues %s, want %s", l.Seq, l.Prev, prev)
		case l.Hash != hex.EncodeToString(sum[:]):
			t.Fatalf("seq %d: the hash is not the hash of the line", l.Seq)
		}
		prev, seq = l.Hash, l.Seq
	}
}

func (f *fixture) record(t *testing.T, subject string, action, text string) {
	t.Helper()
	c := f.callers[subject]
	if _, err := identity.RecordAction(t.Context(), f.db, c.Tenant, c.Principal, action, text); err != nil {
		t.Fatal(err)
	}
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"

func TestTheAuditLogRouteWritesTheChainOfTheTenantAsJSONLines(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	for i := 1; i <= 3; i++ {
		f.record(t, personA, "api.record_waiver", fmt.Sprintf("waiver %d", i))
	}
	f.record(t, personB, "api.record_waiver", "waiver of another tenant")
	auditor := f.token(t, auditorA)

	w := c.exchange(t, handler, http.MethodGet, "/v1/audit-log", auditor, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/jsonl" {
		t.Errorf("content type %q", got)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers %v", w.Header())
	}
	lines := readLines(t, w.Body.Bytes())
	if len(lines) != 3 {
		t.Fatalf("%d lines: %s", len(lines), w.Body)
	}
	holds(t, lines, zeros, 0)
	for i, l := range lines {
		if l.Principal != f.callers[personA].Principal.String() || l.Responsible != l.Principal || l.Action != "api.record_waiver" || l.Subject != fmt.Sprintf("waiver %d", i+1) {
			t.Errorf("line %d: %+v", i+1, l)
		}
	}
	if strings.Contains(w.Body.String(), "another tenant") {
		t.Fatal("the answer holds an entry of another tenant")
	}

	// A reader continues from the last position it kept, and the page continues the chain.
	rest := c.exchange(t, handler, http.MethodGet, "/v1/audit-log?after=2", auditor, "", nil)
	tail := readLines(t, rest.Body.Bytes())
	if rest.Code != http.StatusOK || len(tail) != 1 || tail[0].Seq != 3 {
		t.Fatalf("after 2: %d %s", rest.Code, rest.Body)
	}
	holds(t, tail, lines[1].Hash, 2)
	none := c.exchange(t, handler, http.MethodGet, "/v1/audit-log?after=3", auditor, "", nil)
	if none.Code != http.StatusOK || none.Body.Len() != 0 {
		t.Fatalf("after the head: %d %q", none.Code, none.Body)
	}
	f.record(t, personA, "api.record_baseline", "baseline 9")
	more := c.exchange(t, handler, http.MethodGet, "/v1/audit-log?after=3", auditor, "", nil)
	fresh := readLines(t, more.Body.Bytes())
	if len(fresh) != 1 || fresh[0].Seq != 4 {
		t.Fatalf("a new entry: %s", more.Body)
	}
	holds(t, fresh, lines[2].Hash, 3)

	// Another tenant has a chain of its own, from 1.
	other := readLines(t, c.exchange(t, handler, http.MethodGet, "/v1/audit-log", f.token(t, personB), "", nil).Body.Bytes())
	if len(other) != 1 || other[0].Seq != 1 || other[0].Subject != "waiver of another tenant" {
		t.Fatalf("tenant B: %+v", other)
	}
	holds(t, other, zeros, 0)
}

func TestTheAuditLogRouteRefusesWhatItDoesNotUnderstand(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	f.record(t, personA, "api.record_waiver", "waiver 1")
	auditor := f.token(t, auditorA)
	for _, target := range []string{
		"/v1/audit-log?after=-1",
		"/v1/audit-log?after=x",
		"/v1/audit-log?after=",
		"/v1/audit-log?after=1.5",
		"/v1/audit-log?after=1e3",
		"/v1/audit-log?after=99999999999999999999",
		"/v1/audit-log?after=1&after=2",
		"/v1/audit-log?limit=10",
		"/v1/audit-log?tenant=" + tenantB.String(),
	} {
		// The request is not the document's, so only the route's own answer is checked.
		w := call(t, handler, http.MethodGet, target, auditor)
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("%s: %d %s", target, w.Code, w.Body)
		}
	}
	if w := call(t, handler, http.MethodGet, "/v1/audit-log", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}
}

// Who may read the log, and that reading it writes nothing: a poller would otherwise feed on its own entries.
func TestOnlyAnAuditorOrAnAdminReadsTheAuditLogAndReadingIsNotLogged(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	f.record(t, personA, "api.record_waiver", "waiver 1")
	for subject, want := range map[string]int{
		personA: http.StatusOK, auditorA: http.StatusOK, viewerA: http.StatusForbidden, nobodyA: http.StatusForbidden,
		ownerA: http.StatusForbidden, approverA: http.StatusForbidden, contributorA: http.StatusForbidden, agentA: http.StatusForbidden,
	} {
		if w := call(t, handler, http.MethodGet, "/v1/audit-log", f.token(t, subject)); w.Code != want {
			t.Errorf("%s: %d, want %d", subject, w.Code, want)
		}
	}
	report, err := identity.VerifyLog(t.Context(), f.db, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact || report.Entries != 1 {
		t.Fatalf("a read or a refusal wrote an entry: %+v", report)
	}
}

// A page of long subjects ends before the response cap and the reader continues from its last line, so
// no answer is refused whole and the pages together are the chain.
func TestAPageEndsBeforeTheByteCapAndThePagesMakeTheChain(t *testing.T) {
	f := newFixture(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	person := f.callers[personA]
	const total = 900
	if _, err := pgtest.Exec(t.Context(), f.db, tenantA.String(), `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
		SELECT $1, $2, $2, 'api.x', repeat('x', 1900) || g FROM generate_series(1, $3::int) AS g`, tenantA, person.Principal, total); err != nil {
		t.Fatal(err)
	}
	auditor := f.token(t, auditorA)
	var got []auditLine
	pages := 0
	prev, seq := zeros, int64(0)
	for len(got) < total {
		w := call(t, handler, http.MethodGet, fmt.Sprintf("/v1/audit-log?after=%d", seq), auditor)
		if w.Code != http.StatusOK {
			t.Fatalf("after %d: %d %.200s", seq, w.Code, w.Body)
		}
		page := readLines(t, w.Body.Bytes())
		if len(page) == 0 {
			t.Fatalf("an empty page after %d of %d", len(got), total)
		}
		if w.Body.Len() > auditLogBytes+4096 {
			t.Fatalf("a page of %d bytes is past the cap of %d", w.Body.Len(), auditLogBytes)
		}
		holds(t, page, prev, seq)
		got = append(got, page...)
		prev, seq = page[len(page)-1].Hash, page[len(page)-1].Seq
		pages++
	}
	if pages < 2 || len(got) != total {
		t.Fatalf("%d lines in %d pages", len(got), pages)
	}
}
