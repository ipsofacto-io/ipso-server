//go:build integration

package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// The merge instants in q3-before-correction and q3-after are database-clock marks.
// next starts on 2026-06-01, so those two answers assume the clock is after that day.
var auditClockAfter = time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)

type auditFile struct {
	Steps   []auditStep  `json:"steps"`
	Queries []auditQuery `json:"queries"`
}

type auditStep struct {
	Tenant string `json:"tenant"`

	Scope    string `json:"scope"`
	Parent   string `json:"parent"`
	Kind     string `json:"kind"`
	Selector string `json:"selector"`

	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
	Valid    string   `json:"valid"`

	Correct string `json:"correct"`
	Remove  string `json:"remove"`
	Mark    string `json:"mark"`

	Supersede string `json:"supersede"`
	Successor string `json:"successor"`
	At        string `json:"at"`

	Waiver string `json:"waiver"`
	Ticket string `json:"ticket"`
}

type auditQuery struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Tenant   string   `json:"tenant"`
	Repo     string   `json:"repo"`
	Valid    string   `json:"valid"`
	Known    string   `json:"known"`
	Then     string   `json:"then"`
	Now      string   `json:"now"`
	At       string   `json:"at"`
	Decision string   `json:"decision"`
	Want     []string `json:"want"`
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Changed  []string `json:"changed"`
	Links    []string `json:"links"`
	Versions []string `json:"versions"`
	Closed   []string `json:"closed"`
}

type decisionState struct {
	id      uuid.UUID
	tenant  uuid.UUID
	version int
}

func TestAuditGolden(t *testing.T) {
	raw, err := os.ReadFile("../registry/testdata/audit_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden auditFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&golden); err != nil {
		t.Fatal(err)
	}

	r := newRegistryDB(t)
	ctx := t.Context()
	tenants := map[string]uuid.UUID{"a": tenantA, "b": tenantB}
	scopes := map[string]uuid.UUID{}
	decisions := map[string]*decisionState{}
	waivers := map[string]uuid.UUID{}
	marks := map[string]time.Time{}
	refOf := map[uuid.UUID]string{}

	tenantOf := func(name string) uuid.UUID {
		t.Helper()
		id, ok := tenants[name]
		if !ok {
			t.Fatalf("unknown tenant %q", name)
		}
		return id
	}
	scopeIDs := func(refs []string) []uuid.UUID {
		t.Helper()
		ids := make([]uuid.UUID, 0, len(refs))
		for _, ref := range refs {
			id, ok := scopes[ref]
			if !ok {
				t.Fatalf("unknown scope %q", ref)
			}
			ids = append(ids, id)
		}
		return ids
	}

	for i, step := range golden.Steps {
		switch {
		case step.Scope != "" && step.Waiver == "":
			var parent uuid.UUID
			if step.Parent != "" {
				parent = scopes[step.Parent]
				if parent == uuid.Nil {
					t.Fatalf("step %d: unknown parent %q", i, step.Parent)
				}
			}
			scopes[step.Scope] = r.scope(t, tenantOf(step.Tenant), parent, step.Kind, step.Selector)

		case step.Decision != "" && step.Waiver == "":
			id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(step.Decision))
			decisions[step.Decision] = &decisionState{id: id, tenant: tenantOf(step.Tenant), version: 1}
			refOf[id] = step.Decision
			r.decision(t, tenantOf(step.Tenant), id, step.Valid, scopeIDs(step.Scopes)...)

		case step.Correct != "":
			d := decisions[step.Correct]
			if d == nil {
				t.Fatalf("step %d: unknown decision %q", i, step.Correct)
			}
			d.version++
			if _, err := r.app.ExecContext(ctx, `
				UPDATE registry.decision_version
				SET version = $3, valid_period = $4::text::tstzrange
				WHERE tenant_id = $1 AND decision_id = $2`,
				d.tenant, d.id, d.version, step.Valid); err != nil {
				t.Fatalf("step %d: correct %s: %v", i, step.Correct, err)
			}

		case step.Remove != "":
			d := decisions[step.Remove]
			if d == nil {
				t.Fatalf("step %d: unknown decision %q", i, step.Remove)
			}
			if _, err := r.app.ExecContext(ctx, `
				DELETE FROM registry.decision_version
				WHERE tenant_id = $1 AND decision_id = $2`, d.tenant, d.id); err != nil {
				t.Fatalf("step %d: remove %s: %v", i, step.Remove, err)
			}

		case step.Supersede != "":
			from := decisions[step.Supersede]
			to := decisions[step.Successor]
			if from == nil || to == nil {
				t.Fatalf("step %d: unknown supersession %s -> %s", i, step.Supersede, step.Successor)
			}
			at, err := time.Parse(time.RFC3339, step.At)
			if err != nil {
				t.Fatalf("step %d: at: %v", i, err)
			}
			if _, err := r.app.ExecContext(ctx, `
				INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
				VALUES ($1, $2, $3, $4)`, from.tenant, from.id, to.id, at); err != nil {
				t.Fatalf("step %d: supersede: %v", i, err)
			}

		case step.Waiver != "":
			d := decisions[step.Decision]
			scope, ok := scopes[step.Scope]
			if d == nil || !ok {
				t.Fatalf("step %d: unknown waiver %s", i, step.Waiver)
			}
			var id uuid.UUID
			if err := r.app.QueryRowContext(ctx, `
				INSERT INTO registry.waiver
					(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
				VALUES ($1, $2, $3, 'fixture', 'team:payments', $4::text::tstzrange, $5)
				RETURNING id`, d.tenant, d.id, scope, step.Valid, step.Ticket).Scan(&id); err != nil {
				t.Fatalf("step %d: waiver %s: %v", i, step.Waiver, err)
			}
			waivers[step.Waiver] = id

		case step.Mark != "":
			marks[step.Mark] = mark(t, r.admin)

		default:
			t.Fatalf("step %d sets nothing", i)
		}
	}
	marks["end"] = mark(t, r.admin)
	if marks["before"].Before(auditClockAfter) {
		t.Fatal("q3 merge instants expect the database clock to be after 2026-06-01")
	}

	h := Handler(r.app, func(req *http.Request) (uuid.UUID, bool) {
		id, err := uuid.Parse(req.Header.Get("X-Test-Tenant"))
		if err != nil || id == uuid.Nil {
			return uuid.Nil, false
		}
		return id, true
	})

	for _, q := range golden.Queries {
		t.Run(q.Name, func(t *testing.T) {
			runAuditQuery(t, r, h, q, tenants, decisions, refOf, marks)
		})
	}
}

func runAuditQuery(t *testing.T, r registryDB, h http.Handler, q auditQuery, tenants map[string]uuid.UUID, decisions map[string]*decisionState, refOf map[uuid.UUID]string, marks map[string]time.Time) {
	t.Helper()
	tenant := tenants[q.Tenant]
	switch q.Kind {
	case "decisions":
		validAt, knownAt := auditTime(t, marks, q.Valid), auditTime(t, marks, q.Known)
		got, err := registry.Resolve(t.Context(), r.app, tenant, registry.Subject{Repo: q.Repo}, validAt, knownAt)
		if err != nil {
			t.Fatal(err)
		}
		assertDecisionRefs(t, refOf, got, q.Want)
		body := auditGET(t, h, tenant, "/v1/audit/decisions", url.Values{
			"repo": {q.Repo}, "valid": {validAt.Format(time.RFC3339Nano)}, "known": {knownAt.Format(time.RFC3339Nano)},
		})
		var decoded struct {
			Decisions []struct {
				ID      uuid.UUID       `json:"id"`
				Version int             `json:"version"`
				Body    json.RawMessage `json:"body"`
			} `json:"decisions"`
		}
		decodeAudit(t, body, &decoded)
		httpDecisions := make([]registry.Decision, len(decoded.Decisions))
		for i, d := range decoded.Decisions {
			httpDecisions[i] = registry.Decision{ID: d.ID, Version: d.Version, Body: d.Body}
		}
		assertDecisionRefs(t, refOf, httpDecisions, q.Want)

	case "beliefs":
		validAt := auditTime(t, marks, q.Valid)
		then := auditTime(t, marks, q.Then)
		now := auditTime(t, marks, q.Now)
		diff, err := registry.Beliefs(t.Context(), r.app, tenant, registry.Subject{Repo: q.Repo}, validAt, then, now)
		if err != nil {
			t.Fatal(err)
		}
		assertDecisionRefs(t, refOf, diff.Added, q.Added)
		assertDecisionRefs(t, refOf, diff.Removed, q.Removed)
		assertChanges(t, refOf, diff.Changed, q.Changed)
		body := auditGET(t, h, tenant, "/v1/audit/beliefs", url.Values{
			"repo": {q.Repo}, "valid": {validAt.Format(time.RFC3339Nano)},
			"then": {then.Format(time.RFC3339Nano)}, "now": {now.Format(time.RFC3339Nano)},
		})
		var decoded struct {
			Added   []decisionWire `json:"added"`
			Removed []decisionWire `json:"removed"`
			Changed []struct {
				ID   uuid.UUID    `json:"id"`
				Then decisionWire `json:"then"`
				Now  decisionWire `json:"now"`
			} `json:"changed"`
		}
		decodeAudit(t, body, &decoded)
		assertDecisionRefs(t, refOf, wires(decoded.Added), q.Added)
		assertDecisionRefs(t, refOf, wires(decoded.Removed), q.Removed)
		changed := make([]registry.BeliefChange, len(decoded.Changed))
		for i, c := range decoded.Changed {
			changed[i] = registry.BeliefChange{ID: c.ID, Then: c.Then.decision(), Now: c.Now.decision()}
		}
		assertChanges(t, refOf, changed, q.Changed)

	case "merges":
		at := auditTime(t, marks, q.At)
		knownAt := at
		params := url.Values{"repo": {q.Repo}, "at": {at.Format(time.RFC3339Nano)}}
		if q.Known != "" {
			knownAt = auditTime(t, marks, q.Known)
			params.Set("known", knownAt.Format(time.RFC3339Nano))
		}
		got, err := registry.Resolve(t.Context(), r.app, tenant, registry.Subject{Repo: q.Repo}, at, knownAt)
		if err != nil {
			t.Fatal(err)
		}
		assertDecisionRefs(t, refOf, got, q.Want)
		body := auditGET(t, h, tenant, "/v1/audit/merges", params)
		if strings.Contains(body, "verdicts") {
			t.Fatalf("merges response has a verdicts field: %s", body)
		}
		var decoded struct {
			Decisions []decisionWire `json:"decisions"`
		}
		decodeAudit(t, body, &decoded)
		assertDecisionRefs(t, refOf, wires(decoded.Decisions), q.Want)

	case "supersessions":
		d := decisions[q.Decision]
		if d == nil {
			t.Fatalf("unknown decision %q", q.Decision)
		}
		knownAt := auditTime(t, marks, q.Known)
		chain, err := registry.SupersessionChain(t.Context(), r.app, tenant, d.id, knownAt)
		if err != nil {
			t.Fatal(err)
		}
		assertChain(t, refOf, chain, q)
		body := auditGET(t, h, tenant, "/v1/audit/supersessions/"+d.id.String(), url.Values{
			"known": {knownAt.Format(time.RFC3339Nano)},
		})
		if len(q.Links) == 0 && len(q.Versions) == 0 && strings.Contains(body, d.id.String()) {
			t.Fatalf("empty chain echoes the decision id: %s", body)
		}
		var decoded chainWire
		decodeAudit(t, body, &decoded)
		assertChain(t, refOf, decoded.chain(), q)

	case "waivers":
		knownAt := auditTime(t, marks, q.Known)
		now := auditTime(t, marks, q.Now)
		got, err := registry.ExpiringWaivers(t.Context(), r.app, tenant, knownAt, now)
		if err != nil {
			t.Fatal(err)
		}
		assertWaiverTickets(t, got, q.Want)
		body := auditGET(t, h, tenant, "/v1/audit/waivers", url.Values{
			"known": {knownAt.Format(time.RFC3339Nano)}, "now": {now.Format(time.RFC3339Nano)},
		})
		if strings.Contains(body, "fixture") || strings.Contains(body, "team:payments") || strings.Contains(body, "approver") {
			t.Fatalf("waiver response leaks a private field: %s", body)
		}
		var decoded struct {
			Waivers []struct {
				ID         uuid.UUID `json:"id"`
				DecisionID uuid.UUID `json:"decision_id"`
				ScopeID    uuid.UUID `json:"scope_id"`
				TicketRef  string    `json:"ticket_ref"`
				ExpiresAt  time.Time `json:"expires_at"`
			} `json:"waivers"`
		}
		decodeAudit(t, body, &decoded)
		tickets := make([]string, len(decoded.Waivers))
		for i, w := range decoded.Waivers {
			tickets[i] = w.TicketRef
		}
		if !slices.Equal(tickets, q.Want) {
			t.Fatalf("http waivers = %v, want %v", tickets, q.Want)
		}

	default:
		t.Fatalf("unknown kind %q", q.Kind)
	}
}

type decisionWire struct {
	ID      uuid.UUID       `json:"id"`
	Version int             `json:"version"`
	Body    json.RawMessage `json:"body"`
}

func (d decisionWire) decision() registry.Decision {
	return registry.Decision{ID: d.ID, Version: d.Version, Body: d.Body}
}

func wires(in []decisionWire) []registry.Decision {
	out := make([]registry.Decision, len(in))
	for i, d := range in {
		out[i] = d.decision()
	}
	return out
}

type chainWire struct {
	Links []struct {
		ID          uuid.UUID `json:"id"`
		From        uuid.UUID `json:"from"`
		To          uuid.UUID `json:"to"`
		EffectiveAt time.Time `json:"effective_at"`
	} `json:"links"`
	Versions []struct {
		DecisionID uuid.UUID  `json:"decision_id"`
		Version    int        `json:"version"`
		ValidFrom  time.Time  `json:"valid_from"`
		ValidTo    *time.Time `json:"valid_to"`
	} `json:"versions"`
}

func (c chainWire) chain() registry.Chain {
	out := registry.Chain{}
	for _, link := range c.Links {
		out.Links = append(out.Links, registry.SupersessionLink{From: link.From, To: link.To})
	}
	for _, span := range c.Versions {
		out.Versions = append(out.Versions, registry.VersionSpan{
			DecisionID: span.DecisionID, Version: span.Version, ValidTo: span.ValidTo,
		})
	}
	return out
}

func assertDecisionRefs(t *testing.T, refOf map[uuid.UUID]string, got []registry.Decision, want []string) {
	t.Helper()
	if !slices.IsSortedFunc(got, auditCompareDecision) {
		t.Fatalf("decisions are not in id order")
	}
	gotRefs := make([]string, 0, len(got))
	for _, d := range got {
		ref, ok := refOf[d.ID]
		if !ok {
			t.Fatalf("decision %s is not one of the fixture decisions", d.ID)
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(d.Body, &body); err != nil || body.ID != d.ID.String() {
			t.Errorf("decision %s body = %s", ref, d.Body)
		}
		gotRefs = append(gotRefs, ref+"@"+strconv.Itoa(d.Version))
	}
	wantRefs := append([]string(nil), want...)
	slices.Sort(gotRefs)
	slices.Sort(wantRefs)
	if !slices.Equal(gotRefs, wantRefs) {
		t.Fatalf("decisions = %v, want %v", gotRefs, wantRefs)
	}
}

func assertChanges(t *testing.T, refOf map[uuid.UUID]string, got []registry.BeliefChange, want []string) {
	t.Helper()
	gotRefs := make([]string, 0, len(got))
	for _, c := range got {
		ref := refOf[c.ID]
		gotRefs = append(gotRefs, ref+"@"+strconv.Itoa(c.Then.Version)+">"+ref+"@"+strconv.Itoa(c.Now.Version))
	}
	wantRefs := append([]string(nil), want...)
	slices.Sort(gotRefs)
	slices.Sort(wantRefs)
	if !slices.Equal(gotRefs, wantRefs) {
		t.Fatalf("changed = %v, want %v", gotRefs, wantRefs)
	}
}

func assertChain(t *testing.T, refOf map[uuid.UUID]string, chain registry.Chain, q auditQuery) {
	t.Helper()
	links := make([]string, 0, len(chain.Links))
	for _, link := range chain.Links {
		links = append(links, refOf[link.From]+">"+refOf[link.To])
	}
	if !slices.Equal(links, q.Links) {
		t.Fatalf("links = %v, want %v", links, q.Links)
	}
	versions := make([]string, 0, len(chain.Versions))
	closed := map[string]bool{}
	for _, ref := range q.Closed {
		closed[ref] = true
	}
	closeAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, span := range chain.Versions {
		ref := refOf[span.DecisionID]
		versions = append(versions, ref+"@"+strconv.Itoa(span.Version))
		if closed[ref] {
			if span.ValidTo == nil || !span.ValidTo.Equal(closeAt) {
				t.Fatalf("%s valid_to = %v, want %s", ref, span.ValidTo, closeAt)
			}
			continue
		}
		if span.ValidTo != nil {
			t.Fatalf("%s valid_to = %s, want an open period", ref, span.ValidTo)
		}
	}
	wantVersions := append([]string(nil), q.Versions...)
	slices.Sort(versions)
	slices.Sort(wantVersions)
	if !slices.Equal(versions, wantVersions) {
		t.Fatalf("versions = %v, want %v", versions, wantVersions)
	}
}

func assertWaiverTickets(t *testing.T, got []registry.WaiverExpiry, want []string) {
	t.Helper()
	tickets := make([]string, len(got))
	for i, w := range got {
		tickets[i] = w.TicketRef
		if w.TicketRef == "" {
			t.Fatal("empty ticket")
		}
	}
	if !slices.Equal(tickets, want) {
		t.Fatalf("waivers = %v, want %v", tickets, want)
	}
}

func auditGET(t *testing.T, h http.Handler, tenant uuid.UUID, path string, q url.Values) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	req.Header.Set("X-Test-Tenant", tenant.String())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d %s", path, rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	return rec.Body.String()
}

func decodeAudit(t *testing.T, raw string, dest any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func auditTime(t *testing.T, marks map[string]time.Time, raw string) time.Time {
	t.Helper()
	if ts, ok := marks[raw]; ok {
		parsed, err := time.Parse(time.RFC3339Nano, ts.Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.Equal(ts) {
			t.Fatalf("%s did not round-trip", raw)
		}
		return parsed
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("time %q: %v", raw, err)
	}
	return parsed
}

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runAuditTests(m))
}

func runAuditTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

type registryDB struct {
	app   *sql.DB
	admin *sql.DB
}

func newRegistryDB(t *testing.T) registryDB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return registryDB{app: db.Open(t, pgtest.App), admin: db.Open(t, pgtest.Admin)}
}

func (r registryDB) scope(t *testing.T, tenant, parent uuid.UUID, kind, selector string) uuid.UUID {
	t.Helper()
	var parentArg any
	if parent != uuid.Nil {
		parentArg = parent
	}
	var id uuid.UUID
	err := r.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector)
		VALUES ($1, $2, $3, $4) RETURNING id`, tenant, parentArg, kind, selector).Scan(&id)
	if err != nil {
		t.Fatalf("insert %s scope %q: %v", kind, selector, err)
	}
	return id
}

func (r registryDB) decision(t *testing.T, tenant, id uuid.UUID, valid string, scopes ...uuid.UUID) {
	t.Helper()
	_, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, jsonb_build_object('id', $1::uuid::text), $3::uuid[], $4::text::tstzrange)`,
		id, tenant, scopes, valid)
	if err != nil {
		t.Fatalf("insert decision: %v", err)
	}
}

func mark(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	pause := func() {
		if _, err := db.ExecContext(t.Context(), `SELECT pg_sleep(0.02)`); err != nil {
			t.Fatal(err)
		}
	}
	pause()
	var now time.Time
	if err := db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	pause()
	return now
}

func auditCompareDecision(a, b registry.Decision) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}
