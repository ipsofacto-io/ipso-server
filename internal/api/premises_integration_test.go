//go:build integration

package api

import (
	"bytes"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

var (
	premiseDecisionA = uuid.MustParse("00000000-0000-7000-8000-0000000000c1")
	premiseDecisionB = uuid.MustParse("00000000-0000-7000-8000-0000000000c2")
)

// premiseSeed is what the premise reads show. Tenant A has two open reasons (tls-version, and mtls-required
// that opened again after a person cleared the first), one premise whose only reason is cleared, and an
// allowlist of two hosts: a, which was withdrawn and allowed again, and b, which was withdrawn. Tenant B has one
// open reason and one host.
type premiseSeed struct {
	open  []uuid.UUID
	hosts map[string]uuid.UUID
}

const premiseDecisionBody = `{"slug":"%s","title":"%s","premises":[{"id":"tls-version"},{"id":"mtls-required"},{"id":"hsts-enabled"}]}`

// seedPremises writes the rows the way the worker and the routes do, after f.known, so the reads of the other
// tests do not see them. It does not go through the API: nothing there writes an evaluation or a reason.
func (f *fixture) seedPremises(t *testing.T) premiseSeed {
	t.Helper()
	scopeB := f.insert(t, `SELECT id FROM registry.scope WHERE tenant_id = $1`, tenantB)
	for _, d := range []struct {
		tenant, id, scope uuid.UUID
		slug              string
	}{{tenantA, premiseDecisionA, f.org, "tls-premises"}, {tenantB, premiseDecisionB, scopeB, "tls-premises-b"}} {
		f.exec(t, `
			INSERT INTO registry.decision_version (tenant_id, decision_id, version, body, scope_refs, valid_period)
			VALUES ($1, $2, 1, $3::jsonb, ARRAY[$4::uuid], '[2026-01-01,)'::text::tstzrange)`,
			d.tenant, d.id, fmt.Sprintf(premiseDecisionBody, d.slug, d.slug), d.scope)
	}
	fail := func(tenant, decision uuid.UUID, premise, observed string) {
		t.Helper()
		opened, err := registry.RecordEvaluation(t.Context(), f.db, tenant, registry.Evaluation{
			Ref: registry.PremiseRef{Decision: decision, ID: premise}, Result: "fail",
			URL: "https://status.example.com/tls.json", Pointer: "/min", Expected: []byte(`"1.3"`), Observed: []byte(observed),
			BodySHA256: bytes.Repeat([]byte{0xab}, 32),
		})
		if err != nil || !opened {
			t.Fatalf("a fail of %s opened a reason = %v, %v", premise, opened, err)
		}
	}
	closeReason := func(premise string) {
		t.Helper()
		f.exec(t, `
			INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
			SELECT tenant_id, id, 'human' FROM registry.premise_reason
			WHERE tenant_id = $1 AND premise_id = $2 AND id NOT IN (SELECT reason_id FROM registry.premise_clearance)`, tenantA, premise)
	}
	openReason := func(premise string) uuid.UUID {
		return f.insert(t, `
			SELECT id FROM registry.premise_reason
			WHERE tenant_id = $1 AND premise_id = $2 AND id NOT IN (SELECT reason_id FROM registry.premise_clearance)`, tenantA, premise)
	}
	fail(tenantA, premiseDecisionA, "tls-version", `"1.2"`)
	fail(tenantA, premiseDecisionA, "mtls-required", `false`)
	closeReason("mtls-required")
	fail(tenantA, premiseDecisionA, "mtls-required", `"optional"`)
	fail(tenantA, premiseDecisionA, "hsts-enabled", `false`)
	closeReason("hsts-enabled")
	fail(tenantB, premiseDecisionB, "tls-version", `"1.1"`)

	seed := premiseSeed{open: []uuid.UUID{openReason("tls-version"), openReason("mtls-required")}, hosts: map[string]uuid.UUID{}}
	allow := func(tenant uuid.UUID, host string, allowed bool) uuid.UUID {
		t.Helper()
		id := f.insert(t, `INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1, $2, $3) RETURNING id`, tenant, host, allowed)
		clock(t, f.admin)
		return id
	}
	allow(tenantA, "a.example.com", true)
	allow(tenantA, "b.example.com", true)
	seed.hosts["b.example.com"] = allow(tenantA, "b.example.com", false)
	allow(tenantA, "a.example.com", false)
	seed.hosts["a.example.com"] = allow(tenantA, "a.example.com", true)
	allow(tenantB, "c.example.com", true)
	return seed
}

func idsOf(items []any) []string {
	ids := make([]string, 0, len(items))
	for _, raw := range items {
		ids = append(ids, raw.(map[string]any)["id"].(string))
	}
	return ids
}

func descending(ids ...uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	slices.Sort(out)
	slices.Reverse(out)
	return out
}

// Both reads match the document, and a reason shows what the evaluation stored and nothing else: not the body of
// the response and not its digest. A cleared reason is not listed, and a premise that failed again after a
// clearance is listed once, with the new fail.
func TestThePremiseReadsShowTheOpenReasonsAndTheLatestRowOfEachHost(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	seed := f.seedPremises(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	token := f.token(t, personA)

	w := c.exchange(t, handler, http.MethodGet, "/v1/premise-reasons", token, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	reasons := list(answerOf(t, w), "premise_reasons")
	if got, want := idsOf(reasons), descending(seed.open...); !slices.Equal(got, want) {
		t.Fatalf("the reasons are %v, want the two open ones %v", got, want)
	}
	want := []string{"decision_id", "expected", "id", "observed", "opened_at", "pointer", "premise_id", "url"}
	byPremise := map[string]map[string]any{}
	for _, raw := range reasons {
		reason := raw.(map[string]any)
		if got := slices.Sorted(maps.Keys(reason)); !slices.Equal(got, want) {
			t.Errorf("a reason has the keys %v, want %v", got, want)
		}
		byPremise[reason["premise_id"].(string)] = reason
	}
	tls, mtls := byPremise["tls-version"], byPremise["mtls-required"]
	if tls == nil || mtls == nil || tls["decision_id"] != premiseDecisionA.String() || tls["url"] != "https://status.example.com/tls.json" ||
		tls["pointer"] != "/min" || tls["expected"] != "1.3" || tls["observed"] != "1.2" || mtls["observed"] != "optional" {
		t.Errorf("the reasons read %v", reasons)
	}
	if strings.Contains(w.Body.String(), "sha256") {
		t.Errorf("the answer carries the digest of a response: %s", w.Body)
	}

	w = c.exchange(t, handler, http.MethodGet, "/v1/premise-hosts", token, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	hosts := list(answerOf(t, w), "premise_hosts")
	if got, want := idsOf(hosts), descending(seed.hosts["a.example.com"], seed.hosts["b.example.com"]); !slices.Equal(got, want) {
		t.Fatalf("the hosts are %v, want the latest row of each %v", got, want)
	}
	allowed := map[string]any{}
	for _, raw := range hosts {
		host := raw.(map[string]any)
		if got := slices.Sorted(maps.Keys(host)); !slices.Equal(got, []string{"allowed", "host", "id"}) {
			t.Errorf("a host has the keys %v", got)
		}
		allowed[host["host"].(string)] = host["allowed"]
	}
	if allowed["a.example.com"] != true || allowed["b.example.com"] != false || len(allowed) != 2 {
		t.Errorf("the allowlist reads %v, want a allowed and b withdrawn", allowed)
	}
}

// A page is by id from the highest, and walking the pages one row at a time reads every row once, in the order
// of a single read.
func TestThePremiseReadsPageByID(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	f.seedPremises(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	token := f.token(t, personA)
	for _, tc := range []struct{ path, key string }{{"/v1/premise-reasons", "premise_reasons"}, {"/v1/premise-hosts", "premise_hosts"}} {
		whole := idsOf(list(answerOf(t, c.exchange(t, handler, http.MethodGet, tc.path, token, "", nil)), tc.key))
		var walked []string
		target := tc.path + "?limit=1"
		for range len(whole) + 1 {
			page := list(answerOf(t, c.exchange(t, handler, http.MethodGet, target, token, "", nil)), tc.key)
			if len(page) == 0 {
				break
			}
			if len(page) != 1 {
				t.Fatalf("%s: a page of limit 1 holds %d", tc.path, len(page))
			}
			walked = append(walked, idsOf(page)...)
			target = tc.path + "?limit=1&before=" + walked[len(walked)-1]
		}
		if len(whole) != 2 || !slices.Equal(walked, whole) {
			t.Errorf("%s: walking by 1 read %v, one read gave %v, want the same two", tc.path, walked, whole)
		}
		if w := c.exchange(t, handler, http.MethodGet, tc.path+"?limit=100&before="+whole[len(whole)-1], token, "", nil); len(list(answerOf(t, w), tc.key)) != 0 || w.Code != http.StatusOK {
			t.Errorf("%s: a page below the lowest id read %s", tc.path, w.Body)
		}
	}
}

// Tenant B reads its own rows, and tenant A's ids are not in its answers.
func TestThePremiseReadsAreOfTheTenantOfTheToken(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	seed := f.seedPremises(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	token := f.token(t, personB)

	reasons := list(answerOf(t, c.exchange(t, handler, http.MethodGet, "/v1/premise-reasons", token, "", nil)), "premise_reasons")
	if len(reasons) != 1 || reasons[0].(map[string]any)["decision_id"] != premiseDecisionB.String() || reasons[0].(map[string]any)["observed"] != "1.1" {
		t.Fatalf("tenant B read %v", reasons)
	}
	for _, id := range seed.open {
		if slices.Contains(idsOf(reasons), id.String()) {
			t.Errorf("tenant B read the reason %s of tenant A", id)
		}
	}
	hosts := list(answerOf(t, c.exchange(t, handler, http.MethodGet, "/v1/premise-hosts", token, "", nil)), "premise_hosts")
	if len(hosts) != 1 || hosts[0].(map[string]any)["host"] != "c.example.com" {
		t.Fatalf("tenant B read %v", hosts)
	}
}

// Every read that carries a key it does not list, a time, a tenant or a bad page is 400, and the rows stay as
// they were.
func TestThePremiseReadsRefuseWhatTheyDoNotRead(t *testing.T) {
	f := newFixture(t)
	f.seedPremises(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	token := f.token(t, personA)
	for _, path := range []string{"/v1/premise-reasons", "/v1/premise-hosts"} {
		for _, query := range []string{
			"limit=0", "limit=101", "limit=many", "limit=", "before=nope", "before=" + uuid.Nil.String(), "before=",
			"limit=1&limit=2", "known=" + at(f.known), "valid=" + at(f.valid), "decision=" + premiseDecisionA.String(),
			"tenant_id=" + tenantB.String(), "Tenant=" + tenantB.String(),
		} {
			w := call(t, handler, http.MethodGet, path+"?"+query, token)
			if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
				t.Errorf("%s?%s: %d %s", path, query, w.Code, w.Body)
			}
		}
	}
}

// An agent may read, the call is logged with the person who sponsors it, and a person's read is not logged.
func TestAnAgentReadsThePremisesAndItsCallsAreLogged(t *testing.T) {
	f := newFixture(t)
	f.seedPremises(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	for _, path := range []string{"/v1/premise-reasons", "/v1/premise-hosts"} {
		if w := call(t, handler, http.MethodGet, path, f.token(t, agentA)); w.Code != http.StatusOK {
			t.Fatalf("%s as the agent: %d %s", path, w.Code, w.Body)
		}
		if w := call(t, handler, http.MethodGet, path, f.token(t, personA)); w.Code != http.StatusOK {
			t.Fatalf("%s as a person: %d %s", path, w.Code, w.Body)
		}
	}
	actions, err := identity.Actions(t.Context(), f.db, tenantA, 10)
	if err != nil {
		t.Fatal(err)
	}
	logged := map[string]identity.Action{}
	for _, a := range actions {
		logged[a.Action] = a
	}
	if len(actions) != 2 {
		t.Fatalf("%d actions logged, want the two calls of the agent: %+v", len(actions), actions)
	}
	for action, subject := range map[string]string{"api.list_premise_reasons": "/v1/premise-reasons", "api.list_premise_hosts": "/v1/premise-hosts"} {
		got := logged[action]
		if got.Principal != f.callers[agentA].Principal || got.Responsible != f.callers[personA].Principal || got.Subject != subject {
			t.Errorf("%s: %+v", action, got)
		}
	}
}
