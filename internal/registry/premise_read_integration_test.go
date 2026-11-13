//go:build integration

package registry

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var (
	expiredDecision     = uuid.MustParse("00000000-0000-4000-8000-0000000000d2")
	otherTenantDecision = uuid.MustParse("00000000-0000-4000-8000-0000000000d3")
)

// failOf is a failed evaluation of a premise of a decision, with the digest and the observed value a fail stores.
func failOf(decision uuid.UUID, premise, expected, observed string) Evaluation {
	return Evaluation{
		Ref:        PremiseRef{Decision: decision, ID: premise},
		Result:     "fail",
		URL:        "https://status.example.com/" + premise + ".json",
		Pointer:    "/value",
		Expected:   []byte(expected),
		Observed:   []byte(observed),
		BodySHA256: bytes.Repeat([]byte{0xcd}, 32),
	}
}

func (r registryDB) fail(t *testing.T, tenant uuid.UUID, ev Evaluation) {
	t.Helper()
	opened, err := RecordEvaluation(t.Context(), r.app, tenant, ev)
	if err != nil || !opened {
		t.Fatalf("a fail of %s opened a reason = %v, %v", ev.Ref.ID, opened, err)
	}
}

// clear closes the open reason of a premise the way a person does, as the application role.
func (r registryDB) clear(t *testing.T, tenant, decision uuid.UUID, premise string) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), r.app, tenant.String(), `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		SELECT tenant_id, id, 'human' FROM registry.premise_reason
		WHERE tenant_id = $1 AND decision_id = $2 AND premise_id = $3
		  AND id NOT IN (SELECT reason_id FROM registry.premise_clearance)`, tenant, decision, premise); err != nil {
		t.Fatalf("clear %s: %v", premise, err)
	}
}

func reasonsOf(t *testing.T, r registryDB, tenant uuid.UUID, page Page) []PremiseReason {
	t.Helper()
	got, err := OpenPremiseReasons(t.Context(), r.app, tenant, page)
	if err != nil {
		t.Fatalf("OpenPremiseReasons: %v", err)
	}
	return got
}

// A reason is open until a clearance names it, and it carries the fail that opened it, which a later pass does
// not replace. A reason on a decision that is no longer in force is still open, because only a clearance closes it.
func TestTheOpenReasonsAreTheOnesNoClearanceClosesAndCarryTheFailThatOpenedThem(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor, nodeLTS))
	r.premiseOn(t, tenantA, expiredDecision, "[2000-01-01,2001-01-01)", premiseBody(pgMajor))
	r.premiseOn(t, tenantB, otherTenantDecision, inForce, premiseBody(pgMajor))
	if got := reasonsOf(t, r, tenantA, Page{Limit: 10}); got != nil {
		t.Fatalf("a tenant with no reason read %v, want a nil slice", got)
	}

	r.fail(t, tenantA, failOf(premiseDecision, "postgres-major", "16", "15"))
	r.fail(t, tenantA, failOf(premiseDecision, "node-lts", `">=20.0.0"`, `"18.0.0"`))
	r.fail(t, tenantA, failOf(expiredDecision, "postgres-major", "16", "14"))
	r.fail(t, tenantB, failOf(otherTenantDecision, "postgres-major", "16", "13"))
	// A pass after the fail neither closes the reason nor changes what it shows.
	pass := failOf(premiseDecision, "postgres-major", "16", "16")
	pass.Result = "pass"
	if opened, err := RecordEvaluation(t.Context(), r.app, tenantA, pass); err != nil || opened {
		t.Fatalf("a pass opened = %v, %v", opened, err)
	}

	got := reasonsOf(t, r, tenantA, Page{Limit: 10})
	if len(got) != 3 {
		t.Fatalf("%d reasons, want 3: %+v", len(got), got)
	}
	if !slices.IsSortedFunc(got, func(a, b PremiseReason) int { return -bytes.Compare(a.ID[:], b.ID[:]) }) {
		t.Errorf("the reasons are not by id from the highest: %+v", got)
	}
	found := map[string]PremiseReason{}
	for _, reason := range got {
		found[reason.DecisionID.String()+"/"+reason.PremiseID] = reason
	}
	pg := found[premiseDecision.String()+"/postgres-major"]
	if pg.ID == uuid.Nil || string(pg.Expected) != "16" || string(pg.Observed) != "15" ||
		pg.URL != "https://status.example.com/postgres-major.json" || pg.Pointer != "/value" || pg.OpenedAt.IsZero() {
		t.Errorf("the reason of postgres-major is %+v, want the fail that opened it", pg)
	}
	if node := found[premiseDecision.String()+"/node-lts"]; string(node.Expected) != `">=20.0.0"` || string(node.Observed) != `"18.0.0"` {
		t.Errorf("the reason of node-lts is %+v", node)
	}
	if expired := found[expiredDecision.String()+"/postgres-major"]; string(expired.Observed) != "14" {
		t.Errorf("the reason on the expired decision is %+v, want it listed", expired)
	}

	// Another tenant sees its own reason and none of the above.
	if other := reasonsOf(t, r, tenantB, Page{Limit: 10}); len(other) != 1 || other[0].DecisionID != otherTenantDecision || string(other[0].Observed) != "13" {
		t.Errorf("tenant B read %+v", other)
	}

	// A clearance closes a reason, and the next fail opens another that is listed in its place.
	r.clear(t, tenantA, premiseDecision, "postgres-major")
	after := reasonsOf(t, r, tenantA, Page{Limit: 10})
	if len(after) != 2 {
		t.Fatalf("%d reasons after a clearance, want 2: %+v", len(after), after)
	}
	for _, reason := range after {
		if reason.ID == pg.ID {
			t.Errorf("the cleared reason %s is still listed", pg.ID)
		}
	}
	r.fail(t, tenantA, failOf(premiseDecision, "postgres-major", "16", "12"))
	again := reasonsOf(t, r, tenantA, Page{Limit: 10})
	if len(again) != 3 {
		t.Fatalf("%d reasons after a new fail, want 3", len(again))
	}
	reopened := 0
	for _, reason := range again {
		if reason.DecisionID == premiseDecision && reason.PremiseID == "postgres-major" {
			reopened++
			if reason.ID == pg.ID || string(reason.Observed) != "12" {
				t.Errorf("the reopened reason is %+v, want a new one that shows the new fail", reason)
			}
		}
	}
	if reopened != 1 {
		t.Errorf("%d reasons for postgres-major, want one", reopened)
	}
}

func TestOpenReasonsPageByIDFromTheHighest(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor, nodeLTS))
	r.premiseOn(t, tenantA, expiredDecision, "[2000-01-01,2001-01-01)", premiseBody(pgMajor))
	r.fail(t, tenantA, failOf(premiseDecision, "postgres-major", "16", "15"))
	r.fail(t, tenantA, failOf(premiseDecision, "node-lts", "1", "2"))
	r.fail(t, tenantA, failOf(expiredDecision, "postgres-major", "16", "14"))

	all := reasonsOf(t, r, tenantA, Page{Limit: 100})
	var walked []PremiseReason
	page := Page{Limit: 2}
	for range 5 {
		got := reasonsOf(t, r, tenantA, page)
		if len(got) == 0 {
			break
		}
		walked = append(walked, got...)
		page.Before = got[len(got)-1].ID
	}
	if len(walked) != 3 || !slices.EqualFunc(walked, all, func(a, b PremiseReason) bool { return a.ID == b.ID }) {
		t.Fatalf("paging by 2 read %d reasons, want the 3 of one read in the same order", len(walked))
	}
	if got := reasonsOf(t, r, tenantA, Page{Limit: 1, Before: all[len(all)-1].ID}); got != nil {
		t.Errorf("a page below the lowest id read %v", got)
	}
}

// The probe reads the latest row of a host, and so does the list: a host withdrawn is listed as not allowed, a
// host allowed again is listed as allowed, and each host is listed once.
func TestThePremiseAllowlistIsTheLatestRowOfEachHost(t *testing.T) {
	r := newRegistryDB(t)
	read := func(tenant uuid.UUID, page Page) []PremiseHost {
		t.Helper()
		got, err := PremiseHosts(t.Context(), r.app, tenant, page)
		if err != nil {
			t.Fatalf("PremiseHosts: %v", err)
		}
		return got
	}
	if got := read(tenantA, Page{Limit: 10}); got != nil {
		t.Fatalf("an empty allowlist read %v, want a nil slice", got)
	}
	r.allow(t, tenantA, "a.example.com", true)
	r.allow(t, tenantA, "b.example.com", true)
	r.allow(t, tenantA, "B.Example.com", false) // stored in lowercase, and the latest row of b
	r.allow(t, tenantA, "a.example.com", false)
	r.allow(t, tenantA, "a.example.com", true)
	r.allow(t, tenantB, "c.example.com", true)

	latest := func(host string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pgtest.Scan(t.Context(), r.app, tenantA.String(), `
			SELECT id FROM registry.premise_host_allow WHERE tenant_id = $1 AND host = $2
			ORDER BY lower(sys_period) DESC, id DESC LIMIT 1`, []any{tenantA, host}, &id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	got := read(tenantA, Page{Limit: 10})
	if len(got) != 2 {
		t.Fatalf("%d hosts, want 2: %+v", len(got), got)
	}
	byHost := map[string]PremiseHost{}
	for _, host := range got {
		byHost[host.Host] = host
	}
	if a := byHost["a.example.com"]; !a.Allowed || a.ID != latest("a.example.com") {
		t.Errorf("a.example.com is %+v, want its latest row, which allows it", a)
	}
	if b := byHost["b.example.com"]; b.Allowed || b.ID != latest("b.example.com") {
		t.Errorf("b.example.com is %+v, want its latest row, which withdraws it", b)
	}
	if bytes.Compare(got[0].ID[:], got[1].ID[:]) < 0 {
		t.Errorf("the hosts are not by id from the highest: %+v", got)
	}
	// The list says what the probe reads: HostAllowed agrees with every row of it.
	for _, host := range got {
		if allowed, err := HostAllowed(t.Context(), r.app, tenantA, host.Host); err != nil || allowed != host.Allowed {
			t.Errorf("%s is listed as allowed = %v and the probe reads %v, %v", host.Host, host.Allowed, allowed, err)
		}
	}
	if other := read(tenantB, Page{Limit: 10}); len(other) != 1 || other[0].Host != "c.example.com" {
		t.Errorf("tenant B read %+v", other)
	}

	// The bound applies to the latest row, so the older rows of a host never come back on a later page.
	first := read(tenantA, Page{Limit: 1})
	second := read(tenantA, Page{Limit: 1, Before: first[0].ID})
	third := read(tenantA, Page{Limit: 1, Before: second[0].ID})
	if len(first) != 1 || len(second) != 1 || third != nil || first[0].ID == second[0].ID || first[0].Host == second[0].Host {
		t.Errorf("paging by 1 read %+v, %+v, %+v, want the two hosts and then nothing", first, second, third)
	}
}

func TestThePremiseReadsRefuseWhatTheyCannotTrust(t *testing.T) {
	r := newRegistryDB(t)
	for name, call := range map[string]func(uuid.UUID, Page) error{
		"OpenPremiseReasons": func(tenant uuid.UUID, page Page) error {
			_, err := OpenPremiseReasons(t.Context(), r.app, tenant, page)
			return err
		},
		"PremiseHosts": func(tenant uuid.UUID, page Page) error {
			_, err := PremiseHosts(t.Context(), r.app, tenant, page)
			return err
		},
	} {
		if err := call(uuid.Nil, Page{Limit: 1}); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("%s with no tenant: %v", name, err)
		}
		for _, limit := range []int{0, -1, MaxPage + 1} {
			if err := call(tenantA, Page{Limit: limit}); !errors.Is(err, ErrInvalidQuery) {
				t.Errorf("%s with a limit of %d: %v", name, limit, err)
			}
		}
	}
}
