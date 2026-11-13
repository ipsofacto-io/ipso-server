//go:build integration

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/google/uuid"
)

const (
	edrOwner    = "01M5C5QEHHNXJ3D7X2ZCMGXQT7"
	edrDocs     = "01M5C5QEHHNXJ3D7X2ZCMGXQT8"
	edrVersions = "01M5C5QEHHNXJ3D7X2ZCMGXQT9"
)

// seedDecisionVersions inserts one decision with a version for each period, version 1 first, at one scope, and
// returns its id. The body holds the EDR id when it is not empty.
func (f *fixture) seedDecisionVersions(t *testing.T, tenant, scope uuid.UUID, slug, edrID string, periods ...string) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"slug": slug, "title": slug}
	if edrID != "" {
		body["id"] = edrID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for index, period := range periods {
		f.exec(t, `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($2, $3, $1, $4::jsonb, ARRAY[$5::uuid], $6::text::tstzrange)`,
			tenant, id, index+1, string(raw), scope, period)
	}
	return id
}

// seedAnsweredCheck drafts a check for a version of a decision, as the pipeline stores it, and records the
// answer of a person of that tenant when outcome is not empty. It returns the id of the check.
func (f *fixture) seedAnsweredCheck(t *testing.T, tenant, decision uuid.UUID, version int, rego, outcome string) uuid.UUID {
	t.Helper()
	check := f.insert(t, `
		INSERT INTO proposals.check_proposal
			(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
		VALUES ($1, $2, $3, '{"rules":[]}', $4::text, sha256(convert_to($4::text, 'UTF8')), '[{}, {}]', 2, 2, false, 'm', 'p')
		RETURNING id`,
		tenant, decision, version, rego)
	if outcome != "" {
		person := f.callers[personA].Principal
		if tenant == tenantB {
			person = f.callers[personB].Principal
		}
		f.exec(t, `INSERT INTO proposals.check_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, $4)`,
			tenant, check, person, outcome)
	}
	return check
}

// rule is a distinct rule for each n, with a tab, a character outside ASCII and a blank line at the end, so a
// read that trims or re-encodes the text is caught.
func rule(n string) string {
	return "package ipso.checks.generated\n\ndeny contains msg if {\n\tcontains(input.added, \"" + n + "\")\n\tmsg := \"no " + n + " é\"\n}\n\n"
}

func digestOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// The read shows the approved checks of the decisions in force for a repository and nothing else: not a
// rejected check, not one nobody answered, not one of a decision that ended or of another repository, and not
// another tenant's. The Rego is the stored text byte for byte with its digest. A check approved for another
// version of its decision is listed and carries no Rego, so it is not delivered silently.
func TestAcceptedChecksOfARepository(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	token := f.token(t, personA)

	elsewhere := f.insert(t, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'elsewhere') RETURNING id`, tenantA)
	owner := f.seedDecisionVersions(t, tenantA, f.org, "owner-rules", edrOwner, "[2026-01-01,)")
	plain := f.seedDecisionVersions(t, tenantA, f.repo, "repo-rules", "", "[2026-01-01,)")
	notULID := f.seedDecisionVersions(t, tenantA, f.repo, "odd-id", "../../etc/passwd", "[2026-01-01,)")
	docs := f.seedDecisionVersions(t, tenantA, f.docs, "docs-rules", edrDocs, "[2026-01-01,)")
	moved := f.seedDecisionVersions(t, tenantA, f.org, "moved-on", edrVersions, "[2026-01-01,2026-03-01)", "[2026-03-01,)")
	ended := f.seedDecisionVersions(t, tenantA, f.org, "ended", "", "[2025-01-01,2026-03-01)")
	away := f.seedDecisionVersions(t, tenantA, elsewhere, "elsewhere-rules", "", "[2026-01-01,)")

	ownerA := f.seedAnsweredCheck(t, tenantA, owner, 1, rule("a"), "approved")
	f.seedAnsweredCheck(t, tenantA, owner, 1, rule("rejected"), "rejected")
	f.seedAnsweredCheck(t, tenantA, owner, 1, rule("unanswered"), "")
	ownerB := f.seedAnsweredCheck(t, tenantA, owner, 1, rule("b"), "approved")
	plainA := f.seedAnsweredCheck(t, tenantA, plain, 1, rule("plain"), "approved")
	oddA := f.seedAnsweredCheck(t, tenantA, notULID, 1, rule("odd"), "approved")
	docsA := f.seedAnsweredCheck(t, tenantA, docs, 1, rule("docs"), "approved")
	heldA := f.seedAnsweredCheck(t, tenantA, moved, 1, rule("held"), "approved")
	currentA := f.seedAnsweredCheck(t, tenantA, moved, 2, rule("current"), "approved")
	f.seedAnsweredCheck(t, tenantA, ended, 1, rule("ended"), "approved")
	awayA := f.seedAnsweredCheck(t, tenantA, away, 1, rule("away"), "approved")
	otherTenant := f.seedAnsweredCheck(t, tenantB, f.other, 1, rule("tenant-b"), "approved")

	text := func(target string) []any {
		t.Helper()
		w := c.exchange(t, handler, http.MethodGet, target, token, "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
		}
		items := list(answerOf(t, w), "accepted_checks")
		if items == nil {
			t.Fatalf("%s: accepted_checks is not a list: %s", target, w.Body.String())
		}
		return items
	}

	t.Run("the checks of the decisions in force for the repository", func(t *testing.T) {
		items := text("/v1/accepted-checks?repo=acme%2Fapi")
		if got, want := idsOf(items), descending(ownerA, ownerB, plainA, oddA, docsA, heldA, currentA); !slices.Equal(got, want) {
			t.Fatalf("ids %v, want %v", got, want)
		}
		want := map[uuid.UUID]map[string]any{
			ownerA:   {"decision_id": owner.String(), "edr_id": edrOwner, "decision_version": 1.0, "version_in_force": 1.0, "rego": rule("a"), "rego_sha256": digestOf(rule("a"))},
			ownerB:   {"decision_id": owner.String(), "edr_id": edrOwner, "decision_version": 1.0, "version_in_force": 1.0, "rego": rule("b"), "rego_sha256": digestOf(rule("b"))},
			plainA:   {"decision_id": plain.String(), "edr_id": nil, "decision_version": 1.0, "version_in_force": 1.0, "rego": rule("plain"), "rego_sha256": digestOf(rule("plain"))},
			oddA:     {"decision_id": notULID.String(), "edr_id": nil, "decision_version": 1.0, "version_in_force": 1.0, "rego": rule("odd"), "rego_sha256": digestOf(rule("odd"))},
			docsA:    {"decision_id": docs.String(), "edr_id": edrDocs, "decision_version": 1.0, "version_in_force": 1.0, "rego": rule("docs"), "rego_sha256": digestOf(rule("docs"))},
			heldA:    {"decision_id": moved.String(), "edr_id": edrVersions, "decision_version": 1.0, "version_in_force": 2.0, "rego": nil, "rego_sha256": nil},
			currentA: {"decision_id": moved.String(), "edr_id": edrVersions, "decision_version": 2.0, "version_in_force": 2.0, "rego": rule("current"), "rego_sha256": digestOf(rule("current"))},
		}
		for _, raw := range items {
			item := raw.(map[string]any)
			id := uuid.MustParse(item["id"].(string))
			delete(item, "id")
			if !mapsEqual(item, want[id]) {
				t.Errorf("check %s = %v, want %v", id, item, want[id])
			}
		}
	})

	t.Run("another repository, an upper case name, and a repository nothing covers", func(t *testing.T) {
		if got, want := idsOf(text("/v1/accepted-checks?repo=elsewhere%2Fx")), descending(awayA); !slices.Equal(got, want) {
			t.Errorf("elsewhere/x: %v, want %v", got, want)
		}
		if got, want := idsOf(text("/v1/accepted-checks?repo=ACME%2FAPI")), descending(ownerA, ownerB, plainA, oddA, docsA, heldA, currentA); !slices.Equal(got, want) {
			t.Errorf("ACME/API: %v, want %v", got, want)
		}
		if got := text("/v1/accepted-checks?repo=nobody%2Fnothing"); len(got) != 0 {
			t.Errorf("nobody/nothing: %v", got)
		}
	})

	t.Run("pages by the id of the last check", func(t *testing.T) {
		var got []string
		before := ""
		for range 10 {
			target := "/v1/accepted-checks?repo=acme%2Fapi&limit=2"
			if before != "" {
				target += "&before=" + before
			}
			page := idsOf(text(target))
			if len(page) == 0 {
				break
			}
			if len(page) > 2 {
				t.Fatalf("a page of %d, limit 2", len(page))
			}
			got = append(got, page...)
			before = page[len(page)-1]
		}
		if want := descending(ownerA, ownerB, plainA, oddA, docsA, heldA, currentA); !slices.Equal(got, want) {
			t.Fatalf("pages %v, want %v", got, want)
		}
	})

	t.Run("a tenant reads only its own checks", func(t *testing.T) {
		other := f.token(t, personB)
		w := c.exchange(t, handler, http.MethodGet, "/v1/accepted-checks?repo=acme%2Fapi", other, "", nil)
		if items := list(answerOf(t, w), "accepted_checks"); items == nil || len(items) != 0 {
			t.Fatalf("tenant B reads tenant A's checks: %s", w.Body.String())
		}
		w = c.exchange(t, handler, http.MethodGet, "/v1/accepted-checks?repo=globex%2Fweb", other, "", nil)
		if got, want := idsOf(list(answerOf(t, w), "accepted_checks")), descending(otherTenant); !slices.Equal(got, want) {
			t.Fatalf("tenant B: %v, want %v", got, want)
		}
		if got := text("/v1/accepted-checks?repo=globex%2Fweb"); len(got) != 0 {
			t.Fatalf("tenant A reads tenant B's checks: %v", got)
		}
	})

	t.Run("an agent may read it", func(t *testing.T) {
		w := c.exchange(t, handler, http.MethodGet, "/v1/accepted-checks?repo=acme%2Fapi", f.token(t, agentA), "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a request with no repo, a repo that is not a lowercase owner/name, or a bad page", func(t *testing.T) {
		// These break the document on purpose, so they go to the handler directly, and only the answer is
		// checked against the document.
		for _, target := range []string{
			"/v1/accepted-checks",
			"/v1/accepted-checks?repo=",
			"/v1/accepted-checks?repo=acme",
			"/v1/accepted-checks?repo=acme%2F",
			"/v1/accepted-checks?repo=acme%2F*",
			"/v1/accepted-checks?repo=%2Facme%2Fapi",
			"/v1/accepted-checks?repo=acme%2F..%2Fapi",
			"/v1/accepted-checks?repo=" + url.QueryEscape("acme/api\n"),
			"/v1/accepted-checks?repo=acme%2Fapi&limit=0",
			"/v1/accepted-checks?repo=acme%2Fapi&limit=101",
			"/v1/accepted-checks?repo=acme%2Fapi&limit=x",
			"/v1/accepted-checks?repo=acme%2Fapi&before=x",
			"/v1/accepted-checks?repo=acme%2Fapi&tenant_id=" + tenantB.String(),
			"/v1/accepted-checks?repo=acme%2Fapi&repo=acme%2Fapi",
			"/v1/accepted-checks?repo=acme%2Fapi&valid=2026-01-01T00%3A00%3A00Z",
		} {
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, target, nil)
				r.Header.Set("Authorization", token)
				return r
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request())
			if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
				t.Errorf("%s: %d %s", target, w.Code, w.Body.String())
				continue
			}
			if ok, problems := c.validator.ValidateHttpResponse(request(), w.Result()); !ok {
				t.Errorf("%s: the answer breaks the document: %v", target, problems[0].Message)
			}
		}
	})
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}
