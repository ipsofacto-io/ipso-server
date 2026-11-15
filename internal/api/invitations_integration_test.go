//go:build integration

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The routes of ADR-0127, through the real handler against PostgreSQL, each exchange checked against the document.

func (s scribe) openInvitations(tenant uuid.UUID) int {
	s.t.Helper()
	return s.count(tenant, `SELECT count(*) FROM identity.invitation WHERE tenant_id = $1`)
}

func TestAnAdminInvitesAPersonAndGetsTheLinkOnceAndTheDatabaseKeepsOnlyItsHash(t *testing.T) {
	s := newScribe(t)
	created := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/invitations", map[string]any{"name": "Dana", "role": "approver"})
	token, _ := created["token"].(string)
	hash, ok := identity.InvitationHash(token)
	if !ok {
		t.Fatalf("the answer holds %q, which does not read as a token", token)
	}
	if created["url"] != invitationOrigin+"/invitation#"+token {
		t.Errorf("the link is %v", created["url"])
	}
	if created["name"] != "Dana" || created["role"] != "approver" || idOf(t, created, "created_by") != s.f.callers[personA].Principal {
		t.Errorf("%v", created)
	}
	id := idOf(t, created, "id")

	if n := s.count(tenantA, `SELECT count(*) FROM identity.invitation WHERE tenant_id = $1 AND id = $2 AND token_sha256 = $3`, id, hash); n != 1 {
		t.Errorf("the database holds the hash of the token %d times", n)
	}
	if n := s.count(tenantA, `SELECT count(*) FROM identity.invitation i WHERE i.tenant_id = $1 AND i::text LIKE '%' || $2 || '%'`, token); n != 0 {
		t.Errorf("a row holds the token itself")
	}

	// The list shows the invitation and never the token, the hash or the link.
	listed := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/invitations", nil)
	items, _ := listed["invitations"].([]any)
	if len(items) != 1 {
		t.Fatalf("%v", listed)
	}
	item, _ := items[0].(map[string]any)
	for _, key := range []string{"token", "url", "token_sha256", "hash"} {
		if _, has := item[key]; has {
			t.Errorf("the list shows %s", key)
		}
	}
	if idOf(t, item, "id") != id || item["name"] != "Dana" {
		t.Errorf("%v", item)
	}

	// The log names the admin, the invitation and the role, and holds neither the token nor the name.
	var entry *identity.Action
	for _, a := range s.logged() {
		if a.Action == "api.create_invitation" {
			entry = &a
		}
	}
	if entry == nil || entry.Principal != s.f.callers[personA].Principal || entry.Subject != "invitation "+id.String()+" role approver" {
		t.Fatalf("the log has %+v", entry)
	}
	for _, a := range s.logged() {
		if strings.Contains(a.Subject, token) || strings.Contains(a.Subject, "Dana") {
			t.Errorf("a log entry holds the token or the name: %+v", a)
		}
	}

	// The one answer that holds a token is never cached.
	w := s.raw(personA, http.MethodPost, "/v1/invitations", "application/json", `{"name":"Eli","role":"viewer"}`)
	if w.Code != http.StatusCreated || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("%d, Cache-Control %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestTheLinkOfAnInvitationBindsThePersonWhoSignsInWithItToTheRoleItNames(t *testing.T) {
	s := newScribe(t)
	created := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/invitations", map[string]any{"name": "Dana", "role": "auditor"})
	hash, _ := identity.InvitationHash(created["token"].(string))

	// The sign-in of internal/login does this with the token its attempt cookie carries.
	if _, err := identity.AcceptInvitation(t.Context(), s.f.db, tenantA, "https://idp.example.test", "subject-dana", hash, make([]byte, 32), nil); err != nil {
		t.Fatal(err)
	}
	person, err := identity.PrincipalFor(t.Context(), s.f.db, tenantA, "https://idp.example.test", "subject-dana")
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.Get(t.Context(), s.f.db, tenantA, person)
	if err != nil || got.Name != "Dana" || got.Kind != identity.KindHuman || len(got.Grants) != 1 || got.Grants[0].Role != identity.RoleAuditor {
		t.Fatalf("%+v %v", got, err)
	}
	// It is used, so it is no longer listed and cannot be revoked.
	listed := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/invitations", nil)
	if items, _ := listed["invitations"].([]any); len(items) != 0 {
		t.Errorf("%v", listed)
	}
	s.expect(http.StatusNotFound, personA, http.MethodDelete, "/v1/invitations/"+idOf(t, created, "id").String(), nil)
}

func TestAnInvitationNeedsARoleAPersonMayHoldAndANameAPrincipalCouldHave(t *testing.T) {
	s := newScribe(t)
	long := strings.Repeat("n", 201)
	for name, tc := range map[string]struct {
		contentType, body string
		status            int
	}{
		"the agent role":               {"application/json", `{"name":"Dana","role":"agent"}`, http.StatusBadRequest},
		"a role nobody has":            {"application/json", `{"name":"Dana","role":"root"}`, http.StatusBadRequest},
		"no role":                      {"application/json", `{"name":"Dana"}`, http.StatusBadRequest},
		"no name":                      {"application/json", `{"role":"viewer"}`, http.StatusBadRequest},
		"an empty name":                {"application/json", `{"name":"","role":"viewer"}`, http.StatusBadRequest},
		"a name with spaces around it": {"application/json", `{"name":" Dana ","role":"viewer"}`, http.StatusBadRequest},
		"a name with a control":        {"application/json", `{"name":"Da\nna","role":"viewer"}`, http.StatusBadRequest},
		"a name over 200 characters":   {"application/json", `{"name":"` + long + `","role":"viewer"}`, http.StatusBadRequest},
		"a tenant in the body":         {"application/json", `{"name":"Dana","role":"viewer","tenant_id":"` + tenantB.String() + `"}`, http.StatusBadRequest},
		"a creator in the body":        {"application/json", `{"name":"Dana","role":"viewer","created_by":"` + uuid.NewString() + `"}`, http.StatusBadRequest},
		"data after the body":          {"application/json", `{"name":"Dana","role":"viewer"}{}`, http.StatusBadRequest},
		"not json":                     {"application/json", `name=Dana`, http.StatusBadRequest},
		"another content type":         {"text/plain", `{"name":"Dana","role":"viewer"}`, http.StatusUnsupportedMediaType},
	} {
		t.Run(name, func(t *testing.T) {
			w := s.raw(personA, http.MethodPost, "/v1/invitations", tc.contentType, tc.body)
			if w.Code != tc.status {
				t.Fatalf("%d %s, want %d", w.Code, w.Body, tc.status)
			}
			if n := s.openInvitations(tenantA); n != 0 || len(s.logged()) != 0 {
				t.Errorf("a refused request stored %d invitations and logged %d entries", n, len(s.logged()))
			}
		})
	}
}

func TestOnlyAnAdminWhoIsAPersonTakesTheInvitationRoutes(t *testing.T) {
	s := newScribe(t)
	created := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/invitations", map[string]any{"name": "Dana", "role": "viewer"})
	id := idOf(t, created, "id")
	rows, logged := s.openInvitations(tenantA), len(s.logged())

	roles := map[string]string{agentA: "agent", viewerA: "viewer", auditorA: "auditor", contributorA: "contributor", approverA: "approver", ownerA: "decision-owner", nobodyA: ""}
	for subject, role := range roles {
		for _, op := range []string{"create_invitation", "list_invitations", "revoke_invitation"} {
			for _, allowed := range mayCall[op] {
				if allowed == role {
					t.Fatalf("the matrix lets %q take %s", role, op)
				}
			}
			method, target, body := http.MethodPost, "/v1/invitations", `{"name":"Eve","role":"admin"}`
			switch op {
			case "list_invitations":
				method, target, body = http.MethodGet, "/v1/invitations", ""
			case "revoke_invitation":
				method, target, body = http.MethodDelete, "/v1/invitations/"+id.String(), ""
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
	if s.openInvitations(tenantA) != rows || len(s.logged()) != logged {
		t.Errorf("a refusal changed the invitations or the log")
	}
}

func TestAnInvitationIsRevokedOnceAndIsNeverSeenOrTouchedByAnotherTenant(t *testing.T) {
	s := newScribe(t)
	created := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/invitations", map[string]any{"name": "Dana", "role": "viewer"})
	id := idOf(t, created, "id")
	hash, _ := identity.InvitationHash(created["token"].(string))

	// Tenant B's admin sees none of it, and cannot revoke it.
	if listed := s.expect(http.StatusOK, personB, http.MethodGet, "/v1/invitations", nil); len(listed["invitations"].([]any)) != 0 {
		t.Errorf("tenant B lists %v", listed)
	}
	s.expect(http.StatusNotFound, personB, http.MethodDelete, "/v1/invitations/"+id.String(), nil)
	if s.openInvitations(tenantA) != 1 {
		t.Fatal("tenant B revoked the invitation of tenant A")
	}

	s.expect(http.StatusNoContent, personA, http.MethodDelete, "/v1/invitations/"+id.String(), nil)
	s.expect(http.StatusNotFound, personA, http.MethodDelete, "/v1/invitations/"+id.String(), nil)
	if w := s.raw(personA, http.MethodDelete, "/v1/invitations/not-an-id", "", ""); w.Code != http.StatusBadRequest {
		t.Errorf("a bad id is %d", w.Code)
	}
	// The link of a revoked invitation opens nothing.
	if _, err := identity.AcceptInvitation(t.Context(), s.f.db, tenantA, "https://idp.example.test", "subject-dana", hash, make([]byte, 32), nil); err == nil {
		t.Error("a revoked invitation was used")
	}
	var revoked identity.Action
	for _, a := range s.logged() {
		if a.Action == "api.revoke_invitation" {
			revoked = a
		}
	}
	if revoked.Subject != "invitation "+id.String() || revoked.Principal != s.f.callers[personA].Principal {
		t.Errorf("the log has %+v", revoked)
	}
}

func TestInvitationsArePagedFromTheNewest(t *testing.T) {
	s := newScribe(t)
	var ids []uuid.UUID
	for _, name := range []string{"One", "Two", "Three"} {
		ids = append(ids, idOf(t, s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/invitations", map[string]any{"name": name, "role": "viewer"}), "id"))
	}
	first := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/invitations?limit=2", nil)["invitations"].([]any)
	if len(first) != 2 || idOf(t, first[0].(map[string]any), "id") != ids[2] || idOf(t, first[1].(map[string]any), "id") != ids[1] {
		t.Fatalf("%v", first)
	}
	rest := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/invitations?limit=2&before="+ids[1].String(), nil)["invitations"].([]any)
	if len(rest) != 1 || idOf(t, rest[0].(map[string]any), "id") != ids[0] {
		t.Fatalf("%v", rest)
	}
	for _, query := range []string{"limit=0", "limit=101", "before=nope", "limit=1&limit=2", "tenant=x"} {
		if w := s.raw(personA, http.MethodGet, "/v1/invitations?"+query, "", ""); w.Code != http.StatusBadRequest {
			t.Errorf("?%s is %d", query, w.Code)
		}
	}
}

func TestWithBrowserSignInOffNoInvitationIsMadeBecauseNoOneCouldUseTheLink(t *testing.T) {
	s := newScribe(t)
	s.h = s.f.handler(t, Limits{Rate: 1000, Burst: 1000})
	w := s.raw(personA, http.MethodPost, "/v1/invitations", "application/json", `{"name":"Dana","role":"viewer"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("%d %s, want 409", w.Code, w.Body)
	}
	if s.openInvitations(tenantA) != 0 || len(s.logged()) != 0 {
		t.Error("a refused request stored or logged something")
	}
	s.expect(http.StatusOK, personA, http.MethodGet, "/v1/invitations", nil)
}
