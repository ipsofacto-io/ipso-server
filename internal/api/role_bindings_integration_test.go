//go:build integration

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestAnAdminGrantsListsAndRevokesARoleBinding(t *testing.T) {
	s := newScribe(t)
	f := s.f
	nobody := f.callers[nobodyA].Principal
	wide := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": nobody, "role": "contributor",
	})
	if wide["role"] != "contributor" || wide["scope_id"] != nil || idOf(t, wide, "principal_id") != nobody {
		t.Fatalf("the tenant-wide grant answered %v", wide)
	}
	scoped := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": nobody, "role": "approver", "scope_id": f.repo,
	})
	if scoped["scope_id"] != f.repo.String() || scoped["role"] != "approver" {
		t.Fatalf("the scoped grant answered %v", scoped)
	}

	page := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/role-bindings?limit=2", nil)["role_bindings"].([]any)
	if len(page) != 2 || idOf(t, page[0].(map[string]any), "id") != idOf(t, scoped, "id") || idOf(t, page[1].(map[string]any), "id") != idOf(t, wide, "id") {
		t.Fatalf("the page is %v", page)
	}
	if page[1].(map[string]any)["scope_id"] != nil {
		t.Fatalf("a tenant-wide binding answered %v", page[1])
	}
	rest := s.expect(http.StatusOK, personA, http.MethodGet, "/v1/role-bindings?limit=2&before="+idOf(t, scoped, "id").String(), nil)["role_bindings"].([]any)
	if len(rest) == 0 || idOf(t, rest[0].(map[string]any), "id") != idOf(t, wide, "id") {
		t.Fatalf("the next page is %v", rest)
	}

	s.expect(http.StatusNoContent, personA, http.MethodDelete, "/v1/role-bindings/"+idOf(t, scoped, "id").String(), nil)
	s.expect(http.StatusNotFound, personA, http.MethodDelete, "/v1/role-bindings/"+idOf(t, scoped, "id").String(), nil)

	var grant, revoke string
	for _, a := range s.logged() {
		switch a.Action {
		case "api.grant_role_binding":
			if grant == "" || strings.Contains(a.Subject, "scope ") {
				grant = a.Subject
			}
		case "api.revoke_role_binding":
			revoke = a.Subject
		}
	}
	principal := "principal " + nobody.String()
	if !strings.Contains(grant, principal) || strings.Contains(grant, "Vera") || strings.Contains(grant, "Noor") {
		t.Errorf("the grant log is %q", grant)
	}
	if !strings.Contains(revoke, principal) || !strings.Contains(revoke, "scope "+f.repo.String()) || strings.Contains(revoke, "Noor") {
		t.Errorf("the revoke log is %q", revoke)
	}
}

func TestARoleBindingTheDatabaseRefusesStoresNothing(t *testing.T) {
	s := newScribe(t)
	f := s.f
	person := f.callers[viewerA].Principal
	agent := f.callers[agentA].Principal
	before := s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`)
	logs := len(s.logged())

	refused := s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/role-bindings", map[string]any{"principal_id": person, "role": "agent"})
	if refused["error"] != "conflict" {
		t.Fatalf("a person given agent: %v", refused)
	}
	refused = s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/role-bindings", map[string]any{"principal_id": agent, "role": "admin"})
	if refused["error"] != "conflict" {
		t.Fatalf("an agent given admin: %v", refused)
	}
	for _, role := range []string{"viewer", "auditor", "admin"} {
		refused = s.expect(http.StatusBadRequest, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
			"principal_id": person, "role": role, "scope_id": f.repo,
		})
		if refused["error"] != "invalid query" {
			t.Fatalf("%s on a scope: %v", role, refused)
		}
	}
	refused = s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/role-bindings", map[string]any{"principal_id": person, "role": "viewer"})
	if refused["error"] != "conflict" {
		t.Fatalf("a duplicate: %v", refused)
	}
	w := s.raw(personA, http.MethodPost, "/v1/role-bindings", "application/json", `{"principal_id":"`+person.String()+`","role":"root"}`)
	if w.Code != http.StatusBadRequest || errorOf(t, w) != "invalid query" {
		t.Fatalf("an unknown role is %d %s", w.Code, w.Body)
	}
	if body := w.Body.String(); strings.Contains(body, "SQLSTATE") || strings.Contains(body, "role_binding") || strings.Contains(body, "an agent holds") {
		t.Fatalf("the answer holds a database message: %s", body)
	}
	if s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`) != before || len(s.logged()) != logs {
		t.Fatal("a refused grant stored a binding or logged it")
	}
}

func TestARoleBindingOfAnotherTenantIsNotFound(t *testing.T) {
	s := newScribe(t)
	f := s.f
	var otherScope, otherBinding uuid.UUID
	if err := pgtest.Scan(t.Context(), f.db, tenantB.String(), `SELECT id FROM registry.scope WHERE tenant_id = $1 AND selector = 'globex'`, []any{tenantB}, &otherScope); err != nil {
		t.Fatal(err)
	}
	if err := pgtest.Scan(t.Context(), f.db, tenantB.String(), `
		SELECT id FROM identity.role_binding WHERE tenant_id = $1 AND role = 'admin' AND scope_id IS NULL`, []any{tenantB}, &otherBinding); err != nil {
		t.Fatal(err)
	}
	before := s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`)
	s.expect(http.StatusNotFound, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": f.callers[personB].Principal, "role": "viewer",
	})
	s.expect(http.StatusNotFound, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": f.callers[nobodyA].Principal, "role": "approver", "scope_id": otherScope,
	})
	s.expect(http.StatusNotFound, personA, http.MethodDelete, "/v1/role-bindings/"+otherBinding.String(), nil)
	if s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`) != before {
		t.Fatal("a binding of another tenant changed this tenant")
	}
	if s.count(tenantB, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`) == 0 {
		t.Fatal("tenant B lost a binding")
	}
}

func TestTheOnlyAdminCannotBeRevokedThroughTheAPI(t *testing.T) {
	s := newScribe(t)
	var adminBinding uuid.UUID
	if err := pgtest.Scan(t.Context(), s.f.db, tenantA.String(), `
		SELECT id FROM identity.role_binding
		WHERE tenant_id = $1 AND principal_id = $2 AND role = 'admin' AND scope_id IS NULL`,
		[]any{tenantA, s.f.callers[personA].Principal}, &adminBinding); err != nil {
		t.Fatal(err)
	}
	logs := len(s.logged())
	refused := s.expect(http.StatusConflict, personA, http.MethodDelete, "/v1/role-bindings/"+adminBinding.String(), nil)
	if refused["error"] != "conflict" {
		t.Fatalf("the only admin: %v", refused)
	}
	if s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1 AND role = 'admin' AND scope_id IS NULL`) != 1 || len(s.logged()) != logs {
		t.Fatal("the refused revoke removed the admin or was logged")
	}
	s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": s.f.callers[nobodyA].Principal, "role": "admin",
	})
	s.expect(http.StatusNoContent, personA, http.MethodDelete, "/v1/role-bindings/"+adminBinding.String(), nil)
	if s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1 AND role = 'admin' AND scope_id IS NULL`) != 1 {
		t.Fatal("revoking the first admin left the tenant without one, or with both")
	}
}

func TestARoleTheCallerDoesNotHoldChangesNothing(t *testing.T) {
	s := newScribe(t)
	nobody := s.f.callers[nobodyA].Principal
	granted := s.expect(http.StatusCreated, personA, http.MethodPost, "/v1/role-bindings", map[string]any{
		"principal_id": nobody, "role": "viewer",
	})
	target := "/v1/role-bindings/" + idOf(t, granted, "id").String()
	before := s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`)
	logs := len(s.logged())
	body := map[string]any{"principal_id": nobody, "role": "contributor"}
	for _, who := range []string{viewerA, auditorA, contributorA, approverA, ownerA, agentA, nobodyA} {
		for _, call := range []struct {
			method, path string
			payload      any
		}{
			{http.MethodPost, "/v1/role-bindings", body},
			{http.MethodGet, "/v1/role-bindings", nil},
			{http.MethodDelete, target, nil},
		} {
			code, answer := s.send(who, call.method, call.path, call.payload)
			if code != http.StatusForbidden || len(answer) != 1 || answer["error"] != "forbidden" {
				t.Errorf("%s %s as %s: %d %v", call.method, call.path, who, code, answer)
			}
		}
	}
	if s.count(tenantA, `SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1`) != before || len(s.logged()) != logs {
		t.Fatal("a refusal stored a binding or logged it")
	}
}

func TestARoleBindingListRefusesABadPage(t *testing.T) {
	s := newScribe(t)
	for _, query := range []string{"limit=0", "limit=101", "before=nope", "limit=1&limit=2", "tenant=x"} {
		if w := s.raw(personA, http.MethodGet, "/v1/role-bindings?"+query, "", ""); w.Code != http.StatusBadRequest {
			t.Errorf("?%s is %d", query, w.Code)
		}
	}
}
