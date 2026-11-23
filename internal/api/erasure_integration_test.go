//go:build integration

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestAnAdminErasesAPersonsNameAndARepeatWritesNothing(t *testing.T) {
	s := newScribe(t)
	f := s.f
	person := f.callers[viewerA].Principal
	f.exec(t, `
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'Vera', $4, '[2026-05-01,2026-06-10)', 'OPS-2')`,
		tenantA, f.api, f.repo, person)
	f.exec(t, `
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by)
		VALUES ($1, $2, 'Vera', 'viewer', $3)`, tenantA, bytesOf(9), f.callers[personA].Principal)
	f.exec(t, `
		INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, 'vera')`,
		tenantA, person, "https://idp.example.test")
	f.exec(t, `
		INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name) VALUES ($1, $2, 'vera', 'vera')`,
		tenantA, person)

	before, err := identity.VerifyLog(t.Context(), f.db, tenantA)
	if err != nil || !before.Intact {
		t.Fatalf("chain before: %+v %v", before, err)
	}
	logged := len(s.logged())
	s.expect(http.StatusNoContent, personA, http.MethodPost, "/v1/principals/"+person.String()+"/erasure", nil)
	after, err := identity.VerifyLog(t.Context(), f.db, tenantA)
	if err != nil || !after.Intact || after.Entries != before.Entries+1 {
		t.Fatalf("chain after: %+v %v, before %d", after, err, before.Entries)
	}
	var name, approver, invited, userName string
	if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `
		SELECT
		  (SELECT name FROM identity.principal WHERE tenant_id = $1 AND id = $2),
		  (SELECT approver FROM registry.waiver WHERE tenant_id = $1 AND approver_id = $2 AND ticket_ref = 'OPS-2'),
		  (SELECT name FROM identity.invitation WHERE tenant_id = $1 AND token_sha256 = $3),
		  (SELECT user_name FROM identity.scim_user WHERE tenant_id = $1 AND principal_id = $2)`,
		[]any{tenantA, person, bytesOf(9)}, &name, &approver, &invited, &userName); err != nil {
		t.Fatal(err)
	}
	if name != identity.ErasedName || approver != identity.ErasedName || invited != identity.ErasedName || userName != identity.ErasedUserName(person) {
		t.Fatalf("stored name %q approver %q invitation %q filter %q", name, approver, invited, userName)
	}
	var roles int
	if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `
		SELECT count(*) FROM identity.role_binding WHERE tenant_id = $1 AND principal_id = $2`,
		[]any{tenantA, person}, &roles); err != nil || roles != 1 {
		t.Fatalf("role bindings = %d (%v)", roles, err)
	}
	var entry *identity.Action
	for _, a := range s.logged() {
		if a.Action == identity.ActionErasePrincipalName {
			copied := a
			entry = &copied
		}
	}
	if entry == nil || entry.Principal != f.callers[personA].Principal || entry.Subject != person.String() || strings.Contains(entry.Subject, "Vera") {
		t.Fatalf("log entry %+v", entry)
	}
	s.expect(http.StatusNoContent, personA, http.MethodPost, "/v1/principals/"+person.String()+"/erasure", nil)
	if len(s.logged()) != logged+1 {
		t.Fatalf("a repeat wrote an entry: %d then %d", logged, len(s.logged()))
	}

	s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/principals/"+f.callers[personA].Principal.String()+"/erasure", nil)
	s.expect(http.StatusConflict, personA, http.MethodPost, "/v1/principals/"+f.callers[agentA].Principal.String()+"/erasure", nil)
	s.expect(http.StatusNotFound, personA, http.MethodPost, "/v1/principals/"+uuid.NewString()+"/erasure", nil)
	if w := s.raw(personA, http.MethodPost, "/v1/principals/"+person.String()+"/erasure", "application/json", `{"name":"Vera"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("a body: %d %s", w.Code, w.Body)
	}
	var ada string
	if err := pgtest.Scan(t.Context(), f.db, tenantA.String(), `
		SELECT name FROM identity.principal WHERE tenant_id = $1 AND id = $2`,
		[]any{tenantA, f.callers[personA].Principal}, &ada); err != nil || ada != "Ada" {
		t.Fatalf("the only admin is %q (%v)", ada, err)
	}
}

func bytesOf(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}
