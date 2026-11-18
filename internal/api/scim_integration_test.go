//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestDeprovisionRefusesTheNextCall(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler := f.handler(t, Limits{Rate: 1000, Burst: 1000})
	viewer := f.callers[viewerA]
	if w := c.exchange(t, handler, http.MethodGet, "/v1/scopes", f.token(t, viewerA), "", nil); w.Code != http.StatusOK {
		t.Fatalf("before deprovision: %d %s", w.Code, w.Body.String())
	}
	if _, err := pgtest.Exec(t.Context(), f.db, tenantA.String(), `
		INSERT INTO identity.scim_user (tenant_id, principal_id, external_id, user_name)
		VALUES ($1, $2, 'viewer-a', 'vera@example.test')`, tenantA, viewer.Principal); err != nil {
		t.Fatal(err)
	}
	if err := identity.SetSCIMActive(t.Context(), f.db, tenantA, "viewer-a", false); err != nil {
		t.Fatal(err)
	}
	w := c.exchange(t, handler, http.MethodGet, "/v1/scopes", f.token(t, viewerA), "", nil)
	if !refusedPlainly(t, w) {
		t.Fatalf("after deprovision: %d %s", w.Code, w.Body.String())
	}
}
