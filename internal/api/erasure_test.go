package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

func TestTheErasureRouteAsksForPrincipalManageAndNamesNoScope(t *testing.T) {
	routes := erasureRoutes(nil, nil)
	if len(routes) != 1 {
		t.Fatalf("%d routes", len(routes))
	}
	rt := routes[0]
	if rt.op != "erase_principal_name" || rt.action != authz.PrincipalManage || rt.targets != nil || authz.Scoped(rt.action) {
		t.Fatalf("%s asks for %q", rt.op, rt.action)
	}
	if got, want := mayCall[rt.op], []string{identity.RoleAdmin}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("the matrix lets %v take it", got)
	}
}

func TestABodyOnErasureIsRefusedBeforeTheStore(t *testing.T) {
	h := &erasureHandlers{}
	r := httptest.NewRequest(http.MethodPost, "/v1/principals/"+someone.String()+"/erasure", strings.NewReader(`{"name":"Ada"}`))
	r.SetPathValue("id", someone.String())
	w := httptest.NewRecorder()
	h.erase(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"invalid query"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
