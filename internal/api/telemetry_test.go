package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

// The guard knows the route of every request before it decides, so a request that is refused is counted by the
// route it asked for, and never by its path. A path can hold a name.
func TestARefusedRequestIsCountedByItsRouteAndNeverItsPath(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	// The control plane sends everything under /v1/ to the API, and observes the whole of its root mux.
	root := http.NewServeMux()
	root.Handle("/v1/", newAPI(t, callerOf(tenantA), Limits{}))
	handler := tel.Handler(tenantA, root)
	for _, tc := range []struct{ method, target, authorization string }{
		{http.MethodGet, "/v1/decisions", ""},
		{http.MethodGet, "/v1/decisions/ada@example.org?author=ada", "Bearer bad"},
		{http.MethodGet, "/v1/nothing/ada.lovelace", ""},
		{http.MethodDelete, "/v1/decisions", ""},
	} {
		call(t, handler, tc.method, tc.target, tc.authorization)
	}
	var names []string
	for _, s := range rec.Spans() {
		names = append(names, s.Name)
		if got := telemetrytest.Attrs(s.Attributes); got["http.response.status_code"] != "401" || got["ipso.tenant.id"] != tenantA.String() {
			t.Errorf("%s: %v", s.Name, got)
		}
	}
	want := []string{"GET /v1/decisions", "GET /v1/decisions/{ref}", "GET /v1/", "DELETE /v1/"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Errorf("span names %q, want %q", names, want)
	}
	rec.CheckKeys(t)
}
