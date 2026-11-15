package api

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// invitationOrigin is the public origin the sign-in of the tests is configured with, and the origin a link points at.
const invitationOrigin = "https://ipso.example.test"

// The three operations are the writes create_invitation and revoke_invitation and the read of invitationOps, every
// one asks for principal.manage and names no scope, and the matrix says that only an admin takes each one.
func TestTheMatrixHoldsEveryInvitationOperationForTheAdminAlone(t *testing.T) {
	var mounted []string
	for _, rt := range invitationRoutes(nil, nil, invitationOrigin) {
		mounted = append(mounted, rt.op)
		if rt.action != authz.PrincipalManage || rt.targets != nil || authz.Scoped(rt.action) {
			t.Errorf("%s asks for %q with targets %v: want principal.manage and no scope", rt.op, rt.action, rt.targets != nil)
		}
	}
	want := slices.Concat([]string{"create_invitation", "revoke_invitation"}, invitationOps)
	slices.Sort(mounted)
	slices.Sort(want)
	if !slices.Equal(mounted, want) {
		t.Fatalf("the routes are %v, the matrix names %v", mounted, want)
	}
	for _, op := range mounted {
		if !slices.Equal(mayCall[op], []string{identity.RoleAdmin}) {
			t.Errorf("%s may be taken by %v, want the admin alone", op, mayCall[op])
		}
	}
	if !slices.Contains(writeOps, "create_invitation") || !slices.Contains(writeOps, "revoke_invitation") || slices.Contains(writeOps, "list_invitations") {
		t.Errorf("writeOps = %v: create and revoke write, and the list does not", writeOps)
	}
}

// With browser sign-in off there is no origin to point a link at and no one could use it, so nothing is asked of
// the database, nothing is stored and the answer is 409.
func TestAnInvitationIsRefusedWithAConflictBeforeAnythingIsReadWhenSignInIsOff(t *testing.T) {
	for name, body := range map[string]string{"a good body": `{"name":"Dana","role":"viewer"}`, "no body": ``, "a bad body": `{`} {
		t.Run(name, func(t *testing.T) {
			h := &invitationHandlers{origin: ""}
			r := httptest.NewRequest(http.MethodPost, "/v1/invitations", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.create(w, r)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"conflict"`) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}
