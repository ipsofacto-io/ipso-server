package api

import (
	"slices"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// The three operations are the writes grant_role_binding and revoke_role_binding and the read of roleBindingOps.
// Every one asks for principal.manage and names no scope, and the matrix says that only an admin takes each one.
func TestTheMatrixHoldsEveryRoleBindingOperationForTheAdminAlone(t *testing.T) {
	var mounted []string
	for _, rt := range roleBindingRoutes(nil, nil) {
		mounted = append(mounted, rt.op)
		if rt.action != authz.PrincipalManage || rt.targets != nil || authz.Scoped(rt.action) {
			t.Errorf("%s asks for %q with targets %v: want principal.manage and no scope", rt.op, rt.action, rt.targets != nil)
		}
	}
	want := slices.Concat([]string{"grant_role_binding", "revoke_role_binding"}, roleBindingOps)
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
	if !slices.Contains(writeOps, "grant_role_binding") || !slices.Contains(writeOps, "revoke_role_binding") || slices.Contains(writeOps, "list_role_bindings") {
		t.Errorf("writeOps = %v: grant and revoke write, and the list does not", writeOps)
	}
}
