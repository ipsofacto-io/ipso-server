//go:build integration

package identity_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestSCIMClosesAndReopensALogin(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, created, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil || !created || !user.Active {
		t.Fatalf("provision: %+v %v created %v", user, err, created)
	}
	if got, err := identity.PrincipalFor(t.Context(), db, tenantA, issuer, "person-1"); err != nil || got != user.ID {
		t.Fatalf("principal = %s %v", got, err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.login SET subject = 'other'`); err == nil {
		t.Fatal("a login subject changed")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.login SET closed_at = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, issuer, "person-1"); err != identity.ErrUnknownLogin {
		t.Fatalf("a closed login resolved: %v", err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.login SET issuer = 'https://other.example.test'`); err == nil {
		t.Fatal("a login issuer changed")
	}
	again, created, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil || !created || again.ID != user.ID {
		t.Fatalf("reopen: %+v %v created %v", again, err, created)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, issuer, "person-1"); err != nil {
		t.Fatal(err)
	}
	renamed, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada Lovelace")
	if err != nil || renamed.Name != "Ada Lovelace" {
		t.Fatalf("rename: %+v %v", renamed, err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.principal SET kind = 'agent'`); err == nil {
		t.Fatal("a principal kind changed")
	}
}

func TestSCIMGroupSyncLeavesHandBindings(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'approver')`,
		tenantA, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupRole(t.Context(), db, tenantA, user.ID, "engineering", identity.RoleViewer, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	group, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if roles := bindingSources(t, db, user.ID); roles["approver"] != "hand" || roles["viewer"] != "idp" {
		t.Fatalf("bindings = %v", roles)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, nil); err != nil {
		t.Fatal(err)
	}
	if roles := bindingSources(t, db, user.ID); roles["approver"] != "hand" || roles["viewer"] != "" {
		t.Fatalf("after the group emptied: %v", roles)
	}
}

func TestSCIMWillNotRemoveTheLastAdmin(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'admin')`,
		tenantA, user.ID); err != nil {
		t.Fatal(err)
	}
	inactive := false
	if err := identity.ReplaceSCIMUser(t.Context(), db, tenantA, "person-1", "other@example.test", "Renamed", &inactive); err != identity.ErrLastAdmin {
		t.Fatalf("replace last admin: %v", err)
	}
	kept, err := identity.SCIMUserByExternalID(t.Context(), db, tenantA, "person-1")
	if err != nil || kept.Name != "Ada" || kept.UserName != "ada@example.test" || !kept.Active {
		t.Fatalf("a refused replace wrote %+v %v", kept, err)
	}
	if err := identity.SetSCIMActive(t.Context(), db, tenantA, "person-1", false); err != identity.ErrLastAdmin {
		t.Fatalf("last admin: %v", err)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, issuer, "person-1"); err != nil {
		t.Fatalf("the refused deprovision changed the login: %v", err)
	}
	other := principal(t, db, tenantA, identity.KindHuman, "Bea", nil)
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ($1, $2, 'admin')`,
		tenantA, other); err != nil {
		t.Fatal(err)
	}
	if err := identity.SetSCIMActive(t.Context(), db, tenantA, "person-1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, issuer, "person-1"); err != identity.ErrUnknownLogin {
		t.Fatalf("closed login resolved: %v", err)
	}
	got, err := identity.Get(t.Context(), db, tenantA, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 0 {
		t.Fatalf("bindings remained: %+v", got.Grants)
	}
}

func TestSCIMGroupPushWillNotRemoveTheLastAdmin(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupRole(t.Context(), db, tenantA, user.ID, "admins", identity.RoleAdmin, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	group, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "admins")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, nil); err != identity.ErrLastAdmin {
		t.Fatalf("group push: %v", err)
	}
	members, err := identity.SCIMGroupMembers(t.Context(), db, tenantA, group.ID)
	if err != nil || len(members) != 1 || members[0] != user.ID {
		t.Fatalf("membership changed: %v %v", members, err)
	}
	if roles := bindingSources(t, db, user.ID); roles["admin"] != "idp" {
		t.Fatalf("admin binding = %v", roles)
	}
}

func bindingSources(t *testing.T, db *sql.DB, principal uuid.UUID) map[string]string {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.QueryContext(t.Context(), `
		SELECT role, source FROM identity.role_binding WHERE principal_id = $1`, principal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var role, source string
		if err := rows.Scan(&role, &source); err != nil {
			t.Fatal(err)
		}
		out[role] = source
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
