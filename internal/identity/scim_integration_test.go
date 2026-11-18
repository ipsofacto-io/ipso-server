//go:build integration

package identity_test

import (
	"database/sql"
	"errors"
	"strings"
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

func TestSCIMGroupPushSetsAndClearsOwnerTeams(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	row, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform")
	if err != nil {
		t.Fatal(err)
	}
	if subjects := actionSubjects(t, db, "scim.group_owner"); len(subjects) != 1 || subjects[0] != row.ID.String() || strings.Contains(subjects[0], "team:") {
		t.Fatalf("subjects = %v", subjects)
	}
	eng, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, eng.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 1 || owners["team:platform"] != "idp" {
		t.Fatalf("owners = %v", owners)
	}
	if subjects := actionSubjects(t, db, "scim.group_owner"); len(subjects) != 1 {
		t.Fatalf("a member replace wrote %v", subjects)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "platform", "team:platform"); err != nil {
		t.Fatal(err)
	}
	plat, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "platform")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, plat.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, eng.ID, nil); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); owners["team:platform"] != "idp" {
		t.Fatalf("the other group should keep the team: %v", owners)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, plat.ID, nil); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 0 {
		t.Fatalf("owners remained: %v", owners)
	}
}

func TestSCIMGroupPushLeavesAHandOwner(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.principal_owner (tenant_id, principal_id, owner_ref)
		VALUES ($1, $2, 'team:platform')`, tenantA, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform"); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:security"); err != nil {
		t.Fatal(err)
	}
	group, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); owners["team:platform"] != "hand" || owners["team:security"] != "idp" {
		t.Fatalf("owners = %v", owners)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, nil); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 1 || owners["team:platform"] != "hand" {
		t.Fatalf("after leaving: %v", owners)
	}
}

func TestSCIMOwnerMappingRecomputesCurrentMembers(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	group, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	row, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform")
	if err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); owners["team:platform"] != "idp" {
		t.Fatalf("owners = %v", owners)
	}
	if err := identity.DeleteIDPGroupOwner(t.Context(), db, tenantA, user.ID, row.ID); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 0 {
		t.Fatalf("the mapping delete left %v", owners)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform"); err != nil {
		t.Fatal(err)
	}
	if err := identity.DeleteSCIMGroup(t.Context(), db, tenantA, group.ID); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 0 {
		t.Fatalf("the group delete left %v", owners)
	}
}

func TestSCIMDeprovisionClearsOwnerTeams(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform"); err != nil {
		t.Fatal(err)
	}
	group, err := identity.CreateSCIMGroup(t.Context(), db, tenantA, "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.principal_owner (tenant_id, principal_id, owner_ref)
		VALUES ($1, $2, 'team:security')`, tenantA, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := identity.SetSCIMActive(t.Context(), db, tenantA, "person-1", false); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 0 {
		t.Fatalf("deprovision left %v", owners)
	}
	if _, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada"); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 0 {
		t.Fatalf("provision restored %v", owners)
	}
	if err := identity.ReplaceSCIMGroupMembers(t.Context(), db, tenantA, group.ID, []uuid.UUID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if owners := ownerSources(t, db, user.ID); len(owners) != 1 || owners["team:platform"] != "idp" {
		t.Fatalf("after the next push: %v", owners)
	}
}

func TestSCIMOwnerTeamRefusesABadNameAndAnAgent(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	const issuer = "https://idp.example.test/meta"
	user, _, err := identity.ProvisionSCIMUser(t.Context(), db, tenantA, issuer, "person-1", "ada@example.test", "Ada")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform"); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", "team:platform"); !errors.Is(err, identity.ErrSCIMConflict) {
		t.Fatalf("repeat = %v", err)
	}
	for _, name := range []string{"platform", "team:Platform", "team:", "team:a-", "team:platform ", ""} {
		if _, err := identity.PutIDPGroupOwner(t.Context(), db, tenantA, user.ID, "engineering", name); !errors.Is(err, identity.ErrInvalidQuery) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	person := principal(t, db, tenantA, identity.KindHuman, "Bea", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "runner", person)
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.principal_owner (tenant_id, principal_id, owner_ref)
		VALUES ($1, $2, 'team:platform')`, tenantA, agent); err == nil || !strings.Contains(err.Error(), "an owner team belongs to a person") {
		t.Fatalf("agent: %v", err)
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

func ownerSources(t *testing.T, db *sql.DB, principal uuid.UUID) map[string]string {
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
		SELECT owner_ref, source FROM identity.principal_owner WHERE principal_id = $1`, principal)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var team, source string
		if err := rows.Scan(&team, &source); err != nil {
			t.Fatal(err)
		}
		out[team] = source
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func actionSubjects(t *testing.T, db *sql.DB, action string) []string {
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
		SELECT subject FROM identity.action_log WHERE action = $1 ORDER BY subject`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			t.Fatal(err)
		}
		out = append(out, subject)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
