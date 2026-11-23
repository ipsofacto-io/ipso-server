//go:build integration

package identity_test

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// invite makes an invitation as a person, through WithAction as the route does, and returns the token the
// link would hold and what was stored.
func invite(t *testing.T, db *sql.DB, tenant, by uuid.UUID, name, role string) (string, identity.Invitation) {
	t.Helper()
	token, hash, err := identity.NewInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	var inv identity.Invitation
	err = identity.WithAction(t.Context(), db, tenant, by, "api.create_invitation", func(tx *sql.Tx) (string, error) {
		var err error
		inv, err = identity.CreateInvitation(t.Context(), tx, by, name, role, hash)
		return "invitation " + inv.ID.String() + " role " + role, err
	})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	return token, inv
}

func hashOfToken(t *testing.T, token string) []byte {
	t.Helper()
	hash, ok := identity.InvitationHash(token)
	if !ok {
		t.Fatalf("%q does not read as a token", token)
	}
	return hash
}

func count(t *testing.T, admin *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := admin.QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// identityRows counts what an accepted invitation writes, in every tenant.
func identityRows(t *testing.T, admin *sql.DB) [5]int {
	t.Helper()
	return [5]int{
		count(t, admin, `SELECT count(*) FROM identity.principal`),
		count(t, admin, `SELECT count(*) FROM identity.login`),
		count(t, admin, `SELECT count(*) FROM identity.role_binding`),
		count(t, admin, `SELECT count(*) FROM identity.session`),
		count(t, admin, `SELECT count(*) FROM identity.action_log`),
	}
}

func TestAnInvitationIsStoredAsAHashThatNoWriterCanLengthen(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")

	token, inv := invite(t, db, tenantA, ada, "Bea", identity.RoleApprover)
	if inv.Name != "Bea" || inv.Role != identity.RoleApprover || inv.CreatedBy != ada {
		t.Fatalf("%+v", inv)
	}
	if lived := inv.ExpiresAt.Sub(inv.CreatedAt); lived != identity.InvitationTTL {
		t.Errorf("an invitation lives %s, want %s", lived, identity.InvitationTTL)
	}

	// The table holds the hash of the token and nothing that is the token.
	var row string
	if err := admin.QueryRowContext(t.Context(), `SELECT i::text FROM identity.invitation i`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, token) {
		t.Errorf("the row holds the token: %s", row)
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation WHERE token_sha256 = $1`, hashOfToken(t, token)); n != 1 {
		t.Errorf("the hash of the token is stored %d times", n)
	}

	// A writer that names its own times gets the stamped ones, and one that updates gets nothing.
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by, created_at, expires_at)
		VALUES ($1, sha256(convert_to('long', 'UTF8')), 'Cy', 'viewer', $2, now(), now() + interval '10 years')`, tenantA, ada); err != nil {
		t.Fatal(err)
	}
	var created, ends time.Time
	if err := admin.QueryRowContext(t.Context(), `SELECT created_at, expires_at FROM identity.invitation WHERE name = 'Cy'`).Scan(&created, &ends); err != nil {
		t.Fatal(err)
	}
	if ends.Sub(created) != identity.InvitationTTL {
		t.Errorf("a writer lengthened an invitation to %s", ends.Sub(created))
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.invitation SET role = 'admin'`); err == nil {
		t.Error("the application role updated an invitation")
	}
}

func TestTheDatabaseRefusesAnInvitationNoPersonCouldHave(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	addTenant(t, db, tenantB)
	ada := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", ada)
	other := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	_, hash, _ := identity.NewInvitationToken()

	try := func(by uuid.UUID, name, role string, hash []byte) error {
		return identity.WithAction(t.Context(), db, tenantA, ada, "api.create_invitation", func(tx *sql.Tx) (string, error) {
			_, err := identity.CreateInvitation(t.Context(), tx, by, name, role, hash)
			return "invitation", err
		})
	}
	for name, err := range map[string]error{
		"an agent role":                try(ada, "Cy", identity.RoleAgent, hash),
		"a role nobody has":            try(ada, "Cy", "root", hash),
		"an agent as the inviter":      try(agent, "Cy", identity.RoleViewer, hash),
		"an inviter of another tenant": try(other, "Cy", identity.RoleViewer, hash),
		"an empty name":                try(ada, "", identity.RoleViewer, hash),
		"a name with a control":        try(ada, "Cy\nCy", identity.RoleViewer, hash),
		"a name with spaces around it": try(ada, " Cy ", identity.RoleViewer, hash),
		"a hash of the wrong size":     try(ada, "Cy", identity.RoleViewer, hash[:5]),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := try(ada, "Cy", identity.RoleViewer, hash); err != nil {
		t.Fatalf("a good one: %v", err)
	}
	// The same token twice is refused by the unique key, as a conflict and not as a second invitation.
	err := try(ada, "Dee", identity.RoleViewer, hash)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23505" {
		t.Errorf("a repeated token: %v", err)
	}
}

func TestTheFirstSignInWithAnInvitationWritesThePersonTheLoginTheRoleAndTheSessionAndLogsIt(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	token, inv := invite(t, db, tenantA, ada, "Bea", identity.RoleApprover)
	before := identityRows(t, admin)

	expires, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-bea", hashOfToken(t, token), hashOf("bea"), nil)
	if err != nil {
		t.Fatal(err)
	}
	after := identityRows(t, admin)
	// One principal, one login, one binding, one session, one log entry, and the invitation is gone.
	for i, name := range []string{"principals", "logins", "role bindings", "sessions", "log entries"} {
		if after[i] != before[i]+1 {
			t.Errorf("%s: %d, want %d", name, after[i], before[i]+1)
		}
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation`); n != 0 {
		t.Errorf("%d invitations are left", n)
	}

	person, until, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("bea"))
	if err != nil || !until.Equal(expires) {
		t.Fatalf("the session: %v %v", until, err)
	}
	got, err := identity.Get(t.Context(), db, tenantA, person)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != identity.KindHuman || got.Name != "Bea" || got.Sponsor != uuid.Nil || len(got.Grants) != 1 || got.Grants[0] != (identity.Grant{Role: identity.RoleApprover}) {
		t.Fatalf("%+v", got)
	}
	if bound, err := identity.PrincipalFor(t.Context(), db, tenantA, idp, "subject-bea"); err != nil || bound != person {
		t.Fatalf("the login: %v %v", bound, err)
	}

	// The log names the person who accepted, with the invitation's id and role and never the token or the name.
	actions, err := identity.Actions(t.Context(), db, tenantA, 1)
	if err != nil || len(actions) != 1 {
		t.Fatalf("%+v %v", actions, err)
	}
	last := actions[0]
	if last.Action != "auth.accept_invitation" || last.Principal != person || last.Responsible != person ||
		last.Subject != "invitation "+inv.ID.String()+" role approver" {
		t.Errorf("%+v", last)
	}
	if strings.Contains(last.Subject, token) || strings.Contains(last.Subject, "Bea") {
		t.Errorf("the log subject holds the token or the name: %q", last.Subject)
	}
	if verified, err := identity.VerifyLog(t.Context(), db, tenantA); err != nil || !verified.Intact {
		t.Errorf("the chain after an accept: %+v %v", verified, err)
	}
}

func TestASecondUseOfAnInvitationIsRefusedAndWritesNothing(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	token, _ := invite(t, db, tenantA, ada, "Bea", identity.RoleViewer)
	hash := hashOfToken(t, token)
	if _, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-bea", hash, hashOf("one"), nil); err != nil {
		t.Fatal(err)
	}
	before := identityRows(t, admin)

	if _, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-cy", hash, hashOf("two"), nil); !errors.Is(err, identity.ErrUnknownInvitation) {
		t.Fatalf("a second person with the same link: %v", err)
	}
	if err := identity.CheckInvitation(t.Context(), db, tenantA, hash); !errors.Is(err, identity.ErrUnknownInvitation) {
		t.Errorf("a used invitation checks as %v", err)
	}
	if after := identityRows(t, admin); after != before {
		t.Errorf("rows %v became %v", before, after)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, idp, "subject-cy"); !errors.Is(err, identity.ErrUnknownLogin) {
		t.Errorf("the second person is bound: %v", err)
	}
}

func TestAnInvitationThatExpiredWasRevokedOrBelongsToAnotherTenantIsRefused(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	addTenant(t, db, tenantB)

	expired, _ := invite(t, db, tenantA, ada, "Old", identity.RoleViewer)
	revoked, revokedInv := invite(t, db, tenantA, ada, "Gone", identity.RoleViewer)
	foreign, _ := invite(t, db, tenantA, ada, "Foreign", identity.RoleViewer)
	// Only a superuser can age a row, because the application role cannot update one.
	if _, err := admin.ExecContext(t.Context(), `
		UPDATE identity.invitation SET created_at = now() - interval '8 days', expires_at = now() - interval '1 day'
		WHERE name = 'Old'`); err != nil {
		t.Fatal(err)
	}
	if err := identity.WithAction(t.Context(), db, tenantA, ada, "api.revoke_invitation", func(tx *sql.Tx) (string, error) {
		return "invitation " + revokedInv.ID.String(), identity.RevokeInvitation(t.Context(), tx, revokedInv.ID)
	}); err != nil {
		t.Fatal(err)
	}
	before := identityRows(t, admin)

	for name, tc := range map[string]struct {
		tenant uuid.UUID
		token  string
	}{
		"expired":                  {tenantA, expired},
		"revoked":                  {tenantA, revoked},
		"made by another tenant":   {tenantB, foreign},
		"a token nobody ever made": {tenantA, strings.Repeat("A", 43)},
	} {
		hash := hashOfToken(t, tc.token)
		if _, err := identity.AcceptInvitation(t.Context(), db, tc.tenant, idp, "subject-x", hash, hashOf(name), nil); !errors.Is(err, identity.ErrUnknownInvitation) {
			t.Errorf("%s: accept %v", name, err)
		}
		if err := identity.CheckInvitation(t.Context(), db, tc.tenant, hash); !errors.Is(err, identity.ErrUnknownInvitation) {
			t.Errorf("%s: check %v", name, err)
		}
	}
	if after := identityRows(t, admin); after != before {
		t.Errorf("rows %v became %v", before, after)
	}
	// The foreign invitation is still open in its own tenant.
	if err := identity.CheckInvitation(t.Context(), db, tenantA, hashOfToken(t, foreign)); err != nil {
		t.Errorf("the invitation of tenant A is not open there: %v", err)
	}
	// Revoking is once, and an expired invitation cannot be revoked either.
	for _, id := range []uuid.UUID{revokedInv.ID, uuid.New()} {
		err := identity.WithAction(t.Context(), db, tenantA, ada, "api.revoke_invitation", func(tx *sql.Tx) (string, error) {
			return "invitation", identity.RevokeInvitation(t.Context(), tx, id)
		})
		if !errors.Is(err, identity.ErrUnknownInvitation) {
			t.Errorf("revoke %s: %v", id, err)
		}
	}
}

func TestAPersonWhoIsAlreadyBoundSignsInAndLeavesTheInvitationOpen(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	token, _ := invite(t, db, tenantA, ada, "Bea", identity.RoleViewer)
	before := identityRows(t, admin)

	if _, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-ada", hashOfToken(t, token), hashOf("ada"), nil); err != nil {
		t.Fatal(err)
	}
	after := identityRows(t, admin)
	if after[3] != before[3]+1 || after[0] != before[0] || after[1] != before[1] || after[2] != before[2] || after[4] != before[4] {
		t.Errorf("rows %v became %v: only a session should be new", before, after)
	}
	if err := identity.CheckInvitation(t.Context(), db, tenantA, hashOfToken(t, token)); err != nil {
		t.Errorf("the invitation of someone else was used up: %v", err)
	}
}

func TestAnAgentLoginThatSignsInWithAnInvitationIsRefusedAndTheInvitationStaysOpen(t *testing.T) {
	db := migrated(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", ada)
	if err := bind(t, db, tenantA, agent, idp, "subject-agent"); err != nil {
		t.Fatal(err)
	}
	token, _ := invite(t, db, tenantA, ada, "Bea", identity.RoleViewer)

	if _, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-agent", hashOfToken(t, token), hashOf("agent"), nil); !errors.Is(err, identity.ErrNotHuman) {
		t.Fatalf("%v", err)
	}
	if err := identity.CheckInvitation(t.Context(), db, tenantA, hashOfToken(t, token)); err != nil {
		t.Errorf("the invitation was used: %v", err)
	}
}

func TestAnInvitationUsedByManyAtOnceHasOneWinner(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	token, _ := invite(t, db, tenantA, ada, "Bea", identity.RoleViewer)
	hash := hashOfToken(t, token)
	before := identityRows(t, admin)

	const people = 8
	var wg sync.WaitGroup
	results := make([]error, people)
	for i := range people {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = identity.AcceptInvitation(t.Context(), db, tenantA, idp, fmt.Sprintf("subject-%d", i), hash, hashOf(fmt.Sprintf("session-%d", i)), nil)
		}()
	}
	wg.Wait()

	winners := 0
	for i, err := range results {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, identity.ErrUnknownInvitation):
			t.Errorf("person %d: %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d people used one invitation", winners)
	}
	after := identityRows(t, admin)
	for i := range after {
		if after[i] != before[i]+1 {
			t.Errorf("column %d: %d, want %d", i, after[i], before[i]+1)
		}
	}
}

func TestOpenInvitationsAreBoundedAndExpiredOnesGoWhenANewOneIsMade(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	if _, err := admin.ExecContext(t.Context(), `
		INSERT INTO identity.invitation (tenant_id, token_sha256, name, role, created_by)
		SELECT $1, sha256(convert_to('seed ' || n, 'UTF8')), 'Seed ' || n, 'viewer', $2
		FROM generate_series(1, $3) AS n`, tenantA, ada, identity.MaxOpenInvitations); err != nil {
		t.Fatal(err)
	}
	_, hash, _ := identity.NewInvitationToken()
	err := identity.WithAction(t.Context(), db, tenantA, ada, "api.create_invitation", func(tx *sql.Tx) (string, error) {
		_, err := identity.CreateInvitation(t.Context(), tx, ada, "One too many", identity.RoleViewer, hash)
		return "invitation", err
	})
	if !errors.Is(err, identity.ErrTooManyInvitations) {
		t.Fatalf("the %dth invitation: %v", identity.MaxOpenInvitations+1, err)
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation`); n != identity.MaxOpenInvitations {
		t.Errorf("%d rows after the refusal", n)
	}

	// A week later every one has expired, and making a new one drops them first.
	if _, err := admin.ExecContext(t.Context(), `UPDATE identity.invitation SET created_at = now() - interval '8 days', expires_at = now() - interval '1 day'`); err != nil {
		t.Fatal(err)
	}
	invite(t, db, tenantA, ada, "Fresh", identity.RoleViewer)
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation`); n != 1 {
		t.Errorf("%d rows after the expired ones were dropped", n)
	}
}

func TestInvitationsAreListedOpenOnesFirstNewestAndNeverWithAToken(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	addTenant(t, db, tenantB)
	bea := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	_, first := invite(t, db, tenantA, ada, "First", identity.RoleViewer)
	_, second := invite(t, db, tenantA, ada, "Second", identity.RoleAuditor)
	_, third := invite(t, db, tenantA, ada, "Third", identity.RoleAdmin)
	invite(t, db, tenantB, bea, "Elsewhere", identity.RoleViewer)
	_, old := invite(t, db, tenantA, ada, "Old", identity.RoleViewer)
	if _, err := admin.ExecContext(t.Context(), `
		UPDATE identity.invitation SET created_at = now() - interval '8 days', expires_at = now() - interval '1 day' WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}

	page, err := identity.ListInvitations(t.Context(), db, tenantA, uuid.Nil, 2)
	if err != nil || len(page) != 2 || page[0].ID != third.ID || page[1].ID != second.ID {
		t.Fatalf("%+v %v", page, err)
	}
	if page[0].Role != identity.RoleAdmin || page[0].Name != "Third" || page[0].CreatedBy != ada {
		t.Errorf("%+v", page[0])
	}
	rest, err := identity.ListInvitations(t.Context(), db, tenantA, page[1].ID, 2)
	if err != nil || len(rest) != 1 || rest[0].ID != first.ID {
		t.Fatalf("the next page: %+v %v", rest, err)
	}
	for _, bad := range []int{0, 101, -1} {
		if _, err := identity.ListInvitations(t.Context(), db, tenantA, uuid.Nil, bad); !errors.Is(err, identity.ErrInvalidQuery) {
			t.Errorf("limit %d: %v", bad, err)
		}
	}
}

func TestTwoSignInsOfOnePersonAtOnceLeaveOnePersonAndNeitherIsRefused(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	first, _ := invite(t, db, tenantA, ada, "Bea", identity.RoleViewer)
	second, _ := invite(t, db, tenantA, ada, "Bea again", identity.RoleViewer)
	before := identityRows(t, admin)

	// The same person finishes a sign-in with each of two invitations, and a third tab repeats the first. Whichever
	// is second finds the login bound, signs in as it, and leaves its invitation open.
	tokens := []string{first, second, first, second, first, second}
	var wg sync.WaitGroup
	results := make([]error, len(tokens))
	for i, token := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-bea", hashOfToken(t, token), hashOf(fmt.Sprintf("tab-%d", i)), nil)
		}()
	}
	wg.Wait()
	for i, err := range results {
		if err != nil {
			t.Errorf("sign-in %d: %v", i, err)
		}
	}
	after := identityRows(t, admin)
	if after[0] != before[0]+1 || after[1] != before[1]+1 || after[2] != before[2]+1 {
		t.Errorf("rows %v became %v: want one person, one login and one binding", before, after)
	}
	if after[3] != before[3]+len(tokens) {
		t.Errorf("%d sessions, want one for each sign-in", after[3]-before[3])
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation`); n != 1 {
		t.Errorf("%d invitations are left, want the one that was not needed", n)
	}
}

func TestACreateInvitationForARoleNoPersonHoldsIsInvalidAndWritesNothing(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	_, hash, _ := identity.NewInvitationToken()
	err := identity.WithAction(t.Context(), db, tenantA, ada, "api.create_invitation", func(tx *sql.Tx) (string, error) {
		_, err := identity.CreateInvitation(t.Context(), tx, ada, "Cy", identity.RoleAgent, hash)
		return "invitation", err
	})
	if !errors.Is(err, identity.ErrInvalidInvitation) || errors.Is(err, identity.ErrInvalidQuery) {
		t.Fatalf("%v", err)
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation`); n != 0 {
		t.Errorf("%d invitations", n)
	}
}

func TestAnInvitationWhoseNameWasErasedCannotBeAccepted(t *testing.T) {
	db, admin := withAdmin(t)
	addTenant(t, db, tenantA)
	ada := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	token, inv := invite(t, db, tenantA, ada, "Nia", identity.RoleViewer)
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		UPDATE identity.invitation SET name = $2 WHERE tenant_id = $1 AND id = $3`,
		tenantA, identity.ErasedName, inv.ID); err != nil {
		t.Fatal(err)
	}
	_, err := identity.AcceptInvitation(t.Context(), db, tenantA, idp, "subject-nia", hashOfToken(t, token), hashOf("nia"), nil)
	if !errors.Is(err, identity.ErrUnknownInvitation) {
		t.Fatalf("accept: %v", err)
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.invitation WHERE id = $1`, inv.ID); n != 1 {
		t.Fatalf("the invitation is gone: %d", n)
	}
	if n := count(t, admin, `SELECT count(*) FROM identity.principal WHERE name = $1`, identity.ErasedName); n != 0 {
		t.Fatalf("%d principals were created", n)
	}
}
