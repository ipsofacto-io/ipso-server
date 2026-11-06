//go:build integration

package identity_test

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// withAdmin migrates a database and returns the application connection and a superuser's. The
// superuser is how a test ages a session: the application role cannot update one.
func withAdmin(t *testing.T) (app, admin *sql.DB) {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database.Open(t, pgtest.App), database.Open(t, pgtest.Admin)
}

func hashOf(seed string) []byte {
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func sessionCount(t *testing.T, admin *sql.DB) int {
	t.Helper()
	var n int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM identity.session`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// boundPerson adds a tenant row, a person, and the login that binds idp and subject to them.
func boundPerson(t *testing.T, db *sql.DB, tenant uuid.UUID, name, subject string) uuid.UUID {
	t.Helper()
	addTenant(t, db, tenant)
	person := principal(t, db, tenant, identity.KindHuman, name, nil)
	if err := bind(t, db, tenant, person, idp, subject); err != nil {
		t.Fatal(err)
	}
	return person
}

func TestASessionStartsForABoundPersonAndLastsEightHours(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")

	expires, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("one"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expires); left < 7*time.Hour+58*time.Minute || left > 8*time.Hour+2*time.Minute {
		t.Errorf("the session ends in %v, want about 8 hours", left)
	}
	got, until, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("one"))
	if err != nil || got != ada || !until.Equal(expires) {
		t.Fatalf("SessionPrincipal = %v, %v, %v, want %v ending %v", got, until, err, ada, expires)
	}
	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("another token")); !errors.Is(err, identity.ErrUnknownSession) {
		t.Errorf("an unknown token: err = %v, want ErrUnknownSession", err)
	}
	if n := sessionCount(t, admin); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}

func TestASessionNeedsALoginTheTenantBound(t *testing.T) {
	db, admin := withAdmin(t)
	boundPerson(t, db, tenantA, "Ada", "subject-ada")

	for name, args := range map[string][2]string{
		"another subject": {idp, "subject-bea"},
		"another issuer":  {"https://other.example.test", "subject-ada"},
	} {
		if _, err := identity.StartSession(t.Context(), db, tenantA, args[0], args[1], hashOf(name), nil); !errors.Is(err, identity.ErrUnknownLogin) {
			t.Errorf("%s: err = %v, want ErrUnknownLogin", name, err)
		}
	}
	for name, hash := range map[string][]byte{"no hash": nil, "a short hash": make([]byte, 31), "a long hash": make([]byte, 33)} {
		if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hash, nil); !errors.Is(err, identity.ErrInvalidQuery) {
			t.Errorf("%s: err = %v, want ErrInvalidQuery", name, err)
		}
	}
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("x"), make([]byte, 5)); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Errorf("a short previous hash: err = %v, want ErrInvalidQuery", err)
	}
	if n := sessionCount(t, admin); n != 0 {
		t.Errorf("%d sessions after refused sign-ins, want 0", n)
	}
}

func TestAnAgentsLoginGetsNoSession(t *testing.T) {
	db, admin := withAdmin(t)
	person := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	if err := bind(t, db, tenantA, agent, idp, "subject-agent"); err != nil {
		t.Fatalf("an agent keeps its bearer login: %v", err)
	}

	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-agent", hashOf("agent"), nil); !errors.Is(err, identity.ErrNotHuman) {
		t.Fatalf("err = %v, want ErrNotHuman", err)
	}
	if n := sessionCount(t, admin); n != 0 {
		t.Errorf("%d sessions, want 0", n)
	}
}

func TestAnExpiredSessionIsRefusedAndDeletedByTheNextSignIn(t *testing.T) {
	db, admin := withAdmin(t)
	boundPerson(t, db, tenantA, "Ada", "subject-ada")
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("old"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(t.Context(), `
		UPDATE identity.session
		SET created_at = clock_timestamp() - interval '9 hours', expires_at = clock_timestamp() - interval '1 minute'`); err != nil {
		t.Fatal(err)
	}

	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("old")); !errors.Is(err, identity.ErrUnknownSession) {
		t.Fatalf("an expired session: err = %v, want ErrUnknownSession", err)
	}
	if n := sessionCount(t, admin); n != 1 {
		t.Fatalf("%d sessions before the next sign-in, want 1", n)
	}
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("new"), nil); err != nil {
		t.Fatal(err)
	}
	if n := sessionCount(t, admin); n != 1 {
		t.Errorf("%d sessions after the next sign-in, want 1: the expired row should be gone", n)
	}
}

func TestANewSessionEndsThePreviousOne(t *testing.T) {
	db, admin := withAdmin(t)
	ada := boundPerson(t, db, tenantA, "Ada", "subject-ada")
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("first"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("second"), hashOf("first")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("first")); !errors.Is(err, identity.ErrUnknownSession) {
		t.Errorf("the previous session: err = %v, want ErrUnknownSession", err)
	}
	if got, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("second")); err != nil || got != ada {
		t.Errorf("the new session = %v, %v, want %v", got, err, ada)
	}
	if n := sessionCount(t, admin); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}

func TestEndingASessionTwiceIsNotAnError(t *testing.T) {
	db, _ := withAdmin(t)
	boundPerson(t, db, tenantA, "Ada", "subject-ada")
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("one"), nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := identity.EndSession(t.Context(), db, tenantA, hashOf("one")); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("one")); !errors.Is(err, identity.ErrUnknownSession) {
		t.Errorf("err = %v, want ErrUnknownSession", err)
	}
	if err := identity.EndSession(t.Context(), db, tenantA, []byte("short")); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Errorf("a short hash: err = %v, want ErrInvalidQuery", err)
	}
}

func TestASessionOfOneTenantSpeaksForNoOther(t *testing.T) {
	db, admin := withAdmin(t)
	boundPerson(t, db, tenantA, "Ada", "subject-ada")
	bea := boundPerson(t, db, tenantB, "Bea", "subject-bea")
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("ada"), nil); err != nil {
		t.Fatal(err)
	}

	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantB, hashOf("ada")); !errors.Is(err, identity.ErrUnknownSession) {
		t.Errorf("tenant A's cookie at tenant B: err = %v, want ErrUnknownSession", err)
	}
	if _, err := identity.StartSession(t.Context(), db, tenantB, idp, "subject-ada", hashOf("cross"), nil); !errors.Is(err, identity.ErrUnknownLogin) {
		t.Errorf("tenant A's subject at tenant B: err = %v, want ErrUnknownLogin", err)
	}
	if err := identity.EndSession(t.Context(), db, tenantB, hashOf("ada")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("ada")); err != nil {
		t.Errorf("tenant B ended tenant A's session: %v", err)
	}
	// A previous hash from another tenant ends nothing either.
	if _, err := identity.StartSession(t.Context(), db, tenantB, idp, "subject-bea", hashOf("bea"), hashOf("ada")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identity.SessionPrincipal(t.Context(), db, tenantA, hashOf("ada")); err != nil {
		t.Errorf("a sign-in at tenant B ended tenant A's session: %v", err)
	}
	if got, _, err := identity.SessionPrincipal(t.Context(), db, tenantB, hashOf("bea")); err != nil || got != bea {
		t.Errorf("tenant B's session = %v, %v, want %v", got, err, bea)
	}
	if n := sessionCount(t, admin); n != 2 {
		t.Errorf("%d sessions, want 2", n)
	}
}

func TestTheApplicationRoleCannotChangeASessionOrChooseItsLifetime(t *testing.T) {
	db, admin := withAdmin(t)
	boundPerson(t, db, tenantA, "Ada", "subject-ada")
	if _, err := identity.StartSession(t.Context(), db, tenantA, idp, "subject-ada", hashOf("one"), nil); err != nil {
		t.Fatal(err)
	}

	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.session SET expires_at = expires_at + interval '1 year'`); err == nil {
		t.Error("a session was updated")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.session (tenant_id, login_id, token_sha256, created_at, expires_at)
		SELECT tenant_id, id, $1::bytea, now() - interval '1 year', now() + interval '10 years' FROM identity.login`, hashOf("long")); err != nil {
		t.Fatalf("an insert that names a lifetime: %v", err)
	}
	var created, ends time.Time
	if err := admin.QueryRowContext(t.Context(), `SELECT created_at, expires_at FROM identity.session WHERE token_sha256 = $1`, hashOf("long")).Scan(&created, &ends); err != nil {
		t.Fatal(err)
	}
	if got := ends.Sub(created); got != 8*time.Hour {
		t.Errorf("the lifetime = %v, want 8h: the trigger must set it whatever the writer sent", got)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO identity.session (tenant_id, login_id, token_sha256)
		SELECT tenant_id, id, '\x00'::bytea FROM identity.login`); err == nil {
		t.Error("a token hash of one byte was accepted")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantB.String(), `
		INSERT INTO identity.session (tenant_id, login_id, token_sha256)
		SELECT tenant_id, id, $1::bytea FROM identity.login`, hashOf("smuggled")); err == nil {
		// Tenant B has no login, so nothing is selected and the statement is a no-op, not a refusal.
		var n int
		if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM identity.session WHERE token_sha256 = $1`, hashOf("smuggled")).Scan(&n); err != nil || n != 0 {
			t.Errorf("tenant B wrote a session for tenant A's login: %d rows, %v", n, err)
		}
	}
}
