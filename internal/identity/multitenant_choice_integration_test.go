//go:build integration

package identity_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestHumanLoginTenantsFiltersClosedAndAgentsAndOrdersByName(t *testing.T) {
	app, _ := withAdmin(t)
	tenantZ := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	tenantA := uuid.MustParse("00000000-0000-4000-8000-0000000000a2")
	tenantAgent := uuid.MustParse("00000000-0000-4000-8000-0000000000a3")
	tenantClosed := uuid.MustParse("00000000-0000-4000-8000-0000000000a4")

	for _, pair := range []struct {
		id   uuid.UUID
		name string
	}{
		{tenantZ, "Zeta Corp"},
		{tenantA, "Alpha Org"},
		{tenantAgent, "Agent Org"},
		{tenantClosed, "Closed Org"},
	} {
		if _, err := pgtest.Exec(t.Context(), app, pair.id.String(),
			`INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, $2)`, pair.id, pair.name); err != nil {
			t.Fatal(err)
		}
	}

	pZ := principal(t, app, tenantZ, identity.KindHuman, "Alice Z", nil)
	pA := principal(t, app, tenantA, identity.KindHuman, "Alice A", nil)
	pSponsor := principal(t, app, tenantAgent, identity.KindHuman, "Sponsor", nil)
	pAgent := principal(t, app, tenantAgent, identity.KindAgent, "Bot", &pSponsor)
	pClosed := principal(t, app, tenantClosed, identity.KindHuman, "Alice Closed", nil)

	if err := bind(t, app, tenantZ, pZ, idp, "shared-sub"); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, app, tenantA, pA, idp, "shared-sub"); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, app, tenantAgent, pAgent, idp, "shared-sub"); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, app, tenantClosed, pClosed, idp, "shared-sub"); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), app, tenantClosed.String(),
		`UPDATE identity.login SET closed_at = now() WHERE issuer = $1 AND subject = 'shared-sub'`, idp); err != nil {
		t.Fatal(err)
	}

	got, err := identity.HumanLoginTenants(t.Context(), app, idp, "shared-sub")
	if err != nil {
		t.Fatalf("HumanLoginTenants: %v", err)
	}
	if len(got) != 2 || got[0].ID != tenantA || got[0].Name != "Alpha Org" || got[1].ID != tenantZ || got[1].Name != "Zeta Corp" {
		t.Fatalf("HumanLoginTenants = %+v, want [Alpha Org, Zeta Corp]", got)
	}

	// Agent-only subject returns ErrNotHuman.
	if err := bind(t, app, tenantAgent, pAgent, idp, "agent-only-sub"); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.HumanLoginTenants(t.Context(), app, idp, "agent-only-sub"); !errors.Is(err, identity.ErrNotHuman) {
		t.Fatalf("agent-only err = %v, want ErrNotHuman", err)
	}

	// Unknown subject returns ErrUnknownLogin.
	if _, err := identity.HumanLoginTenants(t.Context(), app, idp, "nobody"); !errors.Is(err, identity.ErrUnknownLogin) {
		t.Fatalf("unknown err = %v, want ErrUnknownLogin", err)
	}
}

func TestLoginChoiceLifecycleExpiryAndConcurrentSingleUse(t *testing.T) {
	app, admin := withAdmin(t)
	prevHash := sha256.Sum256([]byte("previous-session"))

	// Browser choice create -> read -> consume -> replay refused.
	_, hash, err := identity.NewChoiceToken()
	if err != nil {
		t.Fatal(err)
	}
	exp, err := identity.CreateLoginChoice(t.Context(), app, hash, identity.LoginChoice{
		Issuer:   idp,
		Subject:  "person-1",
		Previous: prevHash[:],
	})
	if err != nil {
		t.Fatalf("CreateLoginChoice: %v", err)
	}
	if time.Until(exp) <= 4*time.Minute || time.Until(exp) > 6*time.Minute {
		t.Fatalf("expires_at = %v, want ~5 minutes from now", exp)
	}

	read, err := identity.ReadLoginChoice(t.Context(), app, hash)
	if err != nil {
		t.Fatalf("ReadLoginChoice: %v", err)
	}
	if read.Issuer != idp || read.Subject != "person-1" || read.IsCLI {
		t.Fatalf("read = %+v", read)
	}

	// Concurrent consume race: exactly one caller wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	var wonChoice identity.LoginChoice
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := identity.ConsumeLoginChoice(t.Context(), app, hash)
			if err == nil {
				wins.Add(1)
				mu.Lock()
				wonChoice = c
				mu.Unlock()
			} else if !errors.Is(err, identity.ErrUnknownChoice) {
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent wins = %d, want 1", wins.Load())
	}
	if wonChoice.Issuer != idp || wonChoice.Subject != "person-1" || !bytes.Equal(wonChoice.Previous, prevHash[:]) {
		t.Fatalf("wonChoice = %+v", wonChoice)
	}

	// CLI choice fields round-trip and cancel removes the row.
	_, cliHash, err := identity.NewChoiceToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.CreateLoginChoice(t.Context(), app, cliHash, identity.LoginChoice{
		Issuer:       idp,
		Subject:      "person-cli",
		CLIRedirect:  "http://127.0.0.1:54321/callback",
		CLIState:     "state-1",
		CLIChallenge: "challenge-1",
	}); err != nil {
		t.Fatalf("CreateLoginChoice CLI: %v", err)
	}
	readCLI, err := identity.ReadLoginChoice(t.Context(), app, cliHash)
	if err != nil || !readCLI.IsCLI {
		t.Fatalf("ReadLoginChoice CLI = %+v (%v), want IsCLI=true", readCLI, err)
	}
	if err := identity.CancelLoginChoice(t.Context(), app, cliHash); err != nil {
		t.Fatalf("CancelLoginChoice: %v", err)
	}
	if _, err := identity.ReadLoginChoice(t.Context(), app, cliHash); !errors.Is(err, identity.ErrUnknownChoice) {
		t.Fatalf("ReadLoginChoice after cancel = %v, want ErrUnknownChoice", err)
	}

	// Expired row cannot be read or consumed, and is pruned by the next create.
	_, expHash, err := identity.NewChoiceToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.CreateLoginChoice(t.Context(), app, expHash, identity.LoginChoice{
		Issuer:  idp,
		Subject: "person-expired",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(t.Context(), `UPDATE identity.login_choice SET expires_at = clock_timestamp() - interval '1 second' WHERE token_sha256 = $1`, expHash); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.ReadLoginChoice(t.Context(), app, expHash); !errors.Is(err, identity.ErrUnknownChoice) {
		t.Fatalf("ReadLoginChoice expired = %v, want ErrUnknownChoice", err)
	}
	if _, err := identity.ConsumeLoginChoice(t.Context(), app, expHash); !errors.Is(err, identity.ErrUnknownChoice) {
		t.Fatalf("ConsumeLoginChoice expired = %v, want ErrUnknownChoice", err)
	}
	var remaining int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM identity.login_choice WHERE token_sha256 = $1`, expHash).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired row remaining = %d (%v), want 0 after consume prune", remaining, err)
	}
}

func TestRequireMultiTenantLookupsChecksChoiceFunctions(t *testing.T) {
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	app := database.Open(t, pgtest.App)
	if err := identity.RequireMultiTenantLookups(t.Context(), app); err != nil {
		t.Fatalf("RequireMultiTenantLookups on migrated DB: %v", err)
	}
	migrator := database.Open(t, pgtest.Migrate)
	if _, err := migrator.ExecContext(t.Context(), `DROP FUNCTION identity.consume_login_choice(bytea)`); err != nil {
		t.Fatal(err)
	}
	if err := identity.RequireMultiTenantLookups(t.Context(), app); err == nil {
		t.Fatal("RequireMultiTenantLookups succeeded with identity.consume_login_choice dropped")
	}
}
