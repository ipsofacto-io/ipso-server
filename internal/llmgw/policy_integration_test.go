//go:build integration

package llmgw

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")

// The list of repositories is the only switch of llm-advisory checks (ADR-0173): a tenant with no row, an
// empty list, or another tenant's list opts nothing in.
func TestAdvisesRepositoryReadsTheTenantsList(t *testing.T) {
	ledger, admin := newLedger(t)
	db := ledger.DB
	ctx := t.Context()
	if on, err := AdvisesRepository(ctx, db, tenantA, "acme/web"); err != nil || on {
		t.Fatalf("no policy row: %v, %v", on, err)
	}
	for _, tenant := range []string{tenantA.String(), tenantB.String()} {
		if _, err := admin.ExecContext(ctx, `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	err := pgtest.WithTenant(ctx, db, tenantA.String(), func(tx *sql.Tx) error {
		_, err := SetTenantPolicy(ctx, tx, tenantA, TenantPolicy{AdvisoryRepositories: []string{"Acme/Web"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for repo, want := range map[string]bool{"acme/web": true, "ACME/WEB": true, "acme/api": false} {
		if on, err := AdvisesRepository(ctx, db, tenantA, repo); err != nil || on != want {
			t.Errorf("%s: %v, %v", repo, on, err)
		}
	}
	if on, err := AdvisesRepository(ctx, db, tenantB, "acme/web"); err != nil || on {
		t.Fatalf("tenant B reads the list of tenant A: %v, %v", on, err)
	}
	// The table refuses a list the Go writer would not send.
	for _, bad := range []string{`{Acme/Web}`, `{acme}`, `{acme/web,NULL}`} {
		if _, err := pgtest.Exec(ctx, db, tenantA.String(), `UPDATE llm.tenant_policy SET advisory_repositories = $1::text[] WHERE tenant_id = $2`, bad, tenantA); err == nil {
			t.Errorf("%s was stored", bad)
		}
	}
	err = pgtest.WithTenant(ctx, db, tenantA.String(), func(tx *sql.Tx) error {
		_, err := SetTenantPolicy(ctx, tx, tenantA, TenantPolicy{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if on, err := AdvisesRepository(ctx, db, tenantA, "acme/web"); err != nil || on {
		t.Fatalf("an empty list: %v, %v", on, err)
	}
}
