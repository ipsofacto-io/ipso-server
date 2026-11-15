//go:build integration

package migrate_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// A deployment that wrote its action log before migration 00034 has its entries chained by the migration, per
// tenant in the order of their ids and with the times they were written at, and the next entry continues the
// chain (IPSO-68, ADR-0126).
func TestTheMigrationChainsTheEntriesThatExist(t *testing.T) {
	db := server.NewDatabase(t)
	ctx := t.Context()
	if _, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 33); err != nil {
		t.Fatalf("migrate to 33: %v", err)
	}
	admin := db.Open(t, pgtest.Admin)
	tenantA := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	person := func(tenant uuid.UUID, name string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := admin.QueryRowContext(ctx, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', $2) RETURNING id`, tenant, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ada, bea := person(tenantA, "Ada"), person(tenantB, "Bea")
	base := time.Date(2026, time.October, 1, 12, 0, 0, 123456000, time.UTC)
	written := map[string]time.Time{}
	insert := func(tenant, principal uuid.UUID, id string, offset time.Duration, action, subject string) {
		t.Helper()
		at := base.Add(offset)
		written[subject] = at
		if _, err := admin.ExecContext(ctx, `
			INSERT INTO identity.action_log (tenant_id, id, principal_id, responsible_id, action, subject)
			VALUES ($1, $3::uuid, $2, $2, $4, $5)`, tenant, principal, id, action, subject); err != nil {
			t.Fatal(err)
		}
		// A trigger of that release stamps the time of an insert, so the time the entry "was written at" is set after.
		if _, err := admin.ExecContext(ctx, `UPDATE identity.action_log SET sys_period = tstzrange($3::timestamptz, NULL) WHERE tenant_id = $1 AND id = $2::uuid`, tenant, id, at); err != nil {
			t.Fatal(err)
		}
	}
	// The rows go in out of order and the tenants interleave, so the order of a chain is the order of the ids.
	insert(tenantA, ada, "018f0000-0000-7000-8000-000000000003", 3*time.Second, "api.record_waiver", "third of A")
	insert(tenantB, bea, "018f0000-0000-7000-8000-000000000002", 2*time.Second, "api.start_export", "second of B")
	insert(tenantA, ada, "018f0000-0000-7000-8000-000000000001", 1*time.Second, "api.create_scope", "first of A")
	insert(tenantA, ada, "018f0000-0000-7000-8000-000000000004", 4*time.Second, "api.record_baseline", `fourth of A "quoted" é`)
	insert(tenantB, bea, "018f0000-0000-7000-8000-000000000001", 1*time.Second, "api.create_scope", "first of B")

	// Up to 00034 and no further, so a later migration does not change what this test applies.
	applied, err := migrate.RunUpTo(ctx, db.DSN(pgtest.Migrate), 34)
	if err != nil || len(applied) != 1 || applied[0] != "00034_action_log_chain.sql" {
		t.Fatalf("%v %v", applied, err)
	}
	var enabled, forced bool
	if err := admin.QueryRowContext(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'identity.action_log'::regclass`).Scan(&enabled, &forced); err != nil {
		t.Fatal(err)
	}
	if !enabled || !forced {
		t.Fatalf("row-level security on the action log: enabled %t, forced %t", enabled, forced)
	}

	app := db.Open(t, pgtest.App)
	for _, tc := range []struct {
		tenant   uuid.UUID
		subjects []string
	}{
		{tenantA, []string{"first of A", "third of A", `fourth of A "quoted" é`}},
		{tenantB, []string{"first of B", "second of B"}},
	} {
		entries, err := identity.LogPage(ctx, app, tc.tenant, 0, identity.LogPageSize)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != len(tc.subjects) {
			t.Fatalf("%d entries, want %d", len(entries), len(tc.subjects))
		}
		for i, e := range entries {
			if e.Seq != int64(i+1) || e.Subject != tc.subjects[i] || !e.At.Equal(written[e.Subject]) {
				t.Errorf("entry %d: %+v", i+1, e)
			}
			if i == 0 && e.Prev != [32]byte{} {
				t.Errorf("the first entry does not start from zeros")
			}
			if i > 0 && e.Prev != entries[i-1].Hash {
				t.Errorf("entry %d does not carry the hash of the one before it", e.Seq)
			}
			if e.Hash != e.Sum() {
				t.Errorf("entry %d: the hash is not the hash of its fields", e.Seq)
			}
		}
		if report, err := identity.VerifyLog(ctx, app, tc.tenant); err != nil || !report.Intact || report.Entries != int64(len(tc.subjects)) {
			t.Fatalf("%+v %v", report, err)
		}
	}

	// A new entry continues the backfilled chain.
	if _, err := identity.RecordAction(ctx, app, tenantA, ada, "api.record_waiver", "after the migration"); err != nil {
		t.Fatal(err)
	}
	report, err := identity.VerifyLog(ctx, app, tenantA)
	if err != nil || !report.Intact || report.Entries != 4 || report.HeadSeq != 4 {
		t.Fatalf("%+v %v", report, err)
	}
}
