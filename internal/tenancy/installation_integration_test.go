//go:build integration

package tenancy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const installationTable = "tenancy.installation"

func (l *lifecycle) bind(t *testing.T, tenant string, installation int64) tenancy.BindReport {
	t.Helper()
	report, err := tenancy.BindInstallation(t.Context(), l.app, tenancy.BindOptions{Tenant: uuid.MustParse(tenant), Installation: installation})
	if err != nil {
		t.Fatalf("bind %d to %s: %v", installation, tenant, err)
	}
	return report
}

func (l *lifecycle) owner(t *testing.T, installation int64) (uuid.UUID, bool) {
	t.Helper()
	tenant, ok, err := tenancy.InstallationTenant(t.Context(), l.app, installation)
	if err != nil {
		t.Fatalf("look up %d: %v", installation, err)
	}
	return tenant, ok
}

func TestBindInstallationMapsOneInstallationToOneTenant(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	l.provision(t, tenantB, "beta", nil)

	if report := l.bind(t, tenantA, 4242); !report.Bound || report.Installation != 4242 || report.Tenant.String() != tenantA {
		t.Fatalf("first bind = %+v", report)
	}
	if report := l.bind(t, tenantA, 4242); report.Bound {
		t.Fatalf("a repeat bound again: %+v", report)
	}

	// A second tenant cannot take it, and the refusal does not name the owner.
	_, err := tenancy.BindInstallation(t.Context(), l.app, tenancy.BindOptions{Tenant: uuid.MustParse(tenantB), Installation: 4242})
	if !errors.Is(err, tenancy.ErrInstallationBound) {
		t.Fatalf("a second tenant's bind = %v, want ErrInstallationBound", err)
	}
	if strings.Contains(err.Error(), tenantA) {
		t.Errorf("the refusal names the owner: %v", err)
	}
	if l.count(t, installationTable, tenantB) != 0 || l.count(t, installationTable, tenantA) != 1 {
		t.Errorf("rows: A %d, B %d; want 1 and 0", l.count(t, installationTable, tenantA), l.count(t, installationTable, tenantB))
	}
	if owner, ok := l.owner(t, 4242); !ok || owner.String() != tenantA {
		t.Errorf("owner = %v, %v; want tenant A", owner, ok)
	}

	// A tenant may hold several installations.
	if !l.bind(t, tenantA, 4243).Bound || l.count(t, installationTable, tenantA) != 2 {
		t.Errorf("a second installation of one tenant was not bound")
	}
}

func TestBindInstallationRefuses(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	for name, tc := range map[string]struct {
		options tenancy.BindOptions
		want    error
	}{
		"a tenant with no row": {tenancy.BindOptions{Tenant: uuid.MustParse(tenantC), Installation: 1}, tenancy.ErrUnknownTenant},
		"no tenant":            {tenancy.BindOptions{Installation: 1}, nil},
		"no installation":      {tenancy.BindOptions{Tenant: uuid.MustParse(tenantA)}, nil},
		"a negative one":       {tenancy.BindOptions{Tenant: uuid.MustParse(tenantA), Installation: -1}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tenancy.BindInstallation(t.Context(), l.app, tc.options)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("bind = %v, want an error %v", err, tc.want)
			}
		})
	}
	var rows int
	if err := l.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.installation`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("a refused bind wrote %d rows (%v)", rows, err)
	}
}

func TestBindInstallationRefusesAnOffboardedTenant(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	if _, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "alpha"}); err != nil {
		t.Fatal(err)
	}
	_, err := tenancy.BindInstallation(t.Context(), l.app, tenancy.BindOptions{Tenant: uuid.MustParse(tenantA), Installation: 1})
	if !errors.Is(err, tenancy.ErrOffboarded) {
		t.Fatalf("bind for an offboarded tenant = %v, want ErrOffboarded", err)
	}
}

func TestInstallationTenantFindsOnlyWhatIsBound(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	l.provision(t, tenantB, "beta", nil)
	l.bind(t, tenantA, 11)
	l.bind(t, tenantB, 22)

	for installation, want := range map[int64]string{11: tenantA, 22: tenantB} {
		if owner, ok := l.owner(t, installation); !ok || owner.String() != want {
			t.Errorf("owner of %d = %v, %v; want %s", installation, owner, ok, want)
		}
	}
	for _, unbound := range []int64{33, 0, -4} {
		if owner, ok := l.owner(t, unbound); ok || owner != uuid.Nil {
			t.Errorf("owner of %d = %v, %v; want none", unbound, owner, ok)
		}
	}

	// A connection that still holds another tenant's setting must not narrow or change the answer: the
	// lookup runs with no tenant, the way the webhooks process runs it.
	l.app.SetMaxOpenConns(1)
	if _, err := l.app.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, false)`, tenantB); err != nil {
		t.Fatal(err)
	}
	if owner, ok := l.owner(t, 11); !ok || owner.String() != tenantA {
		t.Errorf("owner of 11 on a connection set to tenant B = %v, %v; want tenant A", owner, ok)
	}
}

func TestRequireInstallationLookupNeedsTheMigration(t *testing.T) {
	l := newLifecycle(t)
	if err := tenancy.RequireInstallationLookup(t.Context(), l.app); err != nil {
		t.Fatalf("on a migrated database: %v", err)
	}
	bare := server.NewDatabase(t).Open(t, pgtest.App)
	err := tenancy.RequireInstallationLookup(t.Context(), bare)
	if err == nil || !strings.Contains(err.Error(), "run ipso-server migrate") {
		t.Fatalf("on a database with no migration: %v", err)
	}
}

func TestOffboardRemovesTheBindingsOfTheTenantOnly(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	l.provision(t, tenantB, "beta", nil)
	l.bind(t, tenantA, 11)
	l.bind(t, tenantA, 12)
	l.bind(t, tenantB, 21)

	report, err := tenancy.Offboard(t.Context(), l.migrator, tenancy.OffboardOptions{Tenant: uuid.MustParse(tenantA), Confirm: "alpha"})
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if !report.Verified || report.Rows[installationTable] != 2 {
		t.Fatalf("report = %+v, want 2 bindings removed and verified", report)
	}
	if l.count(t, installationTable, tenantA) != 0 || l.count(t, installationTable, tenantB) != 1 {
		t.Errorf("rows: A %d, B %d; want 0 and 1", l.count(t, installationTable, tenantA), l.count(t, installationTable, tenantB))
	}
	for _, gone := range []int64{11, 12} {
		if owner, ok := l.owner(t, gone); ok {
			t.Errorf("installation %d still maps to %s after offboarding", gone, owner)
		}
	}
	if owner, ok := l.owner(t, 21); !ok || owner.String() != tenantB {
		t.Errorf("the bystander's installation = %v, %v", owner, ok)
	}

	// An installation the offboarded tenant held is free for another tenant.
	if !l.bind(t, tenantB, 11).Bound {
		t.Error("a freed installation could not be bound")
	}
}

func TestExportLeavesTheBindingsOut(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	if l.count(t, installationTable, tenantA) == 0 {
		t.Fatal("the seed bound no installation, so the export would prove nothing")
	}
	_, report := l.export(t, tenantA, identity(t))
	if _, in := report.Rows[installationTable]; in {
		t.Errorf("the export lists %s: %v", installationTable, report.Rows)
	}
}

func (l *lifecycle) unbind(t *testing.T, installation int64) (uuid.UUID, bool) {
	t.Helper()
	tenant, removed, err := tenancy.UnbindInstallation(t.Context(), l.app, installation)
	if err != nil {
		t.Fatalf("unbind %d: %v", installation, err)
	}
	return tenant, removed
}

func TestUnbindInstallationRemovesOneBindingOfItsOwner(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	l.provision(t, tenantB, "beta", nil)
	l.bind(t, tenantA, 11)
	l.bind(t, tenantA, 12)
	l.bind(t, tenantB, 22)

	// The tenant comes from the mapping, as the application role the webhooks process runs as.
	if tenant, removed := l.unbind(t, 11); !removed || tenant.String() != tenantA {
		t.Fatalf("unbind 11 = %v, %v; want tenant A", tenant, removed)
	}
	if owner, ok := l.owner(t, 11); ok {
		t.Errorf("11 still maps to %s", owner)
	}
	// The tenant's other installation and the other tenant's stay bound.
	if l.count(t, installationTable, tenantA) != 1 || l.count(t, installationTable, tenantB) != 1 {
		t.Errorf("rows: A %d, B %d; want 1 and 1", l.count(t, installationTable, tenantA), l.count(t, installationTable, tenantB))
	}

	// A repeat, an installation nobody holds and an id that is not one change nothing.
	for _, installation := range []int64{11, 33, 0, -4} {
		if tenant, removed := l.unbind(t, installation); removed || tenant != uuid.Nil {
			t.Errorf("unbind %d = %v, %v; want nothing removed", installation, tenant, removed)
		}
	}
	if l.count(t, installationTable, tenantA) != 1 || l.count(t, installationTable, tenantB) != 1 {
		t.Errorf("rows after the no-ops: A %d, B %d; want 1 and 1", l.count(t, installationTable, tenantA), l.count(t, installationTable, tenantB))
	}

	// A removed installation is free, so a new installation of the same id could be bound again.
	if !l.bind(t, tenantB, 11).Bound {
		t.Error("an unbound installation could not be bound")
	}
}

// A setting another tenant left on a pooled connection must not stop the removal or widen it.
func TestUnbindInstallationIgnoresAStaleTenantSetting(t *testing.T) {
	l := newLifecycle(t)
	l.provision(t, tenantA, "alpha", nil)
	l.provision(t, tenantB, "beta", nil)
	l.bind(t, tenantA, 11)
	l.bind(t, tenantB, 22)
	l.app.SetMaxOpenConns(1)
	if _, err := l.app.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, false)`, tenantB); err != nil {
		t.Fatal(err)
	}
	if tenant, removed := l.unbind(t, 11); !removed || tenant.String() != tenantA {
		t.Fatalf("unbind 11 on a connection set to tenant B = %v, %v; want tenant A", tenant, removed)
	}
	if l.count(t, installationTable, tenantA) != 0 || l.count(t, installationTable, tenantB) != 1 {
		t.Errorf("rows: A %d, B %d; want 0 and 1", l.count(t, installationTable, tenantA), l.count(t, installationTable, tenantB))
	}
}

func TestUnbindInstallationNeedsADatabase(t *testing.T) {
	if _, _, err := tenancy.UnbindInstallation(t.Context(), nil, 11); err == nil {
		t.Fatal("unbind with no database passed")
	}
}
