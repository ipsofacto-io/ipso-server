package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// verifyDeps are the fakes of the tenant commands with a verifier that answers report and err, and that
// records the tenant it was asked about.
func verifyDeps(values map[string]string, calls *tenantCalls, asked *[]uuid.UUID, report identity.LogReport, err error) deps {
	d := tenantDeps(values, calls)
	d.verifyLog = func(_ context.Context, _ *sql.DB, tenant uuid.UUID) (identity.LogReport, error) {
		*asked = append(*asked, tenant)
		report.Tenant = tenant
		return report, err
	}
	return d
}

func TestAuditLogUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
		out  string
	}{
		"no subcommand":      {[]string{"audit-log"}, 2, "audit-log verify"},
		"unknown subcommand": {[]string{"audit-log", "purge"}, 2, `unknown audit-log command "purge"`},
		"help":               {[]string{"audit-log", "help"}, 0, "ADR-0126"},
		"no tenant":          {[]string{"audit-log", "verify"}, 2, "--tenant is required"},
		"a bad tenant":       {[]string{"audit-log", "verify", "--tenant", "acme"}, 2, "--tenant is required"},
		"a nil tenant":       {[]string{"audit-log", "verify", "--tenant", uuid.Nil.String()}, 2, "--tenant is required"},
		"an extra argument":  {[]string{"audit-log", "verify", "--tenant", testTenant, "now"}, 2, "audit-log verify"},
		"an unknown flag":    {[]string{"audit-log", "verify", "--tenant", testTenant, "--fix"}, 2, "audit-log verify"},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []uuid.UUID
			code, stdout, stderr := invoke(t, verifyDeps(appValues(nil), &tenantCalls{}, &asked, identity.LogReport{}, nil), tc.args...)
			if code != tc.code || !strings.Contains(stdout+stderr, tc.out) {
				t.Errorf("code %d, stdout %q, stderr %q; want code %d containing %q", code, stdout, stderr, tc.code, tc.out)
			}
			if len(asked) != 0 {
				t.Errorf("a chain was read for a command that was refused: %v", asked)
			}
		})
	}
}

func TestAuditLogVerifyReadsTheChainAsTheApplicationAndPrintsTheReport(t *testing.T) {
	calls := &tenantCalls{}
	var asked []uuid.UUID
	head := strings.Repeat("ab", 32)
	code, stdout, stderr := invoke(t, verifyDeps(appValues(nil), calls, &asked, identity.LogReport{Entries: 7, HeadSeq: 7, Head: head, Intact: true}, nil),
		"audit-log", "verify", "--tenant", testTenant)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedApp != 1 || len(calls.opened) != 1 || calls.opened[0] != appURL || calls.checkedMigrate != 0 {
		t.Errorf("opened %v, checked the application %d times and the migration role %d times", calls.opened, calls.checkedApp, calls.checkedMigrate)
	}
	if len(asked) != 1 || asked[0].String() != testTenant {
		t.Errorf("asked about %v", asked)
	}
	var report identity.LogReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || !report.Intact || report.Entries != 7 || report.HeadSeq != 7 || report.Head != head {
		t.Errorf("stdout = %q (%v)", stdout, err)
	}
}

// A chain that does not hold is a failure for a script that checks the exit code, and the report still says where.
func TestAuditLogVerifyFailsAndNamesTheFirstBadEntry(t *testing.T) {
	var asked []uuid.UUID
	broken := identity.LogReport{Entries: 4, HeadSeq: 3, Head: strings.Repeat("cd", 32), Break: &identity.LogBreak{Seq: 4, Reason: identity.BreakHash}}
	code, stdout, _ := invoke(t, verifyDeps(appValues(nil), &tenantCalls{}, &asked, broken, nil), "audit-log", "verify", "--tenant", testTenant)
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	var report identity.LogReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || report.Intact || report.Break == nil || *report.Break != *broken.Break {
		t.Fatalf("stdout = %q (%v)", stdout, err)
	}
}

func TestAuditLogVerifyRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		values map[string]string
		calls  *tenantCalls
		err    error
		want   string
	}{
		"the migration credential":                {appValues(map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}), &tenantCalls{}, nil, "must not hold the migration credential"},
		"no database":                             {map[string]string{}, &tenantCalls{}, nil, "IPSO_DATABASE_URL is not set"},
		"a role that bypasses row-level security": {appValues(nil), &tenantCalls{checkAppErr: errors.New("the role bypasses row-level security")}, nil, "bypasses row-level security"},
		"a read that fails":                       {appValues(nil), &tenantCalls{}, errors.New("verify the action log: boom"), "boom"},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []uuid.UUID
			code, stdout, stderr := invoke(t, verifyDeps(tc.values, tc.calls, &asked, identity.LogReport{Intact: true}, tc.err), "audit-log", "verify", "--tenant", testTenant)
			if code != 1 || !strings.Contains(stderr, tc.want) || stdout != "" {
				t.Errorf("code %d, stdout %q, stderr %q; want code 1 containing %q", code, stdout, stderr, tc.want)
			}
			for _, secret := range []string{"app-pass", "migrate-pass"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("the output holds a credential: %q %q", stdout, stderr)
				}
			}
		})
	}
}
