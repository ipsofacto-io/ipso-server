package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// acceptanceDeps are the fakes of the tenant commands with a reader that answers report and err, and that
// records the tenant it was asked about.
func acceptanceDeps(values map[string]string, calls *tenantCalls, asked *[]uuid.UUID, report proposals.AcceptanceReport, err error) deps {
	d := tenantDeps(values, calls)
	d.acceptance = func(_ context.Context, _ *sql.DB, tenant uuid.UUID) (proposals.AcceptanceReport, error) {
		*asked = append(*asked, tenant)
		report.Tenant = tenant
		return report, err
	}
	return d
}

func TestProposalsUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
		out  string
	}{
		"no subcommand":      {[]string{"proposals"}, 2, "proposals acceptance"},
		"unknown subcommand": {[]string{"proposals", "approve"}, 2, `unknown proposals command "approve"`},
		"help":               {[]string{"proposals", "help"}, 0, "never names the"},
		"no tenant":          {[]string{"proposals", "acceptance"}, 2, "--tenant is required"},
		"a bad tenant":       {[]string{"proposals", "acceptance", "--tenant", "acme"}, 2, "--tenant is required"},
		"a nil tenant":       {[]string{"proposals", "acceptance", "--tenant", uuid.Nil.String()}, 2, "--tenant is required"},
		"an extra argument":  {[]string{"proposals", "acceptance", "--tenant", testTenant, "now"}, 2, "proposals acceptance"},
		"a person flag":      {[]string{"proposals", "acceptance", "--tenant", testTenant, "--by-person"}, 2, "proposals acceptance"},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []uuid.UUID
			code, stdout, stderr := invoke(t, acceptanceDeps(appValues(nil), &tenantCalls{}, &asked, proposals.AcceptanceReport{}, nil), tc.args...)
			if code != tc.code || !strings.Contains(stdout+stderr, tc.out) {
				t.Errorf("code %d, stdout %q, stderr %q; want code %d containing %q", code, stdout, stderr, tc.code, tc.out)
			}
			if len(asked) != 0 {
				t.Errorf("a rate was read for a command that was refused: %v", asked)
			}
		})
	}
}

func TestProposalsAcceptanceReadsAsTheApplicationAndPrintsTheReport(t *testing.T) {
	calls := &tenantCalls{}
	var asked []uuid.UUID
	rate, meets := 0.8, true
	report := proposals.AcceptanceReport{
		Target:      0.7,
		MinAnswered: proposals.AcceptanceMinAnswered,
		Rows: []proposals.AcceptanceRow{
			{Kind: proposals.KindPRDecision, PromptVersion: "pr-decision-v2", Model: "mistral-medium-2508", Approved: 8, Rejected: 2, Rate: &rate, MeetsTarget: &meets},
			{Kind: proposals.KindCheck, PromptVersion: "check-rule-v4", Model: "mistral-medium-2508", Approved: 1, Pending: 2},
		},
	}
	code, stdout, stderr := invoke(t, acceptanceDeps(appValues(nil), calls, &asked, report, nil), "proposals", "acceptance", "--tenant", testTenant)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedApp != 1 || len(calls.opened) != 1 || calls.opened[0] != appURL || calls.checkedMigrate != 0 {
		t.Errorf("opened %v, checked the application %d times and the migration role %d times", calls.opened, calls.checkedApp, calls.checkedMigrate)
	}
	if len(asked) != 1 || asked[0].String() != testTenant {
		t.Errorf("asked about %v", asked)
	}
	var got proposals.AcceptanceReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || len(got.Rows) != 2 || got.Rows[0].Rate == nil || *got.Rows[0].Rate != 0.8 || got.Rows[1].Rate != nil {
		t.Errorf("stdout = %q (%v)", stdout, err)
	}
	// A row that has too few answers prints a null, not a zero, so a script cannot read it as a rate.
	if !strings.Contains(stdout, `"acceptance_rate": null`) || !strings.Contains(stdout, `"meets_target": null`) {
		t.Errorf("a row with too few answers does not print null: %s", stdout)
	}
}

func TestProposalsAcceptanceRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		values map[string]string
		calls  *tenantCalls
		err    error
		want   string
	}{
		"the migration credential":                {appValues(map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}), &tenantCalls{}, nil, "must not hold the migration credential"},
		"no database":                             {map[string]string{}, &tenantCalls{}, nil, "IPSO_DATABASE_URL is not set"},
		"a role that bypasses row-level security": {appValues(nil), &tenantCalls{checkAppErr: errors.New("the role bypasses row-level security")}, nil, "bypasses row-level security"},
		"a read that fails":                       {appValues(nil), &tenantCalls{}, errors.New("read the acceptance rate: boom"), "boom"},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []uuid.UUID
			code, stdout, stderr := invoke(t, acceptanceDeps(tc.values, tc.calls, &asked, proposals.AcceptanceReport{}, tc.err), "proposals", "acceptance", "--tenant", testTenant)
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
