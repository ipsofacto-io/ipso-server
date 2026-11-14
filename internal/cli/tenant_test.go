package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const (
	testKEKValue = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=" // 32 bytes of 7
	appURL       = "postgres://ipso_app:app-pass@db.example.test/ipso"
	migrateURL   = "postgres://ipso_migrate:migrate-pass@db.example.test/ipso"
)

// tenantCalls records what the fakes were asked.
type tenantCalls struct {
	opened          []string
	openedDB        *sql.DB
	checkedApp      int
	checkedMigrate  int
	provision       *tenancy.ProvisionOptions
	export          *tenancy.ExportOptions
	restore         *tenancy.RestoreOptions
	offboard        *tenancy.OffboardOptions
	exportErr       error
	offboardErr     error
	offboardReport  tenancy.OffboardReport
	checkAppErr     error
	checkMigrateErr error
	provisionErr    error

	// The installation mapping (ADR-0101).
	asked          []askedAccount
	accountLogin   string
	accountErr     error
	bind           *tenancy.BindOptions
	bindErr        error
	lookupRequired int
	lookupErr      error
	owners         map[int64]uuid.UUID
	// unbound lists the installations whose binding was removed, and unbindDB the database it was asked on.
	unbound  []int64
	unbindDB *sql.DB
}

// askedAccount is what the fake GitHub was asked.
type askedAccount struct {
	appID        string
	privateKey   string
	installation int64
}

func tenantDeps(values map[string]string, calls *tenantCalls) deps {
	return deps{
		getenv: env(values),
		openDB: func(url string) (*sql.DB, error) {
			calls.opened = append(calls.opened, url)
			db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none")
			calls.openedDB = db
			return db, err
		},
		checkApplication: func(context.Context, *sql.DB) error { calls.checkedApp++; return calls.checkAppErr },
		checkMigration:   func(context.Context, *sql.DB) error { calls.checkedMigrate++; return calls.checkMigrateErr },
		provision: func(_ context.Context, _ *sql.DB, o tenancy.ProvisionOptions) (tenancy.ProvisionReport, error) {
			calls.provision = &o
			return tenancy.ProvisionReport{Tenant: o.Tenant, Created: true, KeyCreated: true}, calls.provisionErr
		},
		exportTenant: func(_ context.Context, _ *sql.DB, o tenancy.ExportOptions) (tenancy.ExportReport, error) {
			calls.export = &o
			_, _ = o.Out.Write([]byte("archive bytes"))
			return tenancy.ExportReport{Tenant: o.Tenant, Total: 3}, calls.exportErr
		},
		restoreTenant: func(_ context.Context, _ *sql.DB, o tenancy.RestoreOptions) (tenancy.RestoreReport, error) {
			calls.restore = &o
			return tenancy.RestoreReport{Tenant: o.Tenant, Total: 3}, nil
		},
		offboardTenant: func(_ context.Context, _ *sql.DB, o tenancy.OffboardOptions) (tenancy.OffboardReport, error) {
			calls.offboard = &o
			return calls.offboardReport, calls.offboardErr
		},
		installationAccount: func(_ context.Context, appID string, privateKey []byte, installation int64) (string, error) {
			calls.asked = append(calls.asked, askedAccount{appID, string(privateKey), installation})
			return calls.accountLogin, calls.accountErr
		},
		bindInstallation: func(_ context.Context, _ *sql.DB, o tenancy.BindOptions) (tenancy.BindReport, error) {
			calls.bind = &o
			return tenancy.BindReport{Tenant: o.Tenant, Installation: o.Installation, Bound: true}, calls.bindErr
		},
		requireInstallations: func(context.Context, *sql.DB) error {
			calls.lookupRequired++
			return calls.lookupErr
		},
		installationTenant: func(_ context.Context, _ *sql.DB, installation int64) (uuid.UUID, bool, error) {
			tenant, ok := calls.owners[installation]
			return tenant, ok, nil
		},
		unbindInstallation: func(_ context.Context, db *sql.DB, installation int64) (uuid.UUID, bool, error) {
			calls.unbound = append(calls.unbound, installation)
			calls.unbindDB = db
			tenant, ok := calls.owners[installation]
			delete(calls.owners, installation)
			return tenant, ok, nil
		},
	}
}

func appValues(extra map[string]string) map[string]string {
	values := map[string]string{"IPSO_DATABASE_URL": appURL, "IPSO_TENANT_KEK": testKEKValue}
	for k, v := range extra {
		values[k] = v
	}
	return values
}

func migrateValues(extra map[string]string) map[string]string {
	values := map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}
	for k, v := range extra {
		values[k] = v
	}
	return values
}

func TestTenantUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
		out  string
	}{
		"no subcommand":      {[]string{"tenant"}, 2, "tenant create"},
		"unknown subcommand": {[]string{"tenant", "purge"}, 2, `unknown tenant command "purge"`},
		"help":               {[]string{"tenant", "help"}, 0, "ADR-0100"},
		"an extra argument":  {[]string{"tenant", "offboard", "--tenant", testTenant, "--confirm", "x", "now"}, 2, "tenant offboard"},
		"an unknown flag":    {[]string{"tenant", "create", "--force"}, 2, "tenant create"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := invoke(t, tenantDeps(nil, &tenantCalls{}), tc.args...)
			if code != tc.code || !strings.Contains(stdout+stderr, tc.out) {
				t.Errorf("code %d, stdout %q, stderr %q; want code %d containing %q", code, stdout, stderr, tc.code, tc.out)
			}
		})
	}
}

func TestTenantCreatePassesTheArgumentsAndPrintsTheReport(t *testing.T) {
	calls := &tenantCalls{}
	person := "00000000-0000-4000-8000-0000000000a1"
	code, stdout, stderr := invoke(t, tenantDeps(appValues(nil), calls), "tenant", "create",
		"--tenant", testTenant, "--name", "acme", "--person", person, "--person-name", "Ada",
		"--issuer", "https://idp.example.test", "--subject", "sub-1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedApp != 1 || len(calls.opened) != 1 || calls.opened[0] != appURL {
		t.Errorf("opened %v, checked %d", calls.opened, calls.checkedApp)
	}
	got := calls.provision
	if got == nil || got.Tenant.String() != testTenant || got.Name != "acme" || got.Person == nil ||
		got.Person.ID.String() != person || got.Person.Name != "Ada" || got.Person.Issuer != "https://idp.example.test" || got.Person.Subject != "sub-1" {
		t.Errorf("provision options = %+v", got)
	}
	var report tenancy.ProvisionReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || !report.Created || report.Tenant.String() != testTenant {
		t.Errorf("stdout = %q (%v)", stdout, err)
	}
}

func TestTenantCreateWithoutAPersonProvisionsNone(t *testing.T) {
	calls := &tenantCalls{}
	if code, _, stderr := invoke(t, tenantDeps(appValues(nil), calls), "tenant", "create", "--tenant", testTenant, "--name", "acme"); code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.provision == nil || calls.provision.Person != nil {
		t.Errorf("provision options = %+v", calls.provision)
	}
}

func TestTenantCreateRefuses(t *testing.T) {
	person := "00000000-0000-4000-8000-0000000000a1"
	for name, tc := range map[string]struct {
		values map[string]string
		args   []string
		code   int
		want   string
	}{
		"no tenant":                {appValues(nil), []string{"--name", "acme"}, 2, "--tenant and --name"},
		"a bad tenant":             {appValues(nil), []string{"--tenant", "acme", "--name", "acme"}, 2, "--tenant and --name"},
		"a nil tenant":             {appValues(nil), []string{"--tenant", uuid.Nil.String(), "--name", "acme"}, 2, "--tenant and --name"},
		"no name":                  {appValues(nil), []string{"--tenant", testTenant}, 2, "--tenant and --name"},
		"half a person":            {appValues(nil), []string{"--tenant", testTenant, "--name", "acme", "--person", person}, 2, "together or not at all"},
		"a person that is no id":   {appValues(nil), []string{"--tenant", testTenant, "--name", "acme", "--person", "ada", "--person-name", "Ada", "--issuer", "https://i", "--subject", "s"}, 2, "together or not at all"},
		"no key":                   {appValues(map[string]string{"IPSO_TENANT_KEK": ""}), []string{"--tenant", testTenant, "--name", "acme"}, 1, "IPSO_TENANT_KEK is not set"},
		"a bad key":                {appValues(map[string]string{"IPSO_TENANT_KEK": "short"}), []string{"--tenant", testTenant, "--name", "acme"}, 1, "IPSO_TENANT_KEK"},
		"no database":              {appValues(map[string]string{"IPSO_DATABASE_URL": ""}), []string{"--tenant", testTenant, "--name", "acme"}, 1, "IPSO_DATABASE_URL is not set"},
		"the migration credential": {appValues(map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}), []string{"--tenant", testTenant, "--name", "acme"}, 1, "must not hold the migration credential"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &tenantCalls{}
			code, _, stderr := invoke(t, tenantDeps(tc.values, calls), append([]string{"tenant", "create"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) {
				t.Errorf("code %d, stderr %q; want code %d containing %q", code, stderr, tc.code, tc.want)
			}
			if calls.provision != nil {
				t.Error("a tenant was provisioned")
			}
			if len(calls.opened) != 0 && name == "the migration credential" {
				t.Errorf("a connection was opened with the migration credential in the environment: %v", calls.opened)
			}
			if strings.Contains(stderr, "short") && name == "a bad key" {
				t.Errorf("stderr quotes the key: %q", stderr)
			}
		})
	}
}

func TestTenantCreateStopsAtTheStartGateAndReportsFailures(t *testing.T) {
	calls := &tenantCalls{checkAppErr: errors.New("refusing to start")}
	code, _, stderr := invoke(t, tenantDeps(appValues(nil), calls), "tenant", "create", "--tenant", testTenant, "--name", "acme")
	if code != 1 || !strings.Contains(stderr, "refusing to start") || calls.provision != nil {
		t.Errorf("code %d, stderr %q, provision %v", code, stderr, calls.provision)
	}
	calls = &tenantCalls{provisionErr: tenancy.ErrOffboarded}
	code, _, stderr = invoke(t, tenantDeps(appValues(nil), calls), "tenant", "create", "--tenant", testTenant, "--name", "acme")
	if code != 1 || !strings.Contains(stderr, "offboarded") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

func recipient(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id, id.Recipient().String()
}

func TestTenantExportWritesAPrivateFileOnceAndRemovesItOnFailure(t *testing.T) {
	_, key := recipient(t)
	out := filepath.Join(t.TempDir(), "acme.age")
	calls := &tenantCalls{}
	code, stdout, stderr := invoke(t, tenantDeps(appValues(nil), calls), "tenant", "export", "--tenant", testTenant, "--recipient", key, "--out", out)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v, %v", info, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "archive bytes" {
		t.Errorf("file holds %q", b)
	}
	if calls.checkedApp != 1 || calls.export == nil || len(calls.export.Recipients) != 1 || !strings.Contains(stdout, `"total": 3`) {
		t.Errorf("calls %+v, stdout %q", calls, stdout)
	}

	// A second run does not replace the file.
	code, _, stderr = invoke(t, tenantDeps(appValues(nil), &tenantCalls{}), "tenant", "export", "--tenant", testTenant, "--recipient", key, "--out", out)
	if code != 1 || !strings.Contains(stderr, "exists") {
		t.Errorf("second export: code %d, stderr %q", code, stderr)
	}
	if b, _ := os.ReadFile(out); string(b) != "archive bytes" {
		t.Errorf("the existing file was changed: %q", b)
	}

	// A failed export leaves nothing behind.
	failed := filepath.Join(t.TempDir(), "failed.age")
	code, _, stderr = invoke(t, tenantDeps(appValues(nil), &tenantCalls{exportErr: errors.New("export: boom")}), "tenant", "export", "--tenant", testTenant, "--recipient", key, "--out", failed)
	if code != 1 || !strings.Contains(stderr, "boom") {
		t.Errorf("failed export: code %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(failed); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file of a failed export remains: %v", err)
	}
}

func TestTenantExportRefuses(t *testing.T) {
	_, key := recipient(t)
	out := filepath.Join(t.TempDir(), "acme.age")
	for name, tc := range map[string]struct {
		values map[string]string
		args   []string
		code   int
		want   string
	}{
		"no recipient":               {appValues(nil), []string{"--tenant", testTenant, "--out", out}, 2, "--recipient"},
		"no output":                  {appValues(nil), []string{"--tenant", testTenant, "--recipient", key}, 2, "--out"},
		"a recipient that is no key": {appValues(nil), []string{"--tenant", testTenant, "--recipient", "hunter2", "--out", out}, 2, "not an age public key"},
		"the migration credential":   {appValues(map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}), []string{"--tenant", testTenant, "--recipient", key, "--out", out}, 1, "migration credential"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &tenantCalls{}
			code, _, stderr := invoke(t, tenantDeps(tc.values, calls), append([]string{"tenant", "export"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) || calls.export != nil {
				t.Errorf("code %d, stderr %q, export %v", code, stderr, calls.export)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("a file was created")
			}
		})
	}
}

func TestTenantRestoreReadsTheIdentityAndTheArchiveAsTheMigrationRole(t *testing.T) {
	id, _ := recipient(t)
	dir := t.TempDir()
	identityFile := filepath.Join(dir, "key.txt")
	if err := os.WriteFile(identityFile, []byte("# created for a test\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "acme.age")
	if err := os.WriteFile(archive, []byte("archive bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := &tenantCalls{}
	code, stdout, stderr := invoke(t, tenantDeps(migrateValues(nil), calls), "tenant", "restore", "--tenant", testTenant, "--identity", identityFile, "--in", archive)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedMigrate != 1 || len(calls.opened) != 1 || calls.opened[0] != migrateURL {
		t.Errorf("opened %v, checked %d", calls.opened, calls.checkedMigrate)
	}
	if calls.restore == nil || len(calls.restore.Identities) != 1 || calls.restore.Tenant.String() != testTenant || calls.restore.In == nil {
		t.Errorf("restore options = %+v", calls.restore)
	}
	if !strings.Contains(stdout, `"total": 3`) {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestTenantRestoreRefuses(t *testing.T) {
	id, _ := recipient(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "key.txt")
	_ = os.WriteFile(good, []byte(id.String()+"\n"), 0o600)
	open := filepath.Join(dir, "open.txt")
	_ = os.WriteFile(open, []byte(id.String()+"\n"), 0o644)
	notAKey := filepath.Join(dir, "none.txt")
	_ = os.WriteFile(notAKey, []byte("# nothing here\n"), 0o600)
	archive := filepath.Join(dir, "acme.age")
	_ = os.WriteFile(archive, []byte("x"), 0o600)
	for name, tc := range map[string]struct {
		values map[string]string
		args   []string
		code   int
		want   string
	}{
		"no archive":              {migrateValues(nil), []string{"--tenant", testTenant, "--identity", good}, 2, "--in"},
		"an identity others read": {migrateValues(nil), []string{"--tenant", testTenant, "--identity", open, "--in", archive}, 1, "readable by others"},
		"a file with no identity": {migrateValues(nil), []string{"--tenant", testTenant, "--identity", notAKey, "--in", archive}, 1, "no age identity"},
		"a missing archive":       {migrateValues(nil), []string{"--tenant", testTenant, "--identity", good, "--in", filepath.Join(dir, "gone.age")}, 1, "open the archive"},
		"no migration credential": {map[string]string{"IPSO_DATABASE_URL": appURL}, []string{"--tenant", testTenant, "--identity", good, "--in", archive}, 1, "IPSO_MIGRATE_DATABASE_URL is not set"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &tenantCalls{}
			code, _, stderr := invoke(t, tenantDeps(tc.values, calls), append([]string{"tenant", "restore"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) || calls.restore != nil {
				t.Errorf("code %d, stderr %q, restore %v", code, stderr, calls.restore)
			}
		})
	}
	calls := &tenantCalls{checkMigrateErr: errors.New("refusing to run as a superuser")}
	code, _, stderr := invoke(t, tenantDeps(migrateValues(nil), calls), "tenant", "restore", "--tenant", testTenant, "--identity", good, "--in", archive)
	if code != 1 || !strings.Contains(stderr, "superuser") || calls.restore != nil {
		t.Errorf("a privileged role: code %d, stderr %q", code, stderr)
	}
}

func TestTenantOffboardNeedsTheNameAndTheMigrationRole(t *testing.T) {
	calls := &tenantCalls{offboardReport: tenancy.OffboardReport{Tenant: uuid.MustParse(testTenant), DeletedRows: 9, Verified: true}}
	code, stdout, stderr := invoke(t, tenantDeps(migrateValues(nil), calls), "tenant", "offboard", "--tenant", testTenant, "--confirm", "acme")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedMigrate != 1 || calls.opened[0] != migrateURL || calls.offboard == nil || calls.offboard.Confirm != "acme" {
		t.Errorf("calls %+v", calls)
	}
	if !strings.Contains(stdout, `"verified": true`) {
		t.Errorf("stdout = %q", stdout)
	}

	for name, tc := range map[string]struct {
		values map[string]string
		args   []string
		code   int
		want   string
	}{
		"no confirmation":         {migrateValues(nil), []string{"--tenant", testTenant}, 2, "--confirm"},
		"no tenant":               {migrateValues(nil), []string{"--confirm", "acme"}, 2, "--tenant"},
		"no migration credential": {appValues(nil), []string{"--tenant", testTenant, "--confirm", "acme"}, 1, "IPSO_MIGRATE_DATABASE_URL is not set"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := &tenantCalls{}
			code, _, stderr := invoke(t, tenantDeps(tc.values, calls), append([]string{"tenant", "offboard"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) || calls.offboard != nil {
				t.Errorf("code %d, stderr %q, offboard %v", code, stderr, calls.offboard)
			}
		})
	}
}

func TestTenantOffboardStillPrintsTheReportWhenRowsRemain(t *testing.T) {
	calls := &tenantCalls{
		offboardErr:    tenancy.ErrNotVerified,
		offboardReport: tenancy.OffboardReport{Tenant: uuid.MustParse(testTenant), DeletedRows: 9},
	}
	code, stdout, stderr := invoke(t, tenantDeps(migrateValues(nil), calls), "tenant", "offboard", "--tenant", testTenant, "--confirm", "acme")
	if code != 1 || !strings.Contains(stderr, "remain") || !strings.Contains(stdout, `"deleted_rows": 9`) {
		t.Errorf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	calls = &tenantCalls{offboardErr: tenancy.ErrConfirm}
	code, stdout, _ = invoke(t, tenantDeps(migrateValues(nil), calls), "tenant", "offboard", "--tenant", testTenant, "--confirm", "other")
	if code != 1 || stdout != "" {
		t.Errorf("a refused confirmation: code %d, stdout %q", code, stdout)
	}
}

func TestTenantCommandsNeverPrintTheCredentials(t *testing.T) {
	calls := &tenantCalls{provisionErr: errors.New("provision: boom"), offboardErr: errors.New("offboard: boom")}
	for _, run := range []struct {
		values map[string]string
		args   []string
	}{
		{appValues(nil), []string{"tenant", "create", "--tenant", testTenant, "--name", "acme"}},
		{migrateValues(nil), []string{"tenant", "offboard", "--tenant", testTenant, "--confirm", "acme"}},
	} {
		_, stdout, stderr := invoke(t, tenantDeps(run.values, calls), run.args...)
		for _, secret := range []string{"app-pass", "migrate-pass", testKEKValue} {
			if strings.Contains(stdout+stderr, secret) {
				t.Errorf("output of %v contains a credential: %q %q", run.args, stdout, stderr)
			}
		}
	}
}

const (
	testAppKey = "-----BEGIN RSA PRIVATE KEY-----\nmarker-private-key\n-----END RSA PRIVATE KEY-----"
)

func bindValues(extra map[string]string) map[string]string {
	values := appValues(map[string]string{appIDEnv: "12345", appPrivateKeyEnv: testAppKey})
	for k, v := range extra {
		values[k] = v
	}
	return values
}

func TestTenantBindInstallationAsksGitHubThenBindsAndPrintsTheReport(t *testing.T) {
	calls := &tenantCalls{accountLogin: "Acme-Corp"}
	// GitHub logins have no case, so the account given matches whatever case GitHub answers.
	code, stdout, stderr := invoke(t, tenantDeps(bindValues(nil), calls), "tenant", "bind-installation",
		"--tenant", testTenant, "--installation", "424242", "--account", "acme-corp")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if calls.checkedApp != 1 || len(calls.opened) != 1 || calls.opened[0] != appURL {
		t.Errorf("opened %v, checked %d", calls.opened, calls.checkedApp)
	}
	if len(calls.asked) != 1 || calls.asked[0] != (askedAccount{"12345", testAppKey, 424242}) {
		t.Errorf("GitHub was asked %+v", calls.asked)
	}
	if calls.bind == nil || calls.bind.Tenant.String() != testTenant || calls.bind.Installation != 424242 {
		t.Errorf("bind options = %+v", calls.bind)
	}
	var report struct {
		Tenant       string `json:"tenant"`
		Installation int64  `json:"installation"`
		Bound        bool   `json:"bound"`
		Account      string `json:"account"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil ||
		report.Tenant != testTenant || report.Installation != 424242 || !report.Bound || report.Account != "Acme-Corp" {
		t.Errorf("stdout = %q (%v)", stdout, err)
	}
}

func TestTenantBindInstallationRefuses(t *testing.T) {
	good := []string{"--tenant", testTenant, "--installation", "7", "--account", "acme"}
	for name, tc := range map[string]struct {
		values map[string]string
		args   []string
		calls  tenantCalls
		code   int
		want   string
		// asked says whether GitHub may have been asked, and bound whether the mapping may have been written.
		asked, bound bool
	}{
		"no tenant":                         {bindValues(nil), []string{"--installation", "7", "--account", "acme"}, tenantCalls{}, 2, "--tenant, --installation", false, false},
		"a bad tenant":                      {bindValues(nil), []string{"--tenant", "acme", "--installation", "7", "--account", "acme"}, tenantCalls{}, 2, "--tenant, --installation", false, false},
		"no installation":                   {bindValues(nil), []string{"--tenant", testTenant, "--account", "acme"}, tenantCalls{}, 2, "--tenant, --installation", false, false},
		"a negative installation":           {bindValues(nil), []string{"--tenant", testTenant, "--installation", "-3", "--account", "acme"}, tenantCalls{}, 2, "--tenant, --installation", false, false},
		"an installation that is no number": {bindValues(nil), []string{"--tenant", testTenant, "--installation", "abc", "--account", "acme"}, tenantCalls{}, 2, "tenant bind-installation", false, false},
		"no account":                        {bindValues(nil), []string{"--tenant", testTenant, "--installation", "7"}, tenantCalls{}, 2, "--tenant, --installation", false, false},
		"no app id":                         {bindValues(map[string]string{appIDEnv: ""}), good, tenantCalls{}, 1, appIDEnv + " is not set", false, false},
		"no app key":                        {bindValues(map[string]string{appPrivateKeyEnv: ""}), good, tenantCalls{}, 1, appPrivateKeyEnv + " is not set", false, false},
		"no database":                       {bindValues(map[string]string{"IPSO_DATABASE_URL": ""}), good, tenantCalls{}, 1, "IPSO_DATABASE_URL is not set", false, false},
		"the migration credential":          {bindValues(map[string]string{"IPSO_MIGRATE_DATABASE_URL": migrateURL}), good, tenantCalls{}, 1, "must not hold the migration credential", false, false},
		"the start gate":                    {bindValues(nil), good, tenantCalls{checkAppErr: errors.New("refusing to start")}, 1, "refusing to start", false, false},
		"GitHub does not know it":           {bindValues(nil), good, tenantCalls{accountErr: errors.New("read the installation: github: not found")}, 1, "not found", true, false},
		"another account":                   {bindValues(nil), good, tenantCalls{accountLogin: "somebody-else"}, 1, `installation 7 is not on the account "acme"`, true, false},
		"the mapping refuses":               {bindValues(nil), good, tenantCalls{accountLogin: "acme", bindErr: tenancy.ErrInstallationBound}, 1, "bound to another tenant", true, true},
	} {
		t.Run(name, func(t *testing.T) {
			calls := tc.calls
			code, stdout, stderr := invoke(t, tenantDeps(tc.values, &calls), append([]string{"tenant", "bind-installation"}, tc.args...)...)
			if code != tc.code || !strings.Contains(stderr, tc.want) {
				t.Errorf("code %d, stderr %q; want code %d containing %q", code, stderr, tc.code, tc.want)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want none", stdout)
			}
			if (len(calls.asked) != 0) != tc.asked {
				t.Errorf("GitHub asked = %v, want %v", calls.asked, tc.asked)
			}
			if (calls.bind != nil) != tc.bound {
				t.Errorf("bind = %+v, want written %v", calls.bind, tc.bound)
			}
			if name == "another account" && strings.Contains(stderr, "somebody-else") {
				t.Errorf("stderr names the account GitHub answered: %q", stderr)
			}
			if name == "the migration credential" && len(calls.opened) != 0 {
				t.Errorf("a connection was opened with the migration credential in the environment: %v", calls.opened)
			}
			for _, secret := range []string{"app-pass", "migrate-pass", "marker-private-key", testKEKValue} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("output contains a credential: %q %q", stdout, stderr)
				}
			}
		})
	}
}
