package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ipsofacto-io/ipso-server/internal/controlplane"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/worker"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func invoke(t *testing.T, d deps, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(context.Background(), args, &out, &errOut, d)
	return code, out.String(), errOut.String()
}

func TestUsage(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no arguments", nil, 2, "usage:"},
		{"unknown command", []string{"serve"}, 2, `unknown command "serve"`},
		{"extra argument to migrate", []string{"migrate", "up"}, 2, "usage: ipso-server migrate"},
		{"extra argument to webhooks", []string{"webhooks", "now"}, 2, "usage: ipso-server webhooks"},
		{"extra argument to runtasks", []string{"runtasks", "now"}, 2, "usage: ipso-server runtasks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := invoke(t, deps{getenv: env(nil)}, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h", "version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			code, stdout, _ := invoke(t, deps{getenv: env(nil)}, arg)
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
			if !strings.Contains(stdout, "ipso-server migrate") {
				t.Errorf("stdout = %q, want the usage text", stdout)
			}
		})
	}
}

func TestMigrateNeedsTheDatabaseURL(t *testing.T) {
	called := false
	d := deps{
		getenv: env(nil),
		migrate: func(context.Context, string) ([]string, error) {
			called = true
			return nil, nil
		},
	}
	code, _, stderr := invoke(t, d, "migrate")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, migrateDatabaseEnv) {
		t.Errorf("stderr = %q, want it to name %s", stderr, migrateDatabaseEnv)
	}
	if called {
		t.Error("migrate ran without a database URL")
	}
}

func TestMigratePassesTheURLFromTheEnvironment(t *testing.T) {
	var got string
	d := deps{
		getenv: env(map[string]string{migrateDatabaseEnv: "postgres://example/db"}),
		migrate: func(_ context.Context, databaseURL string) ([]string, error) {
			got = databaseURL
			return []string{"00001_a.sql", "00002_b.sql"}, nil
		},
	}
	code, stdout, stderr := invoke(t, d, "migrate")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if got != "postgres://example/db" {
		t.Errorf("database URL = %q", got)
	}
	if want := "applied 00001_a.sql\napplied 00002_b.sql\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestMigrateReportsNothingToDo(t *testing.T) {
	d := deps{
		getenv:  env(map[string]string{migrateDatabaseEnv: "postgres://example/db"}),
		migrate: func(context.Context, string) ([]string, error) { return nil, nil },
	}
	code, stdout, _ := invoke(t, d, "migrate")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if stdout != "no pending migrations\n" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestMigrateFailureExitsNonZero(t *testing.T) {
	d := deps{
		getenv: env(map[string]string{migrateDatabaseEnv: "postgres://example/db"}),
		migrate: func(context.Context, string) ([]string, error) {
			return nil, errors.Join(migrate.ErrPrivilegedRole, errors.New("boom"))
		},
	}
	code, stdout, stderr := invoke(t, d, "migrate")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want it empty", stdout)
	}
	if !strings.Contains(stderr, migrate.ErrPrivilegedRole.Error()) {
		t.Errorf("stderr = %q, want the refusal", stderr)
	}
}

// The password sits in the environment variable, so no failure path may print it.
func TestMigrateNeverPrintsThePassword(t *testing.T) {
	const secret = "s3cr3t-value"
	for _, url := range []string{
		"postgres://ipso_migrate:" + secret + "@127.0.0.1:notaport/ipso",
		"host=127.0.0.1 port=notaport user=ipso_migrate password=" + secret,
		"postgres://ipso_migrate:" + secret + "@127.0.0.1:1/ipso?sslmode=disable&connect_timeout=2",
	} {
		d := deps{getenv: env(map[string]string{migrateDatabaseEnv: url}), migrate: migrate.Run}
		code, stdout, stderr := invoke(t, d, "migrate")
		if code != 1 {
			t.Errorf("%q: exit code = %d, want 1", url, code)
		}
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("%q: output leaks the password: %q", url, stdout+stderr)
		}
	}
}

func webhookEnv(t *testing.T) map[string]string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		appIDEnv:         "12345",
		appPrivateKeyEnv: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		webhookSecretEnv: strings.Repeat("s3", 16),
		listenAddrEnv:    "127.0.0.1:0",
		databaseEnv:      appURL,
	}
}

func TestWebhooksRequiresEverySecret(t *testing.T) {
	for _, missing := range []string{appIDEnv, appPrivateKeyEnv, webhookSecretEnv} {
		t.Run(missing, func(t *testing.T) {
			values := webhookEnv(t)
			delete(values, missing)
			code, _, stderr := invoke(t, deps{getenv: env(values)}, "webhooks")
			if code != 1 || !strings.Contains(stderr, missing+" is not set") {
				t.Fatalf("code %d stderr %q", code, stderr)
			}
		})
	}
}

func TestWebhooksRefusesABadKeyWithoutPrintingIt(t *testing.T) {
	values := webhookEnv(t)
	values[appPrivateKeyEnv] = "marker-not-a-key"
	code, _, stderr := invoke(t, deps{getenv: env(values)}, "webhooks")
	if code != 1 || strings.Contains(stderr, "marker-not-a-key") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestWebhooksServes(t *testing.T) {
	values := webhookEnv(t)
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	calls := &tenantCalls{owners: map[int64]uuid.UUID{42: other}}
	var got integrations.Config
	d := tenantDeps(values, calls)
	d.serve = func(_ context.Context, listener net.Listener, cfg integrations.Config) error {
		got = cfg
		return listener.Close()
	}
	code, _, stderr := invoke(t, d, "webhooks")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if string(got.WebhookSecret) != values[webhookSecretEnv] || got.App == nil || got.OnMerged != nil {
		t.Fatalf("config %+v", got)
	}
	// The process opens the database as the application role behind the start gate of the api role, and
	// checks the lookup before it listens.
	if len(calls.opened) != 1 || calls.opened[0] != appURL || calls.checkedApp != 1 || calls.lookupRequired != 1 {
		t.Errorf("opened %v, checked %d, lookup required %d", calls.opened, calls.checkedApp, calls.lookupRequired)
	}
	// A burst of deliveries must not take every connection of a database that the api and worker share.
	if calls.openedDB == nil {
		t.Fatal("the webhooks command opened no database")
	}
	if got := calls.openedDB.Stats().MaxOpenConnections; got != webhookDBConns {
		t.Errorf("the webhooks pool allows %d connections, want %d", got, webhookDBConns)
	}
	// The mapping it hands the service is the lookup of that database.
	if got.Tenants == nil {
		t.Fatal("the service has no installation mapping")
	}
	if tenant, ok, err := got.Tenants(context.Background(), 42); err != nil || !ok || tenant != other {
		t.Errorf("Tenants(42) = %v, %v, %v", tenant, ok, err)
	}
	if _, ok, err := got.Tenants(context.Background(), 43); err != nil || ok {
		t.Errorf("Tenants(43) = %v, %v; want no tenant", ok, err)
	}
	// The removal of a binding on uninstall is the one of that same database (ADR-0125).
	if got.Unbind == nil {
		t.Fatal("the service cannot remove a binding")
	}
	if tenant, removed, err := got.Unbind(context.Background(), 42); err != nil || !removed || tenant != other {
		t.Errorf("Unbind(42) = %v, %v, %v", tenant, removed, err)
	}
	if len(calls.unbound) != 1 || calls.unbound[0] != 42 || calls.unbindDB != calls.openedDB {
		t.Errorf("unbound %v on %p, want 42 on the webhooks database %p", calls.unbound, calls.unbindDB, calls.openedDB)
	}
}

const gatewayConfig = `{"routes":[{"name":"mistral","provider":"mistral","model":"mistral-medium-latest","key_env":"IPSO_LLM_MISTRAL"}],"default":["mistral"],"monthly_tokens":1000000}`

func writeGatewayConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The hook that reads the discussion of a merged pull request and calls a model exists only when the operator
// configured a gateway, and its tenant is the one the installation mapping gave (ADR-0103).
func TestWebhooksBuildsTheMergedHookFromTheGatewayConfig(t *testing.T) {
	t.Setenv("IPSO_LLM_MISTRAL", "key-marker-1")
	values := webhookEnv(t)
	values[gatewayConfigEnv] = writeGatewayConfig(t, gatewayConfig)
	var got integrations.Config
	d := tenantDeps(values, &tenantCalls{})
	d.serve = func(_ context.Context, listener net.Listener, cfg integrations.Config) error {
		got = cfg
		return listener.Close()
	}
	code, _, stderr := invoke(t, d, "webhooks")
	if code != 0 || got.OnMerged == nil {
		t.Fatalf("code %d, hook %v, stderr %q", code, got.OnMerged != nil, stderr)
	}
	// It is the proposals hook: with no tenant it returns before it reads anything from GitHub, and the nil
	// client would panic if it did.
	if err := got.OnMerged(t.Context(), integrations.MergedPullRequest{Repo: "acme/payments", Number: 7}); err == nil || err.Error() != "no tenant" {
		t.Fatalf("the hook answered %v for a merged pull request with no tenant", err)
	}
}

func TestWebhooksRefusesABadGatewayWithoutPrintingAKey(t *testing.T) {
	const key = "key-marker-2"
	for name, tc := range map[string]struct {
		config string // empty means the file does not exist
		key    string
		want   string
	}{
		"a missing file":      {"", key, gatewayConfigEnv},
		"not JSON":            {"{", key, "llm gateway config"},
		"an unknown field":    {`{"routes":[],"surprise":1}`, key, "llm gateway config"},
		"a route with no key": {gatewayConfig, "", "IPSO_LLM_MISTRAL is not set"},
		"a route outside the EU": {`{"routes":[{"name":"bedrock","provider":"bedrock","model":"anthropic.claude-x","region":"us-east-1","key_env":"IPSO_LLM_MISTRAL"}],"default":["bedrock"],"monthly_tokens":1000}`,
			key, "must be EU-resident"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("IPSO_LLM_MISTRAL", tc.key)
			values := webhookEnv(t)
			values[gatewayConfigEnv] = filepath.Join(t.TempDir(), "absent.json")
			if tc.config != "" {
				values[gatewayConfigEnv] = writeGatewayConfig(t, tc.config)
			}
			served := false
			d := tenantDeps(values, &tenantCalls{})
			d.serve = func(_ context.Context, listener net.Listener, _ integrations.Config) error {
				served = true
				return listener.Close()
			}
			code, stdout, stderr := invoke(t, d, "webhooks")
			if code != 1 || served || !strings.Contains(stderr, tc.want) {
				t.Fatalf("code %d, served %v, stderr %q; want code 1 containing %q", code, served, stderr, tc.want)
			}
			for _, secret := range []string{key, "app-pass", values[webhookSecretEnv], "PRIVATE KEY"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("output contains a credential: %q %q", stdout, stderr)
				}
			}
		})
	}
}

func TestWebhooksRefusesToStartWithoutItsDatabase(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(map[string]string)
		calls  tenantCalls
		want   string
	}{
		"no database":              {func(v map[string]string) { delete(v, databaseEnv) }, tenantCalls{}, "IPSO_DATABASE_URL is not set"},
		"the migration credential": {func(v map[string]string) { v[migrateDatabaseEnv] = migrateURL }, tenantCalls{}, "must not hold the migration credential"},
		"the start gate":           {func(map[string]string) {}, tenantCalls{checkAppErr: errors.New("refusing to start")}, "refusing to start"},
		"an unmigrated database":   {func(map[string]string) {}, tenantCalls{lookupErr: errors.New("installation lookup: run ipso-server migrate")}, "run ipso-server migrate"},
	} {
		t.Run(name, func(t *testing.T) {
			values := webhookEnv(t)
			tc.change(values)
			calls := tc.calls
			served := false
			d := tenantDeps(values, &calls)
			d.serve = func(_ context.Context, listener net.Listener, _ integrations.Config) error {
				served = true
				return listener.Close()
			}
			code, stdout, stderr := invoke(t, d, "webhooks")
			if code != 1 || !strings.Contains(stderr, tc.want) || served {
				t.Fatalf("code %d, served %v, stderr %q; want code 1 containing %q", code, served, stderr, tc.want)
			}
			for _, secret := range []string{"app-pass", "migrate-pass", values[webhookSecretEnv], "PRIVATE KEY"} {
				if strings.Contains(stdout+stderr, secret) {
					t.Errorf("output contains a credential: %q %q", stdout, stderr)
				}
			}
		})
	}
}

func TestWebhooksReportsAServeError(t *testing.T) {
	d := tenantDeps(webhookEnv(t), &tenantCalls{})
	d.serve = func(_ context.Context, listener net.Listener, _ integrations.Config) error {
		_ = listener.Close()
		return errors.New("the app permissions are not the set in section 3.1")
	}
	code, _, stderr := invoke(t, d, "webhooks")
	if code != 1 || !strings.Contains(stderr, "section 3.1") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestRunTasksReadsItsConfiguration(t *testing.T) {
	complete := map[string]string{
		runTaskHMACEnv:      "key",
		runTaskBundleEnv:    "layout",
		runTaskDigestEnv:    "sha256:abc",
		runTaskPublicKeyEnv: "public.pem",
		listenAddrEnv:       "127.0.0.1:0",
		runTaskPolicyEnv:    "prod",
		runTaskHostEnv:      "tfe.example.test",
		runTaskPlanHostsEnv: "tfe.example.test,archive.example.test",
	}
	for _, missing := range []string{runTaskHMACEnv, runTaskBundleEnv, runTaskDigestEnv, runTaskPublicKeyEnv} {
		t.Run("without "+missing, func(t *testing.T) {
			values := map[string]string{}
			for key, value := range complete {
				if key != missing {
					values[key] = value
				}
			}
			code, _, stderr := invoke(t, deps{getenv: env(values)}, "runtasks")
			if code != 1 || !strings.Contains(stderr, missing+" is not set") {
				t.Fatalf("code %d stderr %q", code, stderr)
			}
		})
	}
	t.Run("a bundle that does not verify stops the start", func(t *testing.T) {
		d := deps{
			getenv: env(complete),
			loadBundle: func(string, string, string) (integrations.PlanEvaluator, error) {
				return nil, errors.New("bundle-unsigned")
			},
			runTasks: func(context.Context, net.Listener, integrations.RunTaskConfig) error {
				t.Fatal("the service started")
				return nil
			},
		}
		code, _, stderr := invoke(t, d, "runtasks")
		if code != 1 || !strings.Contains(stderr, "bundle-unsigned") {
			t.Fatalf("code %d stderr %q", code, stderr)
		}
	})
	t.Run("the service gets every setting", func(t *testing.T) {
		var got integrations.RunTaskConfig
		var layout, digest, key string
		d := deps{
			getenv: env(complete),
			loadBundle: func(gotLayout, gotDigest, gotKey string) (integrations.PlanEvaluator, error) {
				layout, digest, key = gotLayout, gotDigest, gotKey
				return nil, nil
			},
			runTasks: func(_ context.Context, listener net.Listener, cfg integrations.RunTaskConfig) error {
				got = cfg
				return listener.Close()
			},
		}
		if code, _, stderr := invoke(t, d, "runtasks"); code != 0 {
			t.Fatalf("code %d stderr %q", code, stderr)
		}
		if layout != "layout" || digest != "sha256:abc" || key != "public.pem" {
			t.Fatalf("bundle %q %q %q", layout, digest, key)
		}
		if string(got.HMACKey) != "key" || got.Env != "prod" || got.APIHost != "tfe.example.test" || strings.Join(got.PlanHosts, " ") != "tfe.example.test archive.example.test" {
			t.Fatalf("config %+v", got)
		}
	})
}

const testTenant = "00000000-0000-4000-8000-00000000000a"

func apiEnv(extra map[string]string) func(string) string {
	values := map[string]string{
		"IPSO_DATABASE_URL": "postgres://ipso_app@db.example.test/ipso",
		"IPSO_TENANT_ID":    testTenant,
		"IPSO_OIDC_ISSUER":  "https://idp.example.test",
		"IPSO_API_AUDIENCE": "ipso-api",
		"IPSO_LISTEN_ADDR":  "127.0.0.1:0",
	}
	for k, v := range extra {
		values[k] = v
	}
	return env(values)
}

func apiDeps(getenv func(string) string, got *controlplane.Config) deps {
	return deps{
		getenv: getenv,
		openDB: func(string) (*sql.DB, error) { return sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none") },
		controlPlane: func(_ context.Context, listener net.Listener, cfg controlplane.Config) error {
			_ = listener.Close()
			*got = cfg
			return nil
		},
	}
}

func TestRoleAPIStartsTheControlPlaneFromTheEnvironment(t *testing.T) {
	var got controlplane.Config
	code, _, stderr := invoke(t, apiDeps(apiEnv(map[string]string{
		"IPSO_MCP_ISSUER":       "https://mcp-idp.example.test",
		"IPSO_MCP_RESOURCE_URL": "https://ipso.example.test/mcp",
	}), &got), "--role=api")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if got.Tenant.String() != testTenant || got.Issuer != "https://idp.example.test" || got.Audience != "ipso-api" ||
		got.MCPIssuer != "https://mcp-idp.example.test" || got.MCPResourceURL != "https://ipso.example.test/mcp" || got.DB == nil {
		t.Errorf("config = %+v", got)
	}
}

func TestRoleAPIReadsBrowserSignInFromTheEnvironment(t *testing.T) {
	var got controlplane.Config
	providers := `[{"id":"github","kind":"github","client_id":"gh","client_secret_env":"IPSO_LOGIN_GITHUB"}]`
	code, _, stderr := invoke(t, apiDeps(apiEnv(map[string]string{
		"IPSO_PUBLIC_URL":      "https://ipso.example.test",
		"IPSO_LOGIN_PROVIDERS": providers,
		"IPSO_LOGIN_GITHUB":    "a-secret",
	}), &got), "--role=api")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if got.PublicURL != "https://ipso.example.test" || len(got.Providers) != 1 || got.Providers[0].ID != "github" || got.Providers[0].ClientSecretEnv != "IPSO_LOGIN_GITHUB" {
		t.Errorf("config = %+v", got)
	}
	// The process reads a secret through the environment of the provider that names it, and no other.
	if got.Secrets == nil || got.Secrets("IPSO_LOGIN_GITHUB") != "a-secret" {
		t.Error("the secrets are not read from the environment")
	}
	if strings.Contains(stderr, "a-secret") {
		t.Error("a secret reached stderr")
	}
}

func TestRoleAPIRefusesBrowserSignInItCannotRead(t *testing.T) {
	good := `[{"id":"github","kind":"github","client_id":"gh","client_secret_env":"IPSO_LOGIN_GITHUB"}]`
	for name, extra := range map[string]map[string]string{
		"providers without a public URL": {"IPSO_LOGIN_PROVIDERS": good},
		"a public URL without providers": {"IPSO_PUBLIC_URL": "https://ipso.example.test"},
		"a provider with a field it does not know": {
			"IPSO_PUBLIC_URL": "https://ipso.example.test", "IPSO_LOGIN_PROVIDERS": `[{"id":"github","kind":"github","client_id":"gh","client_secret":"oops"}]`,
		},
		"providers that are not JSON": {"IPSO_PUBLIC_URL": "https://ipso.example.test", "IPSO_LOGIN_PROVIDERS": "github"},
	} {
		t.Run(name, func(t *testing.T) {
			var got controlplane.Config
			code, _, stderr := invoke(t, apiDeps(apiEnv(extra), &got), "--role=api")
			if code != 1 || got.DB != nil {
				t.Fatalf("exit code = %d, started %v: %s", code, got.DB != nil, stderr)
			}
			if strings.Contains(stderr, "oops") {
				t.Errorf("the secret reached stderr: %q", stderr)
			}
		})
	}
}

func TestRoleAPIReadsVerdictUploadsFromTheEnvironment(t *testing.T) {
	app := webhookEnv(t)
	var got controlplane.Config
	code, _, stderr := invoke(t, apiDeps(apiEnv(map[string]string{
		ciAudienceEnv: "https://ipso.example.test/ci", appIDEnv: app[appIDEnv], appPrivateKeyEnv: app[appPrivateKeyEnv],
	}), &got), "--role=api")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if got.CIAudience != "https://ipso.example.test/ci" || got.Repositories == nil || got.CIIssuer != "" {
		t.Errorf("config = %+v", got)
	}
	if strings.Contains(stderr, "PRIVATE KEY") {
		t.Error("the App key reached stderr")
	}

	// Without the audience the route is off, and App settings shared with the webhooks service change nothing.
	for name, extra := range map[string]map[string]string{
		"nothing set":    nil,
		"only the App":   {appIDEnv: app[appIDEnv], appPrivateKeyEnv: app[appPrivateKeyEnv]},
		"only a junk id": {appIDEnv: "twelve"},
	} {
		got = controlplane.Config{}
		if code, _, stderr := invoke(t, apiDeps(apiEnv(extra), &got), "--role=api"); code != 0 || got.CIAudience != "" || got.Repositories != nil {
			t.Fatalf("%s: exit code = %d, config %+v: %s", name, code, got, stderr)
		}
	}
}

func TestRoleAPIRefusesVerdictUploadsItCannotServe(t *testing.T) {
	app := webhookEnv(t)
	full := map[string]string{ciAudienceEnv: "https://ipso.example.test/ci", appIDEnv: app[appIDEnv], appPrivateKeyEnv: app[appPrivateKeyEnv]}
	without := func(name string) map[string]string {
		values := map[string]string{}
		for k, v := range full {
			if k != name {
				values[k] = v
			}
		}
		return values
	}
	for name, extra := range map[string]map[string]string{
		"no app id":          without(appIDEnv),
		"no app key":         without(appPrivateKeyEnv),
		"a key that is junk": {ciAudienceEnv: "https://ipso.example.test/ci", appIDEnv: "12345", appPrivateKeyEnv: "not pem"},
		"an id that is junk": {ciAudienceEnv: "https://ipso.example.test/ci", appIDEnv: "twelve", appPrivateKeyEnv: app[appPrivateKeyEnv]},
	} {
		t.Run(name, func(t *testing.T) {
			var got controlplane.Config
			code, _, stderr := invoke(t, apiDeps(apiEnv(extra), &got), "--role=api")
			if code != 1 || got.DB != nil {
				t.Fatalf("exit code = %d, started %v: %s", code, got.DB != nil, stderr)
			}
			if strings.Contains(stderr, "PRIVATE KEY") || strings.Contains(stderr, "not pem") {
				t.Errorf("the key reached stderr: %q", stderr)
			}
		})
	}
}

func TestRoleAPIAcceptsTheRoleAsASeparateArgument(t *testing.T) {
	var got controlplane.Config
	if code, _, stderr := invoke(t, apiDeps(apiEnv(nil), &got), "--role", "api"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
}

func TestRoleAPIRefusesWhatItCannotServe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		extra    map[string]string
		wantCode int
		wantErr  string
	}{
		{"all", []string{"--role=all"}, nil, 2, "not built yet"},
		{"an unknown role", []string{"--role=web"}, nil, 2, `unknown role "web"`},
		{"no role", []string{"--role="}, nil, 2, "unknown role"},
		{"an extra argument", []string{"--role=api", "now"}, nil, 2, "usage: ipso-server --role=api"},
		{"the migration credential", []string{"--role=api"}, map[string]string{"IPSO_MIGRATE_DATABASE_URL": "postgres://ipso_migrate@db.example.test/ipso"}, 1, "migration credential"},
		{"no database", []string{"--role=api"}, map[string]string{"IPSO_DATABASE_URL": ""}, 1, "IPSO_DATABASE_URL is not set"},
		{"no issuer", []string{"--role=api"}, map[string]string{"IPSO_OIDC_ISSUER": ""}, 1, "IPSO_OIDC_ISSUER is not set"},
		{"no audience", []string{"--role=api"}, map[string]string{"IPSO_API_AUDIENCE": ""}, 1, "IPSO_API_AUDIENCE is not set"},
		{"a bad tenant", []string{"--role=api"}, map[string]string{"IPSO_TENANT_ID": "acme"}, 1, "not a tenant id"},
		{"a nil tenant", []string{"--role=api"}, map[string]string{"IPSO_TENANT_ID": "00000000-0000-0000-0000-000000000000"}, 1, "not a tenant id"},
		{"half of the MCP pair", []string{"--role=api"}, map[string]string{"IPSO_MCP_ISSUER": "https://mcp-idp.example.test"}, 1, "together or not at all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got controlplane.Config
			code, _, stderr := invoke(t, apiDeps(apiEnv(tt.extra), &got), tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d: %s", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
			if got.DB != nil {
				t.Error("the control plane was started")
			}
		})
	}
}

func TestRoleAPIReportsAFailedStart(t *testing.T) {
	d := apiDeps(apiEnv(nil), new(controlplane.Config))
	d.controlPlane = func(context.Context, net.Listener, controlplane.Config) error {
		return errors.New("refusing to start")
	}
	code, _, stderr := invoke(t, d, "--role=api")
	if code != 1 || !strings.Contains(stderr, "refusing to start") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
}

func workerEnv(extra map[string]string) func(string) string {
	values := map[string]string{
		"IPSO_DATABASE_URL": "postgres://ipso_app@db.example.test/ipso",
		"IPSO_TENANT_ID":    testTenant,
	}
	for k, v := range extra {
		values[k] = v
	}
	return env(values)
}

func workerDeps(getenv func(string) string, got *worker.Config) deps {
	return deps{
		getenv: getenv,
		// pgxpool connects on first use, so a pool for an address nobody serves never dials.
		openPool: func(ctx context.Context, _ string) (*pgxpool.Pool, error) {
			return pgxpool.New(ctx, "postgres://nobody@127.0.0.1:1/none")
		},
		runWorker: func(_ context.Context, cfg worker.Config) error {
			*got = cfg
			return nil
		},
	}
}

func TestRoleWorkerStartsTheWorkerForTheTenantOfTheEnvironment(t *testing.T) {
	var got worker.Config
	code, _, stderr := invoke(t, workerDeps(workerEnv(nil), &got), "--role=worker")
	if code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if got.Tenant.String() != testTenant || got.Pool == nil || got.Log == nil {
		t.Errorf("config = %+v", got)
	}
}

func TestRoleWorkerAcceptsTheRoleAsASeparateArgument(t *testing.T) {
	var got worker.Config
	if code, _, stderr := invoke(t, workerDeps(workerEnv(nil), &got), "--role", "worker"); code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
}

func TestRoleWorkerRefusesWhatItCannotServe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		extra    map[string]string
		wantCode int
		wantErr  string
	}{
		{"an extra argument", []string{"--role=worker", "now"}, nil, 2, "usage: ipso-server --role=api|worker"},
		{"the migration credential", []string{"--role=worker"}, map[string]string{"IPSO_MIGRATE_DATABASE_URL": "postgres://ipso_migrate@db.example.test/ipso"}, 1, "migration credential"},
		{"no database", []string{"--role=worker"}, map[string]string{"IPSO_DATABASE_URL": ""}, 1, "IPSO_DATABASE_URL is not set"},
		{"no tenant", []string{"--role=worker"}, map[string]string{"IPSO_TENANT_ID": ""}, 1, "IPSO_TENANT_ID is not set"},
		{"a bad tenant", []string{"--role=worker"}, map[string]string{"IPSO_TENANT_ID": "acme"}, 1, "not a tenant id"},
		{"a nil tenant", []string{"--role=worker"}, map[string]string{"IPSO_TENANT_ID": "00000000-0000-0000-0000-000000000000"}, 1, "not a tenant id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got worker.Config
			code, _, stderr := invoke(t, workerDeps(workerEnv(tt.extra), &got), tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d: %s", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantErr)
			}
			if got.Pool != nil {
				t.Error("the worker was started")
			}
		})
	}
}

func TestRoleWorkerOpensNoConnectionWithTheMigrationCredential(t *testing.T) {
	d := workerDeps(workerEnv(map[string]string{"IPSO_MIGRATE_DATABASE_URL": "postgres://ipso_migrate@db.example.test/ipso"}), new(worker.Config))
	d.openPool = func(context.Context, string) (*pgxpool.Pool, error) {
		t.Error("a connection was opened with the migration credential in the environment")
		return nil, errors.New("not reached")
	}
	if code, _, _ := invoke(t, d, "--role=worker"); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRoleWorkerReportsAFailedStart(t *testing.T) {
	d := workerDeps(workerEnv(nil), new(worker.Config))
	d.runWorker = func(context.Context, worker.Config) error { return errors.New("refusing to start") }
	code, _, stderr := invoke(t, d, "--role=worker")
	if code != 1 || !strings.Contains(stderr, "worker: refusing to start") {
		t.Errorf("exit code = %d, stderr = %q", code, stderr)
	}
}

func TestRoleWorkerNeverPrintsThePassword(t *testing.T) {
	const password = "s3cret-pass-word"
	d := deps{
		getenv: workerEnv(map[string]string{"IPSO_DATABASE_URL": "postgres://ipso_app:" + password + "@db.example.test:notaport/ipso"}),
		openPool: func(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
			return pgxpool.New(ctx, databaseURL)
		},
		runWorker: func(context.Context, worker.Config) error { return errors.New("not reached") },
	}
	code, _, stderr := invoke(t, d, "--role=worker")
	if code != 1 || !strings.Contains(stderr, "open the database") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if strings.Contains(stderr, password) {
		t.Errorf("stderr shows the password: %q", stderr)
	}
}
