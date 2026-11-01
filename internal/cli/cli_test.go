package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
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
	if !strings.Contains(stderr, databaseURLEnv) {
		t.Errorf("stderr = %q, want it to name %s", stderr, databaseURLEnv)
	}
	if called {
		t.Error("migrate ran without a database URL")
	}
}

func TestMigratePassesTheURLFromTheEnvironment(t *testing.T) {
	var got string
	d := deps{
		getenv: env(map[string]string{databaseURLEnv: "postgres://example/db"}),
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
		getenv:  env(map[string]string{databaseURLEnv: "postgres://example/db"}),
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
		getenv: env(map[string]string{databaseURLEnv: "postgres://example/db"}),
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
		d := deps{getenv: env(map[string]string{databaseURLEnv: url}), migrate: migrate.Run}
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
	var got integrations.Config
	d := deps{getenv: env(values), serve: func(_ context.Context, listener net.Listener, cfg integrations.Config) error {
		got = cfg
		return listener.Close()
	}}
	code, _, stderr := invoke(t, d, "webhooks")
	if code != 0 {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if string(got.WebhookSecret) != values[webhookSecretEnv] || got.App == nil || got.OnMerged != nil {
		t.Fatalf("config %+v", got)
	}
}

func TestWebhooksReportsAServeError(t *testing.T) {
	d := deps{getenv: env(webhookEnv(t)), serve: func(_ context.Context, listener net.Listener, _ integrations.Config) error {
		_ = listener.Close()
		return errors.New("the app permissions are not the set in section 3.1")
	}}
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
