package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

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
