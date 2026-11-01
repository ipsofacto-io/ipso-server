// Package cli dispatches the ipso-server subcommands.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
)

// databaseURLEnv names the only place the migration credential is read from.
// A flag would show the credential in the process list.
const databaseURLEnv = "IPSO_MIGRATE_DATABASE_URL"

// The webhook service reads its secrets from the environment for the same reason.
const (
	appIDEnv         = "IPSO_GITHUB_APP_ID"
	appPrivateKeyEnv = "IPSO_GITHUB_APP_PRIVATE_KEY"
	webhookSecretEnv = "IPSO_GITHUB_WEBHOOK_SECRET"
	listenAddrEnv    = "IPSO_LISTEN_ADDR"
	defaultListen    = ":8080"
)

// Version, Commit, and Date are set with -X at release time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// deps is the environment and the migration runner for one invocation.
// Tests inject both. The binary uses the process environment and the embedded migrations.
type deps struct {
	getenv  func(string) string
	migrate func(ctx context.Context, databaseURL string) ([]string, error)
	serve   func(ctx context.Context, listener net.Listener, cfg integrations.Config) error
}

// Run executes one CLI invocation. args excludes the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdout, stderr, deps{getenv: os.Getenv, migrate: migrate.Run, serve: integrations.Serve})
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "migrate":
		if len(args) != 1 {
			fprintln(stderr, "usage: ipso-server migrate")
			return 2
		}
		return migrateCmd(ctx, stdout, stderr, d)
	case "webhooks":
		if len(args) != 1 {
			fprintln(stderr, "usage: ipso-server webhooks")
			return 2
		}
		return webhooksCmd(ctx, stderr, d)
	case "-h", "--help", "help", "version", "--version", "-v":
		fprintln(stdout, helpText())
		return 0
	default:
		fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}

func helpText() string {
	return fmt.Sprintf("ipso-server %s (%s, %s)\n\n%s", Version, Commit, Date, usage)
}

const usage = `ipso-server is the ipso control plane.

usage:
  ipso-server migrate
  ipso-server webhooks

migrate applies the pending schema migrations and exits. It reads the
connection string from ` + databaseURLEnv + ` and must run as the migration role.

webhooks serves the GitHub App webhook on ` + listenAddrEnv + ` (default ` + defaultListen + `). It reads
` + appIDEnv + `, ` + appPrivateKeyEnv + `, and ` + webhookSecretEnv + `, holds no
tenant data, and opens no database connection.`

func migrateCmd(ctx context.Context, stdout, stderr io.Writer, d deps) int {
	databaseURL := d.getenv(databaseURLEnv)
	if databaseURL == "" {
		fprintf(stderr, "migrate: %s is not set\n", databaseURLEnv)
		return 1
	}
	applied, err := d.migrate(ctx, databaseURL)
	if err != nil {
		fprintf(stderr, "migrate: %v\n", err)
		return 1
	}
	if len(applied) == 0 {
		fprintln(stdout, "no pending migrations")
		return 0
	}
	for _, name := range applied {
		fprintf(stdout, "applied %s\n", name)
	}
	return 0
}

func webhooksCmd(ctx context.Context, stderr io.Writer, d deps) int {
	for _, name := range []string{appIDEnv, appPrivateKeyEnv, webhookSecretEnv} {
		if d.getenv(name) == "" {
			fprintf(stderr, "webhooks: %s is not set\n", name)
			return 1
		}
	}
	app, err := integrations.NewApp(d.getenv(appIDEnv), []byte(d.getenv(appPrivateKeyEnv)))
	if err != nil {
		fprintf(stderr, "webhooks: %v\n", err)
		return 1
	}
	address := d.getenv(listenAddrEnv)
	if address == "" {
		address = defaultListen
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		fprintf(stderr, "webhooks: %v\n", err)
		return 1
	}
	err = d.serve(ctx, listener, integrations.Config{
		App:           app,
		WebhookSecret: []byte(d.getenv(webhookSecretEnv)),
		Logger:        slog.New(slog.NewJSONHandler(stderr, nil)),
	})
	if err != nil {
		fprintf(stderr, "webhooks: %v\n", err)
		return 1
	}
	return 0
}

func fprintln(w io.Writer, a ...any) {
	_, _ = fmt.Fprintln(w, a...)
}

func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}
