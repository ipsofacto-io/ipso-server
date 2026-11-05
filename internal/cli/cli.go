// Package cli dispatches the ipso-server subcommands.
package cli

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/ipsofacto-io/ipso/pkg/plancheck"

	"github.com/ipsofacto-io/ipso-server/internal/controlplane"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
)

// migrateDatabaseEnv names the only place the migration credential is read from.
// A flag would show the credential in the process list.
const migrateDatabaseEnv = "IPSO_MIGRATE_DATABASE_URL"

// The webhook service reads its secrets from the environment for the same reason.
const (
	appIDEnv         = "IPSO_GITHUB_APP_ID"
	appPrivateKeyEnv = "IPSO_GITHUB_APP_PRIVATE_KEY"
	webhookSecretEnv = "IPSO_GITHUB_WEBHOOK_SECRET"
	listenAddrEnv    = "IPSO_LISTEN_ADDR"
	defaultListen    = ":8080"
)

// The run task service reads the same way. The bundle is verified at start and held in memory.
const (
	runTaskHMACEnv      = "IPSO_RUNTASK_HMAC_KEY"
	runTaskBundleEnv    = "IPSO_RUNTASK_BUNDLE"
	runTaskDigestEnv    = "IPSO_RUNTASK_BUNDLE_DIGEST"
	runTaskPublicKeyEnv = "IPSO_RUNTASK_BUNDLE_PUBLIC_KEY"
	runTaskPolicyEnv    = "IPSO_RUNTASK_ENV"
	runTaskHostEnv      = "IPSO_RUNTASK_HOST"
	runTaskPlanHostsEnv = "IPSO_RUNTASK_PLAN_HOSTS"
)

// The api role reads its settings from the environment, and the database URL is a credential. It is
// the application role's: the migration credential is never read here, and the role refuses to start
// when it finds it (ADR-0094).
const (
	databaseEnv    = "IPSO_DATABASE_URL"
	tenantEnv      = "IPSO_TENANT_ID"
	oidcIssuerEnv  = "IPSO_OIDC_ISSUER"
	apiAudienceEnv = "IPSO_API_AUDIENCE"
	mcpIssuerEnv   = "IPSO_MCP_ISSUER"
	mcpResourceEnv = "IPSO_MCP_RESOURCE_URL"
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
	// runTasks and loadBundle serve the run task command. Tests inject both.
	runTasks   func(ctx context.Context, listener net.Listener, cfg integrations.RunTaskConfig) error
	loadBundle func(layout, digest, publicKey string) (integrations.PlanEvaluator, error)
	// openDB and controlPlane serve --role=api. Tests inject both.
	openDB       func(databaseURL string) (*sql.DB, error)
	controlPlane func(ctx context.Context, listener net.Listener, cfg controlplane.Config) error
}

// Run executes one CLI invocation. args excludes the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdout, stderr, deps{
		getenv:   os.Getenv,
		migrate:  migrate.Run,
		serve:    integrations.Serve,
		runTasks: integrations.ServeRunTasks,
		openDB: func(databaseURL string) (*sql.DB, error) {
			return sql.Open("pgx", databaseURL)
		},
		controlPlane: controlplane.Serve,
		loadBundle: func(layout, digest, publicKey string) (integrations.PlanEvaluator, error) {
			return plancheck.Load(layout, digest, publicKey)
		},
	})
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, usage)
		return 2
	}
	if strings.HasPrefix(args[0], "--role") || strings.HasPrefix(args[0], "-role") {
		return roleCmd(ctx, args, stderr, d)
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
	case "runtasks":
		if len(args) != 1 {
			fprintln(stderr, "usage: ipso-server runtasks")
			return 2
		}
		return runTasksCmd(ctx, stderr, d)
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
  ipso-server --role=api
  ipso-server migrate
  ipso-server webhooks
  ipso-server runtasks

--role=api serves the control plane API on ` + listenAddrEnv + ` (default ` + defaultListen + `) as the application role. It
reads ` + databaseEnv + `, ` + tenantEnv + `, ` + oidcIssuerEnv + `, and ` + apiAudienceEnv + `, and optionally
the pair ` + mcpIssuerEnv + ` and ` + mcpResourceEnv + ` for the remote MCP handler. It refuses to start as a
role that can bypass row-level security, for a tenant with no row, or when it holds the migration
credential. The roles worker and all are not built yet.

migrate applies the pending schema migrations and exits. It reads the
connection string from ` + migrateDatabaseEnv + ` and must run as the migration role.

webhooks serves the GitHub App webhook on ` + listenAddrEnv + ` (default ` + defaultListen + `). It reads
` + appIDEnv + `, ` + appPrivateKeyEnv + `, and ` + webhookSecretEnv + `, holds no
tenant data, and opens no database connection.

runtasks serves the HCP Terraform run task on ` + listenAddrEnv + ` (default ` + defaultListen + `). It reads
` + runTaskHMACEnv + `, ` + runTaskBundleEnv + `, ` + runTaskDigestEnv + `,
and ` + runTaskPublicKeyEnv + `, and optionally ` + runTaskPolicyEnv + `, ` + runTaskHostEnv + `,
and ` + runTaskPlanHostsEnv + `. It holds no tenant data and opens no database connection.`

// roleCmd starts ipso-server by role, the form of ADR-0017. Only api exists: the worker waits for the
// job runtime of IPSO-132.
func roleCmd(ctx context.Context, args []string, stderr io.Writer, d deps) int {
	flags := flag.NewFlagSet("ipso-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	role := flags.String("role", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, "usage: ipso-server --role=api")
		return 2
	}
	switch *role {
	case "api":
		return apiCmd(ctx, stderr, d)
	case "worker", "all":
		fprintf(stderr, "role %q is not built yet: the job runtime is chosen by IPSO-132\n", *role)
		return 2
	default:
		fprintf(stderr, "unknown role %q\nusage: ipso-server --role=api\n", *role)
		return 2
	}
}

func apiCmd(ctx context.Context, stderr io.Writer, d deps) int {
	cfg, err := apiConfig(d.getenv)
	if err != nil {
		fprintf(stderr, "api: %v\n", err)
		return 1
	}
	address := d.getenv(listenAddrEnv)
	if address == "" {
		address = defaultListen
	}
	db, err := d.openDB(d.getenv(databaseEnv))
	if err != nil {
		fprintf(stderr, "api: open the database: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	cfg.DB = db
	cfg.Version = Version
	cfg.Log = slog.New(slog.NewJSONHandler(stderr, nil))
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		fprintf(stderr, "api: %v\n", err)
		return 1
	}
	if err := d.controlPlane(ctx, listener, cfg); err != nil {
		fprintf(stderr, "api: %v\n", err)
		return 1
	}
	return 0
}

// apiConfig reads the settings that need no connection. It refuses the migration credential, so an
// api process cannot be started with the role that owns the tables.
func apiConfig(getenv func(string) string) (controlplane.Config, error) {
	if getenv(migrateDatabaseEnv) != "" {
		return controlplane.Config{}, fmt.Errorf("%s is set: the api role must not hold the migration credential", migrateDatabaseEnv)
	}
	for _, name := range []string{databaseEnv, tenantEnv, oidcIssuerEnv, apiAudienceEnv} {
		if getenv(name) == "" {
			return controlplane.Config{}, fmt.Errorf("%s is not set", name)
		}
	}
	tenant, err := uuid.Parse(getenv(tenantEnv))
	if err != nil || tenant == uuid.Nil {
		return controlplane.Config{}, fmt.Errorf("%s is not a tenant id", tenantEnv)
	}
	if (getenv(mcpIssuerEnv) == "") != (getenv(mcpResourceEnv) == "") {
		return controlplane.Config{}, errors.New(mcpIssuerEnv + " and " + mcpResourceEnv + " are set together or not at all")
	}
	return controlplane.Config{
		Tenant:         tenant,
		Issuer:         getenv(oidcIssuerEnv),
		Audience:       getenv(apiAudienceEnv),
		MCPIssuer:      getenv(mcpIssuerEnv),
		MCPResourceURL: getenv(mcpResourceEnv),
	}, nil
}

func migrateCmd(ctx context.Context, stdout, stderr io.Writer, d deps) int {
	databaseURL := d.getenv(migrateDatabaseEnv)
	if databaseURL == "" {
		fprintf(stderr, "migrate: %s is not set\n", migrateDatabaseEnv)
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

func runTasksCmd(ctx context.Context, stderr io.Writer, d deps) int {
	for _, name := range []string{runTaskHMACEnv, runTaskBundleEnv, runTaskDigestEnv, runTaskPublicKeyEnv} {
		if d.getenv(name) == "" {
			fprintf(stderr, "runtasks: %s is not set\n", name)
			return 1
		}
	}
	bundle, err := d.loadBundle(d.getenv(runTaskBundleEnv), d.getenv(runTaskDigestEnv), d.getenv(runTaskPublicKeyEnv))
	if err != nil {
		fprintf(stderr, "runtasks: %v\n", err)
		return 1
	}
	address := d.getenv(listenAddrEnv)
	if address == "" {
		address = defaultListen
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		fprintf(stderr, "runtasks: %v\n", err)
		return 1
	}
	var planHosts []string
	if hosts := d.getenv(runTaskPlanHostsEnv); hosts != "" {
		planHosts = strings.Split(hosts, ",")
	}
	err = d.runTasks(ctx, listener, integrations.RunTaskConfig{
		HMACKey:   []byte(d.getenv(runTaskHMACEnv)),
		Bundle:    bundle,
		Env:       d.getenv(runTaskPolicyEnv),
		APIHost:   d.getenv(runTaskHostEnv),
		PlanHosts: planHosts,
		Logger:    slog.New(slog.NewJSONHandler(stderr, nil)),
	})
	if err != nil {
		fprintf(stderr, "runtasks: %v\n", err)
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
