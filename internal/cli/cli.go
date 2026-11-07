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
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/ipsofacto-io/ipso/pkg/plancheck"

	"github.com/ipsofacto-io/ipso-server/internal/controlplane"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/login"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
	"github.com/ipsofacto-io/ipso-server/internal/worker"
)

// migrateDatabaseEnv names the only place the migration credential is read from.
// A flag would show the credential in the process list.
const migrateDatabaseEnv = "IPSO_MIGRATE_DATABASE_URL"

// webhookDBConns bounds the connections of the webhooks process. Each delivery that starts work holds one
// for its tenant lookup, which is a short read, and a delivery that cannot get one within the lookup
// timeout is answered 503 for GitHub to redeliver. The database is shared with the api and the worker, so
// a burst of deliveries must not take every connection.
const webhookDBConns = 8

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

// The api and worker roles read their settings from the environment, and the database URL is a
// credential. It is the application role's: the migration credential is never read here, and a role
// refuses to start when it finds it (ADR-0094, ADR-0097).
const (
	databaseEnv    = "IPSO_DATABASE_URL"
	tenantEnv      = "IPSO_TENANT_ID"
	oidcIssuerEnv  = "IPSO_OIDC_ISSUER"
	apiAudienceEnv = "IPSO_API_AUDIENCE"
	mcpIssuerEnv   = "IPSO_MCP_ISSUER"
	mcpResourceEnv = "IPSO_MCP_RESOURCE_URL"
	// ciAudienceEnv turns on verdict uploads (ADR-0102) together with the GitHub App settings.
	ciAudienceEnv = "IPSO_CI_AUDIENCE"
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
	// openPool and runWorker serve --role=worker. Tests inject both.
	openPool  func(ctx context.Context, databaseURL string) (*pgxpool.Pool, error)
	runWorker func(ctx context.Context, cfg worker.Config) error
	// The tenant commands (ADR-0100). checkApplication is the start gate of the api role and checkMigration
	// refuses a superuser or BYPASSRLS role. Tests inject all of them.
	checkApplication func(ctx context.Context, db *sql.DB) error
	checkMigration   func(ctx context.Context, db *sql.DB) error
	provision        func(ctx context.Context, db *sql.DB, o tenancy.ProvisionOptions) (tenancy.ProvisionReport, error)
	exportTenant     func(ctx context.Context, db *sql.DB, o tenancy.ExportOptions) (tenancy.ExportReport, error)
	restoreTenant    func(ctx context.Context, db *sql.DB, o tenancy.RestoreOptions) (tenancy.RestoreReport, error)
	offboardTenant   func(ctx context.Context, db *sql.DB, o tenancy.OffboardOptions) (tenancy.OffboardReport, error)
	// The installation to tenant mapping (ADR-0101). installationAccount asks GitHub which account an
	// installation is on, bindInstallation writes the mapping, and installationTenant and
	// requireInstallations serve the webhooks command. Tests inject all of them.
	installationAccount  func(ctx context.Context, appID string, privateKey []byte, installation int64) (string, error)
	bindInstallation     func(ctx context.Context, db *sql.DB, o tenancy.BindOptions) (tenancy.BindReport, error)
	installationTenant   func(ctx context.Context, db *sql.DB, installation int64) (uuid.UUID, bool, error)
	requireInstallations func(ctx context.Context, db *sql.DB) error
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
		openPool: func(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
			return pgxpool.New(ctx, databaseURL)
		},
		runWorker:        worker.Run,
		checkApplication: rls.Check,
		checkMigration:   migrate.RefusePrivilegedRole,
		provision:        tenancy.Provision,
		exportTenant:     tenancy.Export,
		restoreTenant:    tenancy.Restore,
		offboardTenant:   tenancy.Offboard,
		installationAccount: func(ctx context.Context, appID string, privateKey []byte, installation int64) (string, error) {
			app, err := integrations.NewApp(appID, privateKey)
			if err != nil {
				return "", err
			}
			return app.InstallationAccount(ctx, installation)
		},
		bindInstallation:     tenancy.BindInstallation,
		installationTenant:   tenancy.InstallationTenant,
		requireInstallations: tenancy.RequireInstallationLookup,
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
	case "tenant":
		return tenantCmd(ctx, args[1:], stdout, stderr, d)
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
  ipso-server --role=worker
  ipso-server migrate
  ipso-server tenant create|export|restore|offboard|bind-installation
  ipso-server webhooks
  ipso-server runtasks

--role=api serves the control plane API on ` + listenAddrEnv + ` (default ` + defaultListen + `) as the application role. It
reads ` + databaseEnv + `, ` + tenantEnv + `, ` + oidcIssuerEnv + `, and ` + apiAudienceEnv + `, and optionally
the pair ` + mcpIssuerEnv + ` and ` + mcpResourceEnv + ` for the remote MCP handler, the pair
` + login.PublicURLEnv + ` and ` + login.ProvidersEnv + ` for browser sign-in, whose client secrets are the
variables the providers name, and ` + ciAudienceEnv + ` with ` + appIDEnv + ` and ` + appPrivateKeyEnv + ` for the
upload of verdicts by CI jobs, which it accepts with a GitHub Actions token only. It refuses to start as a role that can bypass row-level security, for a
tenant with no row, or when it holds the migration credential.

--role=worker works the jobs of the control plane on River, in the registry's PostgreSQL, as the
application role. It reads ` + databaseEnv + ` and ` + tenantEnv + `, serves no request, and runs the waiver notice
sweep and the premise sweep every hour. It refuses to start as a role that can bypass row-level security, for a tenant with no
row, before the schema is migrated, or when it holds the migration credential. The role all is not built
yet.

migrate applies the pending schema migrations and exits. It reads the
connection string from ` + migrateDatabaseEnv + ` and must run as the migration role.

tenant creates, exports, restores and offboards a tenant, and binds a GitHub App installation to it. Run
ipso-server tenant help for the commands, their flags and the credential each one uses.

webhooks serves the GitHub App webhook on ` + listenAddrEnv + ` (default ` + defaultListen + `). It reads
` + appIDEnv + `, ` + appPrivateKeyEnv + `, and ` + webhookSecretEnv + `, and opens ` + databaseEnv + `
as the application role to ask which tenant owns the installation of a delivery. It holds no tenant data, and a
delivery from an installation that no tenant owns starts nothing. Bind an installation first with
ipso-server tenant bind-installation.

runtasks serves the HCP Terraform run task on ` + listenAddrEnv + ` (default ` + defaultListen + `). It reads
` + runTaskHMACEnv + `, ` + runTaskBundleEnv + `, ` + runTaskDigestEnv + `,
and ` + runTaskPublicKeyEnv + `, and optionally ` + runTaskPolicyEnv + `, ` + runTaskHostEnv + `,
and ` + runTaskPlanHostsEnv + `. It holds no tenant data and opens no database connection.`

// roleCmd starts ipso-server by role, the form of ADR-0017. The roles api and worker are built, and all is
// not.
func roleCmd(ctx context.Context, args []string, stderr io.Writer, d deps) int {
	flags := flag.NewFlagSet("ipso-server", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	role := flags.String("role", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, "usage: ipso-server --role=api|worker")
		return 2
	}
	switch *role {
	case "api":
		return apiCmd(ctx, stderr, d)
	case "worker":
		return workerCmd(ctx, stderr, d)
	case "all":
		fprintf(stderr, "role %q is not built yet\n", *role)
		return 2
	default:
		fprintf(stderr, "unknown role %q\nusage: ipso-server --role=api|worker\n", *role)
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

// tenantSettings reads what a role that serves one tenant needs before it connects: the database URL and
// the tenant, then the settings only that role has. It refuses the migration credential, so such a process
// cannot be started with the role that owns the tables.
func tenantSettings(getenv func(string) string, role string, own ...string) (uuid.UUID, error) {
	if getenv(migrateDatabaseEnv) != "" {
		return uuid.Nil, fmt.Errorf("%s is set: the %s role must not hold the migration credential", migrateDatabaseEnv, role)
	}
	for _, name := range append([]string{databaseEnv, tenantEnv}, own...) {
		if getenv(name) == "" {
			return uuid.Nil, fmt.Errorf("%s is not set", name)
		}
	}
	tenant, err := uuid.Parse(getenv(tenantEnv))
	if err != nil || tenant == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%s is not a tenant id", tenantEnv)
	}
	return tenant, nil
}

// apiConfig reads the settings of the api role that need no connection.
func apiConfig(getenv func(string) string) (controlplane.Config, error) {
	tenant, err := tenantSettings(getenv, "api", oidcIssuerEnv, apiAudienceEnv)
	if err != nil {
		return controlplane.Config{}, err
	}
	if (getenv(mcpIssuerEnv) == "") != (getenv(mcpResourceEnv) == "") {
		return controlplane.Config{}, errors.New(mcpIssuerEnv + " and " + mcpResourceEnv + " are set together or not at all")
	}
	cfg := controlplane.Config{
		Tenant:         tenant,
		Issuer:         getenv(oidcIssuerEnv),
		Audience:       getenv(apiAudienceEnv),
		MCPIssuer:      getenv(mcpIssuerEnv),
		MCPResourceURL: getenv(mcpResourceEnv),
	}
	// Verdict uploads (ADR-0102): the audience of CI tokens turns them on, and then the GitHub App that maps a
	// repository to its installation is required. The App settings alone change nothing, because a deployment
	// may share them with the webhooks service.
	if ciAudience := getenv(ciAudienceEnv); ciAudience != "" {
		appID, appKey := getenv(appIDEnv), getenv(appPrivateKeyEnv)
		if appID == "" || appKey == "" {
			return controlplane.Config{}, errors.New(appIDEnv + " and " + appPrivateKeyEnv + " are required when " + ciAudienceEnv + " is set")
		}
		app, err := integrations.NewApp(appID, []byte(appKey))
		if err != nil {
			return controlplane.Config{}, err
		}
		cfg.CIAudience, cfg.Repositories = ciAudience, app
	}
	// Browser sign-in (ADR-0099): the public origin and the providers, together or not at all. A provider
	// names the variable that holds its client secret, so the JSON can be logged and committed.
	publicURL, providers := getenv(login.PublicURLEnv), getenv(login.ProvidersEnv)
	if (publicURL == "") != (providers == "") {
		return controlplane.Config{}, errors.New(login.PublicURLEnv + " and " + login.ProvidersEnv + " are set together or not at all")
	}
	if providers != "" {
		parsed, err := login.ParseProviders(strings.NewReader(providers))
		if err != nil {
			return controlplane.Config{}, err
		}
		cfg.PublicURL, cfg.Providers, cfg.Secrets = publicURL, parsed, getenv
	}
	return cfg, nil
}

// workerCmd works the jobs for the one tenant of IPSO_TENANT_ID until the process is told to stop. The
// start gates run in worker.Run, after the connection opens.
func workerCmd(ctx context.Context, stderr io.Writer, d deps) int {
	tenant, err := tenantSettings(d.getenv, "worker")
	if err != nil {
		fprintf(stderr, "worker: %v\n", err)
		return 1
	}
	pool, err := d.openPool(ctx, d.getenv(databaseEnv))
	if err != nil {
		fprintf(stderr, "worker: open the database: %v\n", err)
		return 1
	}
	defer pool.Close()
	err = d.runWorker(ctx, worker.Config{
		Pool:   pool,
		Tenant: tenant,
		Log:    slog.New(slog.NewJSONHandler(stderr, nil)),
	})
	if err != nil {
		fprintf(stderr, "worker: %v\n", err)
		return 1
	}
	return 0
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
	// The mapping from an installation to its tenant lives in the database. The process opens it as the
	// application role, with the start gate of the api role, and holds no tenant data (ADR-0101).
	db, err := applicationDB(ctx, d, "webhooks")
	if err != nil {
		fprintf(stderr, "webhooks: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(webhookDBConns)
	if err := d.requireInstallations(ctx, db); err != nil {
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
		Tenants: func(ctx context.Context, installation int64) (uuid.UUID, bool, error) {
			return d.installationTenant(ctx, db, installation)
		},
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
