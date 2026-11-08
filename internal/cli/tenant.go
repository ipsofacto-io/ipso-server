package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// tenantKEKEnv names the key encryption key that wraps the data key of a new tenant. Only tenant create
// reads it (ADR-0100).
const tenantKEKEnv = "IPSO_TENANT_KEK"

const tenantUsage = `usage:
  ipso-server tenant create --tenant <id> --name <name> [--person <id> --person-name <name> --issuer <url> --subject <subject>]
  ipso-server tenant export --tenant <id> --recipient <age public key> [--recipient ...] --out <file>
  ipso-server tenant restore --tenant <id> --identity <age identity file> --in <file>
  ipso-server tenant offboard --tenant <id> --confirm <name of the tenant>
  ipso-server tenant bind-installation --tenant <id> --installation <id> --account <login>`

const tenantHelp = `tenant manages the lifecycle of a tenant (ADR-0100). Each command prints a JSON report of counts, never
rows.

create adds the tenant, its wrapped data key, and optionally its first person with the login that binds the
identity provider's subject to them and the admin role over the tenant (ADR-0108). It runs as the application role from ` + databaseEnv + `, reads the key encryption
key from ` + tenantKEKEnv + ` (base64 of 32 bytes), and is safe to run again with the same arguments.

export writes every row of the tenant to an age file for the recipients, as the application role. The file is
created with mode 0600 and removed when the export fails.

restore reads such a file into a tenant that create made without a person and that has no other rows. It runs as
the migration role from ` + migrateDatabaseEnv + `, which the install allows to skip triggers for one transaction.

offboard deletes the tenant, its wrapped data key, its jobs, and its installation bindings, counts again, and records
a tombstone. It runs as the migration role from ` + migrateDatabaseEnv + `. Stop the api and the worker of the tenant first.

bind-installation says that a GitHub App installation belongs to the tenant, so a webhook delivery from it reaches the
tenant (ADR-0101). It asks GitHub, with ` + appIDEnv + ` and ` + appPrivateKeyEnv + `, which account the installation
is on and binds nothing unless that is the login given with --account. An installation belongs to one tenant: a
second tenant's bind is refused. It runs as the application role from ` + databaseEnv + `.`

// stringList is a flag that can be given several times.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func tenantCmd(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	switch args[0] {
	case "create":
		return tenantCreate(ctx, args[1:], stdout, stderr, d)
	case "export":
		return tenantExport(ctx, args[1:], stdout, stderr, d)
	case "restore":
		return tenantRestore(ctx, args[1:], stdout, stderr, d)
	case "offboard":
		return tenantOffboard(ctx, args[1:], stdout, stderr, d)
	case "bind-installation":
		return tenantBindInstallation(ctx, args[1:], stdout, stderr, d)
	case "-h", "--help", "help":
		fprintln(stdout, tenantHelp+"\n\n"+tenantUsage)
		return 0
	default:
		fprintf(stderr, "unknown tenant command %q\n%s\n", args[0], tenantUsage)
		return 2
	}
}

// newFlags makes a flag set that prints nothing: the caller prints the usage.
func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func parseTenantID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("--tenant is not a tenant id")
	}
	return id, nil
}

// applicationDB opens the database as the application role, and refuses to start for a process that also
// holds the migration credential, like the api and worker roles. It runs the start gate of the api role.
func applicationDB(ctx context.Context, d deps, command string) (*sql.DB, error) {
	if d.getenv(migrateDatabaseEnv) != "" {
		return nil, fmt.Errorf("%s is set: the %s command must not hold the migration credential", migrateDatabaseEnv, command)
	}
	if d.getenv(databaseEnv) == "" {
		return nil, fmt.Errorf("%s is not set", databaseEnv)
	}
	db, err := d.openDB(d.getenv(databaseEnv))
	if err != nil {
		return nil, fmt.Errorf("open the database: %w", err)
	}
	if err := d.checkApplication(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// migrationDB opens the database as the migration role and refuses a superuser or BYPASSRLS role, which
// would make the policies of the purge and the restore meaningless.
func migrationDB(ctx context.Context, d deps) (*sql.DB, error) {
	if d.getenv(migrateDatabaseEnv) == "" {
		return nil, fmt.Errorf("%s is not set", migrateDatabaseEnv)
	}
	db, err := d.openDB(d.getenv(migrateDatabaseEnv))
	if err != nil {
		return nil, fmt.Errorf("open the database: %w", err)
	}
	if err := d.checkMigration(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func printReport(stdout io.Writer, report any) {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

func tenantCreate(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("tenant create")
	tenant := flags.String("tenant", "", "")
	name := flags.String("name", "", "")
	person := flags.String("person", "", "")
	personName := flags.String("person-name", "", "")
	issuer := flags.String("issuer", "", "")
	subject := flags.String("subject", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil || *name == "" {
		fprintf(stderr, "tenant create: --tenant and --name are required\n%s\n", tenantUsage)
		return 2
	}
	var first *tenancy.Person
	if given := countSet(*person, *personName, *issuer, *subject); given != 0 {
		personID, err := uuid.Parse(*person)
		if given != 4 || err != nil || personID == uuid.Nil {
			fprintf(stderr, "tenant create: --person (an id), --person-name, --issuer and --subject are given together or not at all\n")
			return 2
		}
		first = &tenancy.Person{ID: personID, Name: *personName, Issuer: *issuer, Subject: *subject}
	}
	if d.getenv(tenantKEKEnv) == "" {
		fprintf(stderr, "tenant create: %s is not set\n", tenantKEKEnv)
		return 1
	}
	kek, err := tenancy.ParseKEK(d.getenv(tenantKEKEnv))
	if err != nil {
		fprintf(stderr, "tenant create: %s: %v\n", tenantKEKEnv, err)
		return 1
	}
	db, err := applicationDB(ctx, d, "tenant create")
	if err != nil {
		fprintf(stderr, "tenant create: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	report, err := d.provision(ctx, db, tenancy.ProvisionOptions{Tenant: id, Name: *name, Person: first, KEK: kek})
	if err != nil {
		fprintf(stderr, "tenant create: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	return 0
}

func countSet(values ...string) int {
	n := 0
	for _, v := range values {
		if v != "" {
			n++
		}
	}
	return n
}

func tenantExport(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("tenant export")
	tenant := flags.String("tenant", "", "")
	out := flags.String("out", "", "")
	var recipients stringList
	flags.Var(&recipients, "recipient", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil || *out == "" || len(recipients) == 0 {
		fprintf(stderr, "tenant export: --tenant, --out and at least one --recipient are required\n%s\n", tenantUsage)
		return 2
	}
	keys, err := age.ParseRecipients(strings.NewReader(strings.Join(recipients, "\n")))
	if err != nil || len(keys) != len(recipients) {
		fprintf(stderr, "tenant export: a --recipient is not an age public key (age1...)\n")
		return 2
	}
	db, err := applicationDB(ctx, d, "tenant export")
	if err != nil {
		fprintf(stderr, "tenant export: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	// The file holds the whole tenant, even though it is encrypted. It is created for its owner only and
	// never replaces a file, and a failed export leaves nothing behind.
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fprintf(stderr, "tenant export: create the file: %v\n", err)
		return 1
	}
	report, err := d.exportTenant(ctx, db, tenancy.ExportOptions{Tenant: id, Recipients: keys, Out: file})
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(*out)
		fprintf(stderr, "tenant export: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	return 0
}

func tenantRestore(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("tenant restore")
	tenant := flags.String("tenant", "", "")
	identityFile := flags.String("identity", "", "")
	in := flags.String("in", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil || *identityFile == "" || *in == "" {
		fprintf(stderr, "tenant restore: --tenant, --identity and --in are required\n%s\n", tenantUsage)
		return 2
	}
	identities, err := readIdentities(*identityFile)
	if err != nil {
		fprintf(stderr, "tenant restore: %v\n", err)
		return 1
	}
	archive, err := os.Open(*in)
	if err != nil {
		fprintf(stderr, "tenant restore: open the archive: %v\n", err)
		return 1
	}
	defer func() { _ = archive.Close() }()
	db, err := migrationDB(ctx, d)
	if err != nil {
		fprintf(stderr, "tenant restore: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	report, err := d.restoreTenant(ctx, db, tenancy.RestoreOptions{Tenant: id, Identities: identities, In: archive})
	if err != nil {
		fprintf(stderr, "tenant restore: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	return 0
}

// readIdentities reads an age identity file. A private key that others can read is refused, the rule ssh
// applies to its own keys.
func readIdentities(path string) ([]age.Identity, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the identity file: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read the identity file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("the identity file is readable by others: run chmod 600 on it")
	}
	identities, err := age.ParseIdentities(file)
	if err != nil || len(identities) == 0 {
		return nil, errors.New("the identity file holds no age identity")
	}
	return identities, nil
}

func tenantOffboard(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("tenant offboard")
	tenant := flags.String("tenant", "", "")
	confirm := flags.String("confirm", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil || *confirm == "" {
		fprintf(stderr, "tenant offboard: --tenant and --confirm are required\n%s\n", tenantUsage)
		return 2
	}
	db, err := migrationDB(ctx, d)
	if err != nil {
		fprintf(stderr, "tenant offboard: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	report, err := d.offboardTenant(ctx, db, tenancy.OffboardOptions{Tenant: id, Confirm: *confirm})
	if err != nil {
		// A purge that committed and then found rows still prints what it did, so the operator can see it.
		if errors.Is(err, tenancy.ErrNotVerified) {
			printReport(stdout, report)
		}
		fprintf(stderr, "tenant offboard: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	return 0
}

// bindReport is the report of bind-installation: the database's report and the account GitHub named.
type bindReport struct {
	tenancy.BindReport
	Account string `json:"account"`
}

func tenantBindInstallation(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("tenant bind-installation")
	tenant := flags.String("tenant", "", "")
	installation := flags.Int64("installation", 0, "")
	account := flags.String("account", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, tenantUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil || *installation <= 0 || *account == "" {
		fprintf(stderr, "tenant bind-installation: --tenant, --installation (a positive number) and --account are required\n%s\n", tenantUsage)
		return 2
	}
	for _, name := range []string{appIDEnv, appPrivateKeyEnv} {
		if d.getenv(name) == "" {
			fprintf(stderr, "tenant bind-installation: %s is not set\n", name)
			return 1
		}
	}
	// The local gates come first: a process that holds the migration credential, or a database role that
	// bypasses row-level security, stops before the App key is used.
	db, err := applicationDB(ctx, d, "tenant bind-installation")
	if err != nil {
		fprintf(stderr, "tenant bind-installation: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	// GitHub says whose installation this is. An installation id that is not this App's, or is on another
	// account than the one named, binds nothing, the way offboard needs the name of the tenant.
	login, err := d.installationAccount(ctx, d.getenv(appIDEnv), []byte(d.getenv(appPrivateKeyEnv)), *installation)
	if err != nil {
		fprintf(stderr, "tenant bind-installation: %v\n", err)
		return 1
	}
	if !strings.EqualFold(login, *account) {
		fprintf(stderr, "tenant bind-installation: installation %d is not on the account %q\n", *installation, *account)
		return 1
	}
	report, err := d.bindInstallation(ctx, db, tenancy.BindOptions{Tenant: id, Installation: *installation})
	if err != nil {
		fprintf(stderr, "tenant bind-installation: %v\n", err)
		return 1
	}
	printReport(stdout, bindReport{BindReport: report, Account: login})
	return 0
}
