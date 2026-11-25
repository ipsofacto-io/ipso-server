package cli

import (
	"context"
	"io"
)

const proposalsUsage = `usage:
  ipso-server proposals acceptance --tenant <id>`

const proposalsHelp = `proposals reads what reviewers answered to the proposals a model wrote (ADR-0165).

acceptance reads one tenant in one read-only snapshot, as the application role from ` + databaseEnv + `, under row-level
security. It prints a JSON report with a row for each kind of proposal (pr_decision, tracker_decision, check), prompt
version and model: the proposals approved, rejected and still pending, and the share approved of those answered, which
section 1.6 of the spec wants at 70% or more. A row with fewer than 10 answered proposals reports no rate. A check that
a person wrote is left out, because it is approved when it is stored. The report holds counts only. It never names the
person who answered and never groups by one (ADR-0012).`

func proposalsCmd(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, proposalsUsage)
		return 2
	}
	switch args[0] {
	case "acceptance":
		return proposalsAcceptance(ctx, args[1:], stdout, stderr, d)
	case "-h", "--help", "help":
		fprintln(stdout, proposalsHelp+"\n\n"+proposalsUsage)
		return 0
	default:
		fprintf(stderr, "unknown proposals command %q\n%s\n", args[0], proposalsUsage)
		return 2
	}
}

func proposalsAcceptance(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("proposals acceptance")
	tenant := flags.String("tenant", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, proposalsUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil {
		fprintf(stderr, "proposals acceptance: --tenant is required and must be a tenant id\n%s\n", proposalsUsage)
		return 2
	}
	db, err := applicationDB(ctx, d, "proposals acceptance")
	if err != nil {
		fprintf(stderr, "proposals acceptance: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	report, err := d.acceptance(ctx, db, id)
	if err != nil {
		fprintf(stderr, "proposals acceptance: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	return 0
}
