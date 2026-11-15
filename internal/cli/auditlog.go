package cli

import (
	"context"
	"io"
)

const auditLogUsage = `usage:
  ipso-server audit-log verify --tenant <id>`

const auditLogHelp = `audit-log checks the hash chain of the action log of a tenant (ADR-0126).

verify reads every entry of the tenant in one snapshot, as the application role from ` + databaseEnv + `, and checks that
the positions run from 1 without a gap, that each entry carries the hash of the entry before it, and that each hash
is the hash of the fields of its entry. It prints a JSON report with the number of entries and the head of the chain,
the last position and hash, and exits 1 and names the first entry that fails when the chain is broken. Keep the head
somewhere else, such as the SIEM that reads the audit log route: a chain proves itself from its first entry on, and
only an older head shows that entries after it were not removed or rewritten as a whole.`

func auditLogCmd(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, auditLogUsage)
		return 2
	}
	switch args[0] {
	case "verify":
		return auditLogVerify(ctx, args[1:], stdout, stderr, d)
	case "-h", "--help", "help":
		fprintln(stdout, auditLogHelp+"\n\n"+auditLogUsage)
		return 0
	default:
		fprintf(stderr, "unknown audit-log command %q\n%s\n", args[0], auditLogUsage)
		return 2
	}
}

func auditLogVerify(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	flags := newFlags("audit-log verify")
	tenant := flags.String("tenant", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fprintln(stderr, auditLogUsage)
		return 2
	}
	id, err := parseTenantID(*tenant)
	if err != nil {
		fprintf(stderr, "audit-log verify: --tenant is required and must be a tenant id\n%s\n", auditLogUsage)
		return 2
	}
	db, err := applicationDB(ctx, d, "audit-log verify")
	if err != nil {
		fprintf(stderr, "audit-log verify: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	report, err := d.verifyLog(ctx, db, id)
	if err != nil {
		fprintf(stderr, "audit-log verify: %v\n", err)
		return 1
	}
	printReport(stdout, report)
	if !report.Intact {
		return 1
	}
	return 0
}
