package verification

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MaxCommitVerdicts bounds the verdicts that one read of a commit returns (ADR-0124 decision 5). A commit has
// one upload for each check command, run, attempt and environment, and one verdict for each decision check of
// its report, so a repository has far fewer.
const MaxCommitVerdicts = 1000

// ErrTooMany is returned when a commit holds more than MaxCommitVerdicts verdicts. The read refuses the whole
// answer and never returns the first of them, because a partial list would be taken for a whole one.
var ErrTooMany = errors.New("too many verdicts")

// Commit returns sha in the form an upload stores it, which is lowercase, or ErrInvalid when it is not a
// commit of 40 or 64 hexadecimal digits. A caller checks it before it opens a connection.
func Commit(sha string) (string, error) {
	lower := strings.ToLower(sha)
	if !commitSHA.MatchString(lower) {
		return "", invalid("sha is not a commit")
	}
	return lower, nil
}

// ByCommit returns every stored verdict of the uploads of one repository and one commit, newest first, as the
// server knew them at transaction time known (ADR-0124). Each verdict is read as List reads it: against the
// recorded baseline of its decision and repository and the waivers recorded for its decision, with the time the
// server stored its upload as valid time (ADR-0122, ADR-0123). It counts every run, attempt, check command and
// environment of the commit.
//
// stored is false when no upload of the repository and the commit was stored by known, and the verdicts are
// then nil: the commit is unknown, which a reader must not take for clean. When uploads exist and none holds a
// verdict, stored is true and the verdicts are empty. More than MaxCommitVerdicts verdicts is ErrTooMany. It
// reads with ipso.tenant set, so another tenant's rows are not visible to it.
func ByCommit(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo, sha string, known time.Time) (verdicts []Item, stored bool, err error) {
	if db == nil || tenant == uuid.Nil || known.IsZero() {
		return nil, false, errors.New("by commit: a database, a tenant and a transaction time are required")
	}
	repo = strings.ToLower(repo)
	if !validRepo(repo) {
		return nil, false, invalid("repo is not owner/name")
	}
	sha, err = Commit(sha)
	if err != nil {
		return nil, false, err
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, false, reduce("by commit: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return nil, false, reduce("by commit: set the tenant", err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM verification.upload AS u
			WHERE u.tenant_id = $1 AND u.repo = $2 AND u.sha = $3 AND u.sys_period @> $4::timestamptz)`,
		tenant, repo, sha, known).Scan(&stored); err != nil {
		return nil, false, reduce("by commit: read the uploads", err)
	}
	if !stored {
		return nil, false, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT `+verdictColumns+`
		`+verdictFrom+`
		WHERE v.tenant_id = $1 AND u.repo = $2 AND u.sha = $3 AND u.sys_period @> $4::timestamptz
		ORDER BY v.id DESC
		LIMIT $5`, tenant, repo, sha, known, MaxCommitVerdicts+1)
	if err != nil {
		return nil, false, reduce("by commit: read", err)
	}
	items, digests, err := scanVerdicts(rows, "by commit")
	if err != nil {
		return nil, false, err
	}
	_ = tx.Rollback()
	if len(items) > MaxCommitVerdicts {
		return nil, false, ErrTooMany
	}
	if err := readReadings(ctx, db, tenant, items, digests, known); err != nil {
		return nil, false, err
	}
	return items, true, nil
}
