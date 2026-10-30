package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrInvalidQuery is returned when the tenant or a time passed to Resolve is not usable.
var ErrInvalidQuery = errors.New("invalid query")

// ErrDamagedClosure is returned when a scope that matched has no closure row for itself. The
// closure trigger writes that row with the scope, so a missing one means the closure was
// changed around the triggers, and the ancestors of the scope cannot be trusted. Reading on
// would drop every decision that applies through those ancestors.
var ErrDamagedClosure = errors.New("scope closure is damaged")

// Subject is what a check evaluates: a repository, and optionally a path inside it and an
// environment. Repo is a lowercase owner/name. Path is relative to the repository root. An
// empty Path or Env is omitted, and an omitted field matches every scope. That widens the
// answer, so a caller that is limited to a path or an environment must pass it.
type Subject struct {
	Repo string
	Path string
	Env  string
}

// Decision is a version of a decision in force for a subject.
type Decision struct {
	ID      uuid.UUID
	Version int
	Body    json.RawMessage
}

// The tenant filter reads the setting that Resolve sets, so a session with no tenant matches no
// row. It is the filter of section 2.3 Q1 and the one the row-level security policies use.
const (
	// selectingScopes reads the nodes that may select the subject: those of its org, with the
	// literal repo or no literal repo, that were recorded by transaction time T. A domain and a
	// service select nothing themselves. They apply through the closure.
	selectingScopes = `
SELECT id, match_repo, match_path, match_env
FROM registry.scope
WHERE tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND kind IN ('org', 'repo', 'path', 'env')
  AND match_org = $1
  AND repo_key IN ('', $2)
  AND sys_period @> $3::timestamptz`

	// ancestorsOfMatched reads the closure rows of the matched nodes: each node and every
	// ancestor of it.
	ancestorsOfMatched = `
SELECT descendant_id, ancestor_id
FROM registry.scope_closure
WHERE tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND descendant_id = ANY($1::uuid[])`

	// decisionsInForce reads the decisions that name one of the given scopes, valid at V as
	// known at T. A decision is returned once, at its highest version.
	decisionsInForce = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.scope_refs && $1::uuid[]
  AND d.valid_period @> $2::timestamptz
  AND d.sys_period @> $3::timestamptz
  AND d.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
ORDER BY d.decision_id, d.version DESC`
)

// Resolve returns the decisions in force for the subject at valid time validAt, as the registry
// knew them at transaction time knownAt, ordered by decision id. No decision is a nil slice, and
// a caller tells that from a failure by err alone.
//
// The tenant must be the authenticated one, because Resolve trusts it. It reads that tenant in
// one read-only REPEATABLE READ transaction, so a scope or a decision written while it runs
// cannot split the answer. A scope recorded after knownAt does not change the answer for knownAt.
//
// The database narrows the scope nodes to the subject's org and repo, the selectors are matched
// here, and the closure adds every ancestor of a matching node. A stored selector that does not
// parse fails the call with ErrInvalidSelector, and a matched node with no closure row of its
// own fails it with ErrDamagedClosure. Neither drops a decision from the answer.
func Resolve(ctx context.Context, db *sql.DB, tenant uuid.UUID, in Subject, validAt, knownAt time.Time) ([]Decision, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if validAt.IsZero() || knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	subject, err := newSubject(in)
	if err != nil {
		return nil, err
	}

	var decisions []Decision
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		matched, err := matchingScopes(ctx, tx, subject, knownAt)
		if err != nil {
			return err
		}
		if len(matched) == 0 {
			return nil
		}
		scopes, err := ancestorsOf(ctx, tx, matched)
		if err != nil {
			return err
		}
		decisions, err = readDecisions(ctx, tx, scopes, validAt, knownAt)
		return err
	})
	return decisions, err
}

// readTx runs fn in one read-only REPEATABLE READ transaction with ipso.tenant set for that
// transaction only. A session with no tenant matches no row, and a pooled connection does not
// keep the setting. fn's error is returned as it is.
func readTx(ctx context.Context, db *sql.DB, tenant uuid.UUID, fn func(context.Context, *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return fmt.Errorf("set the tenant: %w", err)
	}
	return fn(ctx, tx)
}

func matchingScopes(ctx context.Context, tx *sql.Tx, s subject, knownAt time.Time) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, selectingScopes, s.org, s.repoString(), knownAt)
	if err != nil {
		return nil, fmt.Errorf("read scopes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var matched []uuid.UUID
	for rows.Next() {
		var (
			id uuid.UUID
			c  candidate
		)
		if err := rows.Scan(&id, &c.repo, &c.path, &c.env); err != nil {
			return nil, fmt.Errorf("read scopes: %w", err)
		}
		selected, err := s.selects(c)
		if err != nil {
			return nil, fmt.Errorf("scope %s: %w", id, err)
		}
		if selected {
			matched = append(matched, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read scopes: %w", err)
	}
	return matched, nil
}

// ancestorsOf returns the matched nodes and every ancestor of them, each once. It fails when a
// matched node has no closure row for itself. It does not recount the ancestors: the trigger
// is the only writer of the closure, so a changed closure means a superuser or a trigger bypass,
// and that actor can edit decisions directly (ADR-0051).
func ancestorsOf(ctx context.Context, tx *sql.Tx, matched []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, ancestorsOfMatched, matched)
	if err != nil {
		return nil, fmt.Errorf("read scope closure: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var (
		scopes  []uuid.UUID
		seen    = make(map[uuid.UUID]bool)
		hasSelf = make(map[uuid.UUID]bool, len(matched))
	)
	for rows.Next() {
		var descendant, ancestor uuid.UUID
		if err := rows.Scan(&descendant, &ancestor); err != nil {
			return nil, fmt.Errorf("read scope closure: %w", err)
		}
		if descendant == ancestor {
			hasSelf[descendant] = true
		}
		if !seen[ancestor] {
			seen[ancestor] = true
			scopes = append(scopes, ancestor)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read scope closure: %w", err)
	}
	for _, id := range matched {
		if !hasSelf[id] {
			return nil, fmt.Errorf("scope %s: %w", id, ErrDamagedClosure)
		}
	}
	return scopes, nil
}

func readDecisions(ctx context.Context, tx *sql.Tx, scopes []uuid.UUID, validAt, knownAt time.Time) ([]Decision, error) {
	rows, err := tx.QueryContext(ctx, decisionsInForce, scopes, validAt, knownAt)
	if err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var decisions []Decision
	for rows.Next() {
		var d Decision
		var body []byte
		if err := rows.Scan(&d.ID, &d.Version, &body); err != nil {
			return nil, fmt.Errorf("read decisions: %w", err)
		}
		d.Body = body
		decisions = append(decisions, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	return decisions, nil
}
