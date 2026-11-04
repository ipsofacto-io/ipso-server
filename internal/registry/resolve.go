package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// The tenant filter calls ipso.current_tenant(), the leakproof function the policies use.
// A session with no tenant matches no row. It is the filter of section 2.3 Q1.
const (
	// selectingScopes reads the nodes that may select the subject: those of its org, with the
	// literal repo or no literal repo, that were recorded by transaction time T. A domain and a
	// service select nothing themselves. They apply through the closure. scope_all includes a
	// row archived by a later re-parent or retirement.
	selectingScopes = `
SELECT id, match_repo, match_path, match_env
FROM registry.scope_all
WHERE tenant_id = ipso.current_tenant()
  AND kind IN ('org', 'repo', 'path', 'env')
  AND match_org = $1
  AND repo_key IN ('', $2)
  AND sys_period @> $3::timestamptz`

	// ancestorsOfMatched reads the closure rows of the matched nodes as known at T: each
	// node and every ancestor of it.
	ancestorsOfMatched = `
SELECT descendant_id, ancestor_id
FROM registry.scope_closure_all
WHERE tenant_id = ipso.current_tenant()
  AND descendant_id = ANY($1::uuid[])
  AND sys_period @> $2::timestamptz`

	// decisionsInForce reads the decisions that name one of the given scopes, valid at V as
	// known at T. A decision is returned once, at its highest version.
	decisionsInForce = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.scope_refs && $1::uuid[]
  AND d.valid_period @> $2::timestamptz
  AND d.sys_period @> $3::timestamptz
  AND d.tenant_id = ipso.current_tenant()
ORDER BY d.decision_id, d.version DESC`

	// decisionsInForceForScopes is decisionsInForce plus each row's scope refs as text.
	// ResolvePaths reads it once for every scope any path matched, then keeps each body once.
	decisionsInForceForScopes = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body, d.scope_refs::text
FROM registry.decision_version_all d
WHERE d.scope_refs && $1::uuid[]
  AND d.valid_period @> $2::timestamptz
  AND d.sys_period @> $3::timestamptz
  AND d.tenant_id = ipso.current_tenant()
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
		var err error
		decisions, err = decisionsFor(ctx, tx, subject, validAt, knownAt)
		return err
	})
	return decisions, err
}

// MaxResolvePaths bounds the paths of one check request. A larger change is sent in parts.
const MaxResolvePaths = 500

// Resolution names the decisions in force for one path. DecisionIDs refers to Resolved.Decisions.
type Resolution struct {
	Path        string
	DecisionIDs []uuid.UUID
}

// Resolved is the answer of one check request. Decisions holds each decision once, in decision id
// order. Resolutions holds one entry per path, in the order given (ADR-0092).
type Resolved struct {
	Decisions   []Decision
	Resolutions []Resolution
}

// decisionScopes is one decision and the scopes it names. The body is not copied when the answer
// keeps the decision.
type decisionScopes struct {
	decision Decision
	scopes   []uuid.UUID
}

// ResolvePaths answers a check request: the decisions in force for each changed path of repo in
// env, one resolution for each path, in the order given. repo, env, and every path are required,
// because an omitted field matches every scope and widens the answer (ADR-0051). Every path is read
// in one read-only REPEATABLE READ transaction, so a write while it runs cannot answer two paths
// from two different registries.
//
// Decision bodies are read once, for the union of the scopes any path matched, and each body is
// kept once. A path names those decisions by id. An org-wide decision is not stored again for
// every path (ADR-0092).
//
// The tenant must be the authenticated one, because ResolvePaths trusts it.
func ResolvePaths(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo, env string, paths []string, validAt, knownAt time.Time) (Resolved, error) {
	if tenant == uuid.Nil {
		return Resolved{}, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if validAt.IsZero() || knownAt.IsZero() {
		return Resolved{}, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	if repo == "" || env == "" {
		return Resolved{}, fmt.Errorf("%w: a check request names the repo and the env", ErrInvalidSubject)
	}
	if len(paths) == 0 || len(paths) > MaxResolvePaths {
		return Resolved{}, fmt.Errorf("%w: a check request names 1 to %d paths", ErrInvalidQuery, MaxResolvePaths)
	}
	subjects := make([]subject, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			return Resolved{}, fmt.Errorf("%w: an empty path", ErrInvalidSubject)
		}
		s, err := newSubject(Subject{Repo: repo, Path: p, Env: env})
		if err != nil {
			return Resolved{}, err
		}
		subjects = append(subjects, s)
	}

	var resolved Resolved
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		scopes := make([][]uuid.UUID, len(subjects))
		seen := make(map[uuid.UUID]struct{})
		union := make([]uuid.UUID, 0)
		for i, s := range subjects {
			matched, err := matchingScopes(ctx, tx, s, knownAt)
			if err != nil {
				return err
			}
			if len(matched) == 0 {
				continue
			}
			ancestors, err := ancestorsOf(ctx, tx, matched, knownAt)
			if err != nil {
				return err
			}
			scopes[i] = ancestors
			for _, id := range ancestors {
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				union = append(union, id)
			}
		}
		var decisions []decisionScopes
		if len(union) > 0 {
			var err error
			decisions, err = readDecisionsWithRefs(ctx, tx, union, validAt, knownAt)
			if err != nil {
				return err
			}
		}
		resolved = assignPathDecisions(paths, scopes, decisions)
		return nil
	})
	if err != nil {
		return Resolved{}, err
	}
	return resolved, nil
}

// readDecisionsWithRefs reads each decision in force for the scopes once, with the scopes it names.
func readDecisionsWithRefs(ctx context.Context, tx *sql.Tx, scopes []uuid.UUID, validAt, knownAt time.Time) ([]decisionScopes, error) {
	rows, err := tx.QueryContext(ctx, decisionsInForceForScopes, scopes, validAt, knownAt)
	if err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var decisions []decisionScopes
	for rows.Next() {
		var (
			item     decisionScopes
			body     []byte
			refsText sql.NullString
		)
		if err := rows.Scan(&item.decision.ID, &item.decision.Version, &body, &refsText); err != nil {
			return nil, fmt.Errorf("read decisions: %w", err)
		}
		if !refsText.Valid {
			return nil, fmt.Errorf("decision %s: missing scope refs", item.decision.ID)
		}
		refs, err := parseUUIDArray(refsText.String)
		if err != nil {
			return nil, fmt.Errorf("decision %s: %w", item.decision.ID, err)
		}
		item.decision.Body = body
		item.scopes = refs
		decisions = append(decisions, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read decisions: %w", err)
	}
	return decisions, nil
}

// assignPathDecisions keeps each decision once and names it by id on every path whose scopes
// overlap the decision. A decision that overlaps no path is left out. paths and scopes are
// parallel. Decision bodies are the slices from decisions, not copies.
func assignPathDecisions(paths []string, scopes [][]uuid.UUID, decisions []decisionScopes) Resolved {
	resolved := Resolved{
		Decisions:   make([]Decision, 0, len(decisions)),
		Resolutions: make([]Resolution, len(paths)),
	}
	used := make([]bool, len(decisions))
	for i := range paths {
		ids := make([]uuid.UUID, 0)
		if len(scopes[i]) > 0 {
			set := make(map[uuid.UUID]struct{}, len(scopes[i]))
			for _, id := range scopes[i] {
				set[id] = struct{}{}
			}
			for j, item := range decisions {
				if overlaps(item.scopes, set) {
					ids = append(ids, item.decision.ID)
					used[j] = true
				}
			}
		}
		resolved.Resolutions[i] = Resolution{Path: paths[i], DecisionIDs: ids}
	}
	for j, item := range decisions {
		if used[j] {
			resolved.Decisions = append(resolved.Decisions, item.decision)
		}
	}
	return resolved
}

func overlaps(refs []uuid.UUID, scopes map[uuid.UUID]struct{}) bool {
	for _, id := range refs {
		if _, ok := scopes[id]; ok {
			return true
		}
	}
	return false
}

// parseUUIDArray reads the text form PostgreSQL gives a uuid array, such as {id,id}.
func parseUUIDArray(text string) ([]uuid.UUID, error) {
	if text == "{}" {
		return []uuid.UUID{}, nil
	}
	if len(text) < 2 || text[0] != '{' || text[len(text)-1] != '}' {
		return nil, errors.New("scope refs are not a uuid array")
	}
	parts := strings.Split(text[1:len(text)-1], ",")
	refs := make([]uuid.UUID, len(parts))
	for i, part := range parts {
		id, err := uuid.Parse(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("scope refs are not a uuid array")
		}
		refs[i] = id
	}
	return refs, nil
}

// decisionsFor is the Q1 read inside a transaction that already has ipso.tenant set.
// No match is a nil slice, which the caller tells from a failure by err alone.
func decisionsFor(ctx context.Context, tx *sql.Tx, subject subject, validAt, knownAt time.Time) ([]Decision, error) {
	matched, err := matchingScopes(ctx, tx, subject, knownAt)
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		return nil, nil
	}
	scopes, err := ancestorsOf(ctx, tx, matched, knownAt)
	if err != nil {
		return nil, err
	}
	return readDecisions(ctx, tx, scopes, validAt, knownAt)
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

// ancestorsOf returns the matched nodes and every ancestor of them as known at knownAt, each
// once. It fails when a matched node has no closure row for itself at that time. It does not
// recount the ancestors: the trigger is the only writer of the closure, so a changed closure
// means a superuser or a trigger bypass, and that actor can edit decisions directly (ADR-0051).
func ancestorsOf(ctx context.Context, tx *sql.Tx, matched []uuid.UUID, knownAt time.Time) ([]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, ancestorsOfMatched, matched, knownAt)
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
