package registry

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// ErrDamagedChain is returned when the supersession walk meets a directed cycle or
// more decisions than chainNodeLimit. The insert trigger refuses a cycle, so either
// result means the rows were written around it. A partial chain would hide that.
var ErrDamagedChain = errors.New("supersession chain is damaged")

// chainNodeLimit is the most decisions one chain may name. A longer walk is treated
// as damage. Tests lower it.
var chainNodeLimit = 100

// BeliefChange is one decision whose version or body differs between two transaction times.
type BeliefChange struct {
	ID   uuid.UUID
	Then Decision
	Now  Decision
}

// BeliefDiff is Q2: the decisions in force at one valid time, as known at Then, compared
// with the same valid time as known at Now. A decision present at both times with the same
// version and the same body bytes is omitted.
type BeliefDiff struct {
	Added   []Decision
	Removed []Decision
	Changed []BeliefChange
}

// SupersessionLink is one recorded replacement of a decision by its successor.
type SupersessionLink struct {
	ID          uuid.UUID
	From        uuid.UUID
	To          uuid.UUID
	EffectiveAt time.Time
}

// VersionSpan is one decision version as known at a transaction time.
// ValidTo is nil when the valid period has no end.
type VersionSpan struct {
	DecisionID uuid.UUID
	Version    int
	ValidFrom  time.Time
	ValidTo    *time.Time
}

// Chain is Q4: the supersession links that reach a decision, and the valid periods of
// every decision on that chain, both as known at one transaction time.
type Chain struct {
	Links    []SupersessionLink
	Versions []VersionSpan
}

// WaiverExpiry is one waiver whose expiry is still ahead and falls inside the 14-day window.
// Reason and approver are not part of the audit answer (ADR-0012).
type WaiverExpiry struct {
	ID         uuid.UUID
	DecisionID uuid.UUID
	ScopeID    uuid.UUID
	TicketRef  string
	ExpiresAt  time.Time
}

// Beliefs answers Q2. then and now are the two transaction times. Added are decisions
// present only at now, removed are present only at then, and changed are present at both
// with a different version or different body bytes. Each list is ordered by decision id.
//
// The tenant must be the authenticated one, because Beliefs trusts it. Both reads run in
// one read-only REPEATABLE READ transaction, so a correction that commits while the call
// runs cannot appear on only one side. No difference is a zero diff, and a caller tells
// that from a failure by err alone.
func Beliefs(ctx context.Context, db *sql.DB, tenant uuid.UUID, in Subject, validAt, then, now time.Time) (BeliefDiff, error) {
	if tenant == uuid.Nil {
		return BeliefDiff{}, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if validAt.IsZero() || then.IsZero() || now.IsZero() {
		return BeliefDiff{}, fmt.Errorf("%w: the valid time and both transaction times are required", ErrInvalidQuery)
	}
	subject, err := newSubject(in)
	if err != nil {
		return BeliefDiff{}, err
	}

	var diff BeliefDiff
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		before, err := decisionsFor(ctx, tx, subject, validAt, then)
		if err != nil {
			return err
		}
		after, err := decisionsFor(ctx, tx, subject, validAt, now)
		if err != nil {
			return err
		}
		diff = diffDecisions(before, after)
		return nil
	})
	if err != nil {
		return BeliefDiff{}, err
	}
	return diff, nil
}

func diffDecisions(then, now []Decision) BeliefDiff {
	thenByID := make(map[uuid.UUID]Decision, len(then))
	for _, d := range then {
		thenByID[d.ID] = d
	}
	nowByID := make(map[uuid.UUID]Decision, len(now))
	for _, d := range now {
		nowByID[d.ID] = d
	}

	var diff BeliefDiff
	for id, d := range nowByID {
		old, ok := thenByID[id]
		if !ok {
			diff.Added = append(diff.Added, d)
			continue
		}
		if old.Version != d.Version || !bytes.Equal(old.Body, d.Body) {
			diff.Changed = append(diff.Changed, BeliefChange{ID: id, Then: old, Now: d})
		}
	}
	for id, d := range thenByID {
		if _, ok := nowByID[id]; !ok {
			diff.Removed = append(diff.Removed, d)
		}
	}
	slices.SortFunc(diff.Added, compareDecision)
	slices.SortFunc(diff.Removed, compareDecision)
	slices.SortFunc(diff.Changed, func(a, b BeliefChange) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return diff
}

func compareDecision(a, b Decision) int {
	return bytes.Compare(a.ID[:], b.ID[:])
}

// Links whose ends touch the decisions found so far, as known at the transaction time.
// A nil exclude list matches every row. coalesce keeps a NULL parameter from matching nothing.
const incidentSupersessions = `
SELECT id, from_decision, to_decision, effective_at
FROM registry.supersession
WHERE tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND sys_period @> $1::timestamptz
  AND (from_decision = ANY($2::uuid[]) OR to_decision = ANY($2::uuid[]))
  AND NOT (id = ANY(coalesce($3::uuid[], '{}'::uuid[])))`

const chainVersions = `
SELECT decision_id, version, lower(valid_period),
       CASE WHEN upper_inf(valid_period) THEN NULL ELSE upper(valid_period) END
FROM registry.decision_version_all
WHERE tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND decision_id = ANY($1::uuid[])
  AND sys_period @> $2::timestamptz
ORDER BY decision_id, version`

// SupersessionChain answers Q4. The links are the supersession rows, as known at knownAt,
// on the undirected chain that reaches decision, ordered by effective time and then id.
// Versions are the decision rows of every decision on that chain, including decision itself
// when this tenant has one. An unknown id and another tenant's id are an empty chain.
//
// The tenant must be the authenticated one, because SupersessionChain trusts it. A directed
// cycle or a chain of more than chainNodeLimit decisions fails with ErrDamagedChain.
func SupersessionChain(ctx context.Context, db *sql.DB, tenant, decision uuid.UUID, knownAt time.Time) (Chain, error) {
	if tenant == uuid.Nil {
		return Chain{}, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if decision == uuid.Nil {
		return Chain{}, fmt.Errorf("%w: no decision", ErrInvalidQuery)
	}
	if knownAt.IsZero() {
		return Chain{}, fmt.Errorf("%w: the transaction time is required", ErrInvalidQuery)
	}

	var chain Chain
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		links, nodes, err := walkChain(ctx, tx, decision, knownAt)
		if err != nil {
			return err
		}
		versions, err := readVersionSpans(ctx, tx, nodes, knownAt)
		if err != nil {
			return err
		}
		chain = Chain{Links: links, Versions: versions}
		return nil
	})
	if err != nil {
		return Chain{}, err
	}
	return chain, nil
}

func walkChain(ctx context.Context, tx *sql.Tx, seed uuid.UUID, knownAt time.Time) ([]SupersessionLink, []uuid.UUID, error) {
	nodes := []uuid.UUID{seed}
	nodeSet := map[uuid.UUID]bool{seed: true}
	var (
		links []SupersessionLink
		seen  []uuid.UUID
	)
	for {
		rows, err := tx.QueryContext(ctx, incidentSupersessions, knownAt, nodes, seenIDs(seen))
		if err != nil {
			return nil, nil, fmt.Errorf("read supersession: %w", err)
		}
		found, err := collectLinks(rows, &links, &seen, nodeSet, &nodes)
		if err != nil {
			return nil, nil, err
		}
		if found == 0 {
			break
		}
	}
	if directedCycle(links) {
		return nil, nil, fmt.Errorf("%w", ErrDamagedChain)
	}
	slices.SortFunc(links, func(a, b SupersessionLink) int {
		if c := a.EffectiveAt.Compare(b.EffectiveAt); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return links, nodes, nil
}

// seenIDs returns nil for an empty list so the query coalesces it to an empty array.
// A nil Go slice is what the driver sends as NULL, and ANY(NULL) would match no row.
func seenIDs(seen []uuid.UUID) any {
	if len(seen) == 0 {
		return nil
	}
	return seen
}

func collectLinks(rows *sql.Rows, links *[]SupersessionLink, seen *[]uuid.UUID, nodeSet map[uuid.UUID]bool, nodes *[]uuid.UUID) (found int, err error) {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var link SupersessionLink
		if err := rows.Scan(&link.ID, &link.From, &link.To, &link.EffectiveAt); err != nil {
			return 0, fmt.Errorf("read supersession: %w", err)
		}
		*links = append(*links, link)
		*seen = append(*seen, link.ID)
		found++
		addNode(nodeSet, nodes, link.From)
		addNode(nodeSet, nodes, link.To)
		if len(nodeSet) > chainNodeLimit || len(*seen) > chainNodeLimit {
			return 0, fmt.Errorf("%w", ErrDamagedChain)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read supersession: %w", err)
	}
	return found, nil
}

func addNode(nodeSet map[uuid.UUID]bool, nodes *[]uuid.UUID, id uuid.UUID) {
	if nodeSet[id] {
		return
	}
	nodeSet[id] = true
	*nodes = append(*nodes, id)
}

func directedCycle(links []SupersessionLink) bool {
	adj := make(map[uuid.UUID][]uuid.UUID, len(links))
	for _, link := range links {
		adj[link.From] = append(adj[link.From], link.To)
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[uuid.UUID]int, len(adj))
	var visit func(uuid.UUID) bool
	visit = func(n uuid.UUID) bool {
		color[n] = gray
		for _, next := range adj[n] {
			switch color[next] {
			case gray:
				return true
			case white:
				if visit(next) {
					return true
				}
			}
		}
		color[n] = black
		return false
	}
	for n := range adj {
		if color[n] == white && visit(n) {
			return true
		}
	}
	return false
}

func readVersionSpans(ctx context.Context, tx *sql.Tx, nodes []uuid.UUID, knownAt time.Time) ([]VersionSpan, error) {
	rows, err := tx.QueryContext(ctx, chainVersions, nodes, knownAt)
	if err != nil {
		return nil, fmt.Errorf("read decision versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var versions []VersionSpan
	for rows.Next() {
		var (
			span VersionSpan
			from sql.NullTime
			to   sql.NullTime
		)
		if err := rows.Scan(&span.DecisionID, &span.Version, &from, &to); err != nil {
			return nil, fmt.Errorf("read decision versions: %w", err)
		}
		if !from.Valid {
			return nil, fmt.Errorf("decision %s: valid period has no start", span.DecisionID)
		}
		span.ValidFrom = from.Time
		if to.Valid {
			span.ValidTo = &to.Time
		}
		versions = append(versions, span)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read decision versions: %w", err)
	}
	return versions, nil
}

// Waivers whose expiry is still ahead and falls within 14 days, as known at the transaction
// time. This is the Q5 query in section 2.3. reason and approver are not selected.
const expiringWaivers = `
SELECT w.id, w.decision_id, w.scope_id, w.ticket_ref, upper(w.valid_period)
FROM registry.waiver w
WHERE w.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND w.sys_period @> $1::timestamptz
  AND upper(w.valid_period) > $2::timestamptz
  AND upper(w.valid_period) <= $2::timestamptz + interval '14 days'
ORDER BY upper(w.valid_period), w.id`

// ExpiringWaivers answers Q5. now is the clock the window is measured from, so a caller can
// ask about a past window and a test does not depend on the wall clock. A waiver whose expiry
// is at or before now, or more than 14 days after now, is absent. No waiver is a nil slice.
//
// The tenant must be the authenticated one, because ExpiringWaivers trusts it.
func ExpiringWaivers(ctx context.Context, db *sql.DB, tenant uuid.UUID, knownAt, now time.Time) ([]WaiverExpiry, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if knownAt.IsZero() || now.IsZero() {
		return nil, fmt.Errorf("%w: the transaction time and the window clock are required", ErrInvalidQuery)
	}

	var waivers []WaiverExpiry
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, expiringWaivers, knownAt, now)
		if err != nil {
			return fmt.Errorf("read waivers: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var w WaiverExpiry
			if err := rows.Scan(&w.ID, &w.DecisionID, &w.ScopeID, &w.TicketRef, &w.ExpiresAt); err != nil {
				return fmt.Errorf("read waivers: %w", err)
			}
			waivers = append(waivers, w)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return waivers, nil
}
