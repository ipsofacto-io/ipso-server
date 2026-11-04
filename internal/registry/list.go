package registry

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MaxPage bounds one page of a list read.
const MaxPage = 100

// Page is one keyset page of a list read: at most Limit rows whose id is below Before, highest id
// first. A nil Before starts at the highest id. The last id of a page is the Before of the next.
type Page struct {
	Before uuid.UUID
	Limit  int
}

func (p Page) check() error {
	if p.Limit < 1 || p.Limit > MaxPage {
		return fmt.Errorf("%w: a page holds 1 to %d rows", ErrInvalidQuery, MaxPage)
	}
	return nil
}

// before is the keyset bound as a query argument: NULL when the page starts at the top.
func (p Page) before() any {
	if p.Before == uuid.Nil {
		return nil
	}
	return p.Before
}

// Scope is a node of the scope tree as it was known at a transaction time. ParentID is nil for an org.
type Scope struct {
	ID       uuid.UUID
	ParentID *uuid.UUID
	Kind     string
	Selector string
}

// Waiver is a waiver in force. Reason and approver are left out, as in Q5 (ADR-0055).
type Waiver struct {
	ID         uuid.UUID
	DecisionID uuid.UUID
	ScopeID    uuid.UUID
	TicketRef  string
	ValidFrom  time.Time
	ExpiresAt  time.Time
}

// decisionsPage reads one page of the decisions valid at V as known at T, each once at its highest
// version, by decision id from the highest.
const decisionsPage = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND d.valid_period @> $1::timestamptz
  AND d.sys_period @> $2::timestamptz
  AND ($3::uuid IS NULL OR d.decision_id < $3::uuid)
ORDER BY d.decision_id DESC, d.version DESC
LIMIT $4`

// scopesPage reads one page of the scope tree as known at T. scope_all includes a row archived by a
// later re-parent or retirement, so a past tree reads as it was.
const scopesPage = `
SELECT s.id, s.parent_id, s.kind, s.selector
FROM registry.scope_all s
WHERE s.tenant_id = ipso.current_tenant()
  AND s.sys_period @> $1::timestamptz
  AND ($2::uuid IS NULL OR s.id < $2::uuid)
ORDER BY s.id DESC
LIMIT $3`

// waiversPage reads one page of the waivers whose period covers V, as known at T. reason and
// approver are not selected.
const waiversPage = `
SELECT w.id, w.decision_id, w.scope_id, w.ticket_ref, lower(w.valid_period), upper(w.valid_period)
FROM registry.waiver w
WHERE w.tenant_id = ipso.current_tenant()
  AND w.valid_period @> $1::timestamptz
  AND w.sys_period @> $2::timestamptz
  AND ($3::uuid IS NULL OR w.id < $3::uuid)
ORDER BY w.id DESC
LIMIT $4`

// Decisions returns one page of the decisions valid at validAt as the registry knew them at knownAt,
// each at its highest version. No decision is a nil slice. The tenant must be the authenticated one,
// because Decisions trusts it.
func Decisions(ctx context.Context, db *sql.DB, tenant uuid.UUID, validAt, knownAt time.Time, page Page) ([]Decision, error) {
	if err := checkList(tenant, page, validAt, knownAt); err != nil {
		return nil, err
	}
	var decisions []Decision
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, decisionsPage, validAt, knownAt, page.before(), page.Limit)
		if err != nil {
			return fmt.Errorf("read decisions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var d Decision
			var body []byte
			if err := rows.Scan(&d.ID, &d.Version, &body); err != nil {
				return fmt.Errorf("read decisions: %w", err)
			}
			d.Body = body
			decisions = append(decisions, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return decisions, nil
}

// Scopes returns one page of the scope tree as the registry knew it at knownAt. No scope is a nil
// slice. The tenant must be the authenticated one, because Scopes trusts it.
func Scopes(ctx context.Context, db *sql.DB, tenant uuid.UUID, knownAt time.Time, page Page) ([]Scope, error) {
	if err := checkList(tenant, page, knownAt); err != nil {
		return nil, err
	}
	var scopes []Scope
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, scopesPage, knownAt, page.before(), page.Limit)
		if err != nil {
			return fmt.Errorf("read scopes: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s Scope
			var parent uuid.NullUUID
			if err := rows.Scan(&s.ID, &parent, &s.Kind, &s.Selector); err != nil {
				return fmt.Errorf("read scopes: %w", err)
			}
			if parent.Valid {
				s.ParentID = &parent.UUID
			}
			scopes = append(scopes, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

// Waivers returns one page of the waivers whose period covers validAt, as the registry knew them at
// knownAt. A waiver turns a fail into waived only while its decision is also in force, which Apply
// decides, so a waiver here may cover a decision no longer in force. No waiver is a nil slice. The
// tenant must be the authenticated one, because Waivers trusts it.
func Waivers(ctx context.Context, db *sql.DB, tenant uuid.UUID, validAt, knownAt time.Time, page Page) ([]Waiver, error) {
	if err := checkList(tenant, page, validAt, knownAt); err != nil {
		return nil, err
	}
	var waivers []Waiver
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, waiversPage, validAt, knownAt, page.before(), page.Limit)
		if err != nil {
			return fmt.Errorf("read waivers: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var w Waiver
			if err := rows.Scan(&w.ID, &w.DecisionID, &w.ScopeID, &w.TicketRef, &w.ValidFrom, &w.ExpiresAt); err != nil {
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

func checkList(tenant uuid.UUID, page Page, times ...time.Time) error {
	if tenant == uuid.Nil {
		return fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	for _, at := range times {
		if at.IsZero() {
			return fmt.Errorf("%w: the times are required", ErrInvalidQuery)
		}
	}
	return page.check()
}
