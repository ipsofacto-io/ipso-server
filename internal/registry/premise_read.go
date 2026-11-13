package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PremiseReason is an open review reason, read with the fail that opened it (ADR-0053, ADR-0117). Open means
// no clearance row names it. Expected and Observed are what the evaluation stored, each at most 1024 bytes,
// and Observed is a value taken from a public URL, so it is untrusted. The body of the response and its digest
// are not here: the first is never stored, and the second means nothing to a person.
type PremiseReason struct {
	ID         uuid.UUID
	DecisionID uuid.UUID
	PremiseID  string
	OpenedAt   time.Time
	URL        string
	Pointer    string
	Expected   json.RawMessage
	Observed   json.RawMessage
}

// PremiseHost is the latest row of the allowlist for one host. Allowed false means the host was withdrawn.
type PremiseHost struct {
	ID      uuid.UUID
	Host    string
	Allowed bool
}

const (
	// openReasonsPage reads one page of the reasons no clearance closes, by id from the highest, whatever the
	// valid period of the decision: the clearance route is the only thing that closes a reason (ADR-0117). The
	// evaluation is read in the same statement, so the reason and the fail it names cannot disagree.
	openReasonsPage = `
SELECT r.id, r.decision_id, r.premise_id, lower(r.sys_period), e.url, e.pointer, e.expected::text, e.observed::text
FROM registry.premise_reason r
JOIN registry.premise_evaluation e
  ON e.tenant_id = r.tenant_id AND e.id = r.evaluation_id
WHERE r.tenant_id = ipso.current_tenant()
  AND NOT EXISTS (
      SELECT 1
      FROM registry.premise_clearance c
      WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id)
  AND ($1::uuid IS NULL OR r.id < $1::uuid)
ORDER BY r.id DESC
LIMIT $2`

	// hostsPage reads one page of the allowlist as the probe reads it: the latest row of each host, which is
	// the greatest start of sys_period and then the greatest id (hostAllowed). The page bound applies to the id
	// of that latest row, after it is picked, so a row a later row replaced never comes back. The allowlist is
	// append-only and edited by hand, so reading all of a tenant's rows for a page is bounded by that.
	hostsPage = `
SELECT id, host, allowed
FROM (
    SELECT DISTINCT ON (host) id, host, allowed
    FROM registry.premise_host_allow
    WHERE tenant_id = ipso.current_tenant()
    ORDER BY host, lower(sys_period) DESC, id DESC
) latest
WHERE ($1::uuid IS NULL OR id < $1::uuid)
ORDER BY id DESC
LIMIT $2`
)

// OpenPremiseReasons returns one page of the open review reasons of the tenant, by id from the highest. No
// reason is a nil slice. The tenant must be the authenticated one, because OpenPremiseReasons trusts it.
func OpenPremiseReasons(ctx context.Context, db *sql.DB, tenant uuid.UUID, page Page) ([]PremiseReason, error) {
	if err := checkList(tenant, page); err != nil {
		return nil, err
	}
	var reasons []PremiseReason
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, openReasonsPage, page.before(), page.Limit)
		if err != nil {
			return fmt.Errorf("read premise reasons: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r PremiseReason
			var expected, observed string
			if err := rows.Scan(&r.ID, &r.DecisionID, &r.PremiseID, &r.OpenedAt, &r.URL, &r.Pointer, &expected, &observed); err != nil {
				return fmt.Errorf("read premise reasons: %w", err)
			}
			// A reason names a fail, and the table stores the expected and the observed value of every fail.
			r.Expected, r.Observed = json.RawMessage(expected), json.RawMessage(observed)
			reasons = append(reasons, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return reasons, nil
}

// PremiseHosts returns one page of the allowlist of the tenant: the latest row of each host, withdrawn hosts
// included, by the id of that row from the highest. No row is a nil slice. The tenant must be the
// authenticated one, because PremiseHosts trusts it.
func PremiseHosts(ctx context.Context, db *sql.DB, tenant uuid.UUID, page Page) ([]PremiseHost, error) {
	if err := checkList(tenant, page); err != nil {
		return nil, err
	}
	var hosts []PremiseHost
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, hostsPage, page.before(), page.Limit)
		if err != nil {
			return fmt.Errorf("read the allowlist: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var h PremiseHost
			if err := rows.Scan(&h.ID, &h.Host, &h.Allowed); err != nil {
				return fmt.Errorf("read the allowlist: %w", err)
			}
			hosts = append(hosts, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return hosts, nil
}
