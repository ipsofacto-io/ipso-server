package registry

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// decisionByRef reads the versions of a decision named by id or slug, valid at V as known at T. A
// decision is returned once, at its highest version.
const decisionByRef = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND (d.decision_id::text = $1 OR d.body->>'slug' = $1)
  AND d.valid_period @> $2::timestamptz
  AND d.sys_period @> $3::timestamptz
ORDER BY d.decision_id, d.version DESC`

// Lookup returns the decisions an id or a slug names at valid time validAt, as the registry knew
// them at transaction time knownAt, ordered by decision id. A slug can name more than one decision,
// and a caller decides what that means. The tenant must be the authenticated one, because Lookup
// trusts it.
func Lookup(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref string, validAt, knownAt time.Time) ([]Decision, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if ref == "" {
		return nil, fmt.Errorf("%w: no id or slug", ErrInvalidQuery)
	}
	if validAt.IsZero() || knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	var found []Decision
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, decisionByRef, ref, validAt, knownAt)
		if err != nil {
			return fmt.Errorf("read decisions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item Decision
			if err := rows.Scan(&item.ID, &item.Version, &item.Body); err != nil {
				return fmt.Errorf("read decisions: %w", err)
			}
			found = append(found, item)
		}
		return rows.Err()
	})
	return found, err
}
