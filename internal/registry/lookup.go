package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// decisionByRef reads the versions of a decision named by id or slug, valid at V as known at T. A
// decision is returned once, at its highest version.
const decisionByRef = `
SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
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

// decisionsByEDRID reads which decisions hold each of a set of EDR ids as the id of their body, in a version the
// registry knew at T, whatever its valid period. A decision is read once however many versions it has.
const decisionsByEDRID = `
SELECT DISTINCT d.body->>'id', d.decision_id
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND d.body->>'id' = ANY($1::text[])
  AND d.sys_period @> $2::timestamptz`

// DecisionsByEDRID maps EDR ids to the registry decision whose body holds that id, as the registry knew the
// decisions at transaction time knownAt. A runner names a decision by the id of its EDR file and the registry
// by a uuid (ADR-0120). An id that no decision holds, or that more than one holds, is left out, so a caller never
// guesses between two decisions. The tenant must be the authenticated one, because DecisionsByEDRID trusts it.
func DecisionsByEDRID(ctx context.Context, db *sql.DB, tenant uuid.UUID, edrIDs []string, knownAt time.Time) (map[string]uuid.UUID, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the transaction time is required", ErrInvalidQuery)
	}
	if len(edrIDs) == 0 {
		return map[string]uuid.UUID{}, nil
	}
	held := make(map[string][]uuid.UUID, len(edrIDs))
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, decisionsByEDRID, edrIDs, knownAt)
		if err != nil {
			return fmt.Errorf("read decisions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var edrID string
			var decision uuid.UUID
			if err := rows.Scan(&edrID, &decision); err != nil {
				return fmt.Errorf("read decisions: %w", err)
			}
			held[edrID] = append(held[edrID], decision)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]uuid.UUID, len(held))
	for edrID, decisions := range held {
		if len(decisions) == 1 {
			out[edrID] = decisions[0]
		}
	}
	return out, nil
}

// DecisionVersionKey identifies one stored version of a decision.
type DecisionVersionKey struct {
	ID      uuid.UUID
	Version int
}

const decisionTitlesByVersion = `
SELECT DISTINCT ON (d.decision_id, d.version) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND (d.decision_id, d.version) IN (
    SELECT * FROM unnest($1::uuid[], $2::integer[])
  )
ORDER BY d.decision_id, d.version, upper(d.sys_period) NULLS FIRST`

// DecisionTitlesByVersion maps each requested (decision_id, version) pair to its title under row-level
// security. Missing versions, versions without a title, and sensitive decisions (sensitive: true or the
// "sensitive" tag, ADR-0072) are omitted.
func DecisionTitlesByVersion(ctx context.Context, db *sql.DB, tenant uuid.UUID, keys []DecisionVersionKey) (map[DecisionVersionKey]string, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if len(keys) == 0 {
		return map[DecisionVersionKey]string{}, nil
	}
	seen := make(map[DecisionVersionKey]struct{}, len(keys))
	ids := make([]uuid.UUID, 0, len(keys))
	versions := make([]int32, 0, len(keys))
	for _, k := range keys {
		if k.ID == uuid.Nil || k.Version < 1 {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		ids = append(ids, k.ID)
		versions = append(versions, int32(k.Version))
	}
	if len(ids) == 0 {
		return map[DecisionVersionKey]string{}, nil
	}
	out := make(map[DecisionVersionKey]string, len(ids))
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, decisionTitlesByVersion, ids, versions)
		if err != nil {
			return fmt.Errorf("read decision titles: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var version int
			var raw []byte
			if err := rows.Scan(&id, &version, &raw); err != nil {
				return fmt.Errorf("read decision titles: %w", err)
			}
			var meta struct {
				Title     string   `json:"title"`
				Sensitive bool     `json:"sensitive"`
				Tags      []string `json:"tags"`
			}
			if json.Unmarshal(raw, &meta) != nil {
				continue
			}
			if meta.Sensitive || slices.Contains(meta.Tags, "sensitive") {
				continue
			}
			if title := strings.TrimSpace(meta.Title); title != "" {
				out[DecisionVersionKey{ID: id, Version: version}] = title
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
