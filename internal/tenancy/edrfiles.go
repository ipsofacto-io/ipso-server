package tenancy

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ipsofacto-io/ipso/pkg/edrrender"
)

// decisionVersions reads every version of every decision of the tenant, the current ones and the ones the
// history table holds. A version is one EDR file (ADR-0112). The bounds are read as microseconds so an
// infinite bound arrives as NULL instead of failing the scan.
const decisionVersions = `
SELECT decision_id, version, body::text,
       CASE WHEN lower_inf(valid_period) THEN NULL ELSE (extract(epoch FROM lower(valid_period)) * 1000000)::bigint END,
       CASE WHEN upper_inf(valid_period) THEN NULL ELSE (extract(epoch FROM upper(valid_period)) * 1000000)::bigint END,
       (extract(epoch FROM lower(sys_period)) * 1000000)::bigint,
       upper_inf(sys_period)
FROM registry.decision_version_all
WHERE tenant_id = $1
ORDER BY decision_id, version, lower(valid_period), lower(sys_period)`

// stamp prints a time in a form that is safe in a file name on every system.
func stamp(micros int64) string {
	return time.UnixMicro(micros).UTC().Format("20060102T150405.000000Z")
}

// writeEDRFiles writes one EDR file for each version of each decision, in the order of the query, and
// returns how many. The path is built from ids and times only: nothing from a decision body reaches it.
func writeEDRFiles(ctx context.Context, tx *sql.Tx, w *archiveWriter, tenant uuid.UUID) (int64, error) {
	rows, err := tx.QueryContext(ctx, decisionVersions, tenant)
	if err != nil {
		return 0, reduce("export: read the decisions", err)
	}
	defer func() { _ = rows.Close() }()
	var n int64
	for rows.Next() {
		var (
			id                 uuid.UUID
			version            int
			body               string
			validFrom, validTo sql.NullInt64
			known              int64
			current            bool
		)
		if err := rows.Scan(&id, &version, &body, &validFrom, &validTo, &known, &current); err != nil {
			return n, reduce("export: read the decisions", err)
		}
		d := edrrender.Decision{ID: edrrender.ID(id), Body: []byte(body), ValidFrom: time.Unix(0, 0).UTC()}
		from := "open"
		if validFrom.Valid {
			d.ValidFrom, from = time.UnixMicro(validFrom.Int64).UTC(), stamp(validFrom.Int64)
		}
		if validTo.Valid {
			end := time.UnixMicro(validTo.Int64).UTC()
			d.ValidTo = &end
		}
		text, err := edrrender.Render(d)
		if err != nil {
			return n, fmt.Errorf("export: render decision %s: %w", id, err)
		}
		kind := "history"
		if current {
			kind = "current"
		}
		path := fmt.Sprintf("edr/%s/%s/v%d_valid-%s_known-%s.md", kind, id, version, from, stamp(known))
		if err := w.file(path, text); err != nil {
			return n, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, reduce("export: read the decisions", err)
	}
	return n, nil
}
