package proposals

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// ulidExpr is the id an EDR file holds, which a decision body carries as its id (ADR-0109).
var ulidExpr = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// AcceptedCheck is one drafted check that a person approved, for a decision in force for a repository
// (ADR-0120, ADR-0160, ADR-0165). A template check carries Ref, ipso:<id>, and no Rego; a Semgrep template has
// no Target. Rego/LLMSpec/Ref and the digests are nil when the check was approved for a version of its
// decision that is not the version in force.
type AcceptedCheck struct {
	ID              uuid.UUID       `json:"id"`
	DecisionID      uuid.UUID       `json:"decision_id"`
	EDRID           *string         `json:"edr_id"`
	DecisionVersion int             `json:"decision_version"`
	VersionInForce  int             `json:"version_in_force"`
	Engine          string          `json:"engine"`
	Target          *string         `json:"target"`
	MaxAgeDays      *int            `json:"max_age_days,omitempty"`
	Rego            *string         `json:"rego"`
	RegoSHA256      *string         `json:"rego_sha256"`
	LLMSpec         json.RawMessage `json:"llm_spec,omitempty"`
	LLMSpecSHA256   *string         `json:"llm_spec_sha256,omitempty"`
	Ref             *string         `json:"ref,omitempty"`
}

const acceptedChecks = `
SELECT c.id, c.decision_id, c.decision_version, c.engine, c.target, c.max_age_days, c.rego, c.rego_sha256, c.ref
FROM proposals.check_proposal c
JOIN proposals.check_approval a ON a.tenant_id = c.tenant_id AND a.proposal_id = c.id
WHERE c.tenant_id = $1 AND a.outcome = 'approved'
  AND c.decision_id = ANY($2::uuid[])
  AND ($3::uuid IS NULL OR c.id < $3::uuid)
ORDER BY c.id DESC
LIMIT $4`

// AcceptedChecks lists the approved checks of the decisions in force for a repository at now (ADR-0120, ADR-0160).
func AcceptedChecks(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo string, now time.Time, page registry.Page) ([]AcceptedCheck, error) {
	if tenant == uuid.Nil || page.Limit < 1 || page.Limit > registry.MaxPage {
		return nil, fmt.Errorf("%w: a tenant and a page of 1 to %d rows are required", registry.ErrInvalidQuery, registry.MaxPage)
	}
	decisions, err := registry.Resolve(ctx, db, tenant, registry.Subject{Repo: repo}, now, now)
	if err != nil {
		return nil, err
	}
	out := []AcceptedCheck{}
	if len(decisions) == 0 {
		return out, nil
	}
	type inForce struct {
		version int
		edrID   *string
	}
	byID := make(map[uuid.UUID]inForce, len(decisions))
	ids := make([]uuid.UUID, 0, len(decisions))
	for _, decision := range decisions {
		var body struct {
			ID string `json:"id"`
		}
		current := inForce{version: decision.Version}
		if json.Unmarshal(decision.Body, &body) == nil && ulidExpr.MatchString(body.ID) {
			current.edrID = &body.ID
		}
		byID[decision.ID] = current
		ids = append(ids, decision.ID)
	}
	var before any
	if page.Before != uuid.Nil {
		before = page.Before
	}
	err = tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, acceptedChecks, tenant, ids, before, page.Limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item AcceptedCheck
			var artifact, ref sql.NullString
			var digest []byte
			var maxAge sql.NullInt32
			if err := rows.Scan(&item.ID, &item.DecisionID, &item.DecisionVersion, &item.Engine, &item.Target, &maxAge, &artifact, &digest, &ref); err != nil {
				return err
			}
			if maxAge.Valid {
				age := int(maxAge.Int32)
				item.MaxAgeDays = &age
			}
			current := byID[item.DecisionID]
			item.EDRID, item.VersionInForce = current.edrID, current.version
			if item.DecisionVersion == current.version {
				sum := hex.EncodeToString(digest)
				switch {
				case ref.Valid:
					item.Ref = &ref.String
				case item.Engine == "llm":
					item.LLMSpec = json.RawMessage(artifact.String)
					item.LLMSpecSHA256 = &sum
				default:
					item.Rego, item.RegoSHA256 = &artifact.String, &sum
				}
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
