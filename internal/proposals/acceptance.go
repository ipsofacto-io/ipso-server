package proposals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
)

// The acceptance rate is the share of the proposals a model wrote that a person approved, the measure
// of section 1.6 of the spec (ADR-0165). It is read for one tenant under row-level security, grouped by
// kind, prompt version and model, and never by person: no query here selects who answered, and the
// report has no field that could name them (ADR-0012, ADR-0152).

const (
	// AcceptanceTargetPercent is the share of answered proposals that section 1.6 asks reviewers to approve.
	AcceptanceTargetPercent = 70
	// AcceptanceMinAnswered is how many answered proposals a row needs before it reports a rate. A smaller
	// row is too few answers to mean anything as a share. The counts of such a row are still printed, so the
	// threshold is about what a rate means and is not a privacy control: ADR-0012 is kept by what the report
	// never selects or groups by, and not by hiding small rows.
	AcceptanceMinAnswered = 10
	// HumanAuthoredModel is the model id of a check that a person wrote. It is approved when it is stored,
	// so it says nothing about a model.
	HumanAuthoredModel = "human-authored"
)

// The kinds of proposal a model writes.
const (
	KindPRDecision      = "pr_decision"
	KindTrackerDecision = "tracker_decision"
	KindCheck           = "check"
)

// AcceptanceRow counts the answers to the proposals of one kind, prompt version and model. Rate and
// MeetsTarget are nil until AcceptanceMinAnswered proposals are answered.
type AcceptanceRow struct {
	Kind          string   `json:"kind"`
	PromptVersion string   `json:"prompt_version"`
	Model         string   `json:"model"`
	Approved      int      `json:"approved"`
	Rejected      int      `json:"rejected"`
	Pending       int      `json:"pending"`
	Rate          *float64 `json:"acceptance_rate"`
	MeetsTarget   *bool    `json:"meets_target"`
}

// AcceptanceReport is the acceptance rate of one tenant. It holds counts and no row of any proposal.
type AcceptanceReport struct {
	Tenant      uuid.UUID       `json:"tenant"`
	Target      float64         `json:"target"`
	MinAnswered int             `json:"min_answered"`
	Rows        []AcceptanceRow `json:"rows"`
}

// acceptanceQuery lists each proposal a model wrote with the outcome of its one answer, null while it is
// pending, and counts them. A drafted check is counted only when a model drafted it.
const acceptanceQuery = `
WITH answered AS (
	SELECT 'pr_decision' AS kind, p.prompt_version, p.model_id, a.outcome
	FROM proposals.proposal p
	LEFT JOIN proposals.approval a ON a.tenant_id = p.tenant_id AND a.proposal_id = p.id
	WHERE p.tenant_id = $1
	UNION ALL
	SELECT 'tracker_decision', p.prompt_version, p.model_id, a.outcome
	FROM proposals.tracker_proposal p
	LEFT JOIN proposals.tracker_approval a ON a.tenant_id = p.tenant_id AND a.proposal_id = p.id
	WHERE p.tenant_id = $1
	UNION ALL
	SELECT 'check', c.prompt_version, c.model_id, a.outcome
	FROM proposals.check_proposal c
	LEFT JOIN proposals.check_approval a ON a.tenant_id = c.tenant_id AND a.proposal_id = c.id
	WHERE c.tenant_id = $1 AND c.model_id <> $2
)
SELECT kind, prompt_version, model_id,
	count(*) FILTER (WHERE outcome = 'approved'),
	count(*) FILTER (WHERE outcome = 'rejected'),
	count(*) FILTER (WHERE outcome IS NULL)
FROM answered
GROUP BY kind, prompt_version, model_id
ORDER BY kind, prompt_version, model_id`

// Acceptance reads the acceptance rate of a tenant in one read-only snapshot.
func Acceptance(ctx context.Context, db *sql.DB, tenant uuid.UUID) (AcceptanceReport, error) {
	if tenant == uuid.Nil {
		return AcceptanceReport{}, errors.New("no tenant")
	}
	report := AcceptanceReport{
		Tenant:      tenant,
		Target:      float64(AcceptanceTargetPercent) / 100,
		MinAnswered: AcceptanceMinAnswered,
		Rows:        []AcceptanceRow{},
	}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, acceptanceQuery, tenant, HumanAuthoredModel)
		if err != nil {
			return fmt.Errorf("read the acceptance rate: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var row AcceptanceRow
			if err := rows.Scan(&row.Kind, &row.PromptVersion, &row.Model, &row.Approved, &row.Rejected, &row.Pending); err != nil {
				return err
			}
			row.rate()
			report.Rows = append(report.Rows, row)
		}
		return rows.Err()
	})
	if err != nil {
		return AcceptanceReport{}, err
	}
	return report, nil
}

// rate sets the share approved of the proposals answered, and whether it reaches the target. The
// comparison is on counts, so 7 of 10 meets 70% without a rounding step in between.
func (r *AcceptanceRow) rate() {
	answered := r.Approved + r.Rejected
	if answered < AcceptanceMinAnswered {
		return
	}
	rate := math.Round(float64(r.Approved)/float64(answered)*10000) / 10000
	meets := r.Approved*100 >= AcceptanceTargetPercent*answered
	r.Rate, r.MeetsTarget = &rate, &meets
}
