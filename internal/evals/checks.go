package evals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

// CheckCase is one synthetic decision with the edits a person wrote for it. Examples are what the
// pipeline shows the model and validates against. Holdout edits are never shown, and measure
// whether the drafted rule follows the decision or only its examples. Reference is a rule in the
// answer format that passes both, which a unit test of the proposals package runs.
type CheckCase struct {
	ID        string              `json:"id"`
	Title     string              `json:"title"`
	Statement string              `json:"statement"`
	Examples  []proposals.Fixture `json:"examples"`
	Holdout   []proposals.Fixture `json:"holdout"`
	Reference json.RawMessage     `json:"reference"`
}

// LoadCheckCases reads a check generation dataset.
func LoadCheckCases(path string) ([]CheckCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []CheckCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	return cases, nil
}

// CheckSuite scores check generation of ADR-0086. drafted is the share of decisions for which the
// pipeline proposes a rule, which passes every example by construction; IPSO-57 holds it at 0.9
// or more. first is the share proposed without the repair round. holdout is the share whose
// proposed rule also passes every held-out edit.
func CheckSuite(ctx context.Context, complete CompleteFunc, cases []CheckCase) (Scores, error) {
	var drafted, first, general int
	for _, c := range cases {
		check, stats, err := proposals.DraftCheck(ctx, proposals.CompleteFunc(complete), proposals.CheckRequest{
			DecisionID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("ipso-evals:"+c.ID)), Version: 1,
			Title: c.Title, Statement: c.Statement, Fixtures: c.Examples,
		})
		if errors.Is(err, proposals.ErrCheckFailed) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		drafted++
		if !stats.Repaired {
			first++
		}
		ok, err := passes(check.Rego(), c.Holdout)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		if ok {
			general++
		}
	}
	return Scores{
		"checks.drafted": Ratio(drafted, len(cases)),
		"checks.first":   Ratio(first, len(cases)),
		"checks.holdout": Ratio(general, len(cases)),
	}, nil
}

func passes(rego string, fixtures []proposals.Fixture) (bool, error) {
	rule, err := rulecheck.Compile([]byte(rego))
	if err != nil {
		return false, err
	}
	return proposals.Passes(rule, fixtures), nil
}
