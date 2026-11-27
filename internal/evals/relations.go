package evals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// RelationCase is one synthetic pending proposal and the decisions in force of its tenant, each with the
// relation a person would name for it: duplicates, supersedes, conflicts, or none (ADR-0172).
type RelationCase struct {
	ID        string             `json:"id"`
	Title     string             `json:"title"`
	Statement string             `json:"statement"`
	Decisions []RelationDecision `json:"decisions"`
}

// RelationDecision is one decision in force of a case. Key names it within the case, and its id is derived
// from the case and the key, so a recording replays.
type RelationDecision struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Statement string `json:"statement"`
	Relation  string `json:"relation"`
}

// relationWords is every relation a case may expect.
var relationWords = []string{string(proposals.RelationDuplicates), string(proposals.RelationSupersedes), string(proposals.RelationConflicts), "none"}

// relationDecisionID is the id of a decision of a case.
func relationDecisionID(caseID, key string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("ipso-evals:"+caseID+"/"+key))
}

// LoadRelationCases reads a relation dataset. Every case has a title and two to six decisions, each with a
// key, a title, and one of the four relations.
func LoadRelationCases(path string) ([]RelationCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []RelationCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	for _, c := range cases {
		if c.ID == "" || c.Title == "" || len(c.Decisions) < 2 || len(c.Decisions) > 6 {
			return nil, fmt.Errorf("%s: case %q needs an id, a title, and two to six decisions", path, c.ID)
		}
		keys := map[string]bool{}
		for _, d := range c.Decisions {
			if d.Key == "" || keys[d.Key] || d.Title == "" || !slices.Contains(relationWords, d.Relation) {
				return nil, fmt.Errorf("%s: case %s has a decision with no key, a repeated key, no title, or an unknown relation", path, c.ID)
			}
			keys[d.Key] = true
		}
	}
	return cases, nil
}

// inForce returns the decisions of a case as the pipeline reads them, and the relation each expects by id.
func (c RelationCase) inForce() ([]proposals.DecisionInForce, map[uuid.UUID]string) {
	decisions := make([]proposals.DecisionInForce, 0, len(c.Decisions))
	want := make(map[uuid.UUID]string, len(c.Decisions))
	for _, d := range c.Decisions {
		id := relationDecisionID(c.ID, d.Key)
		decisions = append(decisions, proposals.DecisionInForce{ID: id, Version: 1, Title: d.Title, Statement: d.Statement})
		want[id] = d.Relation
	}
	return decisions, want
}

// RelationSuite scores the relation annotation of ADR-0172 with the ranking it runs on: each case is ranked
// with RelationCandidates and the candidates go to Relate. The precision of a relation is the share of hints
// with that relation that the case expects; IPSO-159 holds supersedes and conflicts at 0.8 or more. valid is
// the share of calls answered with one known word for each decision sent; IPSO-159 holds it at 0.9 or more.
// recall is the share of the decisions a case relates, that the ranking sent and the model named right, of
// every decision a case relates. A hint that names a decision outside the candidates stops the run, because
// the server could never store it. Each case logs its outcome on t.
func RelationSuite(t *testing.T, ctx context.Context, complete SchemaCompleteFunc, cases []RelationCase) (Metrics, error) {
	var calls, valid, related, found int
	hints := map[string]int{}
	right := map[string]int{}
	for i, c := range cases {
		decisions, want := c.inForce()
		for _, relation := range want {
			if relation != "none" {
				related++
			}
		}
		candidates := proposals.RelationCandidates(c.Title, c.Statement, decisions)
		if len(candidates) == 0 {
			t.Logf("relations %d/%d %s sent=0", i+1, len(cases), c.ID)
			continue
		}
		calls++
		annotation, err := proposals.Relate(ctx, proposals.SchemaCompleteFunc(complete), c.Title, c.Statement, candidates)
		switch {
		case err == nil:
			valid++
		case errors.Is(err, proposals.ErrRelationAnswer):
			t.Logf("relations %d/%d %s sent=%d malformed", i+1, len(cases), c.ID, len(candidates))
			continue
		default:
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		got := map[uuid.UUID]string{}
		for _, hint := range annotation.Hints {
			if !slices.ContainsFunc(candidates, func(d proposals.DecisionInForce) bool { return d.ID == hint.DecisionID && d.Version == hint.Version }) {
				return nil, fmt.Errorf("case %s: a hint names %s, which was not sent", c.ID, hint.DecisionID)
			}
			got[hint.DecisionID] = string(hint.Relation)
			hints[string(hint.Relation)]++
			if want[hint.DecisionID] == string(hint.Relation) {
				right[string(hint.Relation)]++
				found++
			}
		}
		var outcome []string
		for _, d := range c.Decisions {
			id := relationDecisionID(c.ID, d.Key)
			answer, ok := got[id]
			switch {
			case !slices.ContainsFunc(candidates, func(candidate proposals.DecisionInForce) bool { return candidate.ID == id }):
				answer = "unsent"
			case !ok:
				answer = "none"
			}
			outcome = append(outcome, fmt.Sprintf("%s:%s/%s", d.Key, d.Relation, answer))
		}
		t.Logf("relations %d/%d %s sent=%d %v", i+1, len(cases), c.ID, len(candidates), outcome)
	}
	return Metrics{
		"relations.supersedes.precision": Count(right[string(proposals.RelationSupersedes)], hints[string(proposals.RelationSupersedes)]),
		"relations.conflicts.precision":  Count(right[string(proposals.RelationConflicts)], hints[string(proposals.RelationConflicts)]),
		"relations.duplicates.precision": Count(right[string(proposals.RelationDuplicates)], hints[string(proposals.RelationDuplicates)]),
		"relations.valid":                Count(valid, calls),
		"relations.recall":               Count(found, related),
	}, nil
}
