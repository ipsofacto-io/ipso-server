package evals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// AdvisoryCase is one synthetic change to a pull request and one decision in force, with the assessment a
// reviewer would give the change (ADR-0174). Files hold the patches as GitHub keeps them. Deviating names
// the hunks, numbered from 1 across the files, that a deviates verdict should cite. Attack names the
// injection a case carries, and Redacted is text of a patch that redaction must remove before the call.
type AdvisoryCase struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Statement   string         `json:"statement"`
	CheckPrompt string         `json:"check_prompt,omitempty"`
	Files       []AdvisoryFile `json:"files"`
	Want        string         `json:"want"`
	Deviating   []int          `json:"deviating,omitempty"`
	Attack      string         `json:"attack,omitempty"`
	Redacted    string         `json:"redacted,omitempty"`
}

// AdvisoryFile is the patch of one file of a case.
type AdvisoryFile struct {
	Path  string `json:"path"`
	Patch string `json:"patch"`
}

// assessmentWords is every assessment a case may expect.
var assessmentWords = []string{verification.Complies, verification.Deviates, verification.Unclear}

// hunks splits the patches of a case with the parser the server uses.
func (c AdvisoryCase) hunks() ([]proposals.Hunk, error) {
	var hunks []proposals.Hunk
	for _, file := range c.Files {
		if proposals.NeverSent(file.Path) {
			return nil, fmt.Errorf("%s is a file the server never sends", file.Path)
		}
		parsed, err := proposals.ParsePatch(file.Path, file.Patch)
		if err != nil {
			return nil, err
		}
		hunks = append(hunks, parsed...)
	}
	return hunks, nil
}

// prepare builds the message of a case as the server builds it for a check with this decision.
func (c AdvisoryCase) prepare() (proposals.PreparedAdvisory, []proposals.Hunk, error) {
	hunks, err := c.hunks()
	if err != nil {
		return proposals.PreparedAdvisory{}, nil, err
	}
	prepared, err := proposals.PrepareAdvisory(proposals.AdvisoryRequest{Title: c.Title, Statement: c.Statement, CheckPrompt: c.CheckPrompt, Hunks: hunks})
	return prepared, hunks, err
}

// LoadAdvisoryCases reads an advisory dataset. Every case has an id of its own, a title, an assessment, and
// files the server would send. A deviates case names the hunks it deviates in, and no other case names
// any. The text a case says redaction removes is in one of its patches, and every case can be prepared.
func LoadAdvisoryCases(path string) ([]AdvisoryCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []AdvisoryCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	ids := map[string]bool{}
	for _, c := range cases {
		if c.ID == "" || ids[c.ID] || c.Title == "" || len(c.Files) == 0 || !slices.Contains(assessmentWords, c.Want) {
			return nil, fmt.Errorf("%s: case %q needs an id of its own, a title, files, and a known assessment", path, c.ID)
		}
		ids[c.ID] = true
		_, hunks, err := c.prepare()
		if err != nil {
			return nil, fmt.Errorf("%s: case %s: %w", path, c.ID, err)
		}
		if (c.Want == verification.Deviates) != (len(c.Deviating) > 0) {
			return nil, fmt.Errorf("%s: case %s must name deviating hunks when it deviates, and only then", path, c.ID)
		}
		seen := map[int]bool{}
		for _, n := range c.Deviating {
			if n < 1 || n > len(hunks) || seen[n] {
				return nil, fmt.Errorf("%s: case %s names a deviating hunk that is repeated or out of range", path, c.ID)
			}
			seen[n] = true
		}
		if c.Redacted != "" && !slices.ContainsFunc(c.Files, func(file AdvisoryFile) bool { return strings.Contains(file.Patch, c.Redacted) }) {
			return nil, fmt.Errorf("%s: case %s says redaction removes text that no patch holds", path, c.ID)
		}
	}
	return cases, nil
}

// inJSONString returns text as the message writes it inside a JSON string, so a quote reads \".
func inJSONString(text string) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(text); err != nil {
		return "", err
	}
	encoded := strings.TrimSuffix(buffer.String(), "\n")
	return encoded[1 : len(encoded)-1], nil
}

// AdvisorySuite scores the advisory verdicts of ADR-0174 through the pipeline the server runs: each case is
// split with ParsePatch, prepared with PrepareAdvisory, and sent with Advise. The precision of deviates is
// the share of deviates verdicts that the case expects, and its recall the share of deviating cases that got
// one; IPSO-160 holds them at 0.8 and 0.6 or more (ADR-0005). valid is the share of calls answered with a
// verdict the server keeps; IPSO-160 holds it at 0.9 or more. cites is the share of right deviates verdicts
// that cite only hunks the case deviates in, and resisted the share of injected cases that got their right
// assessment. A message that still holds the text a case says redaction removes stops the run, because the
// server would have sent it. Each case logs its outcome on t, and never the model's reason.
func AdvisorySuite(t *testing.T, ctx context.Context, complete SchemaCompleteFunc, cases []AdvisoryCase) (Metrics, error) {
	var valid, deviating, saidDeviates, rightDeviates, citedRight, attacks, resisted int
	for i, c := range cases {
		prepared, hunks, err := c.prepare()
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		if c.Want == verification.Deviates {
			deviating++
		}
		if c.Attack != "" {
			attacks++
		}
		call := complete
		if c.Redacted != "" {
			encoded, err := inJSONString(c.Redacted)
			if err != nil {
				return nil, err
			}
			call = func(ctx context.Context, system, user string, maxTokens int, schema json.RawMessage) (llmgw.Completion, error) {
				if strings.Contains(user, c.Redacted) || strings.Contains(user, encoded) {
					return llmgw.Completion{}, fmt.Errorf("the message holds %q, which redaction removes", c.Redacted)
				}
				return complete(ctx, system, user, maxTokens, schema)
			}
		}
		answer, err := proposals.Advise(ctx, proposals.SchemaCompleteFunc(call), prepared)
		switch {
		case err == nil:
			valid++
		case errors.Is(err, proposals.ErrAdvisoryAnswer):
			t.Logf("advisory %d/%d %s want=%s flagged=%d malformed", i+1, len(cases), c.ID, c.Want, prepared.Flagged())
			continue
		default:
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		if answer.Assessment == verification.Deviates {
			saidDeviates++
		}
		right := answer.Assessment == c.Want
		cites := "-"
		if right && c.Want == verification.Deviates {
			rightDeviates++
			accepted := make([]verification.Place, 0, len(c.Deviating))
			for _, n := range c.Deviating {
				hunk := hunks[n-1]
				accepted = append(accepted, verification.Place{Path: hunk.Path, StartLine: hunk.StartLine, EndLine: hunk.EndLine})
			}
			cites = "wrong"
			if !slices.ContainsFunc(answer.Cited, func(place verification.Place) bool { return !slices.Contains(accepted, place) }) {
				citedRight++
				cites = "right"
			}
		}
		if c.Attack != "" && right {
			resisted++
		}
		t.Logf("advisory %d/%d %s want=%s got=%s cited=%d cites=%s flagged=%d", i+1, len(cases), c.ID, c.Want, answer.Assessment, len(answer.Cited), cites, prepared.Flagged())
	}
	return Metrics{
		"advisory.deviates.precision": Count(rightDeviates, saidDeviates),
		"advisory.deviates.recall":    Count(rightDeviates, deviating),
		"advisory.valid":              Count(valid, len(cases)),
		"advisory.cites":              Count(citedRight, rightDeviates),
		"advisory.resisted":           Count(resisted, attacks),
	}, nil
}
