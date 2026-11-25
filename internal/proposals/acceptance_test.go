package proposals

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/google/uuid"
)

func TestAcceptanceRateNeedsEnoughAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		approved, rejected, pending int
		rate                        float64
		meets                       bool
		reported                    bool
	}{
		"nothing answered":          {0, 0, 4, 0, false, false},
		"nine answered":             {9, 0, 1, 0, false, false},
		"ten answered, all":         {10, 0, 0, 1, true, true},
		"seven of ten":              {7, 3, 0, 0.7, true, true},
		"six of ten":                {6, 4, 2, 0.6, false, true},
		"69 of 100":                 {69, 31, 0, 0.69, false, true},
		"70 of 100":                 {70, 30, 0, 0.7, true, true},
		"pending does not count":    {7, 3, 50, 0.7, true, true},
		"a third, rounded":          {4, 8, 0, 0.3333, false, true},
		"two thirds is under 70":    {8, 4, 0, 0.6667, false, true},
		"all rejected":              {0, 12, 0, 0, false, true},
		"just under the row cutoff": {5, 4, 0, 0, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			row := AcceptanceRow{Approved: tc.approved, Rejected: tc.rejected, Pending: tc.pending}
			row.rate()
			if (row.Rate != nil) != tc.reported || (row.MeetsTarget != nil) != tc.reported {
				t.Fatalf("rate %v, meets %v, want reported %v", row.Rate, row.MeetsTarget, tc.reported)
			}
			if !tc.reported {
				return
			}
			if *row.Rate != tc.rate || *row.MeetsTarget != tc.meets {
				t.Fatalf("rate %v meets %v, want %v and %v", *row.Rate, *row.MeetsTarget, tc.rate, tc.meets)
			}
		})
	}
}

// The report is counts by kind, prompt version and model. No key of it may name who answered (ADR-0012).
func TestAcceptanceReportNamesNoPerson(t *testing.T) {
	rate, meets := 0.7, true
	raw, err := json.Marshal(AcceptanceReport{
		Tenant:      uuid.New(),
		Target:      0.7,
		MinAnswered: AcceptanceMinAnswered,
		Rows: []AcceptanceRow{{
			Kind: KindPRDecision, PromptVersion: "pr-decision-v2", Model: "m", Approved: 7, Rejected: 3, Rate: &rate, MeetsTarget: &meets,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	person := regexp.MustCompile(`(?i)approver|reviewer|author|person|principal|actor|user|login|email|name`)
	for _, key := range regexp.MustCompile(`"([a-z_]+)":`).FindAllSubmatch(raw, -1) {
		if person.Match(key[1]) {
			t.Errorf("the report has the key %q, which names or groups by a person", key[1])
		}
	}
}
