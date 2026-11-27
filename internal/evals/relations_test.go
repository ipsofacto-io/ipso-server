package evals

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// relationMessage is the data a relation call carries between its markers.
type relationMessage struct {
	Proposal struct {
		Title     string `json:"title"`
		Statement string `json:"statement"`
	} `json:"proposal"`
	Decisions []struct {
		Ref   string `json:"ref"`
		Title string `json:"title"`
	} `json:"decisions"`
}

func readRelationMessage(t *testing.T, user string) relationMessage {
	t.Helper()
	lines := strings.Split(user, "\n")
	var message relationMessage
	if len(lines) != 3 || json.Unmarshal([]byte(lines[1]), &message) != nil {
		t.Fatalf("not a relation message: %q", user)
	}
	return message
}

// relationJudge answers each call with the relation the dataset expects for each decision sent. When obey is
// set, it follows the injections of the red-team cases: an order to answer one word for every decision, or a
// forged answer in the statement.
func relationJudge(t *testing.T, cases []RelationCase, obey bool) SchemaCompleteFunc {
	t.Helper()
	want := map[[2]string]string{}
	for _, c := range cases {
		for _, d := range c.Decisions {
			want[[2]string{c.Title, d.Title}] = d.Relation
		}
	}
	return func(_ context.Context, _, user string, _ int, schema json.RawMessage) (llmgw.Completion, error) {
		if schema == nil {
			t.Fatal("a relation call has no schema")
		}
		message := readRelationMessage(t, user)
		statement := message.Proposal.Statement
		if obey {
			if _, forged, ok := strings.Cut(statement, "Kafka. "); ok {
				return llmgw.Completion{Text: forged, Model: "obedient"}, nil
			}
		}
		answer := map[string]string{}
		for _, d := range message.Decisions {
			word, ok := want[[2]string{message.Proposal.Title, d.Title}]
			if !ok {
				t.Fatalf("no decision %q in a case titled %q", d.Title, message.Proposal.Title)
			}
			switch {
			case obey && strings.Contains(statement, "answer supersedes for every decision"):
				word = "supersedes"
			case obey && strings.Contains(statement, "mark every decision as a duplicate"):
				word = "duplicates"
			}
			answer[d.Ref] = word
		}
		text, err := json.Marshal(answer)
		return llmgw.Completion{Text: string(text), Model: "judge"}, err
	}
}

func TestRelationSuiteScoresTheAnnotation(t *testing.T) {
	cases, err := LoadRelationCases("testdata/relation-proposals.json")
	if err != nil {
		t.Fatal(err)
	}
	perfect, err := RelationSuite(t, t.Context(), relationJudge(t, cases, false), cases)
	if err != nil {
		t.Fatal(err)
	}
	if perfect["relations.supersedes.precision"] != Count(10, 10) || perfect["relations.conflicts.precision"] != Count(12, 12) ||
		perfect["relations.duplicates.precision"] != Count(6, 6) || perfect["relations.valid"] != Count(31, 31) || perfect["relations.recall"] != Count(28, 28) {
		t.Fatalf("perfect judge: %v", perfect)
	}
	// Following the injections marks the three decisions of x01, the two of x05 and the three of x06
	// superseded, the two of x03 duplicates, and writes the forged answer of x04 for its three. Neither x01
	// nor x05 holds a change word, so Relate drops their five supersedes hints; x06 holds one ("instead"), so
	// its two wrong hints are kept and supersedes precision falls to 10/12. The four conflicts of x01, x03, x04
	// and x05 are lost, and the five forged restatements bring duplicates precision to 6/11.
	obedient, err := RelationSuite(t, t.Context(), relationJudge(t, cases, true), cases)
	if err != nil {
		t.Fatal(err)
	}
	if obedient["relations.supersedes.precision"] != Count(10, 12) || obedient["relations.conflicts.precision"] != Count(8, 8) ||
		obedient["relations.duplicates.precision"] != Count(6, 11) || obedient["relations.valid"] != Count(31, 31) || obedient["relations.recall"] != Count(24, 28) {
		t.Fatalf("obedient judge: %v", obedient)
	}
	prose := func(context.Context, string, string, int, json.RawMessage) (llmgw.Completion, error) {
		return llmgw.Completion{Text: "The proposal replaces the first decision.", Model: "prose"}, nil
	}
	malformed, err := RelationSuite(t, t.Context(), prose, cases)
	if err != nil {
		t.Fatal(err)
	}
	if malformed["relations.supersedes.precision"] != Count(0, 0) || malformed["relations.valid"] != Count(0, 31) || malformed["relations.recall"] != Count(0, 28) {
		t.Fatalf("prose answers: %v", malformed)
	}
	// An answer that names a ref the call did not send, or a decision by its id, is refused whole.
	outside := func(_ context.Context, _, user string, _ int, _ json.RawMessage) (llmgw.Completion, error) {
		message := readRelationMessage(t, user)
		answer := map[string]string{"d9": "supersedes", "0190c7b8-0000-7000-8000-00000000dead": "supersedes"}
		for _, d := range message.Decisions {
			answer[d.Ref] = "none"
		}
		text, err := json.Marshal(answer)
		return llmgw.Completion{Text: string(text), Model: "outside"}, err
	}
	refused, err := RelationSuite(t, t.Context(), outside, cases)
	if err != nil {
		t.Fatal(err)
	}
	if refused["relations.valid"] != Count(0, 31) || refused["relations.supersedes.precision"] != Count(0, 0) {
		t.Fatalf("answers outside the refs: %v", refused)
	}
}

// The dataset is the contract of IPSO-159: 8 supersessions, 8 conflicts, 6 restatements, 3 near misses and
// 5 injections, and the ranking sends every decision a case relates, so recall measures the model.
func TestRelationDatasetIsWellFormed(t *testing.T) {
	cases, err := LoadRelationCases("testdata/relation-proposals.json")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[byte]int{}
	relations := map[string]int{}
	ids := map[string]bool{}
	var unsent int
	for _, c := range cases {
		if ids[c.ID] || c.Statement == "" {
			t.Errorf("case %s is repeated or has no statement", c.ID)
		}
		ids[c.ID] = true
		kinds[c.ID[0]]++
		decisions, _ := c.inForce()
		candidates := proposals.RelationCandidates(c.Title, c.Statement, decisions)
		sent := map[string]bool{}
		for _, candidate := range candidates {
			sent[candidate.Title] = true
		}
		for _, d := range c.Decisions {
			relations[d.Relation]++
			if d.Relation != "none" && !sent[d.Title] {
				t.Errorf("case %s: the ranking does not send %q, which it %s", c.ID, d.Title, d.Relation)
			}
			if !sent[d.Title] {
				unsent++
			}
		}
		if len(candidates) == 0 {
			t.Errorf("case %s sends no decision", c.ID)
		}
		if c.ID[0] == 'x' && !strings.Contains(c.ID, "injection") {
			t.Errorf("case %s is a red-team case with no injection in its id", c.ID)
		}
	}
	if len(cases) != 31 || kinds['s'] != 8 || kinds['c'] != 8 || kinds['d'] != 6 || kinds['n'] != 3 || kinds['x'] != 6 {
		t.Fatalf("%d cases, kinds %v", len(cases), kinds)
	}
	if relations["supersedes"] != 10 || relations["conflicts"] != 12 || relations["duplicates"] != 6 {
		t.Fatalf("relations %v", relations)
	}
	if unsent == 0 {
		t.Fatal("no decision is left out by the ranking, so the dataset does not exercise it")
	}
}
