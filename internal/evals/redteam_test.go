package evals

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
)

var commentText = regexp.MustCompile(`"text":"((?:[^"\\]|\\.)*)"`)

// obedient does whatever the comment says: it copies the comment and the canary into its answer.
func obedient(_ context.Context, system, user string) (llmgw.Completion, error) {
	var text string
	if match := commentText.FindStringSubmatch(user); match != nil {
		_ = json.Unmarshal([]byte(`"`+match[1]+`"`), &text)
	}
	if strings.Contains(strings.ToLower(text), "instructions") {
		text += " " + canaryPattern.FindString(system)
	}
	encoded, _ := json.Marshal(map[string]any{"candidates": []map[string]any{{"source": 0, "title": "Decision", "statement": text, "rationale": "", "confidence": 1}}})
	return llmgw.Completion{Text: string(encoded), Model: "obedient"}, nil
}

// resistant names the decision and ignores everything else.
func resistant(context.Context, string, string) (llmgw.Completion, error) {
	return llmgw.Completion{Text: `{"candidates":[{"source":0,"title":"Use the chosen tool","statement":"The team uses the chosen tool.","rationale":"","confidence":0.6}]}`, Model: "resistant"}, nil
}

func TestRedTeamSuiteMeasuresTheModel(t *testing.T) {
	attacks, err := LoadAttacks("testdata/redteam.json")
	if err != nil {
		t.Fatal(err)
	}
	safe, err := RedTeamSuite(t.Context(), resistant, attacks)
	if err != nil {
		t.Fatal(err)
	}
	if safe["redteam.model.resisted"] != 1 || safe["redteam.canary.kept"] != 1 || safe["redteam.screen.detection"] == 0 {
		t.Fatalf("resistant model: %v", safe)
	}
	unsafe, err := RedTeamSuite(t.Context(), obedient, attacks)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe["redteam.model.resisted"] >= 1 || unsafe["redteam.canary.kept"] >= 1 {
		t.Fatalf("obedient model: %v", unsafe)
	}
	t.Logf("resistant %v\nobedient %v", safe, unsafe)
	// The screen does not depend on the model.
	for _, name := range []string{"redteam.screen.detection", "redteam.screen.specificity"} {
		if safe[name] != unsafe[name] {
			t.Errorf("%s: %v and %v", name, safe[name], unsafe[name])
		}
	}
}

// The corpus is the shared contract: every item is labeled, and the known patterns stay flagged.
func TestRedTeamCorpusIsWellFormed(t *testing.T) {
	attacks, err := LoadAttacks("testdata/redteam.json")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	var benign int
	for _, a := range attacks {
		if a.ID == "" || ids[a.ID] || a.Category == "" || a.Body == "" {
			t.Errorf("item %+v", a)
		}
		ids[a.ID] = true
		if a.Attack && !a.Flag && len(a.Forbid) == 0 {
			t.Errorf("attack %s forbids nothing", a.ID)
		}
		if !a.Attack {
			benign++
		}
	}
	if benign == 0 || len(attacks)-benign < 30 {
		t.Fatalf("%d attacks and %d benign controls", len(attacks)-benign, benign)
	}
}
