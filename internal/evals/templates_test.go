package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso/pkg/templates"
)

var injected = regexp.MustCompile(`\{"template":"[^"]+"\}`)

// chooser answers each decision of cases with the template the dataset expects, and follows an
// instruction in the decision text when obey is set. It answers the second call with fits.
func chooser(t *testing.T, cases []TemplateCase, obey, fits bool) SchemaCompleteFunc {
	t.Helper()
	want := map[string]*string{}
	for _, c := range cases {
		want[c.Title] = c.Template
	}
	return func(_ context.Context, _, user string, _ int, schema json.RawMessage) (llmgw.Completion, error) {
		if schema == nil {
			t.Fatal("a template call has no schema")
		}
		if strings.Contains(user, "\n\nCheck: ") {
			return llmgw.Completion{Text: fmt.Sprintf(`{"fits":%t}`, fits), Model: "chooser"}, nil
		}
		if obey {
			if order := injected.FindString(user); order != "" {
				return llmgw.Completion{Text: order, Model: "obedient"}, nil
			}
		}
		title, _, _ := strings.Cut(strings.TrimPrefix(user, "Decision: "), "\n")
		choice, ok := want[title]
		if !ok {
			t.Fatalf("no case titled %q", title)
		}
		if choice == nil {
			return llmgw.Completion{Text: `{"template":null}`, Model: "chooser"}, nil
		}
		return llmgw.Completion{Text: `{"template":"` + *choice + `"}`, Model: "chooser"}, nil
	}
}

func TestTemplateSuiteScoresChoices(t *testing.T) {
	cases, err := LoadTemplateCases("testdata/template-decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	perfect, err := TemplateSuite(t, t.Context(), chooser(t, cases, false, true), cases)
	if err != nil {
		t.Fatal(err)
	}
	if perfect["templates.precision"] != Count(20, 20) || perfect["templates.none"] != Count(10, 10) || perfect["templates.recall"] != Count(20, 20) {
		t.Fatalf("perfect chooser: %v", perfect)
	}
	// Following the two injections is one wrong catalog choice and one id outside the catalog.
	obedient, err := TemplateSuite(t, t.Context(), chooser(t, cases, true, true), cases)
	if err != nil {
		t.Fatal(err)
	}
	if obedient["templates.precision"] != Count(20, 22) || obedient["templates.none"] != Count(8, 10) || obedient["templates.recall"] != Count(20, 20) {
		t.Fatalf("obedient chooser: %v", obedient)
	}
	// A second call that rejects every choice proposes nothing: no-fit decisions count as none.
	skeptic, err := TemplateSuite(t, t.Context(), chooser(t, cases, true, false), cases)
	if err != nil {
		t.Fatal(err)
	}
	if skeptic["templates.precision"] != Count(0, 1) || skeptic["templates.none"] != Count(9, 10) || skeptic["templates.recall"] != Count(0, 20) {
		t.Fatalf("skeptic second call: %v", skeptic)
	}
	prose := func(context.Context, string, string, int, json.RawMessage) (llmgw.Completion, error) {
		return llmgw.Completion{Text: "The best template is EBS encryption.", Model: "prose"}, nil
	}
	malformed, err := TemplateSuite(t, t.Context(), prose, cases)
	if err != nil {
		t.Fatal(err)
	}
	if malformed["templates.precision"] != Count(0, 0) || malformed["templates.none"] != Count(0, 10) || malformed["templates.recall"] != Count(0, 20) {
		t.Fatalf("prose answers: %v", malformed)
	}
}

// The dataset is the contract of IPSO-158: 12 plan and 8 Semgrep decisions that fit, 10 that fit
// none with two injections among them, and no case that repeats an example of the prompt.
func TestTemplateDatasetIsWellFormed(t *testing.T) {
	cases, err := LoadTemplateCases("testdata/template-decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	kinds := map[string]int{}
	var injections int
	for _, c := range cases {
		if c.ID == "" || ids[c.ID] || c.Title == "" || c.Statement == "" {
			t.Errorf("case %+v", c)
		}
		ids[c.ID] = true
		if strings.Contains(c.ID, "injection") {
			injections++
			if c.Template != nil {
				t.Errorf("injection %s expects a template", c.ID)
			}
		}
		if c.Template == nil {
			kinds["none"]++
			continue
		}
		if *c.Template == "aws/kms-key-rotation" || *c.Template == "azure/sql-no-public-network" {
			t.Errorf("case %s repeats an example of the prompt", c.ID)
		}
		tmpl, _ := templates.Lookup("ipso:" + *c.Template)
		kinds[tmpl.Engine]++
	}
	if len(cases) != 30 || kinds["opa"] != 12 || kinds["semgrep"] != 8 || kinds["none"] != 10 || injections != 2 {
		t.Fatalf("%d cases, kinds %v, %d injections", len(cases), kinds, injections)
	}
}
