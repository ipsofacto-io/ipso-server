package proposals

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

var testDecision = uuid.MustParse("0190c7b8-0000-7000-8000-000000000001")

var envFixtures = []Fixture{
	{Tool: "write", Path: "service/.env", Content: "PORT=1\n", Added: "PORT=1\n", Deny: true},
	{Tool: "write", Path: "service/main.go", Content: "package main\n", Added: "package main\n"},
}

const envRule = `{"rules":[{"when":[{"field":"path","op":"suffix","value":".env"}],"message":"Do not commit .env files."}]}`

// answer is a model answer that holds these candidate rules.
func answer(candidates ...string) string {
	return `{"difference":"The edit to deny writes a .env file.","candidates":[` + strings.Join(candidates, ",") + `]}`
}

func checkRequest(fixtures []Fixture) CheckRequest {
	return CheckRequest{
		DecisionID: testDecision, Version: 1, Title: "Never commit .env files",
		Statement: "No file whose name ends in .env is written to the repository.", Fixtures: fixtures,
	}
}

// scriptedLLM answers each call with the next of its answers.
type scriptedLLM struct {
	answers []string
	users   []string
}

func (s *scriptedLLM) complete(_ context.Context, _, user string) (Completion, error) {
	s.users = append(s.users, user)
	if len(s.users) > len(s.answers) {
		return Completion{}, errors.New("no answer left")
	}
	return Completion{Text: s.answers[len(s.users)-1], Model: "test-model"}, nil
}

func TestDraftCheckProposesARuleThatPassesItsFixtures(t *testing.T) {
	llm := &scriptedLLM{answers: []string{"```json\n" + answer(envRule) + "\n```"}}
	check, stats, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Calls != 1 || stats.Repaired || check.Repaired || check.DecisionID != testDecision || check.Model != "test-model" || check.PromptVersion != checkPromptVersion {
		t.Fatalf("check %+v stats %+v", check, stats)
	}
	if !strings.Contains(llm.users[0], `"path":"service/.env"`) || !strings.Contains(llm.users[0], "Never commit .env files") {
		t.Fatalf("prompt %q", llm.users[0])
	}
	if _, err := rulecheck.Compile([]byte(check.Rego())); err != nil {
		t.Fatalf("rego %q: %v", check.Rego(), err)
	}
}

func TestDraftCheckProposesTheFirstCandidateThatPasses(t *testing.T) {
	wrong := strings.Replace(envRule, `".env"`, `".go"`, 1)
	broad := strings.Replace(envRule, `"suffix","value":".env"`, `"contains","value":"e"`, 1)
	llm := &scriptedLLM{answers: []string{answer(wrong, `{"rules":[]}`, envRule)}}
	check, stats, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
	if err != nil || stats.Calls != 1 {
		t.Fatalf("err %v stats %+v", err, stats)
	}
	if spec, _ := json.Marshal(check.Spec); string(spec) != envRule {
		t.Fatalf("spec %s", spec)
	}
	llm = &scriptedLLM{answers: []string{answer(envRule, broad)}}
	if check, _, err = DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures)); err != nil || check.Spec.Rules[0].When[0].Op != "suffix" {
		t.Fatalf("a later candidate replaced the first that passes: %+v %v", check.Spec, err)
	}
}

func TestDraftCheckRepairsOnceWithWhatFailed(t *testing.T) {
	wrong := strings.Replace(envRule, `".env"`, `".go"`, 1)
	llm := &scriptedLLM{answers: []string{answer(wrong), answer(envRule)}}
	check, stats, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Calls != 2 || !stats.Repaired || !check.Repaired {
		t.Fatalf("check %+v stats %+v", check, stats)
	}
	repair := llm.users[1]
	if !strings.Contains(repair, "candidate 1: edit 1 must be denied") || !strings.Contains(repair, "candidate 1: edit 2 must be allowed") || !strings.Contains(repair, wrong) {
		t.Fatalf("repair prompt %q", repair)
	}
}

// TestRepairNamesTheConditionsThatDecide shows the feedback for each wrong edit: for an edit to
// deny, the conditions that do not hold, and for an edit to allow, the rules that hold.
func TestRepairNamesTheConditionsThatDecide(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   RuleSpec
		want   string
		absent string
	}{
		{
			name: "edit to deny",
			spec: RuleSpec{Rules: []Rule{{Message: "m", When: []Condition{
				{Field: "path", Op: "suffix", Value: ".env"}, {Field: "content", Op: "contains", Value: "SECRET"},
			}}}},
			want:   `edit 1 must be denied, and the rule allows it: in rule 1, {"field":"content","op":"contains","value":"SECRET"} does not hold. Edit 1 is {"tool":"write","path":"service/.env","content":"PORT=1\n","added":"PORT=1\n","deny":true}`,
			absent: `"value":".env"} does not hold`,
		},
		{
			name: "pattern in plain text",
			spec: RuleSpec{Rules: []Rule{{Message: "m", When: []Condition{{Field: "path", Op: "contains", Value: `\.env`}}}}},
			want: `in rule 1, {"field":"path","op":"contains","value":"\\.env"} (contains compares plain text; for a pattern, use regex) does not hold.`,
		},
		{
			name: "edit to allow",
			spec: RuleSpec{Rules: []Rule{
				{Message: "m", When: []Condition{{Field: "path", Op: "suffix", Value: ".env"}}},
				{Message: "m", When: []Condition{{Field: "path", Op: "suffix", Value: ".env", Not: true}}},
			}},
			want: `edit 2 must be allowed, and the rule denies it: every condition of rule 2 holds for it. Edit 2 is {"tool":"write","path":"service/main.go"`,
		},
	} {
		rule, err := rulecheck.Compile([]byte(render(tc.spec)))
		if err != nil {
			t.Fatal(err)
		}
		problems := strings.Join(failingFixtures(tc.spec, rule, envFixtures), "\n")
		if !strings.Contains(problems, tc.want) || (tc.absent != "" && strings.Contains(problems, tc.absent)) {
			t.Errorf("%s: problems %q", tc.name, problems)
		}
	}
}

func TestDraftCheckGivesUpAfterOneRepair(t *testing.T) {
	for _, tc := range []struct{ name, answer, problem string }{
		{"wrong rule", answer(strings.Replace(envRule, `".env"`, `".go"`, 1)), "candidate 1: edit 1 must be denied"},
		{"prose", "Here is the rule: " + answer(envRule), "not one JSON object"},
		{"broken JSON", answer(strings.Replace(envRule, `"value":".env"`, `"value",".env"`, 1)), `invalid character ',' after object key, where the answer reads ` + `:[{"field":"path","op":"suffix","value",)`},
		{"two values", answer(envRule) + answer(envRule), "more than one JSON value"},
		{"bare rule", envRule, `unknown field "rules"`},
		{"no candidates", answer(), "one to 3 candidates"},
		{"four candidates", answer(envRule, envRule, envRule, envRule), "one to 3 candidates"},
		{"unknown field", answer(strings.Replace(envRule, `"message"`, `"allow":true,"message"`, 1)), "not one JSON object"},
		{"unknown op", answer(strings.Replace(envRule, `"suffix"`, `"endswith"`, 1)), "candidate 1: rule 1: condition 1: op must be"},
		{"unknown field name", answer(strings.Replace(envRule, `"field":"path"`, `"field":"file"`, 1)), "field must be"},
		{"bad regex", answer(strings.Replace(envRule, `"op":"suffix","value":".env"`, `"op":"regex","value":"(.env"`, 1)), "regex does not compile"},
		{"no conditions", answer(`{"rules":[{"when":[],"message":"x"}]}`), "one to 5 conditions"},
		{"no rules", answer(`{"rules":[]}`), "candidate 1: it needs one to 3 rules"},
		{"no message", answer(strings.Replace(envRule, `"Do not commit .env files."`, `""`, 1)), "message needs"},
	} {
		llm := &scriptedLLM{answers: []string{tc.answer, tc.answer}}
		_, stats, err := DraftCheck(t.Context(), llm.complete, checkRequest(envFixtures))
		if !errors.Is(err, ErrCheckFailed) || stats.Calls != 2 {
			t.Errorf("%s: err %v stats %+v", tc.name, err, stats)
			continue
		}
		if !strings.Contains(llm.users[1], tc.problem) {
			t.Errorf("%s: repair prompt does not name %q: %q", tc.name, tc.problem, llm.users[1])
		}
	}
}

func TestDraftCheckNeedsAnEditToDenyAndOneToAllow(t *testing.T) {
	for _, fixtures := range [][]Fixture{nil, envFixtures[:1], envFixtures[1:], {{Path: "a.env", Deny: true}, envFixtures[1]}} {
		llm := &scriptedLLM{answers: []string{envRule}}
		if _, _, err := DraftCheck(t.Context(), llm.complete, checkRequest(fixtures)); !errors.Is(err, ErrCheckRequest) || len(llm.users) != 0 {
			t.Errorf("fixtures %+v: err %v calls %d", fixtures, err, len(llm.users))
		}
	}
	request := checkRequest(envFixtures)
	request.DecisionID = uuid.Nil
	if _, _, err := DraftCheck(t.Context(), (&scriptedLLM{}).complete, request); !errors.Is(err, ErrCheckRequest) {
		t.Fatalf("no decision: %v", err)
	}
}

// TestRenderKeepsTheAnswerData writes a value and a message that try to close the string and add
// a rule. They stay string literals: the module compiles, the forged rule does not exist, and the
// message comes back as it was written.
func TestRenderKeepsTheAnswerData(t *testing.T) {
	forged := "\"}\ndeny contains \"forged\" if { true }\n#"
	spec := RuleSpec{Rules: []Rule{{
		When:    []Condition{{Field: "path", Op: "suffix", Value: forged}},
		Message: "line one\nline \"two\" \\ <b>",
	}}}
	rule, err := rulecheck.Compile([]byte(render(spec)))
	if err != nil {
		t.Fatalf("%q: %v", render(spec), err)
	}
	if denials, err := rule.Deny(rulecheck.Edit{Tool: "write", Path: "main.go"}); err != nil || len(denials) != 0 {
		t.Fatalf("main.go: denials %q err %v", denials, err)
	}
	denials, err := rule.Deny(rulecheck.Edit{Tool: "write", Path: "x" + forged})
	if err != nil || len(denials) != 1 || denials[0] != spec.Rules[0].Message {
		t.Fatalf("forged path: denials %q err %v", denials, err)
	}
}

type checkCase struct {
	ID        string    `json:"id"`
	Examples  []Fixture `json:"examples"`
	Holdout   []Fixture `json:"holdout"`
	Reference RuleSpec  `json:"reference"`
}

// TestGoldenReferenceRulesPassEveryFixture shows that each decision of the check golden set has a
// rule in the answer format that passes its examples and its held-out edits, so the set measures
// the model and not an impossible task.
func TestGoldenReferenceRulesPassEveryFixture(t *testing.T) {
	raw, err := os.ReadFile("../evals/testdata/check-decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []checkCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 20 {
		t.Fatalf("%d cases", len(cases))
	}
	for _, c := range cases {
		if err := c.Reference.validate(); err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if err := validFixtures(c.Examples); err != nil {
			t.Errorf("%s: examples: %v", c.ID, err)
		}
		rule, err := rulecheck.Compile([]byte(render(c.Reference)))
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if problems := failingFixtures(c.Reference, rule, append(append([]Fixture{}, c.Examples...), c.Holdout...)); len(problems) > 0 {
			t.Errorf("%s: %v", c.ID, problems)
		}
	}
}

// TestPromptsAskForJSON keeps both system prompts naming JSON: the gateway asks every chat route
// for a JSON object, and Azure OpenAI refuses that mode when no message mentions JSON (ADR-0087).
func TestPromptsAskForJSON(t *testing.T) {
	for name, prompt := range map[string]string{"pull request": systemPrompt, "check": checkPrompt} {
		if !strings.Contains(prompt, "JSON object") {
			t.Errorf("the %s prompt does not ask for a JSON object", name)
		}
	}
}
