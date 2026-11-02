package proposals

import (
	"bytes"
	"context"
	_ "embed" // the prompt template is versioned in this repository
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

// Check generation drafts an agent-edit check for a decision in force (ADR-0086). The model answers
// with a rule as data, the server writes the Rego from it, and the rule reaches review only when
// it compiles as `ipso compile` compiles it and passes every fixture a person wrote.
const (
	checkPromptVersion = "check-rule-v1"
	maxFixtures        = 50
	maxFixtureRunes    = 8 << 10
	maxFixturesBytes   = 1 << 20
	maxPathRunes       = 1024
	maxToolRunes       = 50
	maxDecisionRunes   = 4000
	maxShownRunes      = 1000
	maxRules           = 3
	maxConditions      = 5
	maxValueRunes      = 200
	maxMessageRunes    = 200
	maxProblems        = 10
)

//go:embed prompts/check-rule-v1.txt
var checkPrompt string

// ErrCheckFailed means no drafted rule passed every fixture, after one repair. Nothing is proposed.
var ErrCheckFailed = errors.New("no drafted rule passes every fixture")

// ErrCheckRequest means the request cannot be drafted: it names no decision, its text is too long,
// or its fixtures do not hold at least one edit to deny and one to allow, at most 50 in all.
var ErrCheckRequest = errors.New("invalid check request")

// Fixture is one edit a person wrote for a decision, in the agent-edit input of ipso hooks, and
// whether a check of the decision must deny it.
type Fixture struct {
	Tool    string `json:"tool"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
	Added   string `json:"added,omitempty"`
	Command string `json:"command,omitempty"`
	Deny    bool   `json:"deny"`
}

func (f Fixture) edit() rulecheck.Edit {
	return rulecheck.Edit{Tool: f.Tool, Path: f.Path, Content: f.Content, Added: f.Added, Command: f.Command}
}

// CheckRequest is a decision in force and the fixtures a person wrote for it.
type CheckRequest struct {
	DecisionID uuid.UUID
	Version    int
	Title      string
	Statement  string
	Fixtures   []Fixture
}

// RuleSpec is the model's answer: rules that each deny an edit meeting all of their conditions.
type RuleSpec struct {
	Rules []Rule `json:"rules"`
}

// Rule denies an edit when every condition holds, with its message.
type Rule struct {
	When    []Condition `json:"when"`
	Message string      `json:"message"`
}

// Condition tests one field of the edit. Not inverts it.
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
	Not   bool   `json:"not,omitempty"`
}

// Check is a drafted rule that passed every fixture of its request. It has no status, because the
// only status a check proposal can have is pending.
type Check struct {
	DecisionID    uuid.UUID
	Version       int
	Spec          RuleSpec
	Fixtures      []Fixture
	Repaired      bool
	Model         string
	PromptVersion string
}

// Rego is the module the server writes from the rule, the one a reviewer reads and accepts.
func (c Check) Rego() string {
	return render(c.Spec)
}

// CheckStats says what drafting did: how many calls it made and whether it needed the repair.
type CheckStats struct {
	Calls    int
	Repaired bool
}

var editFields = map[string]bool{"tool": true, "path": true, "content": true, "added": true, "command": true}

// DraftCheck asks the model for a rule, writes and compiles its Rego, and runs every fixture. When
// the answer fails, it asks once more with what failed. A rule that still fails is ErrCheckFailed.
func DraftCheck(ctx context.Context, complete CompleteFunc, req CheckRequest) (Check, CheckStats, error) {
	if err := req.validate(); err != nil {
		return Check{}, CheckStats{}, err
	}
	user, err := checkUser(req)
	if err != nil {
		return Check{}, CheckStats{}, err
	}
	var stats CheckStats
	prompt := user
	for {
		answer, err := complete(ctx, checkPrompt, prompt)
		stats.Calls++
		if err != nil {
			return Check{}, stats, err
		}
		spec, problems := draft(answer.Text, req.Fixtures)
		if len(problems) == 0 {
			return Check{
				DecisionID: req.DecisionID, Version: req.Version, Spec: spec, Fixtures: req.Fixtures,
				Repaired: stats.Repaired, Model: answer.Model, PromptVersion: checkPromptVersion,
			}, stats, nil
		}
		if stats.Repaired {
			return Check{}, stats, ErrCheckFailed
		}
		stats.Repaired = true
		prompt = repairPrompt(user, answer.Text, problems)
	}
}

func (req CheckRequest) validate() error {
	if req.DecisionID == uuid.Nil || req.Version < 1 || strings.TrimSpace(req.Title) == "" {
		return fmt.Errorf("%w: it names no decision", ErrCheckRequest)
	}
	if utf8.RuneCountInString(req.Title)+utf8.RuneCountInString(req.Statement) > maxDecisionRunes {
		return fmt.Errorf("%w: the decision text is too long", ErrCheckRequest)
	}
	return validFixtures(req.Fixtures)
}

func validFixtures(fixtures []Fixture) error {
	if len(fixtures) > maxFixtures {
		return fmt.Errorf("%w: more than %d fixtures", ErrCheckRequest, maxFixtures)
	}
	denied, allowed := false, false
	for i, f := range fixtures {
		if f.Tool == "" || utf8.RuneCountInString(f.Tool) > maxToolRunes || utf8.RuneCountInString(f.Path) > maxPathRunes ||
			utf8.RuneCountInString(f.Content) > maxFixtureRunes || utf8.RuneCountInString(f.Added) > maxFixtureRunes ||
			utf8.RuneCountInString(f.Command) > maxFixtureRunes {
			return fmt.Errorf("%w: fixture %d has no tool or a field that is too long", ErrCheckRequest, i)
		}
		denied = denied || f.Deny
		allowed = allowed || !f.Deny
	}
	if !denied || !allowed {
		return fmt.Errorf("%w: the fixtures need an edit to deny and an edit to allow", ErrCheckRequest)
	}
	if encoded, err := json.Marshal(fixtures); err != nil || len(encoded) > maxFixturesBytes {
		return fmt.Errorf("%w: the fixtures are larger than %d bytes", ErrCheckRequest, maxFixturesBytes)
	}
	return nil
}

// checkUser shows the decision and its fixtures, with each field cut to maxShownRunes.
func checkUser(req CheckRequest) (string, error) {
	shown := make([]Fixture, len(req.Fixtures))
	for i, f := range req.Fixtures {
		shown[i] = Fixture{Tool: cut(f.Tool), Path: cut(f.Path), Content: cut(f.Content), Added: cut(f.Added), Command: cut(f.Command), Deny: f.Deny}
	}
	fixtures, err := json.Marshal(shown)
	if err != nil {
		return "", err
	}
	return "Decision: " + req.Title + "\n" + req.Statement + "\n\nEdits a person wrote for this decision, and whether the check must deny each one:\n" + string(fixtures), nil
}

func cut(text string) string {
	if utf8.RuneCountInString(text) <= maxShownRunes {
		return text
	}
	return string([]rune(text)[:maxShownRunes])
}

func repairPrompt(user, previous string, problems []string) string {
	if len(problems) > maxProblems {
		problems = append(problems[:maxProblems], fmt.Sprintf("and %d more", len(problems)-maxProblems))
	}
	return user + "\n\nYour previous answer:\n" + cut(previous) + "\n\nIt fails:\n- " + strings.Join(problems, "\n- ") +
		"\n\nAnswer again with one corrected JSON object."
}

// draft parses an answer, writes and compiles its Rego, and runs every fixture. It returns what
// failed, in words the model can act on, and none when the rule passes.
func draft(text string, fixtures []Fixture) (RuleSpec, []string) {
	spec, err := parseSpec(text)
	if err != nil {
		return RuleSpec{}, []string{err.Error()}
	}
	rule, err := rulecheck.Compile([]byte(render(spec)))
	if err != nil {
		return RuleSpec{}, []string{"the rule does not compile: " + rulecheck.Code(err)}
	}
	return spec, failingFixtures(rule, fixtures)
}

func failingFixtures(rule *rulecheck.Rule, fixtures []Fixture) []string {
	var problems []string
	for i, f := range fixtures {
		denials, err := rule.Deny(f.edit())
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("edit %d: the rule fails to evaluate (%s)", i+1, rulecheck.Code(err)))
		case f.Deny && len(denials) == 0:
			problems = append(problems, fmt.Sprintf("edit %d must be denied, and the rule allows it", i+1))
		case !f.Deny && len(denials) > 0:
			problems = append(problems, fmt.Sprintf("edit %d must be allowed, and the rule denies it", i+1))
		}
	}
	return problems
}

func parseSpec(text string) (RuleSpec, error) {
	if len(text) > maxOutputBytes {
		return RuleSpec{}, errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	decoder.DisallowUnknownFields()
	var spec RuleSpec
	if err := decoder.Decode(&spec); err != nil {
		return RuleSpec{}, errors.New("the answer is not one JSON object with the fields of the example")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return RuleSpec{}, errors.New("the answer holds more than one JSON value")
	}
	if err := spec.validate(); err != nil {
		return RuleSpec{}, err
	}
	return spec, nil
}

func (s RuleSpec) validate() error {
	if len(s.Rules) == 0 || len(s.Rules) > maxRules {
		return fmt.Errorf("the answer needs one to %d rules", maxRules)
	}
	for i, rule := range s.Rules {
		if err := rule.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

func (r Rule) validate() error {
	if len(r.When) == 0 || len(r.When) > maxConditions {
		return fmt.Errorf("it needs one to %d conditions", maxConditions)
	}
	if strings.TrimSpace(r.Message) == "" || utf8.RuneCountInString(r.Message) > maxMessageRunes {
		return fmt.Errorf("its message needs one to %d characters", maxMessageRunes)
	}
	for i, c := range r.When {
		if !editFields[c.Field] {
			return fmt.Errorf("condition %d: field must be tool, path, content, added, or command", i+1)
		}
		if c.Value == "" || utf8.RuneCountInString(c.Value) > maxValueRunes {
			return fmt.Errorf("condition %d: value needs one to %d characters", i+1, maxValueRunes)
		}
		switch c.Op {
		case "equals", "prefix", "suffix", "contains", "glob":
		case "regex":
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("condition %d: the regex does not compile", i+1)
			}
		default:
			return fmt.Errorf("condition %d: op must be equals, prefix, suffix, contains, glob, or regex", i+1)
		}
	}
	return nil
}

// render writes the Rego of a rule. Every value from the model is a Rego string literal, so the
// answer is data that cannot add code to the module.
func render(spec RuleSpec) string {
	var b strings.Builder
	b.WriteString("package ipso.checks.generated\n")
	for _, rule := range spec.Rules {
		b.WriteString("\ndeny contains msg if {\n")
		for _, c := range rule.When {
			b.WriteString("\t" + condition(c) + "\n")
		}
		b.WriteString("\tmsg := " + regoString(rule.Message) + "\n}\n")
	}
	return b.String()
}

// condition reads a missing field as the empty string, so a rule never depends on whether the
// hook set it.
func condition(c Condition) string {
	field := "object.get(input, " + regoString(c.Field) + `, "")`
	value := regoString(c.Value)
	var expr string
	switch c.Op {
	case "equals":
		expr = field + " == " + value
	case "prefix":
		expr = "startswith(" + field + ", " + value + ")"
	case "suffix":
		expr = "endswith(" + field + ", " + value + ")"
	case "contains":
		expr = "contains(" + field + ", " + value + ")"
	case "glob":
		expr = "glob.match(" + value + `, ["/"], ` + field + ")"
	case "regex":
		expr = "regex.match(" + value + ", " + field + ")"
	}
	if c.Not {
		return "not " + expr
	}
	return expr
}

// regoString is a JSON string, which Rego reads as the same string.
func regoString(text string) string {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(text)
	return strings.TrimSuffix(b.String(), "\n")
}
