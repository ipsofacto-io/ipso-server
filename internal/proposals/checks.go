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
// with candidate rules as data, the server writes the Rego from each, and a rule reaches review only
// when it compiles as `ipso compile` compiles it and passes every fixture a person wrote.
const (
	checkPromptVersion = "check-rule-v4"
	maxFixtures        = 50
	maxFixtureRunes    = 8 << 10
	maxFixturesBytes   = 1 << 20
	maxPathRunes       = 1024
	maxToolRunes       = 50
	maxDecisionRunes   = 4000
	maxShownRunes      = 1000
	maxQuotedRunes     = 200
	maxDrafts          = 3
	// maxCheckTokens bounds a check answer, so a model that loops stops early: two candidates of a
	// few conditions take about 250.
	maxCheckTokens  = 512
	maxRules        = 3
	maxConditions   = 5
	maxValueRunes   = 200
	maxMessageRunes = 200
	maxProblems     = 6
)

//go:embed prompts/check-rule-v4.txt
var checkPrompt string

// ErrCheckFailed means no candidate rule passed every fixture, after one repair. Nothing is proposed.
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

func (f Fixture) field(name string) string {
	switch name {
	case "tool":
		return f.Tool
	case "path":
		return f.Path
	case "content":
		return f.Content
	case "added":
		return f.Added
	default:
		return f.Command
	}
}

// CheckRequest is a decision in force and the fixtures a person wrote for it.
type CheckRequest struct {
	DecisionID uuid.UUID
	Version    int
	Title      string
	Statement  string
	Fixtures   []Fixture
}

// RuleSpec is the rule the model drafts: rules that each deny an edit meeting all of their
// conditions.
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

// DraftCheck asks the model for up to three candidate rules, writes and compiles the Rego of each,
// and runs every fixture. The first candidate that passes them all is the check. When none does, it
// asks once more with what failed, and a second failure is ErrCheckFailed.
func DraftCheck(ctx context.Context, complete CompleteFunc, req CheckRequest) (Check, CheckStats, error) {
	if err := req.validate(); err != nil {
		return Check{}, CheckStats{}, err
	}
	user := checkUser(req)
	var stats CheckStats
	prompt := user
	for {
		answer, err := complete(ctx, checkPrompt, prompt, maxCheckTokens)
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
		prompt = repairPrompt(user, problems)
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

// checkUser shows the decision and its fixtures, one numbered edit per line, with each field cut to
// maxShownRunes.
func checkUser(req CheckRequest) string {
	var b strings.Builder
	b.WriteString("Decision: " + req.Title + "\n" + req.Statement + "\n\nEdits a person wrote for this decision, and whether the check must deny each one:\n")
	for i, f := range req.Fixtures {
		fmt.Fprintf(&b, "edit %d: %s\n", i+1, f.shown())
	}
	return b.String()
}

// shown is the fixture as the model reads it, with each field cut to maxShownRunes.
func (f Fixture) shown() string {
	return jsonText(Fixture{
		Tool: truncate(f.Tool, maxShownRunes), Path: truncate(f.Path, maxShownRunes), Content: truncate(f.Content, maxShownRunes),
		Added: truncate(f.Added, maxShownRunes), Command: truncate(f.Command, maxShownRunes), Deny: f.Deny,
	})
}

// repairPrompt names what failed without the failed answer: a small model shown its answer tends to
// write it again. Each problem quotes the conditions it is about.
func repairPrompt(user string, problems []string) string {
	if len(problems) > maxProblems {
		problems = append(problems[:maxProblems], fmt.Sprintf("and %d more", len(problems)-maxProblems))
	}
	return user + "\nA previous answer failed:\n- " + strings.Join(problems, "\n- ") +
		"\n\nAnswer with one JSON object. Write two new candidates that avoid each failure."
}

// draft parses an answer and tries its first maxDrafts candidates in order: each is decoded,
// validated, its Rego written and compiled, and every fixture run. It returns the first candidate
// that passes, or what failed for each, in words the model can act on.
func draft(text string, fixtures []Fixture) (RuleSpec, []string) {
	candidates, err := parseCandidates(text)
	if len(candidates) == 0 {
		return RuleSpec{}, []string{err.Error()}
	}
	var problems []string
	if err != nil {
		problems = append(problems, err.Error())
	}
	if len(candidates) > maxDrafts {
		problems = append(problems, fmt.Sprintf("only the first %d candidates are tried", maxDrafts))
	}
	for i, raw := range candidates[:min(len(candidates), maxDrafts)] {
		spec, failed := tryCandidate(raw, fixtures)
		if len(failed) == 0 {
			return spec, nil
		}
		for _, problem := range failed {
			problems = append(problems, fmt.Sprintf("candidate %d: %s", i+1, problem))
		}
	}
	return RuleSpec{}, problems
}

// tryCandidate decodes one candidate on its own, so a malformed one does not hide the others.
func tryCandidate(raw json.RawMessage, fixtures []Fixture) (RuleSpec, []string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var spec RuleSpec
	if err := decoder.Decode(&spec); err != nil {
		return RuleSpec{}, []string{fmt.Sprintf(`it is not an object with "rules" as in the example (%s)`, err)}
	}
	spec = spec.canonical()
	return spec, checkCandidate(spec, fixtures)
}

// canonical rewrites the one op the model writes outside the schema, despite the prompt: "not"
// with no other op, which it uses for an exception. It reads as contains with "not": true, so the
// field holds the value nowhere. The fixtures decide whether that is the rule, as for any other.
func (s RuleSpec) canonical() RuleSpec {
	for r := range s.Rules {
		for c, cond := range s.Rules[r].When {
			if cond.Op == "not" && !cond.Not {
				s.Rules[r].When[c].Op, s.Rules[r].When[c].Not = "contains", true
			}
		}
	}
	return s
}

func checkCandidate(spec RuleSpec, fixtures []Fixture) []string {
	if err := spec.validate(); err != nil {
		return []string{err.Error()}
	}
	rule, err := rulecheck.Compile([]byte(render(spec)))
	if err != nil {
		return []string{"the rule does not compile: " + rulecheck.Code(err)}
	}
	return failingFixtures(spec, rule, fixtures)
}

// failingFixtures runs every fixture through the compiled rule and says what it gets wrong: the
// edit, and the conditions that decide it.
func failingFixtures(spec RuleSpec, rule *rulecheck.Rule, fixtures []Fixture) []string {
	var problems []string
	var probe *rulecheck.Rule
	probed := false
	for i, f := range fixtures {
		denials, err := rule.Deny(f.edit())
		if err != nil {
			problems = append(problems, fmt.Sprintf("edit %d: the rule fails to evaluate (%s)", i+1, rulecheck.Code(err)))
			continue
		}
		if f.Deny == (len(denials) > 0) {
			continue
		}
		if !probed {
			// Each condition compiled inside the rule. Should one fail alone, the problem names the
			// edit without the conditions.
			probe, _ = rulecheck.Compile([]byte(renderConditions(spec)))
			probed = true
		}
		problems = append(problems, explain(spec, probe, i+1, f, fixtures))
	}
	return problems
}

// renderConditions writes each condition as its own rule, whose message is its place, so the engine
// that runs the check also says which conditions hold for an edit.
func renderConditions(spec RuleSpec) string {
	var b strings.Builder
	b.WriteString("package ipso.checks.generated\n")
	for r, rule := range spec.Rules {
		for c, cond := range rule.When {
			b.WriteString("\ndeny contains " + jsonText(place(r, c)) + " if {\n\t" + condition(cond) + "\n}\n")
		}
	}
	return b.String()
}

func place(rule, condition int) string {
	return fmt.Sprintf("%d.%d", rule+1, condition+1)
}

// explain says why the rule gets one edit wrong: for an edit to deny, which conditions of each rule
// do not hold and the text each one tested, and for an edit to allow, which rules hold and where
// the edit differs from an edit to deny. The edit itself is numbered in the request, so it is not
// quoted whole again.
func explain(spec RuleSpec, probe *rulecheck.Rule, number int, f Fixture, fixtures []Fixture) string {
	verdict := fmt.Sprintf("edit %d must be allowed, and the rule denies it", number)
	if f.Deny {
		verdict = fmt.Sprintf("edit %d must be denied, and the rule allows it", number)
	}
	if probe == nil {
		return verdict + "."
	}
	held, err := probe.Deny(f.edit())
	if err != nil {
		return verdict + "."
	}
	holds := map[string]bool{}
	for _, id := range held {
		holds[id] = true
	}
	var reasons, holding []string
	for r, rule := range spec.Rules {
		var unmet []string
		for c, cond := range rule.When {
			if !holds[place(r, c)] {
				text := f.field(cond.Field)
				unmet = append(unmet, jsonText(cond)+patternHint(cond)+" (the "+cond.Field+" is "+jsonText(truncate(text, maxQuotedRunes))+opHint(cond, text)+")")
			}
		}
		switch {
		case f.Deny && len(unmet) > 0:
			reasons = append(reasons, fmt.Sprintf("in rule %d, %s does not hold", r+1, strings.Join(unmet, " and ")))
		case !f.Deny && len(unmet) == 0:
			conditions := make([]string, len(rule.When))
			for c, cond := range rule.When {
				conditions[c] = jsonText(cond)
			}
			reasons = append(reasons, fmt.Sprintf("rule %d (%s)", r+1, strings.Join(conditions, " and ")))
			holding = append(holding, fmt.Sprintf("rule %d", r+1))
		}
	}
	switch {
	case len(reasons) == 0:
		return verdict + "."
	case f.Deny:
		return verdict + ": " + strings.Join(reasons, "; ") + "."
	default:
		return verdict + ": every condition of " + strings.Join(reasons, " and ") + " holds for it." + differs(f, fixtures, holding)
	}
}

// opHint names the plain-text op that holds where the one the model chose does not, as a suffix
// written for a path that starts with the value, and quotes the condition to write: a small model
// copies a condition it is shown more readily than it follows advice.
func opHint(c Condition, text string) string {
	if c.Not || (c.Op != "equals" && c.Op != "prefix" && c.Op != "suffix") {
		return ""
	}
	var where, op string
	switch {
	case c.Op != "prefix" && strings.HasPrefix(text, c.Value):
		where, op = "starts with", "prefix"
	case c.Op != "suffix" && strings.HasSuffix(text, c.Value):
		where, op = "ends with", "suffix"
	case strings.Contains(text, c.Value):
		where, op = "contains", "contains"
	default:
		return ""
	}
	return ", which " + where + " the value: write " + jsonText(Condition{Field: c.Field, Op: op, Value: c.Value}) + " instead"
}

// differs names the fields in which an edit to allow differs from the closest edit to deny: each
// rule that holds for both needs a condition on one of them.
func differs(f Fixture, fixtures []Fixture, rules []string) string {
	closest, fields := 0, []string(nil)
	for i, d := range fixtures {
		if !d.Deny {
			continue
		}
		var diff []string
		for _, name := range []string{"tool", "path", "content", "added", "command"} {
			if f.field(name) != d.field(name) {
				diff = append(diff, name)
			}
		}
		if len(diff) > 0 && (fields == nil || len(diff) < len(fields)) {
			closest, fields = i+1, diff
		}
	}
	if fields == nil {
		return ""
	}
	return fmt.Sprintf(" It differs from edit %d, which must be denied, only in its %s: add a condition on one of them to %s.",
		closest, strings.Join(fields, " and "), strings.Join(rules, " and "))
}

// patternHint flags a plain-text value written as a pattern, the most common reason a condition
// the model meant to hold does not.
func patternHint(c Condition) string {
	pattern := strings.Contains(c.Value, `\`) || strings.Contains(c.Value, ".*")
	if !pattern || c.Op == "regex" || c.Op == "glob" {
		return ""
	}
	return " (" + c.Op + " compares plain text; for a pattern, use regex)"
}

// parseCandidates reads the one object the prompt asks for, token by token. Each candidate is
// decoded on its own afterwards, so one bad candidate does not hide a good one. An answer cut off,
// as at its token bound, keeps the candidates it completed, with a note of where it stops; any
// other break refuses the whole answer.
func parseCandidates(text string) ([]json.RawMessage, error) {
	if len(text) > maxOutputBytes {
		return nil, errors.New("the answer is too large")
	}
	body := unfence(text)
	var candidates []json.RawMessage
	err := readAnswer(json.NewDecoder(strings.NewReader(body)), &candidates)
	switch {
	case err == nil && len(candidates) == 0:
		return nil, fmt.Errorf("the answer needs one to %d candidates", maxDrafts)
	case err == nil:
		return candidates, nil
	case len(candidates) > 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)):
		return candidates, fmt.Errorf("the answer stops after candidate %d", len(candidates))
	default:
		return nil, fmt.Errorf("the answer is not one JSON object with the fields of the example (%s)", decodeProblem(body, err))
	}
}

// readAnswer reads {"difference": ..., "candidates": [...]} and appends each whole candidate. The
// model writes what tells the edits apart before the candidates, and only these are kept.
func readAnswer(decoder *json.Decoder, candidates *[]json.RawMessage) error {
	if err := delim(decoder, '{'); err != nil {
		return err
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, _ := token.(string)
		if seen[key] {
			return fmt.Errorf("the field %q appears twice", key)
		}
		seen[key] = true
		switch key {
		case "difference":
			var difference string
			if err := decoder.Decode(&difference); err != nil {
				return err
			}
		case "candidates":
			if err := delim(decoder, '['); err != nil {
				return err
			}
			for decoder.More() {
				var raw json.RawMessage
				if err := decoder.Decode(&raw); err != nil {
					return err
				}
				*candidates = append(*candidates, raw)
			}
			if err := delim(decoder, ']'); err != nil {
				return err
			}
		default:
			return fmt.Errorf("json: unknown field %q", key)
		}
	}
	if err := delim(decoder, '}'); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("it holds more than one JSON value")
	}
	return nil
}

func delim(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected %q", want.String())
	}
	return nil
}

// decodeProblem names what broke the JSON and, for a syntax error, the text that ends at it, so the
// repair can fix that place.
func decodeProblem(body string, err error) string {
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		return err.Error()
	}
	end := min(len(body), int(syntax.Offset))
	return err.Error() + ", where the answer reads " + strings.Join(strings.Fields(strings.ToValidUTF8(body[max(0, end-40):end], "")), " ")
}

func (s RuleSpec) validate() error {
	if len(s.Rules) == 0 || len(s.Rules) > maxRules {
		return fmt.Errorf("it needs one to %d rules", maxRules)
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
		// The condition is quoted, cut to maxQuotedRunes, since the repair does not show the answer again.
		at := fmt.Sprintf("condition %d %s", i+1, jsonText(Condition{
			Field: truncate(c.Field, maxQuotedRunes), Op: truncate(c.Op, maxQuotedRunes), Value: truncate(c.Value, maxQuotedRunes), Not: c.Not,
		}))
		if !editFields[c.Field] {
			return fmt.Errorf("%s: field must be tool, path, content, added, or command", at)
		}
		if c.Value == "" || utf8.RuneCountInString(c.Value) > maxValueRunes {
			return fmt.Errorf("%s: value needs one to %d characters", at, maxValueRunes)
		}
		switch c.Op {
		case "equals", "prefix", "suffix", "contains", "glob":
		case "regex":
			if _, err := regexp.Compile(c.Value); err != nil {
				return fmt.Errorf("%s: the regex does not compile", at)
			}
		case "not":
			return fmt.Errorf(`%s: "not" is not an op; write equals, prefix, suffix, contains, glob, or regex, and add "not": true`, at)
		default:
			return fmt.Errorf("%s: op must be equals, prefix, suffix, contains, glob, or regex", at)
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
		b.WriteString("\tmsg := " + jsonText(rule.Message) + "\n}\n")
	}
	return b.String()
}

// condition reads a missing field as the empty string, so a rule never depends on whether the
// hook set it.
func condition(c Condition) string {
	field := "object.get(input, " + jsonText(c.Field) + `, "")`
	value := jsonText(c.Value)
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

// jsonText encodes a value as JSON without HTML escaping. Rego reads a JSON string as the same
// string, and the model reads the text as it was written.
func jsonText(v any) string {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}
