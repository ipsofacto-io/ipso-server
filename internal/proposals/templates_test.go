package proposals

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/templates"
)

func templateRequest() TemplateRequest {
	return TemplateRequest{
		DecisionID: testDecision, Version: 2, Title: "EBS volumes are encrypted",
		Statement: "Every EBS volume and every instance root volume is encrypted at rest.",
	}
}

// promptLLM answers once and keeps the system prompt it was sent.
type promptLLM struct {
	scriptedLLM
	systems []string
}

func (p *promptLLM) complete(ctx context.Context, system, user string, maxTokens int) (Completion, error) {
	p.systems = append(p.systems, system)
	return p.scriptedLLM.complete(ctx, system, user, maxTokens)
}

func TestDraftTemplateCheckChoosesACatalogTemplate(t *testing.T) {
	for name, text := range map[string]string{
		"plain":  `{"template":"aws/ebs-encrypted"}`,
		"fenced": "```json\n{\"template\": \"aws/ebs-encrypted\"}\n```",
		"spaced": "  {\n \"template\" : \"aws/ebs-encrypted\" }\n",
	} {
		llm := &promptLLM{scriptedLLM: scriptedLLM{answers: []string{text}}}
		check, stats, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest())
		if err != nil || stats != (TemplateStats{}) {
			t.Fatalf("%s: err %v stats %+v", name, err, stats)
		}
		if check.Template.Ref != "ipso:aws/ebs-encrypted" || check.Template.Engine != "opa" || check.Template.Target != "terraform-plan" ||
			check.DecisionID != testDecision || check.Version != 2 || check.Model != "test-model" || check.PromptVersion != templatePromptVersion {
			t.Fatalf("%s: check %+v", name, check)
		}
		if len(llm.users) != 1 || llm.maxTokens[0] != maxTemplateTokens || !strings.HasPrefix(llm.users[0], "Decision: EBS volumes are encrypted\nEvery EBS volume") {
			t.Fatalf("%s: calls %d tokens %v user %q", name, len(llm.users), llm.maxTokens, llm.users)
		}
	}
}

func TestTemplatePromptListsTheWholeCatalog(t *testing.T) {
	prompt := templatePrompt()
	if !strings.HasPrefix(prompt, templateInstructions) {
		t.Fatal("the prompt does not start with its instructions")
	}
	for _, tmpl := range templates.List() {
		if !strings.Contains(prompt, "- "+tmpl.ID+" (") || !strings.Contains(prompt, tmpl.Title) {
			t.Errorf("the prompt does not list %s", tmpl.ID)
		}
	}
	for _, line := range []string{
		"- aws/ebs-encrypted (Terraform plan): EBS volumes are encrypted. Reads aws_ebs_volume, aws_instance, aws_launch_template.\n",
		"- go/use-slog (Semgrep): Go logging uses slog. Reads go.\n",
	} {
		if !strings.Contains(prompt, line) {
			t.Errorf("the prompt has no line %q", line)
		}
	}
}

func TestDraftTemplateCheckProposesNothing(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		want  error
		stats TemplateStats
	}{
		{"null", `{"template":null}`, ErrNoTemplate, TemplateStats{None: true}},
		{"an id of no template", `{"template":"aws/ebs-encryption"}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"the ref instead of the id", `{"template":"ipso:aws/ebs-encrypted"}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"the helper module", `{"template":"lib/terraform"}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"a path", `{"template":"../aws/ebs-encrypted"}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"upper case", `{"template":"AWS/EBS-ENCRYPTED"}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"an empty id", `{"template":""}`, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"not json", "aws/ebs-encrypted", ErrTemplateAnswer, TemplateStats{}},
		{"an extra field", `{"template":"aws/ebs-encrypted","reason":"it fits"}`, ErrTemplateAnswer, TemplateStats{}},
		{"the field twice", `{"template":null,"template":"aws/ebs-encrypted"}`, ErrTemplateAnswer, TemplateStats{}},
		{"no field", `{}`, ErrTemplateAnswer, TemplateStats{}},
		{"a list of ids", `{"template":["aws/ebs-encrypted","go/use-slog"]}`, ErrTemplateAnswer, TemplateStats{}},
		{"a number", `{"template":1}`, ErrTemplateAnswer, TemplateStats{}},
		{"two objects", `{"template":"aws/ebs-encrypted"}{"template":"go/use-slog"}`, ErrTemplateAnswer, TemplateStats{}},
		{"cut off", `{"template":"aws/ebs-enc`, ErrTemplateAnswer, TemplateStats{}},
		{"too large", `{"template":"` + strings.Repeat("a", maxOutputBytes) + `"}`, ErrTemplateAnswer, TemplateStats{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			llm := &scriptedLLM{answers: []string{test.text}}
			check, stats, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest())
			if !errors.Is(err, test.want) || stats != test.stats || check.Template.Ref != "" || check.DecisionID != uuid.Nil || len(llm.users) != 1 {
				t.Fatalf("err %v stats %+v check %+v calls %d", err, stats, check, len(llm.users))
			}
		})
	}
}

func TestDraftTemplateCheckRefusesARequestBeforeACall(t *testing.T) {
	for name, req := range map[string]TemplateRequest{
		"no decision": {Version: 1, Title: "t"},
		"no version":  {DecisionID: testDecision, Title: "t"},
		"no title":    {DecisionID: testDecision, Version: 1, Title: "  "},
		"too long":    {DecisionID: testDecision, Version: 1, Title: "t", Statement: strings.Repeat("é", maxDecisionRunes)},
	} {
		llm := &scriptedLLM{}
		if _, _, err := DraftTemplateCheck(t.Context(), llm.complete, req); !errors.Is(err, ErrCheckRequest) || len(llm.users) != 0 {
			t.Errorf("%s: err %v calls %d", name, err, len(llm.users))
		}
	}
}

func TestDraftTemplateCheckReturnsAGatewayError(t *testing.T) {
	llm := &scriptedLLM{}
	if _, _, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest()); err == nil || errors.Is(err, ErrTemplateAnswer) {
		t.Fatalf("err %v", err)
	}
}

func TestProposeTemplateCheckRefusesBeforeTheStore(t *testing.T) {
	good, _ := templates.Lookup("ipso:go/use-slog")
	check := TemplateCheck{DecisionID: testDecision, Version: 1, Template: good, Model: "m", PromptVersion: templatePromptVersion}
	tenant := uuid.MustParse("0190c7b8-0000-7000-8000-0000000000aa")
	mutate := func(f func(*TemplateCheck)) TemplateCheck { c := check; f(&c); return c }
	for name, test := range map[string]struct {
		tenant uuid.UUID
		check  TemplateCheck
		want   error
	}{
		"no tenant":            {uuid.Nil, check, nil},
		"no decision":          {tenant, mutate(func(c *TemplateCheck) { c.DecisionID = uuid.Nil }), ErrCheckRequest},
		"no version":           {tenant, mutate(func(c *TemplateCheck) { c.Version = 0 }), ErrCheckRequest},
		"no model":             {tenant, mutate(func(c *TemplateCheck) { c.Model = "" }), ErrCheckRequest},
		"a ref of no template": {tenant, mutate(func(c *TemplateCheck) { c.Template.Ref = "ipso:go/use-zap" }), ErrOutsideCatalog},
		"another engine":       {tenant, mutate(func(c *TemplateCheck) { c.Template.Engine = "opa" }), ErrOutsideCatalog},
		"another target":       {tenant, mutate(func(c *TemplateCheck) { c.Template.Target = "diff" }), ErrOutsideCatalog},
	} {
		// A nil database fails the test if the check reaches the store.
		_, err := ProposeTemplateCheck(t.Context(), nil, test.tenant, test.check)
		if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}
