package proposals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
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

// schemaLLM answers in order and keeps the system prompt and schema of each call.
type schemaLLM struct {
	scriptedLLM
	systems []string
	schemas []json.RawMessage
}

func (s *schemaLLM) complete(ctx context.Context, system, user string, maxTokens int, schema json.RawMessage) (Completion, error) {
	s.systems = append(s.systems, system)
	s.schemas = append(s.schemas, schema)
	return s.scriptedLLM.complete(ctx, system, user, maxTokens)
}

func TestDraftTemplateCheckChoosesACatalogTemplate(t *testing.T) {
	for name, text := range map[string]string{
		"plain":  `{"template":"aws/ebs-encrypted"}`,
		"fenced": "```json\n{\"template\": \"aws/ebs-encrypted\"}\n```",
		"spaced": "  {\n \"template\" : \"aws/ebs-encrypted\" }\n",
	} {
		llm := &schemaLLM{scriptedLLM: scriptedLLM{answers: []string{text, `{"fits":true}`}}}
		check, stats, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest())
		if err != nil || stats != (TemplateStats{}) {
			t.Fatalf("%s: err %v stats %+v", name, err, stats)
		}
		if check.Template.Ref != "ipso:aws/ebs-encrypted" || check.Template.Engine != "opa" || check.Template.Target != "terraform-plan" ||
			check.DecisionID != testDecision || check.Version != 2 || check.Model != "test-model" || check.PromptVersion != templatePromptVersion {
			t.Fatalf("%s: check %+v", name, check)
		}
		decision := "Decision: EBS volumes are encrypted\nEvery EBS volume and every instance root volume is encrypted at rest."
		if len(llm.users) != 2 || llm.maxTokens[0] != maxTemplateTokens || llm.maxTokens[1] != maxTemplateTokens || llm.users[0] != decision ||
			llm.users[1] != decision+"\n\nCheck: aws/ebs-encrypted (Terraform plan): EBS volumes are encrypted. Reads aws_ebs_volume, aws_instance, aws_launch_template." {
			t.Fatalf("%s: calls %d tokens %v users %q", name, len(llm.users), llm.maxTokens, llm.users)
		}
		if llm.systems[0] != templatePrompt() || llm.systems[1] != verifyInstructions ||
			!bytes.Equal(llm.schemas[0], templateSchema()) || !bytes.Equal(llm.schemas[1], fitsSchema) {
			t.Fatalf("%s: systems or schemas differ: %q", name, llm.schemas)
		}
	}
}

func TestTemplatePromptListsTheWholeCatalogByGroup(t *testing.T) {
	prompt := templatePrompt()
	head, tail, _ := strings.Cut(templateInstructions, "{{catalog}}\n")
	if !strings.HasPrefix(prompt, head) || !strings.HasSuffix(prompt, tail) || strings.Contains(prompt, "{{catalog}}") || tail == "" {
		t.Fatal("the prompt does not wrap the catalog in its instructions")
	}
	for _, tmpl := range templates.List() {
		if !strings.Contains(prompt, "- "+tmpl.ID+" (") || !strings.Contains(prompt, tmpl.Title) {
			t.Errorf("the prompt does not list %s", tmpl.ID)
		}
		group, _, _ := strings.Cut(tmpl.ID, "/")
		if _, ok := templateGroups[group]; !ok {
			t.Errorf("the group of %s has no label", tmpl.ID)
		}
	}
	for _, line := range []string{
		"\nAWS checks:\n- aws/ebs-encrypted (Terraform plan): EBS volumes are encrypted. Reads aws_ebs_volume, aws_instance, aws_launch_template.\n",
		"\nGo checks:\n- go/http-client-timeout (Semgrep)",
		"- go/use-slog (Semgrep): Go logging uses slog. Reads go.\n",
	} {
		if !strings.Contains(prompt, line) {
			t.Errorf("the prompt has no line %q", line)
		}
	}
}

func TestTemplateSchemaAllowsOnlyTheCatalogOrNull(t *testing.T) {
	var schema struct {
		Properties struct {
			Template struct {
				AnyOf []struct {
					Type string   `json:"type"`
					Enum []string `json:"enum"`
				} `json:"anyOf"`
			} `json:"template"`
		} `json:"properties"`
		Required             []string `json:"required"`
		AdditionalProperties bool     `json:"additionalProperties"`
	}
	if err := json.Unmarshal(templateSchema(), &schema); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, tmpl := range templates.List() {
		ids = append(ids, tmpl.ID)
	}
	options := schema.Properties.Template.AnyOf
	if len(options) != 2 || options[0].Type != "string" || !slices.Equal(options[0].Enum, ids) || options[1].Type != "null" ||
		!slices.Equal(schema.Required, []string{"template"}) || schema.AdditionalProperties {
		t.Fatalf("schema %s", templateSchema())
	}
}

func TestDraftTemplateCheckProposesNothing(t *testing.T) {
	tests := []struct {
		name    string
		answers []string
		want    error
		stats   TemplateStats
	}{
		{"null", []string{`{"template":null}`}, ErrNoTemplate, TemplateStats{None: true}},
		{"an id of no template", []string{`{"template":"aws/ebs-encryption"}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"the ref instead of the id", []string{`{"template":"ipso:aws/ebs-encrypted"}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"the helper module", []string{`{"template":"lib/terraform"}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"a path", []string{`{"template":"../aws/ebs-encrypted"}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"upper case", []string{`{"template":"AWS/EBS-ENCRYPTED"}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"an empty id", []string{`{"template":""}`}, ErrOutsideCatalog, TemplateStats{Outside: true}},
		{"not json", []string{"aws/ebs-encrypted"}, ErrTemplateAnswer, TemplateStats{}},
		{"an extra field", []string{`{"template":"aws/ebs-encrypted","reason":"it fits"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the field twice", []string{`{"template":null,"template":"aws/ebs-encrypted"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"no field", []string{`{}`}, ErrTemplateAnswer, TemplateStats{}},
		{"a list of ids", []string{`{"template":["aws/ebs-encrypted","go/use-slog"]}`}, ErrTemplateAnswer, TemplateStats{}},
		{"a number", []string{`{"template":1}`}, ErrTemplateAnswer, TemplateStats{}},
		{"two objects", []string{`{"template":"aws/ebs-encrypted"}{"template":"go/use-slog"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"cut off", []string{`{"template":"aws/ebs-enc`}, ErrTemplateAnswer, TemplateStats{}},
		{"too large", []string{`{"template":"` + strings.Repeat("a", maxOutputBytes) + `"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the second call says no", []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":false}`}, ErrTemplateUnfit, TemplateStats{Unfit: true}},
		{"the second call says null", []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":null}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the second call says yes in words", []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":"yes"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the second call answers twice", []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":true,"fits":false}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the second call adds a field", []string{`{"template":"aws/ebs-encrypted"}`, `{"fits":true,"why":"it matches"}`}, ErrTemplateAnswer, TemplateStats{}},
		{"the second call writes prose", []string{`{"template":"aws/ebs-encrypted"}`, "Yes, it fits."}, ErrTemplateAnswer, TemplateStats{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			llm := &schemaLLM{scriptedLLM: scriptedLLM{answers: test.answers}}
			check, stats, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest())
			if !errors.Is(err, test.want) || stats != test.stats || check.Template.Ref != "" || check.DecisionID != uuid.Nil || len(llm.users) != len(test.answers) {
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
		llm := &schemaLLM{}
		if _, _, err := DraftTemplateCheck(t.Context(), llm.complete, req); !errors.Is(err, ErrCheckRequest) || len(llm.users) != 0 {
			t.Errorf("%s: err %v calls %d", name, err, len(llm.users))
		}
	}
}

func TestDraftTemplateCheckReturnsAGatewayError(t *testing.T) {
	for _, answers := range [][]string{nil, {`{"template":"aws/ebs-encrypted"}`}} {
		llm := &schemaLLM{scriptedLLM: scriptedLLM{answers: answers}}
		if _, _, err := DraftTemplateCheck(t.Context(), llm.complete, templateRequest()); err == nil || errors.Is(err, ErrTemplateAnswer) || errors.Is(err, ErrTemplateUnfit) {
			t.Fatalf("after %d answers: err %v", len(answers), err)
		}
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
