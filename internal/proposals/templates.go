package proposals

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/templates"
)

const (
	templatePromptVersion = "check-template-v2"
	// maxTemplateTokens bounds an answer that holds one id, null, or a yes or no (ADR-0165).
	maxTemplateTokens = 128
)

var (
	//go:embed prompts/check-template-v2.txt
	templateInstructions string
	//go:embed prompts/check-template-v2-verify.txt
	verifyInstructions string
)

// fitsSchema is the answer of the step that checks a choice.
var fitsSchema = json.RawMessage(`{"type":"object","properties":{"fits":{"type":"boolean"}},"required":["fits"],"additionalProperties":false}`)

var (
	// ErrNoTemplate means the model answered that no built-in template fits the decision. Nothing is proposed.
	ErrNoTemplate = errors.New("no built-in template fits the decision")
	// ErrOutsideCatalog means the answer names a template that this build of ipso does not ship. Nothing is proposed.
	ErrOutsideCatalog = errors.New("the answer names a template that is not built in")
	// ErrTemplateUnfit means the model chose a template and then answered that it does not enforce the
	// decision. Nothing is proposed.
	ErrTemplateUnfit = errors.New("the chosen template does not enforce the decision")
	// ErrTemplateAnswer means the answer is not the one JSON object the prompt asks for. Nothing is proposed.
	ErrTemplateAnswer = errors.New("the answer is not a template choice")
)

// TemplateRequest is a decision in force for which the model chooses a built-in template.
type TemplateRequest struct {
	DecisionID uuid.UUID
	Version    int
	Title      string
	Statement  string
}

// TemplateCheck is a template the model chose for a version of a decision. Template is the catalog
// entry of the ipso version this server is built with.
type TemplateCheck struct {
	DecisionID    uuid.UUID
	Version       int
	Template      templates.Template
	Model         string
	PromptVersion string
}

// TemplateStats says how the model answered when nothing was chosen: None for an answer of null,
// Outside for an id that is not in the catalog, Unfit for a choice the second call rejected.
type TemplateStats struct {
	None    bool
	Outside bool
	Unfit   bool
}

// templateGroups heads the catalog by the first part of each id. A part with no label here is
// headed by the part itself.
var templateGroups = map[string]string{
	"aws": "AWS", "azure": "Azure", "terraform": "Any cloud", "go": "Go", "java": "Java",
	"javascript": "JavaScript and TypeScript", "python": "Python",
}

// templateLine is how both prompts name a template: id (kind): title, then what it reads.
func templateLine(t templates.Template) string {
	kind, reads := "Terraform plan", strings.Join(t.Resources, ", ")
	if t.Engine == "semgrep" {
		kind, reads = "Semgrep", strings.Join(t.Languages, ", ")
	}
	return fmt.Sprintf("%s (%s): %s. Reads %s.", t.ID, kind, t.Title, reads)
}

// templatePrompt is the instructions with the catalog, grouped by cloud or language with one
// template per line, in place of the {{catalog}} line, so the instructions repeat what to answer
// after the list.
var templatePrompt = sync.OnceValue(func() string {
	head, tail, found := strings.Cut(templateInstructions, "{{catalog}}\n")
	if !found {
		panic("the template prompt has no {{catalog}} line")
	}
	var b strings.Builder
	b.WriteString(head)
	group := ""
	for _, t := range templates.List() {
		if g, _, _ := strings.Cut(t.ID, "/"); g != group {
			group = g
			label, ok := templateGroups[g]
			if !ok {
				label = g
			}
			fmt.Fprintf(&b, "\n%s checks:\n", label)
		}
		b.WriteString("- " + templateLine(t) + "\n")
	}
	b.WriteString(tail)
	return b.String()
})

// templateSchema allows only an id of the catalog or null, so a route that applies it cannot name
// a template that is not built in.
var templateSchema = sync.OnceValue(func() json.RawMessage {
	ids := []string{}
	for _, t := range templates.List() {
		ids = append(ids, t.ID)
	}
	schema, err := json.Marshal(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"template": map[string]any{"anyOf": []any{map[string]any{"type": "string", "enum": ids}, map[string]any{"type": "null"}}},
		},
		"required":             []string{"template"},
		"additionalProperties": false,
	})
	if err != nil {
		panic(err)
	}
	return schema
})

// DraftTemplateCheck asks the model which built-in template enforces the decision, then, for a
// template of the catalog, asks in a second call whether that template enforces the whole decision.
// Each answer must follow a schema: an id of the catalog or null, then a yes or no. Every answer is
// still checked here, because a route may ignore the schema, and no model output is compiled or
// run. An answer of null is ErrNoTemplate, an id outside the catalog is ErrOutsideCatalog, a no is
// ErrTemplateUnfit, and an answer that is not the object asked for is ErrTemplateAnswer. There is
// no repair round.
func DraftTemplateCheck(ctx context.Context, complete SchemaCompleteFunc, req TemplateRequest) (TemplateCheck, TemplateStats, error) {
	if req.DecisionID == uuid.Nil || req.Version < 1 || strings.TrimSpace(req.Title) == "" {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: it names no decision", ErrCheckRequest)
	}
	if utf8.RuneCountInString(req.Title)+utf8.RuneCountInString(req.Statement) > maxDecisionRunes {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: the decision text is too long", ErrCheckRequest)
	}
	decision := "Decision: " + req.Title + "\n" + req.Statement
	answer, err := complete(ctx, templatePrompt(), decision, maxTemplateTokens, templateSchema())
	if err != nil {
		return TemplateCheck{}, TemplateStats{}, err
	}
	id, err := parseTemplate(answer.Text)
	if err != nil {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: %w", ErrTemplateAnswer, err)
	}
	if id == nil {
		return TemplateCheck{}, TemplateStats{None: true}, ErrNoTemplate
	}
	chosen, ok := templates.Lookup("ipso:" + *id)
	if !ok {
		return TemplateCheck{}, TemplateStats{Outside: true}, ErrOutsideCatalog
	}
	verdict, err := complete(ctx, verifyInstructions, decision+"\n\nCheck: "+templateLine(chosen), maxTemplateTokens, fitsSchema)
	if err != nil {
		return TemplateCheck{}, TemplateStats{}, err
	}
	fits, err := parseFits(verdict.Text)
	if err != nil {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: %w", ErrTemplateAnswer, err)
	}
	if !fits {
		return TemplateCheck{}, TemplateStats{Unfit: true}, ErrTemplateUnfit
	}
	return TemplateCheck{
		DecisionID: req.DecisionID, Version: req.Version, Template: chosen,
		Model: answer.Model, PromptVersion: templatePromptVersion,
	}, TemplateStats{}, nil
}

// parseFits reads {"fits": true} or {"fits": false}. null is not an answer.
func parseFits(text string) (bool, error) {
	var fits *bool
	if err := parseField(text, "fits", &fits); err != nil {
		return false, err
	}
	if fits == nil {
		return false, errors.New("the fits field is null")
	}
	return *fits, nil
}

// parseTemplate reads {"template": "<id>"} or {"template": null}. It returns nil for null.
func parseTemplate(text string) (*string, error) {
	var id *string
	if err := parseField(text, "template", &id); err != nil {
		return nil, err
	}
	return id, nil
}

// parseField decodes the one field of an answer that is a single JSON object, with no other or
// repeated field and nothing after the object.
func parseField(text, field string, value any) error {
	if len(text) > maxOutputBytes {
		return errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	if err := delim(decoder, '{'); err != nil {
		return err
	}
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if key, _ := token.(string); key != field || seen {
			return fmt.Errorf("the field %q is not the one %s field", key, field)
		}
		seen = true
		if err := decoder.Decode(value); err != nil {
			return err
		}
	}
	if err := delim(decoder, '}'); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("it holds more than one JSON value")
	}
	if !seen {
		return fmt.Errorf("it has no %s field", field)
	}
	return nil
}

// templateSpec is the catalog entry a template check stores in spec, so a reviewer reads the title
// the check was proposed with even after a later ipso changes the catalog.
type templateSpec struct {
	Ref       string   `json:"ref"`
	Title     string   `json:"title"`
	Resources []string `json:"resources,omitempty"`
	Languages []string `json:"languages,omitempty"`
}

// ProposeTemplateCheck stores a template check for review and reports whether it added a row. It
// looks the template up again in the catalog of this build and stores that entry, whoever built the
// TemplateCheck, so a row names only a template ipso compile builds. The row can only be pending.
func ProposeTemplateCheck(ctx context.Context, db *sql.DB, tenant uuid.UUID, check TemplateCheck) (bool, error) {
	if tenant == uuid.Nil {
		return false, errors.New("no tenant")
	}
	if check.DecisionID == uuid.Nil || check.Version < 1 {
		return false, fmt.Errorf("%w: it names no decision", ErrCheckRequest)
	}
	if check.Model == "" || check.PromptVersion == "" {
		return false, fmt.Errorf("%w: it names no model or prompt version", ErrCheckRequest)
	}
	tmpl, ok := templates.Lookup(check.Template.Ref)
	if !ok || check.Template.Engine != tmpl.Engine || check.Template.Target != tmpl.Target {
		return false, ErrOutsideCatalog
	}
	spec, err := json.Marshal(templateSpec{Ref: tmpl.Ref, Title: tmpl.Title, Resources: tmpl.Resources, Languages: tmpl.Languages})
	if err != nil {
		return false, err
	}
	var target any
	if tmpl.Target != "" {
		target = tmpl.Target
	}
	created := false
	err = tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO proposals.check_proposal
				(tenant_id, decision_id, decision_version, engine, target, ref, spec, rego, rego_sha256, fixtures,
				 fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NULL, NULL, '[]'::jsonb, 0, 0, false, $8, $9)
			ON CONFLICT (tenant_id, decision_id, decision_version, ref) WHERE ref IS NOT NULL DO NOTHING`,
			tenant, check.DecisionID, check.Version, tmpl.Engine, target, tmpl.Ref, string(spec), check.Model, check.PromptVersion)
		if err != nil {
			return fmt.Errorf("insert a template check proposal: %w", err)
		}
		rows, err := result.RowsAffected()
		created = rows == 1
		return err
	})
	return created && err == nil, err
}
