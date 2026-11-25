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
	templatePromptVersion = "check-template-v1"
	// maxTemplateTokens bounds an answer that holds one id or null (ADR-0165).
	maxTemplateTokens = 128
)

//go:embed prompts/check-template-v1.txt
var templateInstructions string

var (
	// ErrNoTemplate means the model answered that no built-in template fits the decision. Nothing is proposed.
	ErrNoTemplate = errors.New("no built-in template fits the decision")
	// ErrOutsideCatalog means the answer names a template that this build of ipso does not ship. Nothing is proposed.
	ErrOutsideCatalog = errors.New("the answer names a template that is not built in")
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
// Outside for an id that is not in the catalog.
type TemplateStats struct {
	None    bool
	Outside bool
}

// templatePrompt is the instructions followed by the catalog, one template per line.
var templatePrompt = sync.OnceValue(func() string {
	var b strings.Builder
	b.WriteString(templateInstructions)
	for _, t := range templates.List() {
		kind, reads := "Terraform plan", strings.Join(t.Resources, ", ")
		if t.Engine == "semgrep" {
			kind, reads = "Semgrep", strings.Join(t.Languages, ", ")
		}
		fmt.Fprintf(&b, "- %s (%s): %s. Reads %s.\n", t.ID, kind, t.Title, reads)
	}
	return b.String()
})

// DraftTemplateCheck asks the model which built-in template enforces the decision, in one call.
// The answer is an id matched against the catalog, so no model output is compiled or run. An
// answer of null is ErrNoTemplate, an id outside the catalog is ErrOutsideCatalog, and an answer
// that is not one {"template": ...} object is ErrTemplateAnswer. There is no repair round.
func DraftTemplateCheck(ctx context.Context, complete CompleteFunc, req TemplateRequest) (TemplateCheck, TemplateStats, error) {
	if req.DecisionID == uuid.Nil || req.Version < 1 || strings.TrimSpace(req.Title) == "" {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: it names no decision", ErrCheckRequest)
	}
	if utf8.RuneCountInString(req.Title)+utf8.RuneCountInString(req.Statement) > maxDecisionRunes {
		return TemplateCheck{}, TemplateStats{}, fmt.Errorf("%w: the decision text is too long", ErrCheckRequest)
	}
	answer, err := complete(ctx, templatePrompt(), "Decision: "+req.Title+"\n"+req.Statement, maxTemplateTokens)
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
	return TemplateCheck{
		DecisionID: req.DecisionID, Version: req.Version, Template: chosen,
		Model: answer.Model, PromptVersion: templatePromptVersion,
	}, TemplateStats{}, nil
}

// parseTemplate reads {"template": "<id>"} or {"template": null}, with no other field and nothing
// after the object. It returns nil for null.
func parseTemplate(text string) (*string, error) {
	if len(text) > maxOutputBytes {
		return nil, errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	if err := delim(decoder, '{'); err != nil {
		return nil, err
	}
	var id *string
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if key, _ := token.(string); key != "template" || seen {
			return nil, fmt.Errorf("the field %q is not the one template field", key)
		}
		seen = true
		if err := decoder.Decode(&id); err != nil {
			return nil, err
		}
	}
	if err := delim(decoder, '}'); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("it holds more than one JSON value")
	}
	if !seen {
		return nil, errors.New("it has no template field")
	}
	return id, nil
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
