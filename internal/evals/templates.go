package evals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso/pkg/templates"
)

// TemplateCase is one synthetic decision with the built-in template a person would choose for it, as
// an id without the ipso: prefix, or null when no template enforces it.
type TemplateCase struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Statement string  `json:"statement"`
	Template  *string `json:"template"`
}

// LoadTemplateCases reads a template choice dataset. Every expected id must be in the catalog, so a
// dataset cannot score a choice that no build of ipso could deliver.
func LoadTemplateCases(path string) ([]TemplateCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []TemplateCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%s: no cases", path)
	}
	for _, c := range cases {
		if c.Template != nil {
			if _, ok := templates.Lookup("ipso:" + *c.Template); !ok {
				return nil, fmt.Errorf("%s: case %s expects %q, which is not a built-in template", path, c.ID, *c.Template)
			}
		}
	}
	return cases, nil
}

// TemplateSuite scores the template choice of ADR-0165. precision is the share of choices that name
// the expected template, where an id outside the catalog is a wrong choice; IPSO-158 holds it at 0.9
// or more. none is the share of decisions that fit no template and propose nothing, answered null
// or with a choice the second call rejects, which the injection cases are part of; IPSO-158 holds
// it at 0.8 or more. recall is the share of fitting decisions answered with the expected template.
// Each case logs its outcome on t.
func TemplateSuite(t *testing.T, ctx context.Context, complete SchemaCompleteFunc, cases []TemplateCase) (Metrics, error) {
	var choices, correct, fitting, nofit, none int
	for i, c := range cases {
		check, _, err := proposals.DraftTemplateCheck(ctx, proposals.SchemaCompleteFunc(complete), proposals.TemplateRequest{
			DecisionID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("ipso-evals:"+c.ID)), Version: 1,
			Title: c.Title, Statement: c.Statement,
		})
		want := "none"
		if c.Template != nil {
			fitting++
			want = "ipso:" + *c.Template
		} else {
			nofit++
		}
		var got string
		switch {
		case err == nil:
			choices++
			got = check.Template.Ref
			if got == want {
				correct++
			}
		case errors.Is(err, proposals.ErrNoTemplate), errors.Is(err, proposals.ErrTemplateUnfit):
			got = "none"
			if errors.Is(err, proposals.ErrTemplateUnfit) {
				got = "unfit"
			}
			if c.Template == nil {
				none++
			}
		case errors.Is(err, proposals.ErrOutsideCatalog):
			choices++
			got = "outside"
		case errors.Is(err, proposals.ErrTemplateAnswer):
			got = "malformed"
		default:
			return nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
		t.Logf("templates %d/%d %s want=%s got=%s", i+1, len(cases), c.ID, want, got)
	}
	return Metrics{
		"templates.precision": Count(correct, choices),
		"templates.none":      Count(none, nofit),
		"templates.recall":    Count(correct, fitting),
	}, nil
}
