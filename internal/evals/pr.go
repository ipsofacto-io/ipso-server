package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// Thread is one synthetic pull request discussion.
type Thread struct {
	ID       string    `json:"id"`
	Repo     string    `json:"repo"`
	Number   int       `json:"number"`
	Comments []Comment `json:"comments"`
}

// Comment is one labeled comment. Decision lists key terms of the decision the comment states,
// and is empty when it states none. A proposal matches when its title or statement holds one.
type Comment struct {
	ID       int      `json:"id"`
	Author   string   `json:"author"`
	Body     string   `json:"body"`
	Decision []string `json:"decision"`
}

// Expected reports whether a correct pipeline proposes a decision from this comment. ADR-0062
// reads only people who can already write to the repository, so a decision stated by anyone else
// is not expected.
func (c Comment) Expected() bool {
	if len(c.Decision) == 0 {
		return false
	}
	switch c.Author {
	case "OWNER", "MEMBER", "COLLABORATOR":
		return true
	}
	return false
}

func (c Comment) externalID() string {
	return fmt.Sprintf("issuecomment-%d", c.ID)
}

func (t Thread) comments() []integrations.Comment {
	out := make([]integrations.Comment, 0, len(t.Comments))
	for _, c := range t.Comments {
		authorType, association := "User", c.Author
		if c.Author == "bot" {
			authorType, association = "Bot", "NONE"
		}
		out = append(out, integrations.Comment{
			ExternalID:  c.externalID(),
			URL:         fmt.Sprintf("https://github.com/%s/pull/%d#%s", t.Repo, t.Number, c.externalID()),
			Body:        c.Body,
			Association: association,
			AuthorType:  authorType,
		})
	}
	return out
}

// LoadThreads reads a dataset of threads.
func LoadThreads(path string) ([]Thread, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var threads []Thread
	if err := json.Unmarshal(raw, &threads); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return threads, nil
}

// PRSuite scores the pull request pipeline of ADR-0062 in two parts. The screen is what reaches
// the LLM: its recall is the share of expected decisions it sends, and its precision is the share
// of what it sends that is an expected decision. Extraction is the whole pipeline: its precision
// is the share of proposals that match an expected decision once, and its recall is the share of
// expected decisions some proposal matches.
func PRSuite(ctx context.Context, complete CompleteFunc, threads []Thread) (Scores, error) {
	var expected, screened, screenedHits, proposed, matched int
	for _, thread := range threads {
		byID := map[string]Comment{}
		for _, c := range thread.Comments {
			byID[c.externalID()] = c
			if c.Expected() {
				expected++
			}
		}
		comments := thread.comments()
		for _, id := range proposals.Screen(thread.Repo, thread.Number, comments) {
			screened++
			if byID[id].Expected() {
				screenedHits++
			}
		}
		found, _, err := proposals.Extract(ctx, proposals.CompleteFunc(complete), thread.Repo, thread.Number, comments, nil)
		if err != nil {
			return nil, fmt.Errorf("thread %s: %w", thread.ID, err)
		}
		seen := map[string]bool{}
		for _, p := range found {
			proposed++
			source := byID[p.ExternalID]
			if source.Expected() && !seen[p.ExternalID] && mentions(p.Title+" "+p.Statement, source.Decision) {
				seen[p.ExternalID] = true
				matched++
			}
		}
	}
	return Scores{
		"pr.screen.precision":  Ratio(screenedHits, screened),
		"pr.screen.recall":     Ratio(screenedHits, expected),
		"pr.extract.precision": Ratio(matched, proposed),
		"pr.extract.recall":    Ratio(matched, expected),
	}, nil
}

func mentions(text string, terms []string) bool {
	text = strings.ToLower(text)
	for _, term := range terms {
		if strings.Contains(text, strings.ToLower(term)) {
			return true
		}
	}
	return false
}
