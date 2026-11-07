package evals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// Thread is one synthetic pull request discussion.
type Thread struct {
	ID       string    `json:"id"`
	Repo     string    `json:"repo"`
	Number   int       `json:"number"`
	Comments []Comment `json:"comments"`
	// Registry lists the titles of decisions the tenant already has.
	Registry []string `json:"registry,omitempty"`
}

// Comment is one labeled comment. Decision lists key terms of the decision the comment states,
// and is empty when it states none. A proposal matches when its title or statement holds one.
// Known marks a decision the registry or an earlier comment of the thread already holds, so a
// proposal from it is a duplicate.
type Comment struct {
	ID       int      `json:"id"`
	Author   string   `json:"author"`
	Body     string   `json:"body"`
	Decision []string `json:"decision"`
	Known    bool     `json:"known,omitempty"`
}

// Expected reports whether a correct pipeline proposes a decision from this comment. ADR-0062
// and ADR-0104 read only people who can already write to the repository, so a decision stated by
// anyone else is not expected.
func (c Comment) Expected() bool {
	return len(c.Decision) > 0 && !c.Known && writes(c.Author)
}

// writes reports whether a dataset label names an author who can write to the repository. The labels
// are the author associations the datasets were written with, and the harness gives them the meaning
// the repository permission has in production (ADR-0104).
func writes(label string) bool {
	switch label {
	case "OWNER", "MEMBER", "COLLABORATOR":
		return true
	}
	return false
}

// canWrite is the WriteAccess of the harness: the label of an author says what the author can do.
func canWrite(_ context.Context, label string) (bool, error) {
	return writes(label), nil
}

func (c Comment) externalID() string {
	return fmt.Sprintf("issuecomment-%d", c.ID)
}

func (t Thread) comments() []integrations.Comment {
	out := make([]integrations.Comment, 0, len(t.Comments))
	for _, c := range t.Comments {
		authorType := "User"
		if c.Author == "bot" {
			authorType = "Bot"
		}
		out = append(out, integrations.Comment{
			ExternalID: c.externalID(),
			URL:        fmt.Sprintf("https://github.com/%s/pull/%d#%s", t.Repo, t.Number, c.externalID()),
			Body:       c.Body,
			Author:     c.Author,
			AuthorType: authorType,
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
// of what it sends that is an expected decision. Extraction is the whole pipeline, dedupe against
// the thread's registry included: its precision is the share of proposals that match an expected
// decision once, so a duplicate counts against it, and its recall is the share of expected
// decisions some proposal matches. Each thread logs its screen, extraction, and proposal count on t.
func PRSuite(t *testing.T, ctx context.Context, complete CompleteFunc, threads []Thread) (Scores, error) {
	var expected, screened, screenedHits, proposed, matched, asked, answered int
	for i, thread := range threads {
		byID := map[string]Comment{}
		for _, c := range thread.Comments {
			byID[c.externalID()] = c
			if c.Expected() {
				expected++
			}
		}
		comments := thread.comments()
		sent, err := proposals.Screen(ctx, canWrite, thread.Repo, thread.Number, comments)
		if err != nil {
			return nil, fmt.Errorf("thread %s: %w", thread.ID, err)
		}
		for _, id := range sent {
			screened++
			if byID[id].Expected() {
				screenedHits++
			}
		}
		found, stats, err := proposals.Extract(ctx, proposals.CompleteFunc(complete), canWrite, thread.Repo, thread.Number, comments, nil)
		if stats.Sent > 0 {
			asked++
		}
		// A malformed answer is a quality failure the scores show. Anything else stops the suite.
		if err != nil && !errors.Is(err, proposals.ErrAnswer) {
			return nil, fmt.Errorf("thread %s: %w", thread.ID, err)
		}
		if err == nil && stats.Sent > 0 {
			answered++
		}
		found, _ = proposals.Dedupe(found, thread.Registry)
		seen := map[string]bool{}
		for _, p := range found {
			proposed++
			source := byID[p.ExternalID]
			if source.Expected() && !seen[p.ExternalID] && mentions(p.Title+" "+p.Statement, source.Decision) {
				seen[p.ExternalID] = true
				matched++
			}
		}
		extract := "ok"
		if errors.Is(err, proposals.ErrAnswer) {
			extract = "bad_answer"
		}
		screen := "kept"
		if len(sent) > 0 {
			screen = "sent"
		}
		t.Logf("pr %d/%d %s screen=%s extract=%s proposals=%d", i+1, len(threads), thread.ID, screen, extract, len(found))
	}
	return Scores{
		"pr.screen.precision":  Ratio(screenedHits, screened),
		"pr.screen.recall":     Ratio(screenedHits, expected),
		"pr.extract.precision": Ratio(matched, proposed),
		"pr.extract.recall":    Ratio(matched, expected),
		"pr.extract.valid":     Ratio(answered, asked),
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
