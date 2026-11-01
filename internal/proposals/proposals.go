// Package proposals turns merged pull request discussion into decision proposals for a person to
// review (ADR-0062). LLM output is advisory, so nothing here can approve a proposal (ADR-0005),
// and the database refuses any status but pending. The binary does not call this package yet:
// the control plane wires it once row-level security and the LLM gateway exist.
package proposals

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed" // the prompt template is versioned in this repository
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
)

const (
	promptVersion  = "pr-decision-v1"
	maxSent        = 20
	maxBodyRunes   = 4000
	maxCandidates  = 5
	maxTitleRunes  = 120
	maxFieldRunes  = 1000
	maxOutputBytes = 64 << 10
)

//go:embed prompts/pr-decision-v1.txt
var systemPrompt string

// Completion is one answer from the LLM gateway.
type Completion struct {
	Text  string
	Model string
}

// CompleteFunc calls the LLM gateway of IPSO-55. It owns routing, budgets, and its own redaction.
type CompleteFunc func(ctx context.Context, system, user string) (Completion, error)

// Proposal is one candidate that passed every check. It has no status field, because the only
// status a proposal can have here is pending.
type Proposal struct {
	Repo           string
	Number         int
	ExternalID     string
	SourceURL      string
	SourceSHA256   [32]byte
	CandidateIndex int
	Title          string
	Statement      string
	Rationale      string
	Confidence     float64
	Model          string
	PromptVersion  string
}

// Stats counts what happened to the discussion. It holds no text and names no person (ADR-0012).
type Stats struct {
	Comments  int
	Untrusted int
	Flagged   int
	Sent      int
	Refused   int
}

type selected struct {
	comment integrations.Comment
	text    string
	digest  [32]byte
}

// Extract screens the discussion, asks the LLM, and checks its answer. A comment passes four
// gates before any egress: a trusted author, a provenance link for this pull request, no
// injection marker, and decision-like text. Redacted text is sent, and only for those comments.
func Extract(ctx context.Context, complete CompleteFunc, repo string, number int, comments []integrations.Comment, seen func(externalID string, digest [32]byte) bool) ([]Proposal, Stats, error) {
	stats := Stats{Comments: len(comments)}
	var picks []selected
	for _, comment := range comments {
		if strings.TrimSpace(comment.Body) == "" {
			continue
		}
		if !trusted(comment) {
			stats.Untrusted++
			continue
		}
		if !provenance(repo, number, comment.URL) || !decisionLike.MatchString(comment.Body) {
			continue
		}
		if suspicious(comment.Body) {
			stats.Flagged++
			continue
		}
		digest := sha256.Sum256([]byte(comment.Body))
		if seen != nil && seen(comment.ExternalID, digest) {
			continue
		}
		if len(picks) == maxSent {
			break
		}
		picks = append(picks, selected{comment: comment, text: truncate(Redact(comment.Body), maxBodyRunes), digest: digest})
	}
	if len(picks) == 0 {
		return nil, stats, nil
	}
	stats.Sent = len(picks)

	user, err := userMessage(picks)
	if err != nil {
		return nil, stats, err
	}
	answer, err := complete(ctx, systemPrompt, user)
	if err != nil {
		return nil, stats, fmt.Errorf("complete: %w", err)
	}
	candidates, err := parseAnswer(answer.Text)
	if err != nil {
		return nil, stats, err
	}

	var proposals []Proposal
	for index, candidate := range candidates {
		if !candidate.valid(len(picks)) {
			stats.Refused++
			continue
		}
		pick := picks[*candidate.Source]
		proposals = append(proposals, Proposal{
			Repo:           repo,
			Number:         number,
			ExternalID:     pick.comment.ExternalID,
			SourceURL:      pick.comment.URL,
			SourceSHA256:   pick.digest,
			CandidateIndex: index,
			Title:          candidate.Title,
			Statement:      candidate.Statement,
			Rationale:      candidate.Rationale,
			Confidence:     *candidate.Confidence,
			Model:          answer.Model,
			PromptVersion:  promptVersion,
		})
	}
	return proposals, stats, nil
}

// provenance reports whether the link is a github.com link to this pull request. The link comes
// from the API, and it is checked again because it ends up in front of a reviewer.
func provenance(repo string, number int, link string) bool {
	prefix := fmt.Sprintf("https://github.com/%s/pull/%d", repo, number)
	rest, found := strings.CutPrefix(link, prefix)
	return found && len(link) <= 2048 && validFragment.MatchString(rest)
}

var validFragment = regexp.MustCompile(`^(#[A-Za-z0-9_-]+)?$`)

// userMessage holds the comments as JSON between markers with a random value, so a comment cannot
// guess the closing marker or close a JSON string.
func userMessage(picks []selected) (string, error) {
	type item struct {
		Index int    `json:"index"`
		Text  string `json:"text"`
	}
	items := make([]item, 0, len(picks))
	for i, pick := range picks {
		items = append(items, item{Index: i, Text: pick.text})
	}
	encoded, err := json.Marshal(map[string]any{"comments": items})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	marker := "DATA-" + hex.EncodeToString(nonce)
	return marker + "\n" + string(encoded) + "\n" + marker, nil
}

type candidate struct {
	Source     *int     `json:"source"`
	Title      string   `json:"title"`
	Statement  string   `json:"statement"`
	Rationale  string   `json:"rationale"`
	Confidence *float64 `json:"confidence"`
}

// parseAnswer refuses anything but the one object the prompt asks for. An unknown field, such as
// a status an injected comment asked for, refuses the whole answer.
func parseAnswer(text string) ([]candidate, error) {
	if len(text) > maxOutputBytes {
		return nil, errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	var answer struct {
		Candidates []candidate `json:"candidates"`
	}
	if err := decoder.Decode(&answer); err != nil {
		return nil, errors.New("the answer is not the expected JSON")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the answer holds more than one value")
	}
	if len(answer.Candidates) > maxCandidates {
		return nil, errors.New("the answer holds too many candidates")
	}
	return answer.Candidates, nil
}

func (c candidate) valid(sources int) bool {
	if c.Source == nil || *c.Source < 0 || *c.Source >= sources {
		return false
	}
	if c.Confidence == nil || *c.Confidence < 0 || *c.Confidence > 1 {
		return false
	}
	title, statement := utf8.RuneCountInString(c.Title), utf8.RuneCountInString(c.Statement)
	if title == 0 || title > maxTitleRunes || statement == 0 || statement > maxFieldRunes || utf8.RuneCountInString(c.Rationale) > maxFieldRunes {
		return false
	}
	return plainField(c.Title) && plainField(c.Statement) && plainField(c.Rationale)
}

func truncate(text string, limit int) string {
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	return string([]rune(text)[:limit])
}

// payload is the stored form of a candidate.
func (p Proposal) payload() ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(map[string]string{"title": p.Title, "statement": p.Statement, "rationale": p.Rationale})
	return buffer.Bytes(), err
}
