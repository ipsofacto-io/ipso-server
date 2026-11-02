// Package proposals turns merged pull request discussion into decision proposals for a person to
// review (ADR-0062). LLM output is advisory, so nothing here can approve a proposal (ADR-0005),
// and the database refuses any status but pending. The binary does not call this package yet:
// the control plane wires it to the LLM gateway once row-level security exists.
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
	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
)

const (
	promptVersion  = "pr-decision-v2"
	maxSent        = 20
	maxBodyRunes   = 4000
	maxCandidates  = 5
	maxTitleRunes  = 120
	maxFieldRunes  = 1000
	maxOutputBytes = 64 << 10
)

//go:embed prompts/pr-decision-v2.txt
var systemPrompt string

// Completion is one answer from the LLM gateway.
type Completion = llmgw.Completion

// ErrAnswer means the model's answer is not the one object the prompt asks for. Nothing from it
// is stored.
var ErrAnswer = errors.New("the answer is not the expected JSON")

// CompleteFunc calls the LLM gateway for one tenant, as llmgw.Gateway.For returns it. The gateway
// owns routing, budgets, and its own redaction (ADR-0081).
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
	picks, stats := screen(repo, number, comments, seen)
	if len(picks) == 0 {
		return nil, stats, nil
	}
	stats.Sent = len(picks)

	user, err := userMessage(picks)
	if err != nil {
		return nil, stats, err
	}
	canary, err := randomHex()
	if err != nil {
		return nil, stats, err
	}
	answer, err := complete(ctx, systemPrompt+" CANARY-"+canary+"\n", user)
	if err != nil {
		return nil, stats, fmt.Errorf("complete: %w", err)
	}
	// An answer that repeats the marker obeyed a comment over the instructions, so none of it is
	// kept. Half the marker is enough to tell.
	if strings.Contains(strings.ToLower(answer.Text), canary[:16]) {
		return nil, stats, fmt.Errorf("%w: it repeats the secret marker", ErrAnswer)
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

// Screen returns the external ids of the comments the four gates would send to the LLM, in order.
// The eval harness measures the gates with it (IPSO-59).
func Screen(repo string, number int, comments []integrations.Comment) []string {
	picks, _ := screen(repo, number, comments, nil)
	ids := make([]string, 0, len(picks))
	for _, pick := range picks {
		ids = append(ids, pick.comment.ExternalID)
	}
	return ids
}

func screen(repo string, number int, comments []integrations.Comment, seen func(externalID string, digest [32]byte) bool) ([]selected, Stats) {
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
	return picks, stats
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
	nonce, err := randomHex()
	if err != nil {
		return "", err
	}
	marker := "DATA-" + nonce
	return marker + "\n" + string(encoded) + "\n" + marker, nil
}

// randomHex returns 32 random hexadecimal digits.
func randomHex() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type candidate struct {
	Source     *int     `json:"source"`
	Title      string   `json:"title"`
	Statement  string   `json:"statement"`
	Rationale  string   `json:"rationale"`
	Confidence *float64 `json:"confidence"`
}

// parseAnswer refuses anything but the one object the prompt asks for, optionally inside one
// Markdown code fence. An unknown field, such as a status an injected comment asked for, refuses
// the whole answer.
func parseAnswer(text string) ([]candidate, error) {
	if len(text) > maxOutputBytes {
		return nil, fmt.Errorf("%w: it is too large", ErrAnswer)
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	decoder.DisallowUnknownFields()
	var answer struct {
		Candidates []candidate `json:"candidates"`
	}
	if err := decoder.Decode(&answer); err != nil {
		return nil, ErrAnswer
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: it holds more than one value", ErrAnswer)
	}
	if len(answer.Candidates) > maxCandidates {
		return nil, fmt.Errorf("%w: it holds too many candidates", ErrAnswer)
	}
	return answer.Candidates, nil
}

// unfence removes one Markdown code fence that wraps the whole answer, as ```json ... ```.
func unfence(text string) string {
	trimmed := strings.TrimSpace(text)
	body, ok := strings.CutPrefix(trimmed, "```")
	if !ok {
		return text
	}
	body, ok = strings.CutSuffix(body, "```")
	if !ok {
		return text
	}
	info, rest, found := strings.Cut(body, "\n")
	if !found || (info != "" && info != "json") {
		return text
	}
	return rest
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
	return plainField(c.Title) && plainField(c.Statement) && plainField(c.Rationale) && grounded(c.Title, c.Statement)
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
