package proposals

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

const (
	relationPromptVersion = "proposal-relation-v1"
	// maxRelationTokens bounds an answer that holds one word for each of at most five refs.
	maxRelationTokens = 128
	// maxRelationCandidates is how many decisions in force one proposal is compared with (ADR-0172).
	maxRelationCandidates = 5
	// maxRelationTitleRunes bounds a title as the model reads it and as a hint stores it.
	maxRelationTitleRunes = 200
	// maxProposalStatementRunes and maxDecisionStatementRunes bound the statements the model reads.
	maxProposalStatementRunes = 2000
	maxDecisionStatementRunes = 1000
	// relationNone is the answer for a decision the proposal does not relate to. It is never stored.
	relationNone = "none"
)

//go:embed prompts/proposal-relation-v1.txt
var relationPrompt string

// Relation is how a pending proposal relates to one decision in force, as a model judged it. It is a
// hint for the reviewer and changes nothing (ADR-0172).
type Relation string

const (
	// RelationDuplicates means the proposal states the decision again.
	RelationDuplicates Relation = "duplicates"
	// RelationSupersedes means the proposal says it replaces, reverses, or retires the decision.
	RelationSupersedes Relation = "supersedes"
	// RelationConflicts means both cannot hold, and the proposal does not say it replaces the decision.
	RelationConflicts Relation = "conflicts"
)

// relationAnswers is every word an answer may hold for a ref, none included.
var relationAnswers = []string{string(RelationDuplicates), string(RelationSupersedes), string(RelationConflicts), relationNone}

var (
	// ErrRelationRequest means the request names no proposal text, or no candidate, or too many.
	ErrRelationRequest = errors.New("invalid relation request")
	// ErrRelationAnswer means the answer is not one known word for each ref the server sent and for
	// no other. Nothing from it is stored.
	ErrRelationAnswer = errors.New("the answer is not a relation for each decision sent")
)

// DecisionInForce is a decision in force that a proposal can be compared with: its id and version, and
// the title and statement of its body.
type DecisionInForce struct {
	ID        uuid.UUID
	Version   int
	Title     string
	Statement string
}

// Hint is one relation the model found. Title is the title the model read.
type Hint struct {
	DecisionID uuid.UUID
	Version    int
	Title      string
	Relation   Relation
}

// Annotation is what one call found for one proposal: the hints that are not none, the model that
// answered, and the prompt version.
type Annotation struct {
	Hints         []Hint
	Model         string
	PromptVersion string
}

// InForce reads the title and statement of each decision. A decision with no title is left out, and so
// is a sensitive one, marked by `sensitive: true` or the `sensitive` tag (ADR-0072), so that its text is
// never sent to a model.
func InForce(decisions []registry.Decision) []DecisionInForce {
	var out []DecisionInForce
	for _, decision := range decisions {
		var body struct {
			Title     string   `json:"title"`
			Statement string   `json:"statement"`
			Sensitive bool     `json:"sensitive"`
			Tags      []string `json:"tags"`
		}
		if json.Unmarshal(decision.Body, &body) != nil || strings.TrimSpace(body.Title) == "" {
			continue
		}
		if body.Sensitive || slices.Contains(body.Tags, "sensitive") {
			continue
		}
		out = append(out, DecisionInForce{ID: decision.ID, Version: decision.Version, Title: body.Title, Statement: body.Statement})
	}
	return out
}

// RelationCandidates ranks the decisions by the Dice coefficient of their subject stems against the
// proposal's, the measure of Dedupe (ADR-0085), and returns the five closest that share at least one
// stem, closest first and then by id. A change word does not keep a decision apart here, because a
// reversal is what the comparison must find. A decision listed twice counts once.
func RelationCandidates(title, statement string, decisions []DecisionInForce) []DecisionInForce {
	proposal := subjectOf(title + " " + statement).stems
	type scored struct {
		decision DecisionInForce
		score    float64
	}
	var ranked []scored
	seen := map[uuid.UUID]bool{}
	for _, decision := range decisions {
		if seen[decision.ID] {
			continue
		}
		seen[decision.ID] = true
		if score := similarity(proposal, subjectOf(decision.Title+" "+decision.Statement).stems); score > 0 {
			ranked = append(ranked, scored{decision: decision, score: score})
		}
	}
	slices.SortStableFunc(ranked, func(a, b scored) int {
		if a.score != b.score {
			if a.score > b.score {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.decision.ID[:], b.decision.ID[:])
	})
	out := make([]DecisionInForce, 0, min(len(ranked), maxRelationCandidates))
	for _, entry := range ranked[:min(len(ranked), maxRelationCandidates)] {
		out = append(out, entry.decision)
	}
	return out
}

// searchStems are the words keyword search reads to find the decisions an agent proposal may relate to:
// the distinct five-letter stems of its subject words, as prefixes, in the order they appear, at least
// three letters long and at most twelve of them.
func searchStems(title, statement string) []string {
	const most = 12
	var out []string
	for _, word := range subjectWords(title + " " + statement) {
		next := stem(word)
		if len([]rune(next)) < 3 || slices.Contains(out, next) {
			continue
		}
		out = append(out, next)
		if len(out) == most {
			break
		}
	}
	return out
}

// shownDecision is a candidate as the model reads it, under a ref that names it in this call only.
type shownDecision struct {
	Ref       string `json:"ref"`
	Title     string `json:"title"`
	Statement string `json:"statement"`
}

// Relate asks the model how the proposal relates to each candidate. Each candidate goes under a ref of
// this call, d1 to d5, and the answer must hold one of four words for each ref and nothing else. The
// answer is checked here whatever schema the route applied: a ref that was not sent, a missing ref, a
// repeated key, another word, or trailing text is ErrRelationAnswer. The hints name only the
// candidates the caller passed, through the refs, so no answer can point at another decision. The
// model writes no text that is kept. There is no repair round.
func Relate(ctx context.Context, complete SchemaCompleteFunc, title, statement string, candidates []DecisionInForce) (Annotation, error) {
	if strings.TrimSpace(title) == "" {
		return Annotation{}, fmt.Errorf("%w: the proposal has no title", ErrRelationRequest)
	}
	if len(candidates) == 0 || len(candidates) > maxRelationCandidates {
		return Annotation{}, fmt.Errorf("%w: it needs 1 to %d decisions", ErrRelationRequest, maxRelationCandidates)
	}
	refs := make([]string, 0, len(candidates))
	shown := make([]shownDecision, 0, len(candidates))
	for i, candidate := range candidates {
		if candidate.ID == uuid.Nil || candidate.Version < 1 {
			return Annotation{}, fmt.Errorf("%w: a decision has no id or version", ErrRelationRequest)
		}
		next := shownDecision{
			Ref:       fmt.Sprintf("d%d", i+1),
			Title:     truncate(Redact(candidate.Title), maxRelationTitleRunes),
			Statement: truncate(Redact(candidate.Statement), maxDecisionStatementRunes),
		}
		if strings.TrimSpace(next.Title) == "" {
			return Annotation{}, fmt.Errorf("%w: a decision has no title", ErrRelationRequest)
		}
		refs = append(refs, next.Ref)
		shown = append(shown, next)
	}
	user, err := relationMessage(title, statement, shown)
	if err != nil {
		return Annotation{}, err
	}
	answer, err := complete(ctx, relationPrompt, user, maxRelationTokens, relationSchema(refs))
	if err != nil {
		return Annotation{}, err
	}
	words, err := parseRelations(answer.Text, refs)
	if err != nil {
		return Annotation{}, fmt.Errorf("%w: %w", ErrRelationAnswer, err)
	}
	if strings.TrimSpace(answer.Model) == "" {
		return Annotation{}, fmt.Errorf("%w: it names no model", ErrRelationAnswer)
	}
	annotation := Annotation{Model: answer.Model, PromptVersion: relationPromptVersion}
	for i, ref := range refs {
		if word := words[ref]; word != relationNone {
			annotation.Hints = append(annotation.Hints, Hint{
				DecisionID: candidates[i].ID, Version: candidates[i].Version, Title: shown[i].Title, Relation: Relation(word),
			})
		}
	}
	return annotation, nil
}

// relationMessage holds the proposal and then the candidates, in the order the prompt names them, as JSON
// between markers with a random value, so the proposal cannot guess the closing marker or close a JSON
// string.
func relationMessage(title, statement string, decisions []shownDecision) (string, error) {
	type proposalText struct {
		Title     string `json:"title"`
		Statement string `json:"statement"`
	}
	encoded, err := json.Marshal(struct {
		Proposal  proposalText    `json:"proposal"`
		Decisions []shownDecision `json:"decisions"`
	}{
		Proposal: proposalText{
			Title:     truncate(Redact(title), maxRelationTitleRunes),
			Statement: truncate(Redact(statement), maxProposalStatementRunes),
		},
		Decisions: decisions,
	})
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

// relationSchema requires exactly the refs sent, each with one of the four words.
func relationSchema(refs []string) json.RawMessage {
	properties := map[string]any{}
	for _, ref := range refs {
		properties[ref] = map[string]any{"type": "string", "enum": relationAnswers}
	}
	schema, err := json.Marshal(map[string]any{
		"type":                 "object",
		"properties":           properties,
		"required":             refs,
		"additionalProperties": false,
	})
	if err != nil {
		panic(err)
	}
	return schema
}

// parseRelations reads one JSON object, optionally inside one Markdown code fence, that holds each ref
// once with one of the four words, and no other key and nothing after it.
func parseRelations(text string, refs []string) (map[string]string, error) {
	if len(text) > maxOutputBytes {
		return nil, errors.New("the answer is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(unfence(text)))
	if err := delim(decoder, '{'); err != nil {
		return nil, err
	}
	words := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, _ := token.(string)
		if !slices.Contains(refs, key) {
			return nil, fmt.Errorf("the key %q names no decision sent", key)
		}
		if _, repeated := words[key]; repeated {
			return nil, fmt.Errorf("the key %q is repeated", key)
		}
		var word string
		if err := decoder.Decode(&word); err != nil {
			return nil, fmt.Errorf("the value of %q is not a word: %w", key, err)
		}
		if !slices.Contains(relationAnswers, word) {
			return nil, fmt.Errorf("the value of %q is not one of the four words", key)
		}
		words[key] = word
	}
	if err := delim(decoder, '}'); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("it holds more than one JSON value")
	}
	if len(words) != len(refs) {
		return nil, errors.New("it does not answer every decision sent")
	}
	return words, nil
}
