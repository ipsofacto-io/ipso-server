package proposals

import (
	"context"
	"crypto/sha256"
	"strings"
	"unicode/utf8"
)

// ExtractTicket screens one tracker ticket and, when it reads like a decision, asks the model.
// The binding is the gate: there is no repository write bit. The text stays untrusted. A flagged
// ticket is not sent. The ticket body is not returned. seen reports a digest this connector and
// external id already stored, so a redelivery does not call the model again (ADR-0133, ADR-0085).
func ExtractTicket(ctx context.Context, complete CompleteFunc, externalID, sourceURL, title, body string, seen func(digest [32]byte) bool) ([]Proposal, bool, error) {
	text := strings.TrimSpace(title)
	if body = strings.TrimSpace(body); body != "" {
		if text != "" {
			text += "\n"
		}
		text += body
	}
	if text == "" || externalID == "" || sourceURL == "" {
		return nil, false, nil
	}
	if suspicious(text) {
		return nil, true, nil
	}
	if !decisionLike.MatchString(text) {
		return nil, false, nil
	}
	digest := sha256.Sum256([]byte(text))
	if seen != nil && seen(digest) {
		return nil, false, nil
	}
	if complete == nil {
		return nil, false, nil
	}
	user, err := userMessage([]selected{{text: truncate(Redact(text), maxBodyRunes), digest: digest}})
	if err != nil {
		return nil, false, err
	}
	canary, err := randomHex()
	if err != nil {
		return nil, false, err
	}
	answer, err := complete(ctx, systemPrompt+" CANARY-"+canary+"\n", user, maxAnswerTokens)
	if err != nil {
		return nil, false, err
	}
	if strings.Contains(strings.ToLower(answer.Text), canary[:16]) {
		return nil, false, ErrAnswer
	}
	candidates, err := parseAnswer(answer.Text)
	if err != nil {
		return nil, false, err
	}
	var found []Proposal
	for index, candidate := range candidates {
		if !candidate.valid(1) {
			continue
		}
		model := strings.TrimSpace(answer.Model)
		if model == "" || utf8.RuneCountInString(model) > 200 || strings.ContainsAny(model, "\r\n") {
			continue
		}
		found = append(found, Proposal{
			ExternalID:     externalID,
			SourceURL:      sourceURL,
			SourceSHA256:   digest,
			CandidateIndex: index,
			Title:          candidate.Title,
			Statement:      candidate.Statement,
			Rationale:      candidate.Rationale,
			Confidence:     *candidate.Confidence,
			Model:          model,
			PromptVersion:  promptVersion,
		})
	}
	return found, false, nil
}
