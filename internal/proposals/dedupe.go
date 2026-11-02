package proposals

// sameDecision is the Dice similarity of two texts' subject words at or above which they state
// the same decision (ADR-0085). The restatement in the golden set scores 0.83 and the paraphrase
// in the unit tests 0.77; "Use Postgres for new services" and "Use Redis for new services" score
// 0.67.
const sameDecision = 0.75

// changeWords mark a text that negates, ends, or replaces a decision. Such a text never folds into
// one without them, so a reversal of a known decision is always proposed.
var changeWords = map[string]bool{
	"not": true, "no": true, "never": true, "nor": true, "without": true, "instead": true, "cannot": true,
	"don": true, "doesn": true, "won": true, "stop": true, "stops": true, "stopped": true, "replace": true,
	"replaces": true, "replaced": true, "switch": true, "switches": true, "switched": true, "migrate": true,
	"migrates": true, "migrated": true, "move": true, "moves": true, "moved": true, "moving": true,
	"drop": true, "drops": true, "dropped": true, "remove": true, "removes": true, "removed": true,
	"deprecate": true, "deprecates": true, "deprecated": true, "retire": true, "retires": true,
	"retired": true, "ban": true, "bans": true, "banned": true, "avoid": true, "avoids": true,
	"non": true, "nicht": true, "kein": true, "keine": true, "pas": true, "nunca": true,
}

// Dedupe drops a proposal that states a decision the tenant already has, as a registry title or
// a pending proposal in known, or that an earlier proposal of found states. found keeps its order,
// so the first comment that states a decision is the one that is proposed. Two texts that differ
// only in the thing they name, with no change word, can still fold; a missed duplicate costs a
// reviewer one rejection, so the threshold leans toward keeping.
func Dedupe(found []Proposal, known []string) ([]Proposal, int) {
	seen := make([]subject, 0, len(known)+len(found))
	for _, text := range known {
		if entry := subjectOf(text); len(entry.stems) > 0 {
			seen = append(seen, entry)
		}
	}
	var kept []Proposal
	dropped := 0
	for _, proposal := range found {
		next := subjectOf(proposal.Title + " " + proposal.Statement)
		if duplicates(next, seen) {
			dropped++
			continue
		}
		seen = append(seen, next)
		kept = append(kept, proposal)
	}
	return kept, dropped
}

// subject is what Dedupe compares of a text: the stems of its subject words, and whether it holds
// a change word.
type subject struct {
	stems   map[string]bool
	changes bool
}

func subjectOf(text string) subject {
	words := subjectWords(text)
	next := subject{stems: make(map[string]bool, len(words))}
	for _, word := range words {
		next.stems[stem(word)] = true
		next.changes = next.changes || changeWords[word]
	}
	return next
}

// stem is a word's first five letters, so two words hold the same stem exactly when holds
// matches them.
func stem(word string) string {
	if runes := []rune(word); len(runes) > 5 {
		return string(runes[:5])
	}
	return word
}

func duplicates(next subject, seen []subject) bool {
	for _, other := range seen {
		if next.changes == other.changes && similarity(next.stems, other.stems) >= sameDecision {
			return true
		}
	}
	return false
}

// similarity is the Dice coefficient of two sets of stems.
func similarity(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	held := 0
	for word := range a {
		if b[word] {
			held++
		}
	}
	return 2 * float64(held) / float64(len(a)+len(b))
}
