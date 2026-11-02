package proposals

// sameDecision is the share of the shorter text's subject words that the other text holds above
// which two texts state the same decision (ADR-0085).
const sameDecision = 0.6

// Dedupe drops a proposal that states a decision the tenant already has, as a registry title or
// a pending proposal in known, or that an earlier proposal of found states. found keeps its order,
// so the first comment that states a decision is the one that is proposed.
func Dedupe(found []Proposal, known []string) ([]Proposal, int) {
	seen := make([][]string, 0, len(known)+len(found))
	for _, text := range known {
		if words := subjectWords(text); len(words) > 0 {
			seen = append(seen, words)
		}
	}
	var kept []Proposal
	dropped := 0
	for _, proposal := range found {
		words := subjectWords(proposal.Title + " " + proposal.Statement)
		if duplicates(words, seen) {
			dropped++
			continue
		}
		seen = append(seen, words)
		kept = append(kept, proposal)
	}
	return kept, dropped
}

func duplicates(words []string, seen [][]string) bool {
	for _, other := range seen {
		if overlap(words, other) >= sameDecision {
			return true
		}
	}
	return false
}

// overlap is the share of the shorter list's words that the other list holds, where a shared
// five-letter stem counts as the same word.
func overlap(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	held := 0
	for _, word := range a {
		for _, other := range b {
			if word == other || sharedPrefix(word, other) >= 5 {
				held++
				break
			}
		}
	}
	return float64(held) / float64(len(a))
}
