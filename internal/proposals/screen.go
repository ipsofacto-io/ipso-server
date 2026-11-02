package proposals

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/redact"
)

// decisionLike is the classifier in front of the LLM. It keeps text that does not read like a
// decision off the wire: a group that decided, agreed, chose, settled, standardized, or is moving
// to something; a stated outcome ("decision:", "the decision is", "outcomes from the", "as
// decided"); something deprecated or retired; a change from now on; and the same
// first-person-plural verbs in Italian, German, French, and Spanish. The eval harness measures
// its precision and recall (ADR-0085).
var decisionLike = regexp.MustCompile(`(?i)` +
	`\b(we|team)\s+(have\s+|'ve\s+)?(decided|agreed|chose|settled\s+on|standardi[sz]ed\s+on|will\s+use|are\s+going\s+with)\b` +
	`|\bwe('re|\s+are)\s+(going|moving|switching|standardi[sz]ing)\s+(\S+\s+){0,3}?(with|to|on)\b|\bwe\s+should\s+standardi[sz]e\b` +
	`|\boutcomes?\s+(from|of)\s+the\b|\b(is|are)\s+(now\s+)?(deprecated|retired)\b` +
	`|\b(decision|settled|rule\s+from\s+today)\s*:|\bthe\s+decision\s+is\b|\bas\s+decided\b|\blet'?s\s+(go|stick)\s+with\b` +
	`|\b(going\s+forward|from\s+now\s+on|from\s+(today|this\s+release)\s+on)\b` +
	`|\babbiamo\s+(deciso|scelto|concordato)\b|\bwir\s+haben\s+(uns\s+)?(entschieden|beschlossen)\b` +
	`|\b(nous\s+avons|on\s+a)\s+(d[ée]cid[ée]|choisi)|\b(hemos\s+decidido|decidimos)\b`)

// injectionMarkers are lowercase, whitespace-collapsed phrases that address a model rather than a
// reader. A comment that holds one is not sent to the LLM. This list is one control among
// several, and IPSO-58 measures it. The others are the trust gate, the data markers, the strict
// output check, and a schema that cannot hold an approval.
var injectionMarkers = regexp.MustCompile(`ignore (all |any |the |your )*(previous|prior|above|earlier)|disregard (all |any |the |your )*(previous|prior|above|earlier|instructions)|forget (all |your |the )*(previous|prior|instructions)|system prompt|developer message|you are now|new instructions|act as (an? )?(admin|system|assistant)|auto[- ]?approve|mark (this|it) as (approved|accepted)|set status|status"? ?: ?"?(approved|accepted)|<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<</?sys>>|(^| )(system|assistant): `)

var (
	mentionPattern = regexp.MustCompile(`(^|[^\w])@[A-Za-z0-9][A-Za-z0-9-]*`)
	// unsafeOutput is what a proposal must not hold, because a reviewer's screen could render it.
	unsafeOutput = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://|\bwww\.|[<>]|!\[|\]\(|@[a-z0-9]`)
)

// Redact removes secrets, email addresses, and mentions. It runs on all text before the LLM.
func Redact(text string) string {
	return mentionPattern.ReplaceAllString(redact.Text(text), "${1}[user]")
}

// trusted reports whether the author can already write to the repository. Anyone can comment on a
// public repository, so text from anyone else never reaches the LLM. A bot is not a person
// deciding anything. The association comes from the API, not from the comment text.
func trusted(comment integrations.Comment) bool {
	if comment.AuthorType != "User" {
		return false
	}
	switch comment.Association {
	case "OWNER", "MEMBER", "COLLABORATOR":
		return true
	default:
		return false
	}
}

// suspicious reports text that addresses a model, or that hides characters from a reader.
func suspicious(text string) bool {
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return true
		}
	}
	return injectionMarkers.MatchString(strings.Join(strings.Fields(strings.ToLower(text)), " "))
}

// plainField reports whether one LLM output field is safe to keep. It refuses a field that a
// reviewer's screen could render, that still holds a secret or an address, or that addresses a
// model.
func plainField(text string) bool {
	return !unsafeOutput.MatchString(text) && Redact(text) == text && !suspicious(text)
}

// fillerWords carry no subject, so a title made of them says nothing the statement does.
var fillerWords = map[string]bool{
	"a": true, "an": true, "and": true, "as": true, "at": true, "be": true, "by": true, "decided": true,
	"decision": true, "for": true, "in": true, "is": true, "it": true, "of": true, "on": true, "or": true,
	"our": true, "team": true, "the": true, "this": true, "to": true, "use": true, "uses": true,
	"using": true, "we": true, "will": true, "with": true,
}

// grounded reports whether a title shares a word with its statement, or a stem of five letters,
// so "Standardize logs" fits "log standardization". A title an injected comment dictated, such as
// one code word above a real statement, does not (ADR-0084).
func grounded(title, statement string) bool {
	stated := subjectWords(statement)
	for _, word := range subjectWords(title) {
		for _, other := range stated {
			if word == other || sharedPrefix(word, other) >= 5 {
				return true
			}
		}
	}
	return false
}

// subjectWords returns the distinct words of a text that are not filler.
func subjectWords(text string) []string {
	var words []string
	seen := map[string]bool{}
	for _, word := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if utf8.RuneCountInString(word) >= 2 && !fillerWords[word] && !seen[word] {
			seen[word] = true
			words = append(words, word)
		}
	}
	return words
}

func sharedPrefix(a, b string) int {
	ar, br := []rune(a), []rune(b)
	n := 0
	for n < len(ar) && n < len(br) && ar[n] == br[n] {
		n++
	}
	return n
}
