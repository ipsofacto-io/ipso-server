package proposals

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
)

// decisionLike is the deterministic filter in front of the LLM. It keeps text that does not read
// like a decision off the wire. Its precision and recall are measured with IPSO-59.
var decisionLike = regexp.MustCompile(`(?i)\b(we|team)\s+(have\s+)?(decided|agreed|chose|will\s+use|are\s+going\s+with)\b|\bdecision\s*:|\blet'?s\s+(go|stick)\s+with\b|\bwe\s+should\s+standardi[sz]e\b|\bgoing\s+forward\b`)

// injectionMarkers are lowercase, whitespace-collapsed phrases that address a model rather than a
// reader. A comment that holds one is not sent to the LLM. This list is one control among
// several, and IPSO-58 measures it. The others are the trust gate, the data markers, the strict
// output check, and a schema that cannot hold an approval.
var injectionMarkers = regexp.MustCompile(`ignore (all |any |the |your )*(previous|prior|above|earlier)|disregard (all |any |the |your )*(previous|prior|above|earlier|instructions)|forget (all |your |the )*(previous|prior|instructions)|system prompt|developer message|you are now|new instructions|act as (an? )?(admin|system|assistant)|auto[- ]?approve|mark (this|it) as (approved|accepted)|set status|status"? ?: ?"?(approved|accepted)|<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<</?sys>>|(^| )(system|assistant): `)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`),
	regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*\S+`),
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@\S+`),
}

var (
	emailPattern   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	mentionPattern = regexp.MustCompile(`(^|[^\w])@[A-Za-z0-9][A-Za-z0-9-]*`)
	// unsafeOutput is what a proposal must not hold, because a reviewer's screen could render it.
	unsafeOutput = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://|\bwww\.|[<>]|!\[|\]\(|@[a-z0-9]`)
)

const redacted = "[REDACTED]"

// Redact removes secrets, email addresses, and mentions. It runs on all text before the LLM.
func Redact(text string) string {
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, redacted)
	}
	text = emailPattern.ReplaceAllString(text, redacted)
	return mentionPattern.ReplaceAllString(text, "${1}[user]")
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
