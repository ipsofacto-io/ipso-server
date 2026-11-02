// Package redact removes secrets and email addresses from text before it leaves the server. The
// LLM gateway runs it on every prompt, and a caller may run it earlier as well (ADR-0062).
package redact

import "regexp"

// Marker replaces each match.
const Marker = "[REDACTED]"

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

var emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

// Text replaces secrets and email addresses with Marker.
func Text(text string) string {
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, Marker)
	}
	return emailPattern.ReplaceAllString(text, Marker)
}
