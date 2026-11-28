package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	// AdvisoryCheckName is the GitHub check run name for llm-advisory verdicts (IPSO-162).
	// It is separate from checkName ("ipso / decisions") so branch protection on deterministic
	// decision checks never entangles with advisory verdicts.
	AdvisoryCheckName = "ipso / advisory"
	// advisoryConclusion is the only conclusion an advisory check run may ever report.
	// It never concludes failure or action_required (ADR-0005, ADR-0152, IPSO-162).
	advisoryConclusion = "neutral"
	// maxAdvisoryTitleRunes bounds one annotation title.
	maxAdvisoryTitleRunes = 255
)

var (
	mdLinkPattern  = regexp.MustCompile(`\[([^\]\r\n]+)\]\([^)\r\n]+\)`)
	urlPattern     = regexp.MustCompile(`(?i)\b(?:https?://|www\.)\S+`)
	mentionPattern = regexp.MustCompile(`@[A-Za-z0-9][A-Za-z0-9_.-]*`)
	anglePattern   = regexp.MustCompile(`[<>]`)
)

// AdvisoryAnnotation is one line annotation on the ipso / advisory check run.
// Level may only be "warning" or "notice"; any other value is clamped to "notice".
type AdvisoryAnnotation struct {
	Path      string
	StartLine int
	EndLine   int
	Level     string
	Title     string
	Message   string
}

// AdvisoryCheckRun is the output of one ipso / advisory check run.
// Title and Summary must be server-authored text and never hold model reasons or repository text.
type AdvisoryCheckRun struct {
	Title       string
	Summary     string
	Annotations []AdvisoryAnnotation
}

// SanitizeAdvisoryText renders untrusted text as safe plain text with no Markdown links,
// bare URLs, HTML angle brackets, mentions, or control characters (IPSO-162).
func SanitizeAdvisoryText(text string) string {
	s := mdLinkPattern.ReplaceAllString(text, "$1")
	s = urlPattern.ReplaceAllString(s, "")
	s = mentionPattern.ReplaceAllString(s, "[mention removed]")
	s = anglePattern.ReplaceAllString(s, "")
	s = stripControlRunes(s, false)
	return strings.Join(strings.Fields(s), " ")
}

// SanitizeAdvisoryLabel strips control characters and angle brackets from model_id or prompt_version
// metadata before placing it into a plain-text annotation label.
func SanitizeAdvisoryLabel(text string) string {
	s := anglePattern.ReplaceAllString(text, "")
	s = stripControlRunes(s, false)
	return strings.TrimSpace(s)
}

func stripControlRunes(s string, keepNewline bool) string {
	return strings.Map(func(r rune) rune {
		if keepNewline && r == '\n' {
			return '\n'
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

func capRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return s
}

func normalizeAdvisoryAnnotation(a AdvisoryAnnotation) (annotation, bool) {
	path := strings.TrimSpace(stripControlRunes(a.Path, false))
	if path == "" {
		return annotation{}, false
	}
	start := max(a.StartLine, 1)
	end := max(a.EndLine, start)
	level := "notice"
	if a.Level == "warning" {
		level = "warning"
	}
	title := capRunes(strings.TrimSpace(SanitizeAdvisoryText(a.Title)), maxAdvisoryTitleRunes)
	if title == "" {
		title = "Advisory verdict"
	}
	msg := capRunes(strings.TrimSpace(stripControlRunes(a.Message, true)), maxMessageRunes)
	if msg == "" {
		msg = "AI-generated advisory verdict. Advisory only; does not block a merge."
	}
	return annotation{
		Path:      path,
		StartLine: start,
		EndLine:   end,
		Level:     level,
		Title:     title,
		Message:   msg,
	}, true
}

// HasAdvisoryCheckRun reports whether this GitHub App already has a completed
// ipso / advisory check run on headSHA.
func (c *RepoClient) HasAdvisoryCheckRun(ctx context.Context, headSHA string) (bool, error) {
	if !validSHA.MatchString(headSHA) {
		return false, errors.New("check advisory check run: head_sha is not a commit SHA")
	}
	var resp struct {
		CheckRuns []struct {
			ID int64 `json:"id"`
		} `json:"check_runs"`
	}
	q := url.Values{
		"check_name": {AdvisoryCheckName},
		"status":     {"completed"},
		"app_id":     {c.app.id},
		"per_page":   {"1"},
	}
	path := c.repoPath("/commits/" + headSHA + "/check-runs?" + q.Encode())
	if err := c.app.call(ctx, c.token, http.MethodGet, path, nil, &resp); err != nil {
		return false, fmt.Errorf("list advisory check runs: %w", err)
	}
	return len(resp.CheckRuns) > 0, nil
}

// PublishAdvisoryCheckRun creates and completes an ipso / advisory check run on headSHA.
// It always concludes neutral and never concludes failure or action_required.
// When annotations fit within 50 items, the check run is created completed in one request;
// when more than 50 items exist, POST opens the run in_progress and only the final PATCH
// marks it completed with conclusion neutral, so a failed intermediate PATCH never fools
// HasAdvisoryCheckRun into skipping retry on webhook redelivery.
func (c *RepoClient) PublishAdvisoryCheckRun(ctx context.Context, headSHA string, run AdvisoryCheckRun) error {
	if !validSHA.MatchString(headSHA) {
		return errors.New("publish advisory check run: head_sha is not a commit SHA")
	}
	title := capRunes(strings.TrimSpace(stripControlRunes(run.Title, false)), maxAdvisoryTitleRunes)
	if title == "" {
		title = "Advisory check"
	}
	summary := strings.TrimSpace(stripControlRunes(run.Summary, true))
	if summary == "" {
		summary = "AI-generated advisory verdicts from llm-advisory checks. These results are advisory only and never block a merge or count toward compliance."
	}

	annotations := make([]annotation, 0, min(len(run.Annotations), maxRunAnnotations))
	omitted := 0
	for _, a := range run.Annotations {
		norm, ok := normalizeAdvisoryAnnotation(a)
		if !ok {
			continue
		}
		if len(annotations) >= maxRunAnnotations {
			omitted++
			continue
		}
		annotations = append(annotations, norm)
	}
	if omitted > 0 {
		summary += fmt.Sprintf(" %d more advisory citations are not annotated.", omitted)
	}

	first := annotations
	var rest []annotation
	if len(first) > maxAnnotations {
		first = annotations[:maxAnnotations]
		rest = annotations[maxAnnotations:]
	}

	var created struct {
		ID int64 `json:"id"`
	}
	postBody := map[string]any{
		"name":     AdvisoryCheckName,
		"head_sha": headSHA,
		"output": checkOutput{
			Title:       title,
			Summary:     summary,
			Annotations: first,
		},
	}
	if len(rest) == 0 {
		postBody["status"] = "completed"
		postBody["conclusion"] = advisoryConclusion
	} else {
		postBody["status"] = "in_progress"
	}
	if err := c.app.call(ctx, c.token, http.MethodPost, c.repoPath("/check-runs"), postBody, &created); err != nil {
		return fmt.Errorf("create advisory check run: %w", err)
	}
	if len(rest) == 0 {
		return nil
	}
	path := c.repoPath("/check-runs/" + strconv.FormatInt(created.ID, 10))
	for len(rest) > 0 {
		batch := rest
		if len(batch) > maxAnnotations {
			batch = rest[:maxAnnotations]
		}
		rest = rest[len(batch):]
		patchBody := map[string]any{
			"output": checkOutput{
				Title:       title,
				Summary:     summary,
				Annotations: batch,
			},
		}
		if len(rest) == 0 {
			patchBody["status"] = "completed"
			patchBody["conclusion"] = advisoryConclusion
		}
		if err := c.app.call(ctx, c.token, http.MethodPatch, path, patchBody, nil); err != nil {
			return fmt.Errorf("append advisory check run annotations: %w", err)
		}
	}
	return nil
}
