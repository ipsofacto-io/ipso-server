package trackers

import "regexp"

var ticketURLs = map[string]*regexp.Regexp{
	Jira:         regexp.MustCompile(`^https://[a-z0-9-]+\.atlassian\.net/browse/[A-Z][A-Z0-9_]+-[0-9]+$`),
	Linear:       regexp.MustCompile(`^https://linear\.app/[a-z0-9-]+/issue/[A-Za-z0-9]+-[0-9]+$`),
	GitHubIssues: regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+$`),
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// AllowedURL reports whether link is a server-built ticket URL for connector.
func AllowedURL(connector, link string) bool {
	pattern := ticketURLs[connector]
	return pattern != nil && len(link) <= 2048 && pattern.MatchString(link)
}
