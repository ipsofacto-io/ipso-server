// Package registry is the bitemporal decision registry.
// It resolves which decisions apply to a repository, a path, and an environment (ADR-0051),
// records supersessions, baselines, and waivers (ADR-0052, ADR-0054), and answers the audit
// reads for a belief diff, a supersession chain, and waiver expiry (ADR-0055).
package registry

import (
	"database/sql"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidSelector is returned when a stored selector does not parse. The database holds the
// same grammar as CHECK constraints, so a failure means the row was written around them.
var ErrInvalidSelector = errors.New("stored selector does not parse")

// ErrInvalidSubject is returned when the repo, path, or env of a subject breaks the rules in
// ADR-0051. A bad subject is an error and never an empty answer.
var ErrInvalidSubject = errors.New("invalid subject")

const (
	maxSelectorLength = 255
	maxSubjectPath    = 4096
	doubleStar        = "**"
)

// The grammar of a stored selector. Every expression is also a CHECK constraint on
// registry.scope in migration 00003_registry_scope.sql, and literalRepoExpr is also the
// baseline_repo constraint in migration 00004_registry_supersession.sql. A test requires
// the database and Go to agree. Each expression is valid in PostgreSQL and in Go.
var (
	nameExpr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	// repoExpr is an owner name and one to ten segments that may hold * and ?.
	repoExpr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9._*?-]{1,100}){1,10}$`)
	// pathCharsExpr is printable ASCII without space, !, [, \, ], {, and }.
	pathCharsExpr = regexp.MustCompile(`^[\x22-\x5a\x5e-\x7a|~]{1,255}$`)
	// dotSegmentExpr finds a "." or ".." segment.
	dotSegmentExpr = regexp.MustCompile(`(^|/)\.{1,2}(/|$)`)
	// badSegmentExpr finds an empty, "." or ".." segment.
	badSegmentExpr = regexp.MustCompile(`(^|/)\.{0,2}(/|$)`)
	// partialDoubleStarExpr finds ** that is not a whole segment.
	partialDoubleStarExpr = regexp.MustCompile(`[^/]\*\*|\*\*[^/]`)
	// literalRepoExpr is a subject repo: repoExpr without the wildcards.
	literalRepoExpr = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9._-]{1,100}){1,10}$`)
)

func validateName(s string) error {
	if !nameExpr.MatchString(s) {
		return fmt.Errorf("%w: name %q", ErrInvalidSelector, s)
	}
	return nil
}

// repoPattern is the segments of a repo selector.
type repoPattern []string

func parseRepoSelector(s string) (repoPattern, error) {
	if len(s) > maxSelectorLength || !repoExpr.MatchString(s) ||
		dotSegmentExpr.MatchString(s) || strings.Contains(s, doubleStar) {
		return nil, fmt.Errorf("%w: repo %q", ErrInvalidSelector, s)
	}
	return strings.Split(s, "/"), nil
}

// matches reports whether the pattern matches the segments of a literal repo.
func (p repoPattern) matches(repo []string) bool {
	if len(p) != len(repo) {
		return false
	}
	for i, segment := range p {
		if !segmentMatches(segment, repo[i]) {
			return false
		}
	}
	return true
}

// pathPattern is the segments of a path selector, anchored at the repository root.
type pathPattern []string

func parsePathSelector(s string) (pathPattern, error) {
	if !pathCharsExpr.MatchString(s) || badSegmentExpr.MatchString(s) || partialDoubleStarExpr.MatchString(s) {
		return nil, fmt.Errorf("%w: path %q", ErrInvalidSelector, s)
	}
	return strings.Split(s, "/"), nil
}

// matches reports whether the pattern matches every segment of a path. A ** segment matches
// zero or more segments, so "terraform/**" matches "terraform" and everything below it.
func (p pathPattern) matches(segments []string) bool {
	// next[j] reports whether the pattern after the current segment matches segments[j:].
	next := make([]bool, len(segments)+1)
	next[len(segments)] = true
	current := make([]bool, len(segments)+1)
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == doubleStar {
			current[len(segments)] = next[len(segments)]
			for j := len(segments) - 1; j >= 0; j-- {
				current[j] = next[j] || current[j+1]
			}
		} else {
			current[len(segments)] = false
			for j := len(segments) - 1; j >= 0; j-- {
				current[j] = next[j+1] && segmentMatches(p[i], segments[j])
			}
		}
		next, current = current, next
	}
	return next[0]
}

// segmentMatches matches one segment, where * is any run of characters and ? is one character.
func segmentMatches(pattern, segment string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == segment
	}
	// path.Match fails only on a bad pattern, and the grammar excludes [ and \ , the characters
	// that can make one bad.
	matched, _ := path.Match(pattern, segment)
	return matched
}

// subject is a validated Subject. Its repo and env are lowercase, and a path is split into
// segments. hasPath and hasEnv are false when the caller left that field out.
type subject struct {
	org     string
	repo    []string
	path    []string
	hasPath bool
	env     string
}

// canonicalRepo folds a repository name to lowercase ASCII and checks the literal repo
// grammar. A subject and a baseline name the same repositories, so both go through here.
func canonicalRepo(repo string) (string, error) {
	folded, ok := asciiLower(repo)
	if !ok || !literalRepoOK(folded) {
		return "", fmt.Errorf("%w: repo must be a lowercase owner/name", ErrInvalidSubject)
	}
	return folded, nil
}

// literalRepoOK reports whether a stored repository name matches the baseline_repo
// constraint. The name is compared as given, with no case folding, because the constraint
// does not fold it either.
func literalRepoOK(repo string) bool {
	return len(repo) <= maxSelectorLength && literalRepoExpr.MatchString(repo) && !dotSegmentExpr.MatchString(repo)
}

func newSubject(in Subject) (subject, error) {
	repo, err := canonicalRepo(in.Repo)
	if err != nil {
		return subject{}, err
	}
	out := subject{repo: strings.Split(repo, "/")}
	out.org = out.repo[0]

	if in.Env != "" {
		env, ok := asciiLower(in.Env)
		if !ok || !nameExpr.MatchString(env) {
			return subject{}, fmt.Errorf("%w: env must be a lowercase name", ErrInvalidSubject)
		}
		out.env = env
	}
	if in.Path != "" {
		segments, err := splitSubjectPath(in.Path)
		if err != nil {
			return subject{}, err
		}
		out.path, out.hasPath = segments, true
	}
	return out, nil
}

// repoString is the literal repo, as the candidate query compares it.
func (s subject) repoString() string {
	return strings.Join(s.repo, "/")
}

// splitSubjectPath checks a changed file path as git reports it: relative to the repository
// root, with no empty, "." or ".." segment. It may hold any other UTF-8 character, because a
// subject is compared as written and never read as a pattern.
func splitSubjectPath(p string) ([]string, error) {
	if len(p) > maxSubjectPath || !utf8.ValidString(p) || strings.HasPrefix(p, "/") ||
		strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("%w: path must be a relative UTF-8 path of at most %d bytes", ErrInvalidSubject, maxSubjectPath)
	}
	segments := strings.Split(p, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return nil, fmt.Errorf("%w: path has an empty, . or .. segment", ErrInvalidSubject)
		}
	}
	return segments, nil
}

// asciiLower lowercases ASCII letters and refuses any other non-ASCII byte, so a character
// such as the Kelvin sign cannot fold into a letter.
func asciiLower(s string) (string, bool) {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

// candidate is the effective selector of a scope row that the database selected for the
// subject's org and repo. A column that is NULL does not constrain the match.
type candidate struct {
	repo, path, env sql.NullString
}

// selects reports whether the effective selector of a scope node matches the subject. A node
// matches when each of its non-NULL columns matches. A subject with no path or no env matches
// a node that names one, so a missing input widens the result and never narrows it. A stored
// value that does not parse is an error, so a damaged row cannot drop out of the answer.
func (s subject) selects(c candidate) (bool, error) {
	if c.repo.Valid {
		pattern, err := parseRepoSelector(c.repo.String)
		if err != nil {
			return false, err
		}
		if !pattern.matches(s.repo) {
			return false, nil
		}
	}
	if c.path.Valid {
		pattern, err := parsePathSelector(c.path.String)
		if err != nil {
			return false, err
		}
		if s.hasPath && !pattern.matches(s.path) {
			return false, nil
		}
	}
	if c.env.Valid {
		if err := validateName(c.env.String); err != nil {
			return false, err
		}
		if s.env != "" && s.env != c.env.String {
			return false, nil
		}
	}
	return true, nil
}
