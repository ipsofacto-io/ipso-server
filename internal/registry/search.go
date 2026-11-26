package registry

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// maxSearchTermRunes matches the 128-character cap in registry.decision_search_terms(jsonb).
	maxSearchTermRunes = 128
	// maxSearchTerms bounds the number of INTERSECT branches built for one query.
	maxSearchTerms = 16
)

// termRange is a half-open [lo, hi) UTF-8 prefix range under COLLATE "C". When hi is empty, there
// is no upper bound (every rune of lo is utf8.MaxRune).
type termRange struct {
	lo string
	hi string
}

// searchTerms extracts distinct lowercase searchable tokens from q and returns their exact UTF-8
// prefix bounds for COLLATE "C" btree range scans (ADR-0169). Punctuation-only input returns nil.
func searchTerms(q string) []termRange {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	var out []termRange
	seen := make(map[string]struct{})
	var cur []rune
	flush := func() {
		if len(cur) == 0 {
			return
		}
		tok := strings.Trim(string(cur), "-.")
		cur = cur[:0]
		if tok == "" {
			return
		}
		if utf8.RuneCountInString(tok) > maxSearchTermRunes {
			runes := []rune(tok)
			tok = string(runes[:maxSearchTermRunes])
		}
		if _, dup := seen[tok]; dup {
			return
		}
		if len(out) >= maxSearchTerms {
			return
		}
		seen[tok] = struct{}{}
		out = append(out, termRange{lo: tok, hi: nextUTF8Prefix(tok)})
	}
	for _, r := range q {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '-' || r == '.' {
			cur = append(cur, r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// nextUTF8Prefix returns the smallest valid UTF-8 string strictly greater than every string with
// prefix s under COLLATE "C" (bytewise order, which matches Unicode scalar value order). Returns ""
// if every rune in s is utf8.MaxRune.
func nextUTF8Prefix(s string) string {
	runes := []rune(s)
	for i := len(runes) - 1; i >= 0; i-- {
		r := runes[i]
		if r >= utf8.MaxRune {
			continue
		}
		next := r + 1
		if next == 0xD800 {
			next = 0xE000
		}
		runes[i] = next
		return string(runes[:i+1])
	}
	return ""
}

// appendSearchClauses appends the indexed decision_search_term candidate filter and authoritative
// per-version re-check to args, returning the two SQL predicates. Every term in terms is
// prefix-matched and ANDed together.
func appendSearchClauses(terms []termRange, args []any) (candidateSQL, recheckSQL string, nextArgs []any) {
	nextArgs = args
	branches := make([]string, len(terms))
	los := make([]string, len(terms))
	his := make([]string, len(terms))
	for i, tr := range terms {
		los[i] = tr.lo
		his[i] = tr.hi
		nextArgs = append(nextArgs, tr.lo)
		loParam := len(nextArgs)
		if tr.hi != "" {
			nextArgs = append(nextArgs, tr.hi)
			hiParam := len(nextArgs)
			branches[i] = fmt.Sprintf(
				`SELECT t.decision_id FROM registry.decision_search_term t WHERE t.tenant_id = ipso.current_tenant() AND t.term >= $%d::text AND t.term < $%d::text`,
				loParam, hiParam,
			)
		} else {
			branches[i] = fmt.Sprintf(
				`SELECT t.decision_id FROM registry.decision_search_term t WHERE t.tenant_id = ipso.current_tenant() AND t.term >= $%d::text`,
				loParam,
			)
		}
	}
	candidateSQL = "d.decision_id IN (\n    " + strings.Join(branches, "\n    INTERSECT\n    ") + "\n)"

	nextArgs = append(nextArgs, los, his)
	loArrParam := len(nextArgs) - 1
	hiArrParam := len(nextArgs)
	recheckSQL = fmt.Sprintf(`NOT EXISTS (
    SELECT 1
    FROM unnest($%d::text[], $%d::text[]) AS q(lo, hi)
    WHERE NOT EXISTS (
        SELECT 1
        FROM unnest(registry.decision_search_terms(d.body)) AS term
        WHERE term COLLATE "C" >= q.lo
          AND (q.hi = '' OR term COLLATE "C" < q.hi)
    )
)`, loArrParam, hiArrParam)
	return candidateSQL, recheckSQL, nextArgs
}

// searchDecisionsQuery builds the real SQL statement and arguments for SearchDecisions when terms
// is non-empty, shared with the RLS plan test so the test guards the exact production query.
func searchDecisionsQuery(terms []termRange, validAt, knownAt time.Time, before any, limit int) (string, []any) {
	args := []any{validAt, knownAt, before, limit}
	candidateSQL, recheckSQL, args := appendSearchClauses(terms, args)
	stmt := `SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND d.valid_period @> $1::timestamptz
  AND d.sys_period @> $2::timestamptz
  AND ($3::uuid IS NULL OR d.decision_id < $3::uuid)
  AND ` + candidateSQL + `
  AND ` + recheckSQL + `
ORDER BY d.decision_id DESC, d.version DESC
LIMIT $4`
	return stmt, args
}

// listDecisionHealthQuery builds the real SQL statement and arguments for ListDecisionHealth. When
// terms is empty, no keyword predicate is emitted so the planner never sees an OR branch with ''.
func listDecisionHealthQuery(terms []termRange, knownAt time.Time, before any, repo string, validAt time.Time, limit int) (string, []any) {
	args := []any{knownAt, before, repo, validAt, limit}
	searchClause := ""
	if len(terms) > 0 {
		var candidateSQL, recheckSQL string
		candidateSQL, recheckSQL, args = appendSearchClauses(terms, args)
		searchClause = "\n  AND " + candidateSQL + "\n  AND " + recheckSQL
	}
	stmt := `SELECT DISTINCT ON (d.decision_id) d.decision_id, d.version, d.body, d.scope_refs::text, lower(d.valid_period), upper(d.valid_period)
FROM registry.decision_version_all d
WHERE d.tenant_id = ipso.current_tenant()
  AND d.sys_period @> $1::timestamptz
  AND ($2::uuid IS NULL OR d.decision_id < $2::uuid)` + searchClause + `
  AND (
      $3 = ''
      OR EXISTS (
          SELECT 1
          FROM registry.scope_all s
          JOIN registry.scope_closure_all sc
            ON sc.tenant_id = s.tenant_id AND sc.descendant_id = s.id
          WHERE s.tenant_id = d.tenant_id
            AND s.sys_period @> $1::timestamptz
            AND sc.sys_period @> $1::timestamptz
            AND sc.ancestor_id = ANY(d.scope_refs)
            AND (
                (s.kind IN ('repo', 'path', 'env') AND s.match_repo = $3)
                OR (s.kind = 'org' AND s.match_org = split_part($3, '/', 1))
            )
      )
  )
ORDER BY d.decision_id DESC, (d.valid_period @> $4::timestamptz) DESC, d.version DESC
LIMIT $5`
	return stmt, args
}
