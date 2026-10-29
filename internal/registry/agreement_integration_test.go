//go:build integration

package registry

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// The grammar of a selector is written twice: as CHECK constraints in migration 00003 and as
// expressions in selector.go. This test inserts the same inputs into PostgreSQL and parses them
// in Go, and the two must give the same verdict. A refusal from PostgreSQL must be a CHECK
// violation, so a refusal for another reason cannot hide a disagreement.
func TestSelectorGrammarAgreesWithPostgreSQL(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	rng := rand.New(rand.NewPCG(1, 2))

	check := func(t *testing.T, kind string, parent uuid.UUID, goAccepts func(string) bool, inputs []string) {
		t.Helper()
		accepted, refused := 0, 0
		for _, input := range inputs {
			// A repo whose owner is not the org of its parent is refused by a rule that is not
			// part of the grammar, so it cannot be compared.
			if kind == "repo" && goAccepts(input) && strings.SplitN(input, "/", 2)[0] != "acme" {
				continue
			}
			_, err := r.tryScope(t.Context(), tenantA, parent, kind, input)
			if err != nil {
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
					t.Errorf("%s %q: PostgreSQL refused it with %v, want a CHECK violation", kind, input, err)
					continue
				}
			}
			if dbAccepts := err == nil; dbAccepts != goAccepts(input) {
				t.Errorf("%s %q: PostgreSQL accepts %v, Go accepts %v", kind, input, dbAccepts, goAccepts(input))
			}
			if err == nil {
				accepted++
			} else {
				refused++
			}
		}
		if accepted == 0 || refused == 0 {
			t.Errorf("%s: %d accepted and %d refused, want both so the comparison means something", kind, accepted, refused)
		}
	}

	names := append(append([]string{}, validNames...), badNames...)
	names = append(names, generate(rng, 400)...)
	for _, kind := range []string{"domain", "service", "env"} {
		t.Run(kind, func(t *testing.T) {
			check(t, kind, org, func(s string) bool { return validateName(s) == nil }, names)
		})
	}
	t.Run("org", func(t *testing.T) {
		check(t, "org", uuid.Nil, func(s string) bool { return validateName(s) == nil }, names)
	})

	repos := append(append([]string{}, validRepos...), badRepos...)
	repos = append(repos, generate(rng, 1200)...)
	for i := range 300 {
		repos = append(repos, "acme/"+generate(rng, 1)[0], "acme/"+strings.Repeat("a", i%110))
	}
	t.Run("repo", func(t *testing.T) {
		check(t, "repo", org, func(s string) bool { _, err := parseRepoSelector(s); return err == nil }, repos)
	})

	paths := append(append([]string{}, validPaths...), badPaths...)
	paths = append(paths, generate(rng, 1500)...)
	paths = append(paths, strings.Repeat("a", 254), strings.Repeat("a", 255), strings.Repeat("a", 256))
	t.Run("path", func(t *testing.T) {
		check(t, "path", repo, func(s string) bool { _, err := parsePathSelector(s); return err == nil }, paths)
	})
}

// generate builds strings from fragments that sit on the edges of the grammar, so that a large
// share of them is valid and the rest breaks exactly one rule.
func generate(rng *rand.Rand, n int) []string {
	fragments := []string{
		"a", "b", "acme", "infra", "x1", "0", "A", "-", "_", ".", "..", "*", "**", "?", "/", "/", "/",
		" ", "!", "[", "]", "{", "}", "\\", "\n", "\u00e9", "~", "|", "^", "$", "\"", "'", "`", ".tf",
	}
	out := make([]string, 0, n)
	for range n {
		var b strings.Builder
		for range 1 + rng.IntN(7) {
			b.WriteString(fragments[rng.IntN(len(fragments))])
		}
		out = append(out, b.String())
	}
	return out
}
