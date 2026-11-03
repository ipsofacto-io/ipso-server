//go:build integration

package registry

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResolvePathsAnswersEachPathInOneRead(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/api")
	docs := r.scope(t, tenantA, repo, "path", "docs/**")
	prod := r.scope(t, tenantA, repo, "env", "prod")
	orgWide, onDocs, onProd := uuid.New(), uuid.New(), uuid.New()
	r.decision(t, tenantA, orgWide, "[2026-01-01,)", org)
	r.decision(t, tenantA, onDocs, "[2026-01-01,)", docs)
	r.decision(t, tenantA, onProd, "[2026-01-01,)", prod)
	knownAt := mark(t, r.admin)
	validAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	got, err := ResolvePaths(t.Context(), r.app, tenantA, "acme/api", "prod", []string{"docs/a.md", "main.go"}, validAt, knownAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "docs/a.md" || got[1].Path != "main.go" {
		t.Fatalf("%+v", got)
	}
	ids := func(ds []Decision) []uuid.UUID {
		out := make([]uuid.UUID, 0, len(ds))
		for _, d := range ds {
			out = append(out, d.ID)
		}
		slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		return out
	}
	want := func(in ...uuid.UUID) []uuid.UUID {
		slices.SortFunc(in, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		return in
	}
	if !slices.Equal(ids(got[0].Decisions), want(orgWide, onDocs, onProd)) {
		t.Fatalf("docs/a.md: %v", ids(got[0].Decisions))
	}
	if !slices.Equal(ids(got[1].Decisions), want(orgWide, onProd)) {
		t.Fatalf("main.go: %v", ids(got[1].Decisions))
	}

	other, err := ResolvePaths(t.Context(), r.app, tenantB, "acme/api", "prod", []string{"docs/a.md"}, validAt, knownAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 1 || len(other[0].Decisions) != 0 {
		t.Fatalf("tenant B read tenant A: %+v", other)
	}
}

func TestResolvePathsRefusesARequestThatWidensTheAnswer(t *testing.T) {
	r := newRegistryDB(t)
	now := time.Now()
	tooMany := make([]string, MaxResolvePaths+1)
	for i := range tooMany {
		tooMany[i] = "f"
	}
	for name, tc := range map[string]struct {
		repo, env string
		paths     []string
		want      error
	}{
		"no repo":        {"", "prod", []string{"a"}, ErrInvalidSubject},
		"no env":         {"acme/api", "", []string{"a"}, ErrInvalidSubject},
		"no paths":       {"acme/api", "prod", nil, ErrInvalidQuery},
		"an empty path":  {"acme/api", "prod", []string{"a", ""}, ErrInvalidSubject},
		"a parent path":  {"acme/api", "prod", []string{"../a"}, ErrInvalidSubject},
		"too many paths": {"acme/api", "prod", tooMany, ErrInvalidQuery},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ResolvePaths(t.Context(), r.app, tenantA, tc.repo, tc.env, tc.paths, now, now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := ResolvePaths(t.Context(), r.app, uuid.Nil, "acme/api", "prod", []string{"a"}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("no tenant: %v", err)
	}
}

func TestDecisionsPagesByIDAsKnown(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	ids := []uuid.UUID{
		uuid.MustParse("00000000-0000-7000-8000-000000000001"),
		uuid.MustParse("00000000-0000-7000-8000-000000000002"),
		uuid.MustParse("00000000-0000-7000-8000-000000000003"),
	}
	for _, id := range ids {
		r.decision(t, tenantA, id, "[2026-01-01,)", org)
	}
	r.decision(t, tenantA, uuid.MustParse("00000000-0000-7000-8000-000000000009"), "[2030-01-01,)", org)
	knownAt := mark(t, r.admin)
	r.decision(t, tenantA, uuid.MustParse("00000000-0000-7000-8000-000000000004"), "[2026-01-01,)", org)
	validAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	first, err := Decisions(t.Context(), r.app, tenantA, validAt, knownAt, Page{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].ID != ids[2] || first[1].ID != ids[1] {
		t.Fatalf("first page %+v", first)
	}
	second, err := Decisions(t.Context(), r.app, tenantA, validAt, knownAt, Page{Before: first[1].ID, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].ID != ids[0] {
		t.Fatalf("second page %+v", second)
	}
	none, err := Decisions(t.Context(), r.app, tenantB, validAt, knownAt, Page{Limit: 10})
	if err != nil || none != nil {
		t.Fatalf("tenant B: %v %+v", err, none)
	}
	if _, err := Decisions(t.Context(), r.app, tenantA, validAt, knownAt, Page{Limit: MaxPage + 1}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("a page too large: %v", err)
	}
}

func TestScopesReadsTheTreeAsKnown(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/api")
	knownAt := mark(t, r.admin)
	r.scope(t, tenantA, repo, "env", "prod")

	scopes, err := Scopes(t.Context(), r.app, tenantA, knownAt, Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 {
		t.Fatalf("%+v", scopes)
	}
	byID := map[uuid.UUID]Scope{}
	for _, s := range scopes {
		byID[s.ID] = s
	}
	if byID[org].ParentID != nil || byID[org].Kind != "org" || byID[org].Selector != "acme" {
		t.Fatalf("org %+v", byID[org])
	}
	if byID[repo].ParentID == nil || *byID[repo].ParentID != org || byID[repo].Kind != "repo" {
		t.Fatalf("repo %+v", byID[repo])
	}
	none, err := Scopes(t.Context(), r.app, tenantB, knownAt, Page{Limit: 10})
	if err != nil || none != nil {
		t.Fatalf("tenant B: %v %+v", err, none)
	}
}

func TestWaiversListsThoseInForceWithoutReasonOrApprover(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	decision := uuid.New()
	r.decision(t, tenantA, decision, "[2026-01-01,)", org)
	inForce := r.addWaiver(t, tenantA, decision, org, "[2026-05-15,2026-06-15)", "OPS-1")
	r.addWaiver(t, tenantA, decision, org, "[2026-07-01,2026-07-15)", "OPS-2")
	knownAt := mark(t, r.admin)
	validAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	waivers, err := Waivers(t.Context(), r.app, tenantA, validAt, knownAt, Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(waivers) != 1 {
		t.Fatalf("%+v", waivers)
	}
	w := waivers[0]
	if w.ID != inForce || w.DecisionID != decision || w.ScopeID != org || w.TicketRef != "OPS-1" ||
		!w.ValidFrom.Equal(time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)) || !w.ExpiresAt.Equal(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", w)
	}
	none, err := Waivers(t.Context(), r.app, tenantB, validAt, knownAt, Page{Limit: 10})
	if err != nil || none != nil {
		t.Fatalf("tenant B: %v %+v", err, none)
	}
}
