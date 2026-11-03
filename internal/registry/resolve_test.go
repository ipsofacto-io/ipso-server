package registry

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAssignPathDecisionsKeepsEachBodyOnce(t *testing.T) {
	org := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	docs := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	prod := uuid.MustParse("00000000-0000-7000-8000-000000000003")
	scopeOrg := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	scopeDocs := uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	scopeProd := uuid.MustParse("00000000-0000-7000-8000-00000000000c")
	body := json.RawMessage(`{"slug":"org-wide"}`)
	decisions := []decisionScopes{
		{decision: Decision{ID: org, Version: 1, Body: body}, scopes: []uuid.UUID{scopeOrg}},
		{decision: Decision{ID: docs, Version: 1, Body: json.RawMessage(`{"slug":"docs"}`)}, scopes: []uuid.UUID{scopeDocs}},
		{decision: Decision{ID: prod, Version: 1, Body: json.RawMessage(`{"slug":"prod"}`)}, scopes: []uuid.UUID{scopeProd}},
	}
	got := assignPathDecisions(
		[]string{"docs/a.md", "main.go"},
		[][]uuid.UUID{{scopeOrg, scopeDocs, scopeProd}, {scopeOrg, scopeProd}},
		decisions,
	)
	if len(got.Decisions) != 3 || &got.Decisions[0].Body[0] != &body[0] {
		t.Fatalf("decisions were copied or dropped: %+v", got.Decisions)
	}
	if !slices.Equal(got.Resolutions[0].DecisionIDs, []uuid.UUID{org, docs, prod}) {
		t.Fatalf("docs/a.md: %v", got.Resolutions[0].DecisionIDs)
	}
	if !slices.Equal(got.Resolutions[1].DecisionIDs, []uuid.UUID{org, prod}) {
		t.Fatalf("main.go: %v", got.Resolutions[1].DecisionIDs)
	}
}

func TestAssignPathDecisionsDoesNotRepeatASharedDecision(t *testing.T) {
	id := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	scope := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	body := json.RawMessage(`{"n":1}`)
	const pathsN = MaxResolvePaths
	paths := make([]string, pathsN)
	scopes := make([][]uuid.UUID, pathsN)
	for i := range paths {
		paths[i] = "f"
		scopes[i] = []uuid.UUID{scope}
	}
	got := assignPathDecisions(paths, scopes, []decisionScopes{{
		decision: Decision{ID: id, Version: 1, Body: body},
		scopes:   []uuid.UUID{scope},
	}})
	if len(got.Decisions) != 1 || &got.Decisions[0].Body[0] != &body[0] {
		t.Fatalf("shared body was stored %d times", len(got.Decisions))
	}
	for _, resolution := range got.Resolutions {
		if len(resolution.DecisionIDs) != 1 || resolution.DecisionIDs[0] != id {
			t.Fatalf("%+v", resolution)
		}
	}
}

func TestAssignPathDecisionsOmitsADecisionThatMatchesNoPath(t *testing.T) {
	kept := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	dropped := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	scope := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	elsewhere := uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	got := assignPathDecisions(
		[]string{"a", "b"},
		[][]uuid.UUID{nil, {scope}},
		[]decisionScopes{
			{decision: Decision{ID: dropped, Version: 1, Body: json.RawMessage(`{"a":1}`)}, scopes: []uuid.UUID{elsewhere}},
			{decision: Decision{ID: kept, Version: 1, Body: json.RawMessage(`{"b":1}`)}, scopes: []uuid.UUID{scope}},
		},
	)
	if len(got.Decisions) != 1 || got.Decisions[0].ID != kept {
		t.Fatalf("%+v", got.Decisions)
	}
	if got.Resolutions[0].DecisionIDs == nil || len(got.Resolutions[0].DecisionIDs) != 0 {
		t.Fatalf("unmatched path: %+v", got.Resolutions[0])
	}
	if !slices.Equal(got.Resolutions[1].DecisionIDs, []uuid.UUID{kept}) {
		t.Fatalf("%v", got.Resolutions[1].DecisionIDs)
	}
}

func TestAssignPathDecisionsNamesADecisionOnceWhenSeveralAncestorsMatch(t *testing.T) {
	id := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	org := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	repo := uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	got := assignPathDecisions(
		[]string{"main.go"},
		[][]uuid.UUID{{org, repo}},
		[]decisionScopes{{
			decision: Decision{ID: id, Version: 1, Body: json.RawMessage(`{"slug":"shared"}`)},
			scopes:   []uuid.UUID{org, repo},
		}},
	)
	if len(got.Decisions) != 1 || !slices.Equal(got.Resolutions[0].DecisionIDs, []uuid.UUID{id}) {
		t.Fatalf("%+v", got)
	}
}

func TestParseUUIDArray(t *testing.T) {
	id := uuid.MustParse("00000000-0000-7000-8000-000000000001")
	other := uuid.MustParse("00000000-0000-7000-8000-000000000002")
	got, err := parseUUIDArray("{" + id.String() + "," + other.String() + "}")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []uuid.UUID{id, other}) {
		t.Fatalf("%v", got)
	}
	empty, err := parseUUIDArray("{}")
	if err != nil || len(empty) != 0 {
		t.Fatalf("%v %v", empty, err)
	}
	for _, text := range []string{"", "not-an-array", "{nope}", "{,}"} {
		if _, err := parseUUIDArray(text); err == nil || !strings.Contains(err.Error(), "scope refs") {
			t.Fatalf("%q: %v", text, err)
		}
	}
}
