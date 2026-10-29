//go:build integration

package registry

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// goldenFile is testdata/q1_golden.json: a timeline of writes and the answers to Q1 of section
// 2.3 that each moment must give. The refs are labels. They are never stored.
type goldenFile struct {
	Steps   []goldenStep  `json:"steps"`
	Queries []goldenQuery `json:"queries"`
}

// goldenStep is one write or one clock reading. Exactly one of Scope, Decision, Correct,
// Remove, and Mark is set.
type goldenStep struct {
	Tenant string `json:"tenant"`

	Scope    string `json:"scope"`
	Parent   string `json:"parent"`
	Kind     string `json:"kind"`
	Selector string `json:"selector"`

	Decision string   `json:"decision"`
	Scopes   []string `json:"scopes"`
	Valid    string   `json:"valid"`

	// Correct writes a new version of the decision with another valid period and, when Scopes
	// is set, other scopes. Remove deletes the current row.
	Correct string `json:"correct"`
	Remove  string `json:"remove"`

	// Mark records the database clock under this name.
	Mark string `json:"mark"`
}

// goldenQuery asks for the decisions in force. Want lists decision refs, with "@2" for a version
// other than 1. Known names a mark and defaults to the end of the timeline.
type goldenQuery struct {
	Name   string   `json:"name"`
	Tenant string   `json:"tenant"`
	Repo   string   `json:"repo"`
	Path   string   `json:"path"`
	Env    string   `json:"env"`
	Valid  string   `json:"valid"`
	Known  string   `json:"known"`
	Want   []string `json:"want"`
}

func TestResolveGoldenQ1(t *testing.T) {
	raw, err := os.ReadFile("testdata/q1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden goldenFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&golden); err != nil {
		t.Fatal(err)
	}

	r := newRegistryDB(t)
	ctx := t.Context()
	tenants := map[string]uuid.UUID{"a": tenantA, "b": tenantB}
	scopes := make(map[string]uuid.UUID)
	type state struct {
		id      uuid.UUID
		tenant  uuid.UUID
		version int
	}
	decisions := make(map[string]*state)
	marks := make(map[string]time.Time)
	refOf := make(map[uuid.UUID]string)

	tenantOf := func(name string) uuid.UUID {
		id, ok := tenants[name]
		if !ok {
			t.Fatalf("unknown tenant %q", name)
		}
		return id
	}
	scopeIDs := func(refs []string) []uuid.UUID {
		ids := make([]uuid.UUID, 0, len(refs))
		for _, ref := range refs {
			id, ok := scopes[ref]
			if !ok {
				t.Fatalf("unknown scope %q", ref)
			}
			ids = append(ids, id)
		}
		return ids
	}

	for i, step := range golden.Steps {
		switch {
		case step.Scope != "":
			var parent uuid.UUID
			if step.Parent != "" {
				parent = scopes[step.Parent]
				if parent == uuid.Nil {
					t.Fatalf("step %d: unknown parent %q", i, step.Parent)
				}
			}
			scopes[step.Scope] = r.scope(t, tenantOf(step.Tenant), parent, step.Kind, step.Selector)

		case step.Decision != "":
			id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(step.Decision))
			decisions[step.Decision] = &state{id: id, tenant: tenantOf(step.Tenant), version: 1}
			refOf[id] = step.Decision
			r.decision(t, tenantOf(step.Tenant), id, step.Valid, scopeIDs(step.Scopes)...)

		case step.Correct != "":
			d := decisions[step.Correct]
			if d == nil {
				t.Fatalf("step %d: unknown decision %q", i, step.Correct)
			}
			d.version++
			var refs any
			if len(step.Scopes) > 0 {
				refs = scopeIDs(step.Scopes)
			}
			_, err := r.app.ExecContext(ctx, `
				UPDATE registry.decision_version
				SET version = $3, valid_period = $4::text::tstzrange, scope_refs = coalesce($5::uuid[], scope_refs)
				WHERE tenant_id = $1 AND decision_id = $2`, d.tenant, d.id, d.version, step.Valid, refs)
			if err != nil {
				t.Fatalf("step %d: correct %s: %v", i, step.Correct, err)
			}

		case step.Remove != "":
			d := decisions[step.Remove]
			if d == nil {
				t.Fatalf("step %d: unknown decision %q", i, step.Remove)
			}
			if _, err := r.app.ExecContext(ctx, `DELETE FROM registry.decision_version WHERE tenant_id = $1 AND decision_id = $2`, d.tenant, d.id); err != nil {
				t.Fatalf("step %d: remove %s: %v", i, step.Remove, err)
			}

		case step.Mark != "":
			marks[step.Mark] = mark(t, r.admin)

		default:
			t.Fatalf("step %d sets nothing", i)
		}
	}
	marks["end"] = mark(t, r.admin)

	for _, q := range golden.Queries {
		t.Run(q.Name, func(t *testing.T) {
			known := "end"
			if q.Known != "" {
				known = q.Known
			}
			knownAt, ok := marks[known]
			if !ok {
				t.Fatalf("unknown mark %q", known)
			}
			validAt, err := time.Parse(time.DateOnly, q.Valid)
			if err != nil {
				t.Fatal(err)
			}

			got, err := Resolve(ctx, r.app, tenantOf(q.Tenant), Subject{Repo: q.Repo, Path: q.Path, Env: q.Env}, validAt, knownAt)
			if err != nil {
				t.Fatal(err)
			}

			var gotRefs []string
			for _, d := range got {
				ref, ok := refOf[d.ID]
				if !ok {
					t.Fatalf("decision %s is not one of the fixture decisions", d.ID)
				}
				var body struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(d.Body, &body); err != nil || body.ID != d.ID.String() {
					t.Errorf("decision %s body = %s, want it to carry its own id (%v)", ref, d.Body, err)
				}
				gotRefs = append(gotRefs, ref+"@"+strconv.Itoa(d.Version))
			}
			wantRefs := make([]string, 0, len(q.Want))
			for _, w := range q.Want {
				if !strings.Contains(w, "@") {
					w += "@1"
				}
				wantRefs = append(wantRefs, w)
			}

			// Results come in decision id order. Compare the sets, because the order of ids
			// is not the order of the labels.
			if !slices.IsSortedFunc(got, func(a, b Decision) int { return bytes.Compare(a.ID[:], b.ID[:]) }) {
				t.Errorf("result is not in decision id order: %v", gotRefs)
			}
			slices.Sort(gotRefs)
			slices.Sort(wantRefs)
			if !slices.Equal(gotRefs, wantRefs) {
				t.Errorf("decisions = %v, want %v", gotRefs, wantRefs)
			}
		})
	}
}
