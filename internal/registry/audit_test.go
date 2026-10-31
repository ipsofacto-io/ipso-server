package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDiffDecisions(t *testing.T) {
	keep := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	gone := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	late := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	same := uuid.MustParse("00000000-0000-4000-8000-000000000004")
	body := Decision{ID: keep, Version: 1, Body: []byte(`{"id":"keep"}`)}
	revised := Decision{ID: keep, Version: 2, Body: []byte(`{"id":"keep"}`)}
	removed := Decision{ID: gone, Version: 1, Body: []byte(`{"id":"gone"}`)}
	added := Decision{ID: late, Version: 1, Body: []byte(`{"id":"late"}`)}
	steady := Decision{ID: same, Version: 1, Body: []byte(`{"id":"same"}`)}

	// late's id sorts before keep. The result must be ordered by id, not by map iteration.
	diff := diffDecisions(
		[]Decision{body, removed, steady},
		[]Decision{revised, added, steady},
	)
	if len(diff.Added) != 1 || diff.Added[0].ID != late {
		t.Fatalf("added = %+v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].ID != gone {
		t.Fatalf("removed = %+v", diff.Removed)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].ID != keep || diff.Changed[0].Then.Version != 1 || diff.Changed[0].Now.Version != 2 {
		t.Fatalf("changed = %+v", diff.Changed)
	}
}

func TestDiffDecisionsBodyBytes(t *testing.T) {
	id := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	diff := diffDecisions(
		[]Decision{{ID: id, Version: 1, Body: []byte(`{"n":1}`)}},
		[]Decision{{ID: id, Version: 1, Body: []byte(`{"n":2}`)}},
	)
	if len(diff.Changed) != 1 || len(diff.Added) != 0 || len(diff.Removed) != 0 {
		t.Fatalf("diff = %+v", diff)
	}
}

func TestAuditReadsRejectBadArgs(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	when := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	subject := Subject{Repo: "acme/payments"}

	if _, err := Beliefs(ctx, nil, uuid.Nil, subject, when, when, when); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("nil tenant: %v", err)
	}
	if _, err := Beliefs(ctx, nil, tenant, subject, time.Time{}, when, when); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("zero valid time: %v", err)
	}
	if _, err := Beliefs(ctx, nil, tenant, Subject{Repo: "not a repo"}, when, when, when); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("bad repo: %v", err)
	}
	if _, err := SupersessionChain(ctx, nil, tenant, uuid.Nil, when); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("nil decision: %v", err)
	}
	if _, err := ExpiringWaivers(ctx, nil, tenant, time.Time{}, when); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("zero known time: %v", err)
	}
}
