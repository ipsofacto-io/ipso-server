package registry

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGrandfatherRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	one := Fingerprint{1}

	if _, err := Grandfather(t.Context(), db, uuid.Nil, decision, "acme/x", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, uuid.Nil, "acme/x", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil decision: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one}, time.Time{}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero valid time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one}, now, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "not a repo", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("bad repo: err = %v, want ErrInvalidSubject", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one, one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("repeated fingerprint: err = %v, want ErrInvalidQuery", err)
	}
	got, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", nil, now, now)
	if err != nil || got != nil {
		t.Errorf("no violations: got %v, err %v, want nil, nil", got, err)
	}
}

func TestResultWords(t *testing.T) {
	if Fail.String() != "fail" || WaivedBaseline.String() != "waived(baseline)" {
		t.Errorf("words = %q and %q", Fail.String(), WaivedBaseline.String())
	}
}

func TestGrandfatherEachRefusesBadReadsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	one := Fingerprint{1}
	good := BaselineRead{Decision: decision, Repo: "acme/x", Violations: []Fingerprint{one}, ValidAt: now}

	bad := map[string]struct {
		tenant uuid.UUID
		reads  []BaselineRead
		known  time.Time
		want   error
	}{
		"nil tenant":             {uuid.Nil, []BaselineRead{good}, now, ErrInvalidQuery},
		"zero transaction time":  {tenant, []BaselineRead{good}, time.Time{}, ErrInvalidQuery},
		"nil decision":           {tenant, []BaselineRead{good, {Repo: "acme/x", Violations: []Fingerprint{one}, ValidAt: now}}, now, ErrInvalidQuery},
		"zero valid time":        {tenant, []BaselineRead{{Decision: decision, Repo: "acme/x", Violations: []Fingerprint{one}}}, now, ErrInvalidQuery},
		"bad repo":               {tenant, []BaselineRead{good, {Decision: decision, Repo: "not a repo", Violations: []Fingerprint{one}, ValidAt: now}}, now, ErrInvalidSubject},
		"repeated fingerprint":   {tenant, []BaselineRead{{Decision: decision, Repo: "acme/x", Violations: []Fingerprint{one, one}, ValidAt: now}}, now, ErrInvalidQuery},
		"bad repo with no digit": {tenant, []BaselineRead{{Decision: decision, Repo: "Acme/../x", ValidAt: now}}, now, ErrInvalidSubject},
	}
	for name, c := range bad {
		if _, err := GrandfatherEach(t.Context(), db, c.tenant, c.reads, c.known); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}

	// A read with no violation needs no database, and its answer is nil, as Grandfather's is.
	answers, err := GrandfatherEach(t.Context(), db, tenant, []BaselineRead{{Decision: decision, Repo: "Acme/X", ValidAt: now}, {Decision: decision, Repo: "acme/y", ValidAt: now}}, now)
	if err != nil || len(answers) != 2 || answers[0] != nil || answers[1] != nil {
		t.Errorf("reads with no violation: got %v, err %v, want two nil answers", answers, err)
	}
	if answers, err := GrandfatherEach(t.Context(), db, tenant, nil, now); err != nil || len(answers) != 0 {
		t.Errorf("no reads: got %v, err %v, want no answers", answers, err)
	}
}

func TestLiteralRepoIsTheRepoGrandfatherAccepts(t *testing.T) {
	for repo, want := range map[string]bool{
		"acme/payments": true, "acme/a/b": true, "Acme/Payments": true,
		"": false, "acme": false, "acme/": false, "not a repo": false, "acme/../x": false, "acme/./x": false,
	} {
		if got := LiteralRepo(repo); got != want {
			t.Errorf("LiteralRepo(%q) = %v, want %v", repo, got, want)
		}
	}
}

func TestDecisionsByEDRIDRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	if _, err := DecisionsByEDRID(t.Context(), db, uuid.Nil, []string{"x"}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := DecisionsByEDRID(t.Context(), db, tenant, []string{"x"}, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	if got, err := DecisionsByEDRID(t.Context(), db, tenant, nil, now); err != nil || len(got) != 0 {
		t.Errorf("no ids: got %v, err %v, want an empty map", got, err)
	}
}
