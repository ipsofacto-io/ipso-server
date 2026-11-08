package registry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	someTenant   = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	someDecision = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	otherDecison = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	someScope    = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	someone      = uuid.MustParse("00000000-0000-4000-8000-0000000000bb")
	june         = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	digest       = strings.Repeat("ab", 32)
)

// The checks that come before the store are the same for every write: a bad value is ErrInvalidQuery and the
// transaction is never touched, so a nil transaction proves it.
func TestAWriteChecksItsValuesBeforeTheStore(t *testing.T) {
	parent := &someScope
	long := strings.Repeat("a", 2001)
	goodWaiver := NewWaiver{DecisionID: someDecision, ScopeID: someScope, Reason: "r", TicketRef: "OPS-1", ValidFrom: june, ExpiresAt: june.AddDate(0, 0, 30)}
	waiver := func(change func(*NewWaiver)) NewWaiver {
		w := goodWaiver
		change(&w)
		return w
	}
	body := func(s string) NewDecision {
		return NewDecision{Body: []byte(s), ScopeRefs: []uuid.UUID{someScope}, ValidFrom: june}
	}
	for name, run := range map[string]func() error{
		"a kind that is not a kind": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{Kind: "region", Selector: "eu"})
			return err
		},
		"an org with a parent": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{ParentID: parent, Kind: "org", Selector: "acme"})
			return err
		},
		"a repo with no parent": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{Kind: "repo", Selector: "acme/api"})
			return err
		},
		"a name that is not a name": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{ParentID: parent, Kind: "domain", Selector: "Not A Name"})
			return err
		},
		"a repo with a double star": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{ParentID: parent, Kind: "repo", Selector: "acme/**"})
			return err
		},
		"a path with a space": func() error {
			_, err := CreateScope(t.Context(), nil, someTenant, NewScope{ParentID: parent, Kind: "path", Selector: "a b"})
			return err
		},
		"a move with no parent":      func() error { _, err := ReparentScope(t.Context(), nil, someTenant, someScope, uuid.Nil); return err },
		"a retirement with no scope": func() error { return RetireScope(t.Context(), nil, someTenant, uuid.Nil) },
		"a decision that replaces itself": func() error {
			_, err := RecordSupersession(t.Context(), nil, someTenant, someDecision, someDecision, june)
			return err
		},
		"a supersession with no date": func() error {
			_, err := RecordSupersession(t.Context(), nil, someTenant, someDecision, otherDecison, time.Time{})
			return err
		},
		"a period with no start": func() error {
			return RecordGrandfatherPeriod(t.Context(), nil, someTenant, someDecision, time.Time{}, nil)
		},
		"a period that ends first": func() error {
			u := june.AddDate(0, -1, 0)
			return RecordGrandfatherPeriod(t.Context(), nil, someTenant, someDecision, june, &u)
		},
		"an uppercase repo": func() error {
			_, err := RecordBaseline(t.Context(), nil, someTenant, someDecision, "Acme/Api", []string{digest})
			return err
		},
		"no fingerprint": func() error {
			_, err := RecordBaseline(t.Context(), nil, someTenant, someDecision, "acme/api", nil)
			return err
		},
		"a short fingerprint": func() error {
			_, err := RecordBaseline(t.Context(), nil, someTenant, someDecision, "acme/api", []string{"ab"})
			return err
		},
		"an uppercase fingerprint": func() error {
			_, err := RecordBaseline(t.Context(), nil, someTenant, someDecision, "acme/api", []string{strings.ToUpper(digest)})
			return err
		},
		"a repeated fingerprint": func() error {
			_, err := RecordBaseline(t.Context(), nil, someTenant, someDecision, "acme/api", []string{digest, digest})
			return err
		},
		"a waiver with no reason": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.Reason = "" }))
			return err
		},
		"a reason with a space at the end": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.Reason = "r " }))
			return err
		},
		"a reason that is too long": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.Reason = long }))
			return err
		},
		"a ticket with a control character": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.TicketRef = "OPS\x07" }))
			return err
		},
		"a waiver of 91 days": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.ExpiresAt = w.ValidFrom.AddDate(0, 0, 91) }))
			return err
		},
		"a waiver that ends where it starts": func() error {
			_, err := RecordWaiver(t.Context(), nil, someTenant, someone, waiver(func(w *NewWaiver) { w.ExpiresAt = w.ValidFrom }))
			return err
		},
		"a waiver with no approver": func() error { _, err := RecordWaiver(t.Context(), nil, someTenant, uuid.Nil, goodWaiver); return err },
		"a premise id in capitals": func() error {
			_, err := ClearPremiseReason(t.Context(), nil, someTenant, someDecision, "TLS")
			return err
		},
		"a host that is an address": func() error { _, err := AllowPremiseHost(t.Context(), nil, someTenant, "10.0.0.1", true); return err },
		"a host with no dot":        func() error { _, err := AllowPremiseHost(t.Context(), nil, someTenant, "localhost", true); return err },
		"a host outside ASCII": func() error {
			_, err := AllowPremiseHost(t.Context(), nil, someTenant, "exämple.com", true)
			return err
		},
		"a decision that is a list": func() error { _, err := InsertDecision(t.Context(), nil, someTenant, body(`[1]`)); return err },
		"a decision with no slug": func() error {
			_, err := InsertDecision(t.Context(), nil, someTenant, body(`{"title":"T"}`))
			return err
		},
		"a slug in capitals": func() error {
			_, err := InsertDecision(t.Context(), nil, someTenant, body(`{"slug":"Use","title":"T"}`))
			return err
		},
		"a decision with no title": func() error {
			_, err := InsertDecision(t.Context(), nil, someTenant, body(`{"slug":"use"}`))
			return err
		},
		"premises that are an object": func() error {
			_, err := InsertDecision(t.Context(), nil, someTenant, body(`{"slug":"use","title":"T","premises":{}}`))
			return err
		},
		"21 premises": func() error {
			_, err := InsertDecision(t.Context(), nil, someTenant, body(`{"slug":"use","title":"T","premises":[`+strings.TrimSuffix(strings.Repeat("{},", 21), ",")+`]}`))
			return err
		},
		"no scope": func() error {
			d := body(`{"slug":"use","title":"T"}`)
			d.ScopeRefs = nil
			_, err := InsertDecision(t.Context(), nil, someTenant, d)
			return err
		},
		"101 scopes": func() error {
			d := body(`{"slug":"use","title":"T"}`)
			d.ScopeRefs = make([]uuid.UUID, 101)
			for i := range d.ScopeRefs {
				d.ScopeRefs[i] = uuid.New()
			}
			_, err := InsertDecision(t.Context(), nil, someTenant, d)
			return err
		},
		"a nil scope": func() error {
			d := body(`{"slug":"use","title":"T"}`)
			d.ScopeRefs = []uuid.UUID{uuid.Nil}
			_, err := InsertDecision(t.Context(), nil, someTenant, d)
			return err
		},
		"a decision with no start": func() error {
			d := body(`{"slug":"use","title":"T"}`)
			d.ValidFrom = time.Time{}
			_, err := InsertDecision(t.Context(), nil, someTenant, d)
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("%s: %v, want ErrInvalidQuery", name, err)
		}
	}
}

// A version of a decision is written only through the approval of a person (ADR-0076), so the one statement
// that inserts one lives in InsertDecision, which proposals.Approve calls. The migrations and the test helpers
// are not in the application.
func TestOnlyInsertDecisionWritesADecisionVersion(t *testing.T) {
	insert := regexp.MustCompile(`(?i)INSERT\s+INTO\s+registry\.decision_version\b`)
	var found []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "pgtest" || d.Name() == "migrations" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if insert.Match(data) {
			found = append(found, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0] != "../registry/write.go" {
		t.Fatalf("decision versions are inserted by %v, want only ../registry/write.go", found)
	}
}
