//go:build integration

package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// commitRun is a run of repo on the commit sha.
func commitRun(repo string, runID int64, attempt int, sha string) Run {
	r := run(repo, runID, attempt)
	r.SHA = sha
	return r
}

var (
	commitA = strings.Repeat("ab", 20)
	commitB = strings.Repeat("cd", 20)
)

// A commit that no upload names is unknown and an upload with no verdict is not: the first reads as no answer and the
// second as an empty list, so a reader never takes a commit that nobody reported on for a clean one (ADR-0124).
func TestACommitWithNoUploadIsUnknownAndOneWithNoVerdictsIsEmpty(t *testing.T) {
	s := newStore(t)
	items, stored, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, s.soon(t))
	if err != nil || stored || items != nil {
		t.Fatalf("ByCommit with nothing stored = %v, %v, %v, want unknown", items, stored, err)
	}

	empty := parsed(t, "plan", func(_, r map[string]any) { r["verdicts"] = []any{} })
	if _, err := Store(t.Context(), s.app, tenantA, commitRun("acme/api", 1, 1, commitA), empty); err != nil {
		t.Fatal(err)
	}
	items, stored, err = ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, s.soon(t))
	if err != nil || !stored || items == nil || len(items) != 0 {
		t.Fatalf("ByCommit with an upload and no verdict = %v, %v, %v, want stored and empty", items, stored, err)
	}
	// Another commit of the same repository is still unknown.
	items, stored, err = ByCommit(t.Context(), s.app, tenantA, "acme/api", commitB, s.soon(t))
	if err != nil || stored || items != nil {
		t.Errorf("another commit = %v, %v, %v, want unknown", items, stored, err)
	}
}

// Every run, attempt, check command and environment of the commit counts, and an upload of another commit, another
// repository or another tenant does not.
func TestByCommitReadsEveryUploadOfTheCommitAndNothingElse(t *testing.T) {
	s := newStore(t)
	put := func(tenant uuid.UUID, r Run, mutate func(upload, report map[string]any)) uuid.UUID {
		t.Helper()
		stored, err := Store(t.Context(), s.app, tenant, r, parsed(t, "plan", mutate))
		if err != nil {
			t.Fatal(err)
		}
		return stored.ID
	}
	first := put(tenantA, commitRun("acme/api", 1, 1, commitA), nil)
	second := put(tenantA, commitRun("acme/api", 1, 2, commitA), nil)
	staging := put(tenantA, commitRun("acme/api", 2, 1, commitA), func(_, r map[string]any) { r["env"] = "staging" })
	semgrep := parsed(t, "semgrep", nil)
	scanned, err := Store(t.Context(), s.app, tenantA, commitRun("acme/api", 3, 1, commitA), semgrep)
	if err != nil {
		t.Fatal(err)
	}
	// None of these is the commit asked about.
	put(tenantA, commitRun("acme/api", 4, 1, commitB), nil)
	put(tenantA, commitRun("acme/web", 5, 1, commitA), nil)
	put(tenantB, commitRun("acme/api", 6, 1, commitA), nil)

	items, stored, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, s.soon(t))
	if err != nil || !stored {
		t.Fatalf("ByCommit = %v, %v", stored, err)
	}
	want := map[uuid.UUID]bool{first: true, second: true, staging: true, scanned.ID: true}
	if len(items) != 2*len(want) {
		t.Fatalf("%d verdicts, want %d, two for each of the four uploads", len(items), 2*len(want))
	}
	envs := map[string]bool{}
	for i, it := range items {
		if !want[it.UploadID] || it.Repo != "acme/api" || it.SHA != commitA {
			t.Errorf("a verdict of %s on %s from upload %s is not one of the commit", it.Repo, it.SHA, it.UploadID)
		}
		if i > 0 && items[i-1].ID.String() <= it.ID.String() {
			t.Errorf("not newest first: %s then %s", items[i-1].ID, it.ID)
		}
		envs[it.Env] = true
	}
	if !envs["prod"] || !envs["staging"] {
		t.Errorf("environments %v: a run in one environment must not hide the other", envs)
	}

	// A commit and a repository are read in either case, as an upload stores them in lowercase.
	for _, args := range [][2]string{{"ACME/API", commitA}, {"acme/api", strings.ToUpper(commitA)}} {
		again, found, err := ByCommit(t.Context(), s.app, tenantA, args[0], args[1], s.soon(t))
		if err != nil || !found || len(again) != len(items) {
			t.Errorf("ByCommit(%s, %s) = %d verdicts, %v, %v, want %d", args[0], args[1], len(again), found, err, len(items))
		}
	}

	// Tenant B holds an upload of the same repository and commit, and tenant A's answer shows nothing of it.
	other, found, err := ByCommit(t.Context(), s.app, tenantB, "acme/api", commitA, s.soon(t))
	if err != nil || !found || len(other) != 2 {
		t.Errorf("tenant B = %d verdicts, %v, %v, want its own two", len(other), found, err)
	}
	for _, it := range other {
		if want[it.UploadID] {
			t.Errorf("tenant B read upload %s of tenant A", it.UploadID)
		}
	}
}

// An upload stored after the transaction time is not seen, as on the list, and the answer is unknown until one is.
func TestByCommitDoesNotSeeAnUploadStoredAfterKnown(t *testing.T) {
	s := newStore(t)
	before := s.mark(t)
	if _, err := Store(t.Context(), s.app, tenantA, commitRun("acme/api", 1, 1, commitA), parsed(t, "plan", nil)); err != nil {
		t.Fatal(err)
	}
	items, stored, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, before)
	if err != nil || stored || items != nil {
		t.Errorf("as known before the upload = %v, %v, %v, want unknown", items, stored, err)
	}
	items, stored, err = ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, s.soon(t))
	if err != nil || !stored || len(items) != 2 {
		t.Errorf("as known after the upload = %d verdicts, %v, %v, want 2", len(items), stored, err)
	}
}

// A verdict reads on a commit as it reads on the list for the same transaction time: the same fields and the same
// reading against the recorded baseline (ADR-0124 decision 4).
func TestByCommitReadsAVerdictAsTheListReadsIt(t *testing.T) {
	w := newWorld(t)
	decision := w.decision(t, tenantA, idOne)
	w.period(t, tenantA, decision, "[2000-01-01,)")
	w.baseline(t, tenantA, decision, "acme/api", digestsFrom(1, 3))
	w.upload(t, "acme/api", 1, []any{}, digestsFrom(1, 3))
	w.upload(t, "acme/api", 2, []any{}, digestsFrom(2, 3))

	known := w.soon(t)
	onList, err := List(t.Context(), w.app, tenantA, Filter{Repo: "acme/api"}, MaxPage, uuid.Nil, known)
	if err != nil {
		t.Fatal(err)
	}
	onCommit, stored, err := ByCommit(t.Context(), w.app, tenantA, "acme/api", commitA, known)
	if err != nil || !stored {
		t.Fatalf("ByCommit = %v, %v", stored, err)
	}
	a, _ := json.Marshal(onList)
	b, _ := json.Marshal(onCommit)
	if len(onCommit) != 4 || string(a) != string(b) {
		t.Fatalf("the commit reads\n%s\nand the list reads\n%s", b, a)
	}
	waived := 0
	for _, it := range onCommit {
		if it.Baseline != nil && it.Baseline.Result == "waived(baseline)" {
			waived++
		}
	}
	if waived != 1 {
		t.Errorf("%d verdicts read waived(baseline), want the one whose digests are all recorded", waived)
	}
}

// A commit with more verdicts than the bound is refused whole and never cut short, and one at the bound is read.
func TestByCommitRefusesMoreThanTheBoundWholeAndReadsExactlyTheBound(t *testing.T) {
	many := func(n int) func(upload, report map[string]any) {
		return func(_, r map[string]any) {
			verdicts := make([]any, n)
			for i := range verdicts {
				verdicts[i] = map[string]any{"decision_id": idOne, "slug": "no-public-buckets", "check_index": i, "mode": "warn", "result": "pass", "violations": 0}
			}
			r["verdicts"] = verdicts
		}
	}
	for _, tc := range []struct {
		verdicts int
		tooMany  bool
	}{{MaxCommitVerdicts, false}, {MaxCommitVerdicts + 1, true}} {
		t.Run(fmt.Sprint(tc.verdicts), func(t *testing.T) {
			s := newStore(t)
			if _, err := Store(t.Context(), s.app, tenantA, commitRun("acme/api", 1, 1, commitA), parsed(t, "plan", many(tc.verdicts))); err != nil {
				t.Fatal(err)
			}
			items, stored, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, s.soon(t))
			switch {
			case tc.tooMany && (!errors.Is(err, ErrTooMany) || items != nil || stored):
				t.Errorf("%d verdicts = %d items, %v, %v, want ErrTooMany and nothing", tc.verdicts, len(items), stored, err)
			case !tc.tooMany && (err != nil || !stored || len(items) != MaxCommitVerdicts):
				t.Errorf("%d verdicts = %d items, %v, %v, want all of them", tc.verdicts, len(items), stored, err)
			}
		})
	}
}

// A commit, a repository, a transaction time or a tenant that is not usable is refused before anything is read.
func TestByCommitRefusesWhatItCannotRead(t *testing.T) {
	s := newStore(t)
	soon := s.soon(t)
	for name, call := range map[string]func() error{
		"a short commit": func() error {
			_, _, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA[:7], soon)
			return err
		},
		"no commit": func() error { _, _, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", "", soon); return err },
		"a bad repository": func() error {
			_, _, err := ByCommit(t.Context(), s.app, tenantA, "not a repo", commitA, soon)
			return err
		},
		"no repository": func() error { _, _, err := ByCommit(t.Context(), s.app, tenantA, "", commitA, soon); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"no tenant": func() error {
			_, _, err := ByCommit(t.Context(), s.app, uuid.Nil, "acme/api", commitA, soon)
			return err
		},
		"no time": func() error {
			_, _, err := ByCommit(t.Context(), s.app, tenantA, "acme/api", commitA, time.Time{})
			return err
		},
		"no database": func() error {
			_, _, err := ByCommit(t.Context(), nil, tenantA, "acme/api", commitA, soon)
			return err
		},
	} {
		if err := call(); err == nil || errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want an error that is not a bad request", name, err)
		}
	}
}
