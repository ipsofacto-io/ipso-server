//go:build integration

package verification

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

// run is a run of repo. Each repository has an id of its own, as it does on GitHub, because an upload is
// unique by repository and run.
func run(repo string, runID int64, attempt int) Run {
	var id int64
	for _, c := range repo {
		id = (id*31 + int64(c)) % 1_000_000_007
	}
	return Run{
		Installation: 42, RepositoryID: id + 1, Repo: repo, RunID: runID, RunAttempt: attempt,
		SHA: strings.Repeat("ab", 20), Ref: "refs/heads/main", Event: "push",
		WorkflowRef: repo + "/.github/workflows/ci.yml@refs/heads/main",
	}
}

func parsed(t *testing.T, check string, mutate func(upload, report map[string]any)) Upload {
	t.Helper()
	up, err := Parse(bodyOf(t, check, mutate))
	if err != nil {
		t.Fatal(err)
	}
	return up
}

func TestStoreWritesAnUploadAndItsVerdictsAndListReadsThemBack(t *testing.T) {
	s := newStore(t)
	up := parsed(t, "semgrep", nil)
	stored, err := Store(t.Context(), s.app, tenantA, run("acme/api", 1001, 1), up)
	if err != nil || !stored.Created || stored.Verdicts != 2 || stored.ID == uuid.Nil {
		t.Fatalf("Store = %+v, %v", stored, err)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.verdict WHERE tenant_id = $1 AND upload_id = $2`, tenantA, stored.ID); n != 2 {
		t.Errorf("%d verdict rows, want 2", n)
	}

	items, err := List(t.Context(), s.app, tenantA, Filter{}, 10, uuid.Nil)
	if err != nil || len(items) != 2 {
		t.Fatalf("List = %d items, %v", len(items), err)
	}
	for _, it := range items {
		if it.UploadID != stored.ID || it.Repo != "acme/api" || it.RunID != 1001 || it.RunAttempt != 1 || it.Check != "semgrep" ||
			it.Env != "prod" || it.IpsoVersion != "0.5.0" || it.Event != "push" || it.SHA != strings.Repeat("ab", 20) ||
			it.RunURL != "https://github.com/acme/api/actions/runs/1001" || it.SarifSHA256 == nil || *it.SarifSHA256 != hashB ||
			it.BuildSHA256 != hashA || it.EvaluatedAt.IsZero() || it.RecordedAt.IsZero() || !strings.Contains(string(it.Evidence), "semgrep_version") {
			t.Errorf("item = %+v", it)
		}
	}
	// Newest first, so the page after the first item holds the other one.
	if items[0].ID.String() <= items[1].ID.String() {
		t.Errorf("not newest first: %s then %s", items[0].ID, items[1].ID)
	}
	next, err := List(t.Context(), s.app, tenantA, Filter{}, 10, items[0].ID)
	if err != nil || len(next) != 1 || next[0].ID != items[1].ID {
		t.Errorf("the page after the first = %d items, %v", len(next), err)
	}
}

func TestListFiltersByRepositoryAndDecision(t *testing.T) {
	s := newStore(t)
	for _, repo := range []string{"acme/api", "acme/web"} {
		if _, err := Store(t.Context(), s.app, tenantA, run(repo, 1, 1), parsed(t, "plan", nil)); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		filter Filter
		want   int
	}{
		"all":                {Filter{}, 4},
		"one repository":     {Filter{Repo: "acme/web"}, 2},
		"any case":           {Filter{Repo: "ACME/Web"}, 2},
		"no such repository": {Filter{Repo: "acme/none"}, 0},
		"a decision by slug": {Filter{Decision: "use-tls"}, 2},
		"a decision by id":   {Filter{Decision: idOne}, 2},
		"no such decision":   {Filter{Decision: "other"}, 0},
		"both":               {Filter{Repo: "acme/api", Decision: "no-public-buckets"}, 1},
	} {
		items, err := List(t.Context(), s.app, tenantA, tc.filter, 50, uuid.Nil)
		if err != nil || len(items) != tc.want {
			t.Errorf("%s: %d items, %v; want %d", name, len(items), err, tc.want)
		}
	}
	for name, tc := range map[string]struct {
		filter Filter
		limit  int
	}{
		"a bad repository": {Filter{Repo: "acme"}, 10},
		"a bad decision":   {Filter{Decision: "Not A Slug"}, 10},
		"no limit":         {Filter{}, 0},
		"too big a limit":  {Filter{}, MaxPage + 1},
	} {
		if _, err := List(t.Context(), s.app, tenantA, tc.filter, tc.limit, uuid.Nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestARepeatedUploadAddsNothing(t *testing.T) {
	s := newStore(t)
	up := parsed(t, "plan", nil)
	first, err := Store(t.Context(), s.app, tenantA, run("acme/api", 5, 1), up)
	if err != nil || !first.Created {
		t.Fatalf("first = %+v, %v", first, err)
	}
	again, err := Store(t.Context(), s.app, tenantA, run("acme/api", 5, 1), parsed(t, "plan", nil))
	if err != nil || again.Created || again.ID != first.ID || again.Verdicts != 2 {
		t.Fatalf("repeat = %+v, %v; want the first upload and nothing created", again, err)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.upload`); n != 1 {
		t.Errorf("%d uploads, want 1", n)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.verdict`); n != 2 {
		t.Errorf("%d verdicts, want 2", n)
	}

	// Another attempt, other content, and another run are other uploads. So is the same upload of another
	// tenant, because a tenant's uploads are its own.
	for name, tc := range map[string]struct {
		tenant uuid.UUID
		run    Run
		up     Upload
	}{
		"another attempt": {tenantA, run("acme/api", 5, 2), up},
		"other content":   {tenantA, run("acme/api", 5, 1), parsed(t, "plan", func(_, r map[string]any) { r["env"] = "stage" })},
		"another run":     {tenantA, run("acme/api", 6, 1), up},
		"another tenant":  {tenantB, run("acme/api", 5, 1), up},
	} {
		stored, err := Store(t.Context(), s.app, tc.tenant, tc.run, tc.up)
		if err != nil || !stored.Created || stored.ID == first.ID {
			t.Errorf("%s: %+v, %v; want a new upload", name, stored, err)
		}
	}
	if n := s.count(t, `SELECT count(*) FROM verification.upload`); n != 5 {
		t.Errorf("%d uploads, want 5", n)
	}
}

// Two uploads of the same run racing each other store it once, and both are answered with the one id.
func TestConcurrentRepeatsStoreOneUpload(t *testing.T) {
	s := newStore(t)
	up := parsed(t, "plan", nil)
	const workers = 8
	var created atomic.Int32
	ids := make(chan uuid.UUID, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			stored, err := Store(t.Context(), s.app, tenantA, run("acme/api", 9, 1), up)
			if err != nil {
				t.Error(err)
				return
			}
			if stored.Created {
				created.Add(1)
			}
			ids <- stored.ID
		})
	}
	wg.Wait()
	close(ids)
	seen := map[uuid.UUID]bool{}
	for id := range ids {
		seen[id] = true
	}
	if created.Load() != 1 || len(seen) != 1 {
		t.Errorf("%d created and %d different ids, want 1 and 1", created.Load(), len(seen))
	}
	if n := s.count(t, `SELECT count(*) FROM verification.upload`); n != 1 {
		t.Errorf("%d uploads, want 1", n)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.verdict`); n != 2 {
		t.Errorf("%d verdict rows, want 2", n)
	}
}

func TestATenantReadsOnlyItsOwnUploads(t *testing.T) {
	s := newStore(t)
	if _, err := Store(t.Context(), s.app, tenantA, run("acme/api", 1, 1), parsed(t, "plan", nil)); err != nil {
		t.Fatal(err)
	}
	items, err := List(t.Context(), s.app, tenantB, Filter{}, 10, uuid.Nil)
	if err != nil || len(items) != 0 {
		t.Errorf("tenant B read %d of tenant A's verdicts (%v)", len(items), err)
	}
	items, err = List(t.Context(), s.app, tenantB, Filter{Repo: "acme/api"}, 10, uuid.Nil)
	if err != nil || len(items) != 0 {
		t.Errorf("tenant B read %d of tenant A's verdicts by repository (%v)", len(items), err)
	}
}

func TestAnUploadWithNoVerdictsIsStoredAlone(t *testing.T) {
	s := newStore(t)
	up := parsed(t, "plan", func(_, r map[string]any) { r["verdicts"] = []any{} })
	stored, err := Store(t.Context(), s.app, tenantA, run("acme/api", 1, 1), up)
	if err != nil || !stored.Created || stored.Verdicts != 0 {
		t.Fatalf("Store = %+v, %v", stored, err)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.upload`); n != 1 {
		t.Errorf("%d uploads, want 1", n)
	}
}

// A failure writes nothing: the upload row is rolled back with the verdicts that failed it, and the error
// names a state and a constraint and never a value.
func TestAFailedStoreLeavesNothingAndQuotesNothing(t *testing.T) {
	s := newStore(t)
	const marker = "SECRET-MARKER-VALUE"
	for name, tc := range map[string]struct {
		tenant uuid.UUID
		run    Run
		up     func() Upload
		want   string
	}{
		"a verdict the table refuses": {tenantA, run("acme/api", 1, 1), func() Upload {
			up := parsed(t, "plan", nil)
			up.Verdicts[1].Mode = marker
			return up
		}, "verdict_mode"},
		"a run the table refuses": {tenantA, func() Run { r := run("acme/api", 1, 1); r.Repo = "Acme/" + marker; return r }(), func() Upload { return parsed(t, "plan", nil) }, "upload_repo"},
		"a tenant with no row":    {uuid.New(), run("acme/api", 1, 1), func() Upload { return parsed(t, "plan", nil) }, "23503"},
	} {
		_, err := Store(t.Context(), s.app, tc.tenant, tc.run, tc.up())
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: error = %v, want one naming %q and not the value", name, err, tc.want)
		}
	}
	if n := s.count(t, `SELECT count(*) FROM verification.upload`); n != 0 {
		t.Errorf("%d uploads left by failed stores, want 0", n)
	}
	if n := s.count(t, `SELECT count(*) FROM verification.verdict`); n != 0 {
		t.Errorf("%d verdicts left by failed stores, want 0", n)
	}
	if _, err := Store(t.Context(), nil, tenantA, run("acme/api", 1, 1), Upload{}); err == nil {
		t.Error("Store accepted no database")
	}
	if _, err := Store(t.Context(), s.app, uuid.Nil, run("acme/api", 1, 1), Upload{}); err == nil {
		t.Error("Store accepted no tenant")
	}
}

// The application role inserts and reads and nothing else, so a stored verdict cannot be changed or
// removed through it.
func TestTheApplicationRoleCannotChangeOrRemoveAVerdict(t *testing.T) {
	s := newStore(t)
	if _, err := Store(t.Context(), s.app, tenantA, run("acme/api", 1, 1), parsed(t, "plan", nil)); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"update an upload":   `UPDATE verification.upload SET env = 'x'`,
		"delete an upload":   `DELETE FROM verification.upload`,
		"update a verdict":   `UPDATE verification.verdict SET result = 'pass'`,
		"delete a verdict":   `DELETE FROM verification.verdict`,
		"truncate a verdict": `TRUNCATE verification.verdict`,
	} {
		if _, err := s.app.ExecContext(t.Context(), query); err == nil {
			t.Errorf("%s: the application role may", name)
		}
	}
	if n := s.count(t, `SELECT count(*) FROM verification.verdict`); n != 2 {
		t.Errorf("%d verdicts, want 2", n)
	}
}
