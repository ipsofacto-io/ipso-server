package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/login"
)

func TestNewRefusesAnIncompleteConfigBeforeItTouchesTheDatabase(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none")
	if err != nil {
		t.Fatal(err)
	}
	valid := Config{DB: db, Tenant: uuid.New(), Issuer: "https://idp.example.test", Audience: "ipso-api"}
	tests := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"no database", func(c *Config) { c.DB = nil }, "database"},
		{"no tenant", func(c *Config) { c.Tenant = uuid.Nil }, "tenant"},
		{"no issuer", func(c *Config) { c.Issuer = "" }, "issuer"},
		{"no audience", func(c *Config) { c.Audience = "" }, "audience"},
		{"an MCP issuer alone", func(c *Config) { c.MCPIssuer = "https://mcp.example.test" }, "together"},
		{"an MCP resource alone", func(c *Config) { c.MCPResourceURL = "https://ipso.example.test/mcp" }, "together"},
		{"a public URL without providers", func(c *Config) { c.PublicURL = "https://ipso.example.test" }, "together"},
		{"providers without a public URL", func(c *Config) {
			c.Providers = []login.ProviderConfig{{ID: "github", Kind: login.KindGitHub, ClientID: "c", ClientSecretEnv: "IPSO_LOGIN_GITHUB"}}
		}, "together"},
		{"a CI audience without the App", func(c *Config) { c.CIAudience = "https://ipso.example.test/ci" }, "together"},
		{"the App without a CI audience", func(c *Config) { c.Repositories = &fakeApp{} }, "together"},
		{"a CI audience equal to the API audience", func(c *Config) {
			c.CIAudience, c.Repositories = c.Audience, &fakeApp{}
		}, "audience of their own"},
		{"a CI audience equal to the MCP resource", func(c *Config) {
			c.MCPIssuer, c.MCPResourceURL = "https://mcp.example.test", "https://ipso.example.test/mcp"
			c.CIAudience, c.Repositories = "https://ipso.example.test/mcp", &fakeApp{}
		}, "audience of their own"},
		{"equal audiences", func(c *Config) {
			c.MCPIssuer, c.MCPResourceURL, c.Audience = "https://mcp.example.test", "https://ipso.example.test/mcp", "https://ipso.example.test/mcp"
		}, "distinct audiences"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.change(&cfg)
			if _, err := New(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestHealthIs503WhenTheDatabaseDoesNotAnswer(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(db, uuid.New(), slog.New(slog.DiscardHandler), api.Limits{})
	rec := httptest.NewRecorder()
	svc.health(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
}

func TestHealthKeepsTheLastAnswerForAMoment(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := newService(db, uuid.New(), slog.New(slog.DiscardHandler), api.Limits{})
	svc.now = func() time.Time { return now }
	svc.healthAt, svc.healthy = now, true
	if rec := httptest.NewRecorder(); true {
		svc.health(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("within the TTL: status %d, want the kept 204", rec.Code)
		}
	}
	now = now.Add(2 * healthTTL)
	rec := httptest.NewRecorder()
	svc.health(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("after the TTL: status %d, want 503 from a fresh ping", rec.Code)
	}
}

func TestAFoundLoginIsKeptAndAMissIsNot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := newService(nil, uuid.New(), slog.New(slog.DiscardHandler), api.Limits{Rate: 1000, Burst: 1000})
	svc.now = func() time.Time { return now }
	bound := uuid.New()
	calls := 0
	svc.lookup = func(_ context.Context, issuer, subject string) (uuid.UUID, error) {
		calls++
		if subject == "known" {
			return bound, nil
		}
		return uuid.Nil, identity.ErrUnknownLogin
	}
	claims := func(subject string) authn.Claims {
		return authn.Claims{Issuer: "https://idp.example.test", Subject: subject}
	}

	for range 3 {
		if got, ok := svc.principal(t.Context(), claims("known")); !ok || got != bound {
			t.Fatalf("known = %v, %v", got, ok)
		}
	}
	if calls != 1 {
		t.Fatalf("a found login was read %d times, want 1", calls)
	}
	for range 2 {
		if _, ok := svc.principal(t.Context(), claims("stranger")); ok {
			t.Fatal("an unbound subject was accepted")
		}
	}
	if calls != 3 {
		t.Fatalf("a miss was kept: %d reads, want 3", calls)
	}
	// Another issuer's subject of the same name is another login.
	other := authn.Claims{Issuer: "https://other.example.test", Subject: "known"}
	if _, ok := svc.principal(t.Context(), other); !ok || calls != 4 {
		t.Fatalf("another issuer: ok %v, reads %d", ok, calls)
	}
	now = now.Add(2 * loginTTL)
	svc.principal(t.Context(), claims("known"))
	if calls != 5 {
		t.Fatalf("an old login was not read again: %d reads", calls)
	}
}

func TestLookupsForLoginsNotKeptAreLimited(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := newService(nil, uuid.New(), slog.New(slog.DiscardHandler), api.Limits{Rate: 0.001, Burst: 3})
	svc.now = func() time.Time { return now }
	reads := 0
	svc.lookup = func(context.Context, string, string) (uuid.UUID, error) {
		reads++
		return uuid.Nil, identity.ErrUnknownLogin
	}
	for i := range 10 {
		svc.principal(t.Context(), authn.Claims{Issuer: "https://idp.example.test", Subject: fmt.Sprint("stranger-", i)})
	}
	if reads != 3 {
		t.Fatalf("the database was read %d times, want the burst of 3", reads)
	}
}

func TestTheLoginCacheStaysBounded(t *testing.T) {
	now := time.Now()
	cache := newLoginCache(time.Minute, 2)
	for _, subject := range []string{"a", "b", "c"} {
		cache.put(loginKey{"https://idp.example.test", subject}, uuid.New(), now)
	}
	if len(cache.entries) > 2 {
		t.Fatalf("%d entries, want at most 2", len(cache.entries))
	}
}

// Each answer of the sign-in maps to the one the guard acts on. internal/login's tests cover the
// lookups, and the integration tests cover the whole path.
func TestEachSignInStatusMapsToTheOneTheGuardActsOn(t *testing.T) {
	for status, want := range map[login.Status]api.SessionStatus{
		login.Found:   api.SessionFound,
		login.Unknown: api.SessionUnknown,
		login.Busy:    api.SessionBusy,
		login.Failed:  api.SessionFailed,
	} {
		if got := sessionStatus(status); got != want {
			t.Errorf("%v maps to %v, want %v", status, got, want)
		}
	}
}

// fakeApp is the GitHub App: it answers from a table and counts its calls.
type fakeApp struct {
	byRepo    map[string]integrations.Installation
	err       error
	verifyErr error
	calls     int
}

func (f *fakeApp) Verify(context.Context) error { return f.verifyErr }

func (f *fakeApp) RepositoryInstallation(_ context.Context, owner, name string) (integrations.Installation, error) {
	f.calls++
	if f.err != nil {
		return integrations.Installation{}, f.err
	}
	installation, ok := f.byRepo[strings.ToLower(owner+"/"+name)]
	if !ok {
		return integrations.Installation{}, integrations.ErrNotFound
	}
	return installation, nil
}

func runOf(owner, name string, repositoryID, ownerID int64) authn.RunClaims {
	return authn.RunClaims{Owner: owner, Name: name, RepositoryID: repositoryID, OwnerID: ownerID, RunID: 7, RunAttempt: 1}
}

func newTestMapper(t *testing.T, app Repositories) *uploadMapper {
	t.Helper()
	// A store no test can reach: a mapping that needs the database fails there, and every refusal the
	// tests expect happens before it.
	db, err := sql.Open("pgx", "postgres://nobody@127.0.0.1:1/none?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return newUploadMapper(db, uuid.New(), app, slog.New(slog.DiscardHandler))
}

func TestARepositoryNoInstallationCoversIsUnknown(t *testing.T) {
	app := &fakeApp{}
	m := newTestMapper(t, app)
	if _, status := m.lookup(t.Context(), runOf("acme", "api", 1, 9)); status != api.MappingUnknown {
		t.Errorf("status = %v, want unknown", status)
	}
	// A not found is never kept, because the account may install the App a moment later.
	if _, status := m.lookup(t.Context(), runOf("acme", "api", 1, 9)); status != api.MappingUnknown || app.calls != 2 {
		t.Errorf("status = %v after %d calls, want unknown after 2", status, app.calls)
	}
}

func TestAnInstallationOnAnotherAccountIsUnknown(t *testing.T) {
	app := &fakeApp{byRepo: map[string]integrations.Installation{"acme/api": {ID: 42, AccountID: 9}}}
	m := newTestMapper(t, app)
	// The token says the repository belongs to account 10, and the installation is on account 9.
	if _, status := m.lookup(t.Context(), runOf("acme", "api", 1, 10)); status != api.MappingUnknown {
		t.Errorf("status = %v, want unknown", status)
	}
}

func TestAFailedAppCallFailsTheMappingAndIsNotKept(t *testing.T) {
	app := &fakeApp{err: fmt.Errorf("github: status 502")}
	m := newTestMapper(t, app)
	if _, status := m.lookup(t.Context(), runOf("acme", "api", 1, 9)); status != api.MappingFailed {
		t.Errorf("status = %v, want failed", status)
	}
	if _, status := m.lookup(t.Context(), runOf("acme", "api", 1, 9)); status != api.MappingFailed || app.calls != 2 {
		t.Errorf("status = %v after %d calls, want failed after 2", status, app.calls)
	}
}

func TestFoundInstallationsAreKeptAndMissesShareOneBudget(t *testing.T) {
	app := &fakeApp{byRepo: map[string]integrations.Installation{"acme/api": {ID: 42, AccountID: 9}}}
	m := newTestMapper(t, app)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	// The database is unreachable, so a found installation ends in a failed read of its tenant. The GitHub
	// answer is kept all the same, and the second upload does not call GitHub again.
	for range 2 {
		if _, status := m.lookup(t.Context(), runOf("Acme", "API", 1, 9)); status != api.MappingFailed {
			t.Fatalf("status = %v, want failed at the store", status)
		}
	}
	if app.calls != 1 {
		t.Errorf("GitHub was called %d times for one repository, want 1", app.calls)
	}

	// Repositories that are not kept spend a budget of appCallBurst calls, then are busy.
	busy := 0
	for id := int64(100); id < 100+2*appCallBurst; id++ {
		if _, status := m.lookup(t.Context(), runOf("stranger", fmt.Sprintf("r%d", id), id, 5)); status == api.MappingBusy {
			busy++
		}
	}
	if app.calls > 1+appCallBurst || busy == 0 {
		t.Errorf("GitHub was called %d times and %d lookups were busy", app.calls, busy)
	}
	// The budget comes back with time.
	now = now.Add(5 * time.Second)
	if _, status := m.lookup(t.Context(), runOf("stranger", "again", 999, 5)); status == api.MappingBusy {
		t.Error("the budget did not refill")
	}
}

func TestACachedInstallationExpires(t *testing.T) {
	app := &fakeApp{byRepo: map[string]integrations.Installation{"acme/api": {ID: 42, AccountID: 9}}}
	m := newTestMapper(t, app)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	m.lookup(t.Context(), runOf("acme", "api", 1, 9))
	now = now.Add(repositoryTTL + time.Second)
	m.lookup(t.Context(), runOf("acme", "api", 1, 9))
	if app.calls != 2 {
		t.Errorf("GitHub was called %d times across the TTL, want 2", app.calls)
	}
	// A renamed repository is another key, so a stale name cannot answer for it.
	m.lookup(t.Context(), runOf("acme", "renamed", 1, 9))
	if app.calls != 3 {
		t.Errorf("GitHub was called %d times after a rename, want 3", app.calls)
	}
}
