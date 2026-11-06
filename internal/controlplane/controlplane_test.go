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
