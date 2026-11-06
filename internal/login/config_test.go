package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
)

func TestParseProvidersIsStrict(t *testing.T) {
	good := `[{"id":"dex","kind":"oidc","issuer":"https://dex.example.test","client_id":"c","client_secret_env":"IPSO_LOGIN_DEX"}]`
	providers, err := ParseProviders(strings.NewReader(good))
	if err != nil || len(providers) != 1 || providers[0].ID != "dex" || providers[0].Issuer != "https://dex.example.test" {
		t.Fatalf("%+v, %v", providers, err)
	}
	for name, input := range map[string]string{
		"an unknown field":    `[{"id":"dex","kind":"oidc","issuer":"https://x","client_id":"c","client_secret_env":"IPSO_LOGIN_X","client_secret":"oops"}]`,
		"an object":           `{"id":"dex"}`,
		"a second value":      good + good,
		"trailing garbage":    good + "x",
		"a number for the id": `[{"id":7}]`,
		"empty":               ``,
		"larger than 1 MiB":   `[{"id":"` + strings.Repeat("a", 1<<20) + `"}]`,
	} {
		if _, err := ParseProviders(strings.NewReader(input)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestProvidersAreValidatedBeforeAnythingConnects(t *testing.T) {
	secrets := map[string]string{"IPSO_LOGIN_A": "a", "IPSO_LOGIN_B": "b", ProvidersEnv: "[]"}
	secret := func(name string) string { return secrets[name] }
	oidc := func(id, issuer string) ProviderConfig {
		return ProviderConfig{ID: id, Kind: KindOIDC, Issuer: issuer, ClientID: "client-" + id, ClientSecretEnv: "IPSO_LOGIN_A"}
	}
	github := ProviderConfig{ID: "github", Kind: KindGitHub, ClientID: "gh-client", ClientSecretEnv: "IPSO_LOGIN_B"}
	with := func(base ProviderConfig, change func(*ProviderConfig)) ProviderConfig { change(&base); return base }

	if err := validate([]ProviderConfig{oidc("google", "https://accounts.google.com"), github, oidc("microsoft", "https://login.microsoftonline.com/t/v2.0")}, nil, secret); err != nil {
		t.Fatalf("a good configuration: %v", err)
	}
	for name, providers := range map[string][]ProviderConfig{
		"none":                                  nil,
		"an upper-case id":                      {with(github, func(p *ProviderConfig) { p.ID = "GitHub" })},
		"an id with a slash":                    {with(github, func(p *ProviderConfig) { p.ID = "a/b" })},
		"an id that starts with a digit":        {with(github, func(p *ProviderConfig) { p.ID = "1a" })},
		"an empty id":                           {with(github, func(p *ProviderConfig) { p.ID = "" })},
		"a long id":                             {with(github, func(p *ProviderConfig) { p.ID = strings.Repeat("a", 33) })},
		"the same id twice":                     {oidc("a", "https://one.example.test"), oidc("a", "https://two.example.test")},
		"the same issuer twice":                 {oidc("a", "https://one.example.test"), oidc("b", "https://one.example.test")},
		"two GitHub providers":                  {github, with(github, func(p *ProviderConfig) { p.ID = "github2" })},
		"an unknown kind":                       {with(github, func(p *ProviderConfig) { p.Kind = "saml" })},
		"an http issuer":                        {oidc("a", "http://one.example.test")},
		"an issuer with a query":                {oidc("a", "https://one.example.test/?x=1")},
		"an issuer with a fragment":             {oidc("a", "https://one.example.test/#x")},
		"no issuer":                             {oidc("a", "")},
		"GitHub's issuer as oidc":               {oidc("a", "https://github.com")},
		"an issuer on GitHub":                   {with(github, func(p *ProviderConfig) { p.Issuer = "https://github.com" })},
		"no client id":                          {with(github, func(p *ProviderConfig) { p.ClientID = "" })},
		"a client id with a newline":            {with(github, func(p *ProviderConfig) { p.ClientID = "a\nb" })},
		"a client id equal to the API audience": {with(github, func(p *ProviderConfig) { p.ClientID = "https://api.example.test/v1" })},
		"a client id equal to the MCP resource": {with(github, func(p *ProviderConfig) { p.ClientID = "https://mcp.example.test" })},
		"a secret variable of another family":   {with(github, func(p *ProviderConfig) { p.ClientSecretEnv = "IPSO_DATABASE_URL" })},
		"the providers variable as a secret":    {with(github, func(p *ProviderConfig) { p.ClientSecretEnv = ProvidersEnv })},
		"a lower-case secret variable":          {with(github, func(p *ProviderConfig) { p.ClientSecretEnv = "ipso_login_a" })},
		"a secret variable that is not set":     {with(github, func(p *ProviderConfig) { p.ClientSecretEnv = "IPSO_LOGIN_MISSING" })},
	} {
		if err := validate(providers, []string{"https://api.example.test/v1", "https://mcp.example.test"}, secret); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := validate([]ProviderConfig{with(github, func(p *ProviderConfig) { p.ClientSecretEnv = "IPSO_LOGIN_BLANK" })}, nil, func(string) string { return "  " }); err == nil {
		t.Error("a blank secret was accepted")
	}
}

func TestThePublicURLIsReducedToAnOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://ipso.example.com":      "https://ipso.example.com",
		"https://IPSO.Example.com/":     "https://ipso.example.com",
		"https://ipso.example.com:443":  "https://ipso.example.com",
		"https://ipso.example.com:8443": "https://ipso.example.com:8443",
		"http://localhost:8080":         "http://localhost:8080",
		"http://localhost":              "http://localhost",
		"http://localhost:80":           "http://localhost",
		"http://127.0.0.1:8080/":        "http://127.0.0.1:8080",
		"http://[::1]:8080":             "http://[::1]:8080",
	} {
		got, err := CanonicalOrigin(in)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "ipso.example.com", "//ipso.example.com", "ftp://ipso.example.com",
		"http://ipso.example.com", "http://192.168.1.5:8080", "http://localhost.example.com", "http://127.0.0.1.example.com",
		"https://user@ipso.example.com", "https://user:pw@ipso.example.com",
		"https://ipso.example.com/app", "https://ipso.example.com/?x=1", "https://ipso.example.com?", "https://ipso.example.com#x",
		"mailto:a@b.c", "https://",
	} {
		if got, err := CanonicalOrigin(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}

func TestStartRefusesWhatItCannotUse(t *testing.T) {
	good := func(t *testing.T) (*authntest.Server, Options) {
		auth := authntest.NewServer(t)
		auth.Meta["authorization_endpoint"] = auth.Server.URL + "/authorize"
		auth.Meta["token_endpoint"] = auth.Server.URL + "/token"
		return auth, Options{
			store:     newFakeStore(nil),
			Tenant:    tenant,
			PublicURL: publicURL,
			Providers: []ProviderConfig{{ID: "fake", Kind: KindOIDC, Issuer: auth.Server.URL, ClientID: clientID, ClientSecretEnv: secretEnv}},
			Secret:    func(string) string { return clientSecret },
			Client:    auth.Server.Client(),
		}
	}
	t.Run("a good one", func(t *testing.T) {
		_, opts := good(t)
		if _, err := New(t.Context(), opts); err != nil {
			t.Fatal(err)
		}
	})
	for name, change := range map[string]func(*authntest.Server, *Options){
		"no tenant":                            func(_ *authntest.Server, o *Options) { o.Tenant = uuid.Nil },
		"a public URL on http":                 func(_ *authntest.Server, o *Options) { o.PublicURL = "http://ipso.example.test" },
		"no public URL":                        func(_ *authntest.Server, o *Options) { o.PublicURL = "" },
		"no secret":                            func(_ *authntest.Server, o *Options) { o.Secret = func(string) string { return "" } },
		"no secret reader":                     func(_ *authntest.Server, o *Options) { o.Secret = nil },
		"a provider that is down":              func(a *authntest.Server, _ *Options) { a.Server.Close() },
		"an issuer the metadata does not name": func(a *authntest.Server, _ *Options) { a.Meta["issuer"] = "https://elsewhere.example.test" },
		"an authorization endpoint on http": func(a *authntest.Server, _ *Options) {
			a.Meta["authorization_endpoint"] = "http://idp.example.test/authorize"
		},
		"a token endpoint on http":  func(a *authntest.Server, _ *Options) { a.Meta["token_endpoint"] = "http://idp.example.test/token" },
		"no authorization endpoint": func(a *authntest.Server, _ *Options) { delete(a.Meta, "authorization_endpoint") },
		"no token endpoint":         func(a *authntest.Server, _ *Options) { delete(a.Meta, "token_endpoint") },
		"a client id equal to the API audience": func(_ *authntest.Server, o *Options) {
			o.Forbidden = []string{clientID}
		},
	} {
		t.Run(name, func(t *testing.T) {
			auth, opts := good(t)
			change(auth, &opts)
			if _, err := New(t.Context(), opts); err == nil {
				t.Fatal("it started")
			}
		})
	}
	t.Run("no database", func(t *testing.T) {
		_, opts := good(t)
		opts.store = nil
		if _, err := New(t.Context(), opts); err == nil {
			t.Fatal("it started")
		}
	})
}

// A provider's redirect is an answer this process does not follow: a token endpoint that redirects is
// a token endpoint it does not use.
func TestAProviderThatRedirectsTheTokenEndpointIsNotFollowed(t *testing.T) {
	r := newRig(t)
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a redirect was followed")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(elsewhere.Close)
	p := r.svc.providers["fake"].(*oidcProvider)
	redirecting := httptest.NewTLSServer(http.RedirectHandler(elsewhere.URL, http.StatusTemporaryRedirect))
	t.Cleanup(redirecting.Close)
	p.oauth.Endpoint.TokenURL = redirecting.URL
	r.store.bind(r.auth.Server.URL, subjectOne, "human")
	_, a := r.start("fake")
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}
