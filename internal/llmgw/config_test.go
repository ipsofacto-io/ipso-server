package llmgw

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func setKeys(t *testing.T) {
	t.Helper()
	for _, name := range []string{"IPSO_LLM_MISTRAL", "IPSO_LLM_BEDROCK", "IPSO_LLM_AZURE", "IPSO_LLM_TENANT"} {
		t.Setenv(name, "synthetic-"+strings.ToLower(name))
	}
}

var (
	mistralRoute = Route{Name: "mistral", Provider: Mistral, Model: "mistral-medium-2508", KeyEnv: "IPSO_LLM_MISTRAL"}
	bedrockRoute = Route{Name: "bedrock-eu", Provider: Bedrock, Region: "eu-central-1", Model: "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"}
	azureRoute   = Route{Name: "azure-eu", Provider: Azure, Endpoint: "https://ipso-eu.openai.azure.com", Region: "swedencentral", DeploymentType: "datazone", Model: "gpt-4-1-mini", KeyEnv: "IPSO_LLM_AZURE"}
)

func baseConfig() Config {
	return Config{
		Routes:        []Route{mistralRoute, bedrockRoute, azureRoute},
		Default:       []string{"mistral", "bedrock-eu", "azure-eu"},
		MonthlyTokens: 1000,
	}
}

func TestDefaultRoutesResolveOnlyToEUEndpoints(t *testing.T) {
	setKeys(t)
	_, defaults, _, err := compile(baseConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://api.mistral.ai/v1/chat/completions",
		"https://bedrock-runtime.eu-central-1.amazonaws.com/model/eu.anthropic.claude-sonnet-4-5-20250929-v1:0/converse",
		"https://ipso-eu.openai.azure.com/openai/v1/chat/completions",
	}
	if len(defaults.routes) != len(want) {
		t.Fatalf("routes = %d", len(defaults.routes))
	}
	for i, route := range defaults.routes {
		if route.url != want[i] || !route.eu {
			t.Errorf("route %s = %s eu %v, want %s", route.name, route.url, route.eu, want[i])
		}
	}
}

func TestOperatorRoutesOutsideTheEUAreRefused(t *testing.T) {
	setKeys(t)
	cases := map[string]Route{
		"bedrock in a US region":        {Name: "x", Provider: Bedrock, Region: "us-east-1", Model: "anthropic.claude-sonnet-4-5-20250929-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"},
		"bedrock in London":             {Name: "x", Provider: Bedrock, Region: "eu-west-2", Model: "mistral.mistral-large-2402-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"},
		"bedrock in Zurich":             {Name: "x", Provider: Bedrock, Region: "eu-central-2", Model: "mistral.mistral-large-2402-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"},
		"bedrock with a US profile":     {Name: "x", Provider: Bedrock, Region: "eu-central-1", Model: "us.anthropic.claude-sonnet-4-5-20250929-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"},
		"bedrock with a global profile": {Name: "x", Provider: Bedrock, Region: "eu-west-1", Model: "global.anthropic.claude-sonnet-4-5-20250929-v1:0", KeyEnv: "IPSO_LLM_BEDROCK"},
		"azure in a US region":          {Name: "x", Provider: Azure, Endpoint: "https://a1.openai.azure.com", Region: "eastus", DeploymentType: "datazone", Model: "m", KeyEnv: "IPSO_LLM_AZURE"},
		"azure global deployment":       {Name: "x", Provider: Azure, Endpoint: "https://a1.openai.azure.com", Region: "swedencentral", DeploymentType: "global", Model: "m", KeyEnv: "IPSO_LLM_AZURE"},
		"azure on another host":         {Name: "x", Provider: Azure, Endpoint: "https://a1.openai.example.com", Region: "swedencentral", DeploymentType: "datazone", Model: "m", KeyEnv: "IPSO_LLM_AZURE"},
		"an openai-compatible endpoint": {Name: "x", Provider: OpenAI, Endpoint: "https://api.openai.com/v1", Model: "m", KeyEnv: "IPSO_LLM_TENANT"},
		"allow_non_eu on an operator":   {Name: "x", Provider: Bedrock, Region: "us-east-1", Model: "m", KeyEnv: "IPSO_LLM_BEDROCK", AllowNonEU: true},
		"a bedrock endpoint override":   {Name: "x", Provider: Bedrock, Region: "eu-central-1", Endpoint: "https://evil.example", Model: "m", KeyEnv: "IPSO_LLM_BEDROCK"},
		"a mistral endpoint override":   {Name: "x", Provider: Mistral, Endpoint: "https://api.mistral.example", Model: "m", KeyEnv: "IPSO_LLM_MISTRAL"},
		"a key from another variable":   {Name: "x", Provider: Mistral, Model: "m", KeyEnv: "IPSO_MIGRATE_DATABASE_URL"},
		"a key that is not set":         {Name: "x", Provider: Mistral, Model: "m", KeyEnv: "IPSO_LLM_UNSET"},
		"an unknown provider":           {Name: "x", Provider: "vertex", Model: "m", KeyEnv: "IPSO_LLM_MISTRAL"},
		"a region injected into a host": {Name: "x", Provider: Bedrock, Region: "eu-central-1.evil.example/x", Model: "m", KeyEnv: "IPSO_LLM_BEDROCK"},
	}
	for name, route := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Routes: []Route{route}, Default: []string{"x"}, MonthlyTokens: 10}
			if _, _, _, err := compile(cfg); err == nil {
				t.Fatal("compile accepted the route")
			}
		})
	}
}

func TestNonEURouteNeedsExplicitBYOK(t *testing.T) {
	setKeys(t)
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	own := Route{Name: "acme-openai", Provider: OpenAI, Endpoint: "https://api.openai.com/v1", Model: "gpt-4.1", KeyEnv: "IPSO_LLM_TENANT"}

	cfg := baseConfig()
	cfg.Tenants = map[string]Tenant{tenant.String(): {BYOK: []Route{own}}}
	if _, _, _, err := compile(cfg); err == nil || !strings.Contains(err.Error(), "allow_non_eu") {
		t.Fatalf("err = %v, want a refusal that names allow_non_eu", err)
	}

	own.AllowNonEU = true
	cfg.Tenants = map[string]Tenant{tenant.String(): {BYOK: []Route{own}, MonthlyTokens: 50}}
	tenants, defaults, _, err := compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := tenants[tenant]
	if len(p.routes) != 1 || p.routes[0].url != "https://api.openai.com/v1/chat/completions" || p.routes[0].eu || p.limit != 50 {
		t.Fatalf("tenant policy = %+v", p)
	}
	for _, route := range defaults.routes {
		if !route.eu {
			t.Errorf("default route %s is not EU-resident", route.name)
		}
	}
}

func TestOpenAIEndpointTakesHTTPOnlyOnLoopback(t *testing.T) {
	setKeys(t)
	cases := map[string]string{
		"https://api.openai.com/v1":    "https://api.openai.com/v1/chat/completions",
		"http://127.0.0.1:8080/v1":     "http://127.0.0.1:8080/v1/chat/completions",
		"http://[::1]:8080/v1/":        "http://[::1]:8080/v1/chat/completions",
		"http://localhost:11434/v1":    "http://localhost:11434/v1/chat/completions",
		"http://api.openai.com/v1":     "",
		"http://10.0.0.5:8080/v1":      "",
		"http://169.254.169.254/v1":    "",
		"http://127.0.0.1.nip.io/v1":   "",
		"http://u:p@127.0.0.1:8080/v1": "",
		"http://127.0.0.1:8080/v1?a=b": "",
		"https://api.openai.com:8443":  "",
		"ftp://127.0.0.1/v1":           "",
	}
	for endpoint, want := range cases {
		route := Route{Name: "own", Provider: OpenAI, Endpoint: endpoint, Model: "m", KeyEnv: "IPSO_LLM_TENANT", AllowNonEU: true}
		got, err := resolve(route, true)
		switch {
		case want == "" && err == nil:
			t.Errorf("%s: accepted as %s", endpoint, got.url)
		case want != "" && err != nil:
			t.Errorf("%s: %v", endpoint, err)
		case want != "" && (got.url != want || got.eu):
			t.Errorf("%s: url %s eu %v, want %s and not EU", endpoint, got.url, got.eu, want)
		}
	}
}

func TestTenantRoutesPickOperatorAndOwnRoutes(t *testing.T) {
	setKeys(t)
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	own := Route{Name: "acme-bedrock", Provider: Bedrock, Region: "eu-west-3", Model: "mistral.mistral-large-2402-v1:0", KeyEnv: "IPSO_LLM_TENANT"}
	cfg := baseConfig()
	cfg.Tenants = map[string]Tenant{tenant.String(): {Routes: []string{"acme-bedrock", "mistral"}, BYOK: []Route{own}}}
	tenants, _, _, err := compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := tenants[tenant]
	if len(p.routes) != 2 || p.routes[0].name != "acme-bedrock" || !p.routes[0].eu || p.routes[1].name != "mistral" || p.limit != 1000 {
		t.Fatalf("tenant policy = %+v", p)
	}
}

func TestConfigErrors(t *testing.T) {
	setKeys(t)
	cases := map[string]func(*Config){
		"no budget":              func(c *Config) { c.MonthlyTokens = 0 },
		"no default":             func(c *Config) { c.Default = nil },
		"an unknown default":     func(c *Config) { c.Default = []string{"nope"} },
		"a default listed twice": func(c *Config) { c.Default = []string{"mistral", "mistral"} },
		"a route defined twice":  func(c *Config) { c.Routes = append(c.Routes, mistralRoute) },
		"a short tenant id":      func(c *Config) { c.Tenants = map[string]Tenant{"0000000000004000800000000000000a": {}} },
		"the nil tenant":         func(c *Config) { c.Tenants = map[string]Tenant{uuid.Nil.String(): {}} },
		"a BYOK name of an operator": func(c *Config) {
			c.Tenants = map[string]Tenant{"00000000-0000-4000-8000-00000000000a": {BYOK: []Route{mistralRoute}}}
		},
		"a pattern that matches empty text": func(c *Config) { c.Redact = []string{"x*"} },
		"an invalid pattern":                func(c *Config) { c.Redact = []string{"("} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseConfig()
			change(&cfg)
			if _, _, _, err := compile(cfg); err == nil {
				t.Fatal("compile accepted the config")
			}
		})
	}
}

func TestParseConfigIsStrict(t *testing.T) {
	if _, err := ParseConfig(strings.NewReader(`{"routes":[],"default":[],"monthly_tokens":1,"allow_everything":true}`)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := ParseConfig(strings.NewReader(`{"monthly_tokens":1} {}`)); err == nil {
		t.Fatal("two values were accepted")
	}
	cfg, err := ParseConfig(strings.NewReader(`{"routes":[{"name":"mistral","provider":"mistral","model":"m","key_env":"IPSO_LLM_MISTRAL"}],"default":["mistral"],"monthly_tokens":5}`))
	if err != nil || cfg.MonthlyTokens != 5 || len(cfg.Routes) != 1 {
		t.Fatalf("cfg %+v err %v", cfg, err)
	}
}
