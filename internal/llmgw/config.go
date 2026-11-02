package llmgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Provider kinds.
const (
	// Mistral is La Plateforme at api.mistral.ai, hosted in the EU.
	Mistral = "mistral"
	// Bedrock is the Amazon Bedrock Converse API in one AWS region.
	Bedrock = "bedrock"
	// Azure is an Azure OpenAI resource, called through its v1 API.
	Azure = "azure"
	// OpenAI is any OpenAI-compatible endpoint. The gateway cannot tell where it runs, so only a
	// tenant's own configuration can name one, with allow_non_eu.
	OpenAI = "openai"
)

const (
	mistralURL    = "https://api.mistral.ai/v1/chat/completions"
	maxConfigSize = 1 << 20
	maxPatterns   = 100
	maxPatternLen = 1000
)

// euAWSRegions are the AWS regions in EU member states. London and Zurich are in Europe but not
// in the EU, so they are left out.
var euAWSRegions = map[string]bool{
	"eu-central-1": true, // Frankfurt
	"eu-west-1":    true, // Ireland
	"eu-west-3":    true, // Paris
	"eu-north-1":   true, // Stockholm
	"eu-south-1":   true, // Milan
	"eu-south-2":   true, // Spain
}

// bedrockGeoPrefixes are the cross-region inference profile prefixes. Only eu keeps a request in
// EU regions. A model id with no prefix runs in the route's own region.
var bedrockGeoPrefixes = map[string]bool{
	"eu": true, "us": false, "us-gov": false, "apac": false, "global": false, "ca": false, "jp": false, "au": false,
}

// euAzureRegions are the Azure regions in EU member states.
var euAzureRegions = map[string]bool{
	"swedencentral":      true,
	"germanywestcentral": true,
	"francecentral":      true,
	"italynorth":         true,
	"polandcentral":      true,
	"spaincentral":       true,
	"westeurope":         true,
	"northeurope":        true,
}

// azureDeploymentTypes keep processing in the EU: a regional Standard deployment, or a Data Zone
// deployment in an EU region. A Global deployment can process anywhere.
var azureDeploymentTypes = map[string]bool{"standard": true, "datazone": true}

var (
	routeName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyEnvName  = regexp.MustCompile(`^IPSO_LLM_[A-Z0-9_]{1,64}$`)
	modelName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$`)
	azureHost   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}\.(openai\.azure\.com|cognitiveservices\.azure\.com)$`)
	regionValue = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
)

// Config is the gateway configuration. It names keys by environment variable and never holds one.
type Config struct {
	// Routes are the operator's routes. Each must be EU-resident.
	Routes []Route `json:"routes"`
	// Default is the order in which a tenant without its own routes tries the operator's routes.
	Default []string `json:"default"`
	// MonthlyTokens is the budget of a tenant that sets none.
	MonthlyTokens int64 `json:"monthly_tokens"`
	// Redact holds extra patterns removed from every prompt, on top of the built-in secrets.
	Redact []string `json:"redact"`
	// Tenants holds per-tenant budgets, route orders, and BYOK routes, keyed by tenant id.
	Tenants map[string]Tenant `json:"tenants"`
}

// Tenant is one tenant's override.
type Tenant struct {
	MonthlyTokens int64    `json:"monthly_tokens"`
	Routes        []string `json:"routes"`
	BYOK          []Route  `json:"byok"`
}

// Route is one provider endpoint with one model.
type Route struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// Region is the AWS region for bedrock and the Azure region of the resource for azure.
	Region string `json:"region"`
	// Endpoint is the resource URL for azure and the base URL for openai.
	Endpoint string `json:"endpoint"`
	// DeploymentType is standard or datazone for azure.
	DeploymentType string `json:"deployment_type"`
	// KeyEnv names the environment variable that holds the key.
	KeyEnv string `json:"key_env"`
	// AllowNonEU accepts a BYOK route the gateway cannot place in the EU. Only a tenant sets it.
	AllowNonEU bool `json:"allow_non_eu"`
}

// ParseConfig reads a configuration strictly: an unknown field is an error.
func ParseConfig(r io.Reader) (Config, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxConfigSize+1))
	if err != nil {
		return Config{}, err
	}
	if len(raw) > maxConfigSize {
		return Config{}, errors.New("llm gateway config is larger than 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("llm gateway config: %w", err)
	}
	if decoder.More() {
		return Config{}, errors.New("llm gateway config holds more than one value")
	}
	return cfg, nil
}

// endpoint is a checked route, ready to call.
type endpoint struct {
	name     string
	provider string
	model    string
	url      string
	key      string
	eu       bool
}

// resolve checks one route and returns where it sends requests. byok is true for a tenant's own
// route. A route the gateway cannot place in the EU needs byok and allow_non_eu.
func resolve(r Route, byok bool) (endpoint, error) {
	if !routeName.MatchString(r.Name) {
		return endpoint{}, fmt.Errorf("route name %q is not a lowercase name", r.Name)
	}
	fail := func(format string, args ...any) (endpoint, error) {
		return endpoint{}, fmt.Errorf("route %s: %s", r.Name, fmt.Sprintf(format, args...))
	}
	if !modelName.MatchString(r.Model) {
		return fail("model %q is not a model id", r.Model)
	}
	if !keyEnvName.MatchString(r.KeyEnv) {
		return fail("key_env must name an IPSO_LLM_ variable")
	}
	key, ok := os.LookupEnv(r.KeyEnv)
	if !ok || strings.TrimSpace(key) == "" {
		return fail("%s is not set", r.KeyEnv)
	}
	if r.AllowNonEU && !byok {
		return fail("allow_non_eu is only for a tenant's own route")
	}

	e := endpoint{name: r.Name, provider: r.Provider, model: r.Model, key: key}
	switch r.Provider {
	case Mistral:
		if r.Endpoint != "" || r.Region != "" || r.DeploymentType != "" {
			return fail("mistral takes no endpoint, region, or deployment_type")
		}
		e.url, e.eu = mistralURL, true
	case Bedrock:
		if r.Endpoint != "" || r.DeploymentType != "" {
			return fail("bedrock takes no endpoint or deployment_type")
		}
		if !regionValue.MatchString(r.Region) {
			return fail("bedrock needs a region")
		}
		e.url = "https://bedrock-runtime." + r.Region + ".amazonaws.com/model/" + url.PathEscape(r.Model) + "/converse"
		e.eu = euAWSRegions[r.Region] && bedrockModelInEU(r.Model)
	case Azure:
		host, err := httpsHost(r.Endpoint)
		if err != nil || !azureHost.MatchString(host) {
			return fail("azure needs an endpoint https://<resource>.openai.azure.com")
		}
		if !regionValue.MatchString(r.Region) || (!azureDeploymentTypes[r.DeploymentType] && r.DeploymentType != "global") {
			return fail("azure needs a region and a deployment_type of standard, datazone, or global")
		}
		e.url = "https://" + host + "/openai/v1/chat/completions"
		e.eu = euAzureRegions[r.Region] && azureDeploymentTypes[r.DeploymentType]
	case OpenAI:
		if r.Region != "" || r.DeploymentType != "" {
			return fail("openai takes no region or deployment_type")
		}
		if !byok {
			return fail("an openai route is only a tenant's own route")
		}
		host, err := httpsHost(r.Endpoint)
		if err != nil {
			return fail("%v", err)
		}
		parsed, _ := url.Parse(r.Endpoint)
		e.url = "https://" + host + strings.TrimSuffix(parsed.EscapedPath(), "/") + "/chat/completions"
	default:
		return fail("provider %q is not mistral, bedrock, azure, or openai", r.Provider)
	}
	if !e.eu && !byok {
		return fail("an operator route must be EU-resident")
	}
	if !e.eu && !r.AllowNonEU {
		return fail("the gateway cannot place this route in the EU; set allow_non_eu to accept that")
	}
	return e, nil
}

// bedrockModelInEU reports whether a Bedrock model id stays in EU regions. A cross-region profile
// such as us. or global. sends requests outside the EU even from an EU endpoint.
func bedrockModelInEU(model string) bool {
	prefix, _, found := strings.Cut(model, ".")
	if !found {
		return true
	}
	inEU, known := bedrockGeoPrefixes[prefix]
	return !known || inEU
}

// httpsHost returns the host of a plain https URL with no user, query, or fragment.
func httpsHost(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("endpoint %q is not a plain https URL", raw)
	}
	if parsed.Port() != "" {
		return "", fmt.Errorf("endpoint %q names a port", raw)
	}
	return strings.ToLower(parsed.Hostname()), nil
}

// policy is what one tenant may use.
type policy struct {
	routes []endpoint
	limit  int64
}

// compile checks the whole configuration. Every error stops the gateway from starting.
func compile(cfg Config) (map[uuid.UUID]policy, policy, []*regexp.Regexp, error) {
	if cfg.MonthlyTokens <= 0 {
		return nil, policy{}, nil, errors.New("monthly_tokens must be positive")
	}
	operator := map[string]endpoint{}
	for _, r := range cfg.Routes {
		e, err := resolve(r, false)
		if err != nil {
			return nil, policy{}, nil, err
		}
		if _, dup := operator[r.Name]; dup {
			return nil, policy{}, nil, fmt.Errorf("route %s is defined twice", r.Name)
		}
		operator[r.Name] = e
	}
	if len(cfg.Default) == 0 {
		return nil, policy{}, nil, errors.New("default names no route")
	}
	fallback, err := order(cfg.Default, operator)
	if err != nil {
		return nil, policy{}, nil, err
	}
	defaults := policy{routes: fallback, limit: cfg.MonthlyTokens}

	tenants := map[uuid.UUID]policy{}
	for id, t := range cfg.Tenants {
		tenant, err := uuid.Parse(id)
		if err != nil || tenant == uuid.Nil || tenant.String() != id {
			return nil, policy{}, nil, fmt.Errorf("tenant %q is not a canonical tenant id", id)
		}
		if t.MonthlyTokens < 0 {
			return nil, policy{}, nil, fmt.Errorf("tenant %s: monthly_tokens is negative", id)
		}
		known := map[string]endpoint{}
		for name, e := range operator {
			known[name] = e
		}
		var own []string
		for _, r := range t.BYOK {
			e, err := resolve(r, true)
			if err != nil {
				return nil, policy{}, nil, fmt.Errorf("tenant %s: %w", id, err)
			}
			if _, dup := known[r.Name]; dup {
				return nil, policy{}, nil, fmt.Errorf("tenant %s: route %s is defined twice", id, r.Name)
			}
			known[r.Name] = e
			own = append(own, r.Name)
		}
		p := defaults
		names := t.Routes
		if len(names) == 0 {
			names = own
		}
		if len(names) > 0 {
			if p.routes, err = order(names, known); err != nil {
				return nil, policy{}, nil, fmt.Errorf("tenant %s: %w", id, err)
			}
		}
		if t.MonthlyTokens > 0 {
			p.limit = t.MonthlyTokens
		}
		tenants[tenant] = p
	}

	if len(cfg.Redact) > maxPatterns {
		return nil, policy{}, nil, fmt.Errorf("redact holds more than %d patterns", maxPatterns)
	}
	var patterns []*regexp.Regexp
	for _, source := range cfg.Redact {
		pattern, err := regexp.Compile(source)
		if err != nil || len(source) > maxPatternLen || pattern.MatchString("") {
			return nil, policy{}, nil, fmt.Errorf("redact pattern %q is invalid or matches empty text", source)
		}
		patterns = append(patterns, pattern)
	}
	return tenants, defaults, patterns, nil
}

func order(names []string, known map[string]endpoint) ([]endpoint, error) {
	seen := map[string]bool{}
	routes := make([]endpoint, 0, len(names))
	for _, name := range names {
		e, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("route %s is not defined", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("route %s is listed twice", name)
		}
		seen[name] = true
		routes = append(routes, e)
	}
	return routes, nil
}
