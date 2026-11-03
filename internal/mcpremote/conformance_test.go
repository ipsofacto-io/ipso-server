//go:build conformance

package mcpremote

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
)

// applicableScenarios are the server scenarios of the 2026-07-28 requirement set that a tools-only
// product server can answer. The rest of the set needs fixture tools such as test_simple_text,
// prompts, resources, completions, and input_required rounds, which exist to exercise an SDK.
var applicableScenarios = []string{
	"server-stateless",
	"tools-list",
	"caching",
	"dns-rebinding-protection",
	"http-header-validation",
}

// TestConformance runs the MCP conformance suite against the real handler and the real token check.
// The suite's client sends no token, so a wrapper attaches a signed one when a request has none.
func TestConformance(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resource := "http://" + listener.Addr().String() + "/mcp"
	auth := authntest.NewServer(t)
	handler, err := NewHandler(Config{ResourceURL: resource, AuthorizationServers: []string{auth.Server.URL}, Version: "conformance"},
		verifierFor(t, auth, resource),
		func(context.Context, authn.Claims) (Caller, bool) {
			return Caller{Tenant: testTenant, Principal: testPrincipal}, true
		},
		func(Caller) mcptools.Backend { return &recordingBackend{} })
	if err != nil {
		t.Fatal(err)
	}
	token := auth.Token(resource, []string{ScopeRead, ScopePropose})
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			handler.ServeHTTP(w, r)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	for _, scenario := range applicableScenarios {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, "conformance", "server", "--url", resource, "--scenario", scenario, "--spec-version", mcptools.LatestVersion, "--expected-failures", "testdata/conformance-baseline.yml")
			var out bytes.Buffer
			command.Stdout = &out
			command.Stderr = &out
			if err := command.Run(); err != nil {
				t.Fatalf("%v\n%s", err, out.String())
			}
			t.Log(out.String())
		})
	}
}
