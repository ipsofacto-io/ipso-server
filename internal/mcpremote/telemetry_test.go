package mcpremote

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

func TestAToolCallIsObservedWithTheTenantAndTheToolName(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	auth, handler := limitedRig(t, Config{Telemetry: tel}, &recordingBackend{})
	token := auth.Token(testResource, []string{ScopeRead})

	if got := callTool(handler, token); got.Code != http.StatusOK {
		t.Fatalf("status %d: %s", got.Code, got.Body)
	}
	span := rec.Span(t, "tools/call "+mcptools.ToolApplicable)
	attrs := telemetrytest.Attrs(span.Attributes)
	if attrs["mcp.method.name"] != "tools/call" || attrs["gen_ai.tool.name"] != mcptools.ToolApplicable || attrs["ipso.tenant.id"] != testTenant.String() {
		t.Errorf("the span: %v", attrs)
	}
	if _, failed := attrs["error.type"]; failed {
		t.Errorf("a call that worked is marked as failed: %v", attrs)
	}
	points := rec.Points(t, "mcp.server.operation.duration")
	if len(points) != 1 || points[0].Count != 1 {
		t.Fatalf("points %+v", points)
	}
	rec.CheckKeys(t)
}

func TestAnOperationTheServerDoesNotDefineIsObservedAsOtherAndAsFailed(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	auth, handler := limitedRig(t, Config{Telemetry: tel}, &recordingBackend{})
	token := auth.Token(testResource, []string{ScopeRead})

	body := `{"jsonrpc":"2.0","id":1,"method":"ada.lovelace/private-method","params":{` + metaLatest + `}}`
	req := httptest.NewRequest(http.MethodPost, testResource, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("MCP-Protocol-Version", mcptools.LatestVersion)
	req.Header.Set("Mcp-Method", "ada.lovelace/private-method")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	span := rec.Span(t, "_OTHER")
	attrs := telemetrytest.Attrs(span.Attributes)
	if attrs["mcp.method.name"] != "_OTHER" || attrs["error.type"] != "rpc_error" {
		t.Errorf("the span: %v", attrs)
	}
	for k, v := range attrs {
		if strings.Contains(v, "ada") {
			t.Errorf("%s = %q holds the name a client sent", k, v)
		}
	}
	rec.CheckKeys(t)
}
