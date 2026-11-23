package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/controlplane"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/worker"
	"github.com/ipsofacto-io/ipso-server/runtask"
)

// collector answers every OTLP request with an empty success, so a role that starts telemetry and stops again
// has nowhere to fail.
func collector(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	return server.URL
}

func runTaskEnv(extra map[string]string) func(string) string {
	values := map[string]string{
		runTaskHMACEnv: "key", runTaskBundleEnv: "layout", runTaskDigestEnv: "sha256:abc", runTaskPublicKeyEnv: "public.pem",
		listenAddrEnv: "127.0.0.1:0",
	}
	for k, v := range extra {
		values[k] = v
	}
	return env(values)
}

func runTaskDeps(getenv func(string) string, got *integrations.RunTaskConfig) deps {
	return deps{
		getenv:     getenv,
		loadBundle: func(string, string, string) (runtask.PlanEvaluator, error) { return nil, nil },
		runTasks: func(_ context.Context, listener net.Listener, cfg integrations.RunTaskConfig) error {
			*got = cfg
			return listener.Close()
		},
	}
}

func TestRolesStartNoTelemetryUnlessAnEndpointIsSet(t *testing.T) {
	var api controlplane.Config
	if code, _, stderr := invoke(t, apiDeps(apiEnv(nil), &api), "--role=api"); code != 0 {
		t.Fatalf("api: %d %s", code, stderr)
	}
	var work worker.Config
	if code, _, stderr := invoke(t, workerDeps(workerEnv(nil), &work), "--role=worker"); code != 0 {
		t.Fatalf("worker: %d %s", code, stderr)
	}
	var tasks integrations.RunTaskConfig
	if code, _, stderr := invoke(t, runTaskDeps(runTaskEnv(nil), &tasks), "runtasks"); code != 0 {
		t.Fatalf("runtasks: %d %s", code, stderr)
	}
	if api.Telemetry != nil || work.Telemetry != nil || tasks.Telemetry != nil {
		t.Errorf("a role started telemetry with no endpoint: %v %v %v", api.Telemetry, work.Telemetry, tasks.Telemetry)
	}
	// A set endpoint that the operator switches off stays off.
	if code, _, stderr := invoke(t, apiDeps(apiEnv(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": collector(t), "OTEL_SDK_DISABLED": "true"}), &api), "--role=api"); code != 0 || api.Telemetry != nil {
		t.Errorf("disabled: %d %s %v", code, stderr, api.Telemetry)
	}
}

func TestRolesStartTelemetryWhenAnEndpointIsSet(t *testing.T) {
	endpoint := map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": collector(t)}
	var api controlplane.Config
	if code, _, stderr := invoke(t, apiDeps(apiEnv(endpoint), &api), "--role=api"); code != 0 {
		t.Fatalf("api: %d %s", code, stderr)
	}
	var work worker.Config
	if code, _, stderr := invoke(t, workerDeps(workerEnv(endpoint), &work), "--role=worker"); code != 0 {
		t.Fatalf("worker: %d %s", code, stderr)
	}
	var tasks integrations.RunTaskConfig
	if code, _, stderr := invoke(t, runTaskDeps(runTaskEnv(endpoint), &tasks), "runtasks"); code != 0 {
		t.Fatalf("runtasks: %d %s", code, stderr)
	}
	if api.Telemetry == nil || work.Telemetry == nil || tasks.Telemetry == nil {
		t.Errorf("a role did not start telemetry: %v %v %v", api.Telemetry, work.Telemetry, tasks.Telemetry)
	}
}

func TestARoleRefusesATelemetryProtocolItCannotSpeak(t *testing.T) {
	bad := map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.example.test:4317", "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"}
	apiD := apiDeps(apiEnv(bad), new(controlplane.Config))
	apiD.controlPlane = func(context.Context, net.Listener, controlplane.Config) error {
		t.Fatal("the api started with a protocol it cannot speak")
		return nil
	}
	workD := workerDeps(workerEnv(bad), new(worker.Config))
	workD.runWorker = func(context.Context, worker.Config) error {
		t.Fatal("the worker started with a protocol it cannot speak")
		return nil
	}
	tasksD := runTaskDeps(runTaskEnv(bad), new(integrations.RunTaskConfig))
	tasksD.runTasks = func(context.Context, net.Listener, integrations.RunTaskConfig) error {
		t.Fatal("runtasks started with a protocol it cannot speak")
		return nil
	}
	for name, run := range map[string]func() (int, string){
		"api":      func() (int, string) { code, _, stderr := invoke(t, apiD, "--role=api"); return code, stderr },
		"worker":   func() (int, string) { code, _, stderr := invoke(t, workD, "--role=worker"); return code, stderr },
		"runtasks": func() (int, string) { code, _, stderr := invoke(t, tasksD, "runtasks"); return code, stderr },
	} {
		if code, stderr := run(); code != 1 || !strings.Contains(stderr, "OTEL_EXPORTER_OTLP_PROTOCOL") {
			t.Errorf("%s: code %d stderr %q", name, code, stderr)
		}
	}
}

func TestWebhooksStartTelemetryOnlyWhenAnEndpointIsSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{{"no endpoint", nil, false}, {"an endpoint", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": collector(t)}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			values := webhookEnv(t)
			for k, v := range tc.env {
				values[k] = v
			}
			var got integrations.Config
			d := tenantDeps(values, &tenantCalls{owners: map[int64]uuid.UUID{}})
			d.serve = func(_ context.Context, listener net.Listener, cfg integrations.Config) error {
				got = cfg
				return listener.Close()
			}
			if code, _, stderr := invoke(t, d, "webhooks"); code != 0 {
				t.Fatalf("code %d stderr %q", code, stderr)
			}
			if (got.Telemetry != nil) != tc.want {
				t.Errorf("telemetry %v, want started %v", got.Telemetry, tc.want)
			}
		})
	}
}
