package integrations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/httpserve"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
	"github.com/ipsofacto-io/ipso-server/runtask"
)

// minSecretBytes refuses a webhook secret short enough to guess.
const minSecretBytes = 32

// Serve verifies the App, then listens until ctx ends. It serves the webhook and a health route. It
// holds no tenant data: it asks cfg.Tenants which tenant owns the installation of a delivery (ADR-0101).
func Serve(ctx context.Context, listener net.Listener, cfg Config) error {
	if len(cfg.WebhookSecret) < minSecretBytes {
		return fmt.Errorf("the webhook secret is shorter than %d bytes", minSecretBytes)
	}
	if cfg.Tenants == nil {
		return errors.New("the webhook service has no installation to tenant mapping")
	}
	if cfg.Unbind == nil {
		return errors.New("the webhook service cannot remove the binding of a deleted installation")
	}
	if err := cfg.App.Verify(ctx); err != nil {
		return err
	}
	service := NewService(cfg)
	mux := http.NewServeMux()
	mux.Handle(webhookPath, service.Handler())
	return listen(ctx, listener, mux, cfg.Telemetry, service.Run)
}

// ServeRunTasks listens until ctx ends. It serves the HCP Terraform run task and a health route, and
// no tenant data (ADR-0065).
func ServeRunTasks(ctx context.Context, listener net.Listener, cfg RunTaskConfig) error {
	if len(cfg.HMACKey) < minSecretBytes {
		return fmt.Errorf("the HMAC key is shorter than %d bytes", minSecretBytes)
	}
	if cfg.Bundle == nil {
		return errors.New("the run task service has no policy bundle")
	}
	if cfg.APIHost != "" && !runtask.ValidHost(cfg.APIHost) {
		return errors.New("the API host is not a host name")
	}
	for _, host := range cfg.PlanHosts {
		if !runtask.ValidHost(host) {
			return errors.New("a plan host is not a host name")
		}
	}
	service := NewRunTaskService(cfg)
	mux := http.NewServeMux()
	mux.Handle(runtask.Path, service.Handler())
	return listen(ctx, listener, mux, cfg.Telemetry, service.Run)
}

// listen serves mux with the health route until ctx ends, and runs the service's workers meanwhile. Neither
// service has a tenant of its own: the webhooks service learns one for each delivery (ADR-0101).
func listen(ctx context.Context, listener net.Listener, mux *http.ServeMux, tel *telemetry.Telemetry, run func(context.Context)) error {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httpserve.Serve(ctx, listener, tel.Handler(uuid.Nil, mux), run)
}
