package integrations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// minSecretBytes refuses a webhook secret short enough to guess.
const minSecretBytes = 32

// Serve verifies the App, then listens until ctx ends. It serves the webhook and a health route,
// and no tenant data (ADR-0061).
func Serve(ctx context.Context, listener net.Listener, cfg Config) error {
	if len(cfg.WebhookSecret) < minSecretBytes {
		return fmt.Errorf("the webhook secret is shorter than %d bytes", minSecretBytes)
	}
	if err := cfg.App.Verify(ctx); err != nil {
		return err
	}
	service := NewService(cfg)
	mux := http.NewServeMux()
	mux.Handle(webhookPath, service.Handler())
	return listen(ctx, listener, mux, service.Run)
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
	if cfg.APIHost != "" && !validHost.MatchString(cfg.APIHost) {
		return errors.New("the API host is not a host name")
	}
	for _, host := range cfg.PlanHosts {
		if !validHost.MatchString(host) {
			return errors.New("a plan host is not a host name")
		}
	}
	service := NewRunTaskService(cfg)
	mux := http.NewServeMux()
	mux.Handle(runTaskPath, service.Handler())
	return listen(ctx, listener, mux, service.Run)
}

// listen serves mux with the health route until ctx ends, and runs the service's workers meanwhile.
func listen(ctx context.Context, listener net.Listener, mux *http.ServeMux, run func(context.Context)) error {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	workers := make(chan struct{})
	go func() {
		run(ctx)
		close(workers)
	}()
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()

	var serveErr error
	select {
	case serveErr = <-served:
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		serveErr = errors.Join(server.Shutdown(shutdown), <-served)
	}
	if !errors.Is(serveErr, http.ErrServerClosed) && serveErr != nil && ctx.Err() == nil {
		return serveErr
	}
	<-workers
	return nil
}
