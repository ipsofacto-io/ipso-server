// Package httpserve is the HTTP server loop that every ipso-server command shares: one set of
// timeouts and size bounds, and a clean stop when the context ends.
package httpserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Serve serves handler on listener until ctx ends, and runs run (when not nil) meanwhile. It returns
// after the server has stopped and run has returned.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler, run func(context.Context)) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	workers := make(chan struct{})
	go func() {
		if run != nil {
			run(ctx)
		}
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
