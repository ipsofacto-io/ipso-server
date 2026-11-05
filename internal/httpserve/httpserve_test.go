package httpserve

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeStopsWhenTheContextEndsAndWaitsForTheWorker(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := false
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), func(ctx context.Context) {
			<-ctx.Done()
			stopped = true
		})
	}()
	resp, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || !stopped {
			t.Fatalf("err = %v, worker stopped = %v", err, stopped)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return")
	}
}
