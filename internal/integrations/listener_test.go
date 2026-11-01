package integrations

import (
	"net"
	"testing"
)

type testListener struct{}

func (*testListener) listen(t *testing.T) (net.Listener, error) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, nil
}
