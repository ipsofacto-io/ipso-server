package migrate

import (
	"context"
	"strings"
	"testing"
)

// A credential must never reach an error message, whichever way the connection fails.
func TestRunDoesNotLeakThePassword(t *testing.T) {
	const secret = "s3cr3t-value"
	tests := []struct {
		name string
		url  string
	}{
		{"url with a bad port", "postgres://ipso_migrate:" + secret + "@127.0.0.1:notaport/ipso"},
		{"keyword value with a bad port", "host=127.0.0.1 port=notaport user=ipso_migrate password=" + secret + " dbname=ipso"},
		{"url with an unknown parameter value", "postgres://ipso_migrate:" + secret + "@127.0.0.1:5432/ipso?sslmode=sideways"},
		{"url that refuses the connection", "postgres://ipso_migrate:" + secret + "@127.0.0.1:1/ipso?sslmode=disable&connect_timeout=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.url)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks the password: %v", err)
			}
		})
	}
}
