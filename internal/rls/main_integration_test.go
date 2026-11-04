//go:build integration

package rls

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = s.Terminate() }()
	server = s
	os.Exit(m.Run())
}
