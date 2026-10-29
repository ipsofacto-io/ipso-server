package main

import (
	"os"

	"github.com/ipsofacto-io/ipso-server/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
