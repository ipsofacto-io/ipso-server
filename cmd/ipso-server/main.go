package main

import (
	"os"

	"github.com/ipsofacto-io/ipso-server/run"
)

func main() {
	os.Exit(run.Run(os.Args[1:], os.Stdout, os.Stderr))
}
