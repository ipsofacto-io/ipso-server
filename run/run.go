// Package run is the public entry the enterprise command calls after it registers its features.
// The community command calls it too. It is a wrapper so ipso-ee does not import internal/cli.
package run

import (
	"io"

	"github.com/ipsofacto-io/ipso-server/internal/cli"
)

// Run executes the server command and returns its exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return cli.Run(args, stdout, stderr)
}
