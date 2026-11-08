// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rafpe/kube-oidc-proxy/cmd/app"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run executes the proxy command with args and returns the process exit
// status. An error raised once the logger existed is already a record on the
// log stream; printing it again would put an unstructured line beside the
// JSON. Only a failure before that point, such as a flag error, is reported
// on stderr.
func run(args []string, stderr io.Writer) int {
	// The signal handler is installed by the command itself, once the root
	// logger it reports through has been built from the parsed flags.
	cmd := app.NewRunCommand()
	cmd.SetArgs(args)
	cmd.SetErr(stderr)

	if err := cmd.Execute(); err != nil {
		if !errors.Is(err, app.ErrReported) {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return 1
	}
	return 0
}
