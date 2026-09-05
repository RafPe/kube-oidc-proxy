// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/rafpe/kube-oidc-proxy/cmd/app"
)

func main() {
	// The signal handler is installed by the command itself, once the root
	// logger it reports through has been built from the parsed flags.
	cmd := app.NewRunCommand()

	if err := cmd.Execute(); err != nil {
		// An error raised once the logger existed is already a record on the
		// log stream; printing it again would put an unstructured line beside
		// the JSON. Only a failure before that point, such as a flag error, is
		// reported here.
		if !errors.Is(err, app.ErrReported) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}
