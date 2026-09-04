// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"fmt"
	"os"

	"github.com/rafpe/kube-oidc-proxy/cmd/app"
)

func main() {
	// The signal handler is installed by the command itself, once the root
	// logger it reports through has been built from the parsed flags.
	cmd := app.NewRunCommand()

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
