// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"fmt"
	"os"

	"github.com/rafpe/kube-oidc-proxy/cmd/app"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
)

func main() {
	stopCh := signals.Handler()
	cmd := app.NewRunCommand(stopCh)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
