// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"fmt"
	"os"

	"github.com/rafpe/kube-oidc-proxy/cmd/app"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	stopCh := signals.Handler()
	cmd := app.NewRunCommand(stopCh)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
