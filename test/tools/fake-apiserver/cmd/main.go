// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
	"github.com/rafpe/kube-oidc-proxy/test/tools/fake-apiserver/cmd/options"
	"github.com/rafpe/kube-oidc-proxy/test/tools/fake-apiserver/pkg/server"
)

func main() {
	opts := new(options.Options)
	// These test tools have no logging flags of their own; the shutdown
	// reporting the handler will do goes to the process default logger.
	stopCh := signals.Handler(slog.Default())

	cmd := &cobra.Command{
		Use:   "fake-apiserver",
		Short: "A fake apiserver that will respond to requests with the same body and headers",
		RunE: func(cmd *cobra.Command, args []string) error {
			server, err := server.New(opts.KeyFile, opts.CertFile, stopCh)
			if err != nil {
				return err
			}

			compCh, err := server.Run(opts.BindAddress, opts.ListenPort)
			if err != nil {
				return err
			}

			<-compCh

			return nil
		},
	}

	opts.AddFlags(cmd)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}
