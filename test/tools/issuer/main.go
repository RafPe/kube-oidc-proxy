// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/rafpe/kube-oidc-proxy/pkg/util/signals"
)

func main() {
	opts := new(options)
	// These test tools have no logging flags of their own; the shutdown
	// reporting the handler will do goes to the process default logger.
	ctx, stop := signals.NotifyContext(context.Background(), slog.Default())
	defer stop()

	cmd := &cobra.Command{
		Use:   "oidc-issuer",
		Short: "A very basic OIDC issuer to present a well-known endpoint.",
		RunE: func(cmd *cobra.Command, args []string) error {

			iss, err := newIssuer(opts.IssuerURL, opts.KeyFile, opts.CertFile, ctx.Done())
			if err != nil {
				return err
			}

			compCh, err := iss.Run(opts.BindAddress, opts.ListenPort)
			if err != nil {
				return err
			}

			<-compCh

			return nil
		},
	}

	opts.addFlags(cmd)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}
