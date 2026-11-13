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
		Use:   "audit-webhook",
		Short: "An server that implements a Kubernetes audit webhook sink",
		RunE: func(cmd *cobra.Command, args []string) error {

			wh, err := newSink(opts.LogPath, opts.KeyFile, opts.CertFile, ctx.Done())
			if err != nil {
				return err
			}

			compCh, err := wh.Run(opts.BindAddress, opts.ListenPort)
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
