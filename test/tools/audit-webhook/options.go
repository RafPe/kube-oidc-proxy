// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"github.com/spf13/cobra"
)

type options struct {
	BindAddress string
	ListenPort  string

	LogPath string

	KeyFile  string
	CertFile string
}

func (o *options) addFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&o.BindAddress, "bind-address",
		"0.0.0.0", "Bound Address to listen and serve on.")

	cmd.PersistentFlags().StringVar(&o.ListenPort, "secure-port",
		"6443", "Port to serve HTTPS.")

	cmd.PersistentFlags().StringVar(&o.LogPath, "audit-file-path",
		"/var/log/audit", "Filepath to write audit logs to.")

	cmd.PersistentFlags().StringVar(&o.KeyFile, "tls-private-key-file",
		"/tls/key.pem", "File location to key for serving.")
	o.must(cmd.MarkPersistentFlagRequired("tls-private-key-file"))

	cmd.PersistentFlags().StringVar(&o.CertFile, "tls-cert-file",
		"/tls/cert.pem", "File location to certificate for serving.")
	o.must(cmd.MarkPersistentFlagRequired("tls-cert-file"))
}

func (o *options) must(err error) {
	if err != nil {
		panic(err)
	}
}
