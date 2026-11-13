// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"github.com/spf13/cobra"
)

type options struct {
	BindAddress string
	ListenPort  string

	IssuerURL string

	KeyFile  string
	CertFile string
}

func (o *options) addFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&o.BindAddress, "bind-address",
		"0.0.0.0", "Bound Address to listen and serve on.")

	cmd.PersistentFlags().StringVar(&o.ListenPort, "secure-port",
		"6443", "Port to serve HTTPS.")

	cmd.PersistentFlags().StringVar(&o.IssuerURL, "issuer-url",
		"", "URL of the issuer that appears in well-known responses.")
	o.must(cmd.MarkPersistentFlagRequired("issuer-url"))

	cmd.PersistentFlags().StringVar(&o.KeyFile, "tls-private-key-file",
		"/tls/key.pem", "File location to key for serving.")

	cmd.PersistentFlags().StringVar(&o.CertFile, "tls-cert-file",
		"/tls/cert.pem", "File location to certificate for serving.")
}

func (o *options) must(err error) {
	if err != nil {
		panic(err)
	}
}
