// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	// Registers client-go's in-tree auth provider plugins (oidc) so a
	// --kubeconfig naming one can authenticate the proxy's own API server
	// client. It lives here, beside buildRESTConfig and the client it builds,
	// because registration is a process-wide side effect the command owns;
	// the options package only parses flags.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)
