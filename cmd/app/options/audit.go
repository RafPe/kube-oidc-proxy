// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	cliflag "k8s.io/component-base/cli/flag"
)

// newAuditOptions binds the apiserver's own audit flags under the Audit flag
// set. The proxy adds nothing to them, so it holds the apiserver type
// directly.
func newAuditOptions(nfs *cliflag.NamedFlagSets) *apiserveroptions.AuditOptions {
	a := apiserveroptions.NewAuditOptions()
	a.AddFlags(nfs.FlagSet("Audit"))
	return a
}
