// Copyright Jetstack Ltd. See LICENSE for details.
package token

import (
	. "github.com/onsi/ginkgo/v2"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
)

// Every spec here reads through the same default proxy deployment and mutates
// no cluster state, so they all share a single deploy.
var _ = framework.CasesDescribe("Token", Ordered, ContinueOnFailure, Label("shard-c"), func() {
	f := framework.NewOrderedDefaultFramework("token")
	sharedtests.RunTokenValidationTests(f)
})
