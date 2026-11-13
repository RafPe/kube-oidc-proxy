// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
)

func TestDeployReadyTimeout(t *testing.T) {
	h := NewHelper(&config.Config{})

	// Normal deploys take 4 to 8 seconds; the default must ride out a single
	// container-runtime stall (30 seconds observed) without masking a proxy
	// that never comes up.
	if got, want := h.deployReadyTimeout(), 60*time.Second; got != want {
		t.Fatalf("default deploy timeout = %s, want %s", got, want)
	}

	h.DeployReadyTimeout = 5 * time.Second
	if got, want := h.deployReadyTimeout(), 5*time.Second; got != want {
		t.Fatalf("overridden deploy timeout = %s, want %s", got, want)
	}
}
