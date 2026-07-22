// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/heptiolabs/healthcheck"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/klog/v2"
)

const (
	timeout = time.Second * 10
)

// IssuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type IssuerReadiness struct {
	IssuerURL string
	FakeJWT   string
}

type HealthCheck struct {
	handler    healthcheck.Handler
	oidcAuther authenticator.Token
	issuers    []IssuerReadiness
	requireAll bool
	ready      atomic.Bool
}

func Run(port string, issuers []IssuerReadiness, requireAll bool, oidcAuther authenticator.Token) error {
	h := &HealthCheck{
		handler:    healthcheck.NewHandler(),
		oidcAuther: oidcAuther,
		issuers:    issuers,
		requireAll: requireAll,
	}

	h.handler.AddReadinessCheck("secure serving", h.Check)

	go func() {
		for {
			err := http.ListenAndServe(net.JoinHostPort("0.0.0.0", port), h.handler)
			if err != nil {
				klog.Errorf("ready probe listener failed: %s", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	return nil
}

func (h *HealthCheck) Check() error {
	if h.ready.Load() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var pending []string
	for _, issuer := range h.issuers {
		_, _, err := h.oidcAuther.AuthenticateToken(ctx, issuer.FakeJWT)
		if err != nil && strings.HasSuffix(err.Error(), "authenticator not initialized") {
			pending = append(pending, issuer.IssuerURL)
		}
	}

	initialized := len(h.issuers) - len(pending)
	if len(pending) > 0 {
		klog.Infof("readiness: %d/%d OIDC issuers initialized, pending: %v",
			initialized, len(h.issuers), pending)
	}

	if h.requireAll && len(pending) > 0 {
		return fmt.Errorf("OIDC providers not yet initialized: %v", pending)
	}
	if !h.requireAll && initialized == 0 {
		return fmt.Errorf("no OIDC provider initialized yet: %v", pending)
	}

	h.ready.Store(true)
	klog.V(4).Info("OIDC provider(s) initialized, marking ready.")
	return nil
}
