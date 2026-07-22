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

type HealthCheck struct {
	handler    healthcheck.Handler
	oidcAuther authenticator.Token
	fakeJWTs   []string
	ready      atomic.Bool
}

func Run(port string, fakeJWTs []string, oidcAuther authenticator.Token) error {
	h := &HealthCheck{
		handler:    healthcheck.NewHandler(),
		oidcAuther: oidcAuther,
		fakeJWTs:   fakeJWTs,
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

	for _, fakeJWT := range h.fakeJWTs {
		_, _, err := h.oidcAuther.AuthenticateToken(ctx, fakeJWT)
		if err != nil && strings.HasSuffix(err.Error(), "authenticator not initialized") {
			err = fmt.Errorf("OIDC provider not yet initialized: %w", err)
			klog.V(4).Info(err)
			return err
		}
	}

	h.ready.Store(true)
	klog.V(4).Info("OIDC provider initialized.")
	return nil
}
