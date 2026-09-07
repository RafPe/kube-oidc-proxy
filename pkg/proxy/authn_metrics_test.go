// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"errors"
	"net/http"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
	accesslogging "github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
)

const (
	metricAuthnAttempts   = "kube_oidc_proxy_authentication_attempts_total"
	metricAccessDecisions = "kube_oidc_proxy_access_decisions_total"
)

func TestRejectedTokenCountsAnOIDCAttemptAndADenial(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "bad").Return(nil, false, errors.New("verify: signature invalid"))
	req := watchRequest()
	req.Header.Set("Authorization", "bearer bad")
	rw := serveChain(t, p, req, noopHandler)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricAuthnAttempts, map[string]string{"auth_method": "oidc", "outcome": "rejected"}); v != 1 {
		t.Fatalf("attempts{oidc,rejected} = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, metricAccessDecisions, map[string]string{"auth_method": "none", "decision": "deny", "reason": "unauthorized"}); v != 1 {
		t.Fatalf("decisions{none,deny,unauthorized} = %v, want 1", v)
	}
}

func TestMissingTokenCountsANoneAttempt(t *testing.T) {
	p := newTestProxy(t)
	rw := serveChain(t, p, watchRequest(), noopHandler)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rw.Code)
	}
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricAuthnAttempts, map[string]string{"auth_method": "none", "outcome": "rejected"}); v != 1 {
		t.Fatalf("attempts{none,rejected} = %v, want 1", v)
	}
}

func TestOIDCFailureThenTokenReviewSuccessIsTwoAttempts(t *testing.T) {
	p := newTestProxy(t)
	p.config.TokenReview = true
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "svc").Return(nil, false, errors.New("not an oidc token"))
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "svc").
		Return(&authenticator.Response{User: &user.DefaultInfo{Name: "system:serviceaccount:a:b"}}, true, nil)
	req := watchRequest()
	req.Header.Set("Authorization", "bearer svc")
	serveChain(t, p, req, noopHandler)
	g := p.metrics.Gatherer()
	if v, _ := metricstest.Value(t, g, metricAuthnAttempts, map[string]string{"auth_method": "oidc", "outcome": "rejected"}); v != 1 {
		t.Fatalf("attempts{oidc,rejected} = %v, want 1", v)
	}
	if v, _ := metricstest.Value(t, g, metricAuthnAttempts, map[string]string{"auth_method": "tokenreview", "outcome": "accepted"}); v != 1 {
		t.Fatalf("attempts{tokenreview,accepted} = %v, want 1", v)
	}
}

func TestTokenReviewDependencyFailureIsAnErrorAttempt(t *testing.T) {
	p := newTestProxy(t)
	p.config.TokenReview = true
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "svc").Return(nil, false, errors.New("not an oidc token"))
	p.fakeReviewer.EXPECT().AuthenticateToken(gomock.Any(), "svc").Return(nil, false, errors.New("apiserver unreachable"))
	req := watchRequest()
	req.Header.Set("Authorization", "bearer svc")
	serveChain(t, p, req, noopHandler)
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricAuthnAttempts, map[string]string{"auth_method": "tokenreview", "outcome": "error"}); v != 1 {
		t.Fatalf("attempts{tokenreview,error} = %v, want 1", v)
	}
}

func TestRecordDecisionCountsAnAllowOnce(t *testing.T) {
	p := newTestProxy(t)
	req := context.WithDecisionHolder(newFakeR())
	p.recordDecision(req, accesslogging.Decision{Allowed: true, AuthMethod: authMethodOIDC})
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricAccessDecisions, map[string]string{"auth_method": "oidc", "decision": "allow", "reason": ""}); v != 1 {
		t.Fatalf("decisions{oidc,allow} = %v, want 1", v)
	}
	// A second denial on the same request is not a second decision.
	p.logDenied(req, reasonUpstreamError, errors.New("late"))
	if v, _ := metricstest.Value(t, p.metrics.Gatherer(), metricAccessDecisions, map[string]string{"decision": "deny"}); v != 0 {
		t.Fatalf("a second decision was counted: %v", v)
	}
}
