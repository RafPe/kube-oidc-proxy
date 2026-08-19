// Copyright Jetstack Ltd. See LICENSE for details.

// Package audit wires the Kubernetes apiserver audit backend into the proxy,
// emitting audit events for proxied requests.
package audit

import (
	"fmt"
	"net/http"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"k8s.io/apimachinery/pkg/util/sets"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	"k8s.io/component-base/compatibility"
	"k8s.io/component-base/version"
)

// longRunningRequests reports whether a request streams for as long as the
// caller holds it open. It decides when the audit log hears about a request: a
// short request is recorded once, at completion; a long-running one is recorded
// when the response starts and again when the stream ends. The generic
// apiserver default treats only watch this way because a generic API server has
// no inherent long-running subresources — but everything this proxy forwards
// goes to a kube-apiserver, so kube-apiserver's own set is the set that applies.
// Without this, an hour-long exec leaves nothing in the audit log for that hour,
// and nothing at all if the proxy is killed before the session ends.
var longRunningRequests = genericfilters.BasicLongRunningRequestCheck(
	sets.NewString("watch", "proxy"),
	sets.NewString("attach", "exec", "proxy", "log", "portforward"))

type Audit struct {
	opts         *options.AuditOptions
	serverConfig *server.CompletedConfig
}

// New creates a new Audit struct to handle auditing for proxy requests. This
// is mostly a wrapper for the apiserver auditing handlers to combine them with
// the proxy.
func New(opts *options.AuditOptions, externalAddress string, secureServingInfo *server.SecureServingInfo) (*Audit, error) {
	serverConfig := &server.Config{
		ExternalAddress: externalAddress,
		SecureServing:   secureServingInfo,

		LongRunningFunc: longRunningRequests,

		// Complete() derives the RequestInfo resolver from this, and
		// server.NewRequestInfoResolver seeds the resolver with the group
		// prefix (/apis) plus these legacy, groupless prefixes. Left empty, a
		// request under /api — the whole core group — parses as a non-resource
		// request: no resource, no subresource, and a verb that is only the
		// lowercased HTTP method. The audit event then carries "post" rather
		// than "create" and no objectRef, and longRunningRequests never sees
		// the subresource it matches on, so exec, attach, portforward and log
		// (all of them core group pod subresources) are never treated as long
		// running however the set above is written.
		LegacyAPIGroupPrefixes: sets.NewString(server.DefaultLegacyAPIPrefix),
	}

	// We do not support dynamic auditing, so leave nil
	if err := opts.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	serverConfig.EffectiveVersion = compatibility.NewEffectiveVersionFromString(version.Get().String(), version.Get().String(), version.Get().String())

	completed := serverConfig.Complete(nil)

	return &Audit{
		opts:         opts,
		serverConfig: &completed,
	}, nil
}

// Run will run the audit backend if configured.
func (a *Audit) Run(stopCh <-chan struct{}) error {
	if a.serverConfig.AuditBackend != nil {
		if err := a.serverConfig.AuditBackend.Run(stopCh); err != nil {
			return fmt.Errorf("failed to run the audit backend: %s", err)
		}
	}

	return nil
}

// Shutdown will shutdown the audit backend if configured.
func (a *Audit) Shutdown() error {
	if a.serverConfig.AuditBackend != nil {
		a.serverConfig.AuditBackend.Shutdown()
	}

	return nil
}

// WithRequest will wrap the given handler to inject the request information
// into the context which is then used by the wrapped audit handler.
func (a *Audit) WithRequest(handler http.Handler) http.Handler {
	handler = genericapifilters.WithAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator, a.serverConfig.LongRunningFunc)
	handler = genericapifilters.WithAuditInit(handler)
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}

// WithUnauthorized will wrap the given handler to inject the request
// information into the context which is then used by the wrapped audit
// handler.
func (a *Audit) WithUnauthorized(handler http.Handler) http.Handler {
	handler = genericapifilters.WithFailedAuthenticationAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator)
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}
