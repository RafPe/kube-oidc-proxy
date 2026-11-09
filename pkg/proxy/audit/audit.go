// Copyright Jetstack Ltd. See LICENSE for details.

// Package audit wires the Kubernetes apiserver audit backend into the proxy,
// emitting audit events for proxied requests.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/component-base/compatibility"
	"k8s.io/component-base/version"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
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

// IsLongRunning reports whether the request is one of the long-running kinds
// above, using the same rule the audit backend applies so a lifecycle record
// and an audit event never disagree about a watch or an exec.
//
// It answers false when the request carries no RequestInfo: nothing has
// resolved it into a verb and a resource yet, so there is no basis on which to
// call it long running.
func IsLongRunning(req *http.Request) bool {
	info, ok := genericapirequest.RequestInfoFrom(req.Context())
	if !ok {
		return false
	}

	return longRunningRequests(req, info)
}

type Audit struct {
	// logger is the audit-component logger this backend reports its own
	// lifecycle through.
	logger *slog.Logger

	// metrics receives the observable backend failures; nil records nothing.
	metrics *metrics.Recorder

	serverConfig *server.CompletedConfig
}

// Config is what the auditor needs from the command: the apiserver audit
// options bound to the flags, the address and serving info the audit events
// describe, and the recorder backend failures are counted on.
type Config struct {
	// Options is the apiserver's own audit configuration. Nil configures no
	// backend, so a request chain built for a test still has every filter in
	// place.
	Options *apiserveroptions.AuditOptions

	ExternalAddress string
	SecureServing   *server.SecureServingInfo

	// Metrics receives start and shutdown failures. Optional: nil records
	// nothing.
	Metrics *metrics.Recorder
}

// New creates the auditor for proxied requests: mostly a wrapper that combines
// the apiserver's audit handlers with the proxy.
//
// logger is the audit-component logger and is required.
func New(cfg Config, logger *slog.Logger) (*Audit, error) {
	if logger == nil {
		return nil, errors.New("audit: logger is required")
	}

	serverConfig := &server.Config{
		ExternalAddress: cfg.ExternalAddress,
		SecureServing:   cfg.SecureServing,

		LongRunningFunc: longRunningRequests,

		// Complete() derives the RequestInfo resolver from this, and
		// server.NewRequestInfoResolver seeds the resolver with the group
		// prefix (/apis) plus these legacy, groupless prefixes. Left empty, a
		// request under /api — the whole core group — parses as a non-resource
		// request: no resource, no subresource, and a verb that is only the
		// lowercased HTTP method. The audit event then carries "post" rather
		// than "create" and no objectRef, and longRunningRequests never sees
		// the verb or subresource it matches on, so exec, attach, portforward,
		// log and proxy are never treated as long running however the set above
		// is written — nor is a core group watch, which the generic default
		// already covered. All of them live under /api.
		LegacyAPIGroupPrefixes: sets.NewString(server.DefaultLegacyAPIPrefix),
	}

	if err := cfg.Options.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	serverConfig.EffectiveVersion = compatibility.NewEffectiveVersionFromString(version.Get().String(), version.Get().String(), version.Get().String())

	completed := serverConfig.Complete(nil)

	return &Audit{
		logger:       logger,
		metrics:      cfg.Metrics,
		serverConfig: &completed,
	}, nil
}

// errorReporter is implemented by an audit backend that can say whether its
// Shutdown flushed successfully. The upstream audit.Backend interface declares
// Shutdown with no return value, so a backend that knows it dropped events has
// no way to report that through the interface; one that implements this is
// asked, and the answer decides between recording audit.flush.completed and
// returning the error from Shutdown.
type errorReporter interface {
	ShutdownErr() error
}

// Start starts the audit backend, if one is configured, and stops it when ctx
// is cancelled. It returns once the backend is running. A backend that fails
// to start is an error the process cannot serve correctly through: without it,
// proxied requests leave no audit trail.
//
// A failure is counted here and returned, not logged: the caller that decides
// what the failure means reports it once, as the startup failure it is.
func (a *Audit) Start(ctx context.Context) error {
	if a.serverConfig.AuditBackend == nil {
		return nil
	}

	// The upstream backend stops on a closed channel, which is what the
	// context's Done channel is.
	if err := a.serverConfig.AuditBackend.Run(ctx.Done()); err != nil {
		a.metrics.AuditBackendFailure(metrics.AuditRun)
		return fmt.Errorf("failed to run the audit backend: %w", err)
	}

	logging.Emit(ctx, a.logger, logging.EventAuditBackendStarted,
		slog.String("backend_kind", a.backendKind()))
	return nil
}

// backendKind names the configured backend for the lifecycle records. The
// upstream backends describe themselves as their type ("log", "buffered<...>"),
// which is what an operator needs to correlate the record with the flags.
func (a *Audit) backendKind() string {
	if a.serverConfig.AuditBackend == nil {
		return "none"
	}
	return logging.Bound(a.serverConfig.AuditBackend.String(), logging.MaxIdentity)
}

// Shutdown flushes the audit backend if configured. A failed flush means audit
// events for requests this process already served were dropped, so it must not
// be swallowed: it is counted here and returned to the caller, which reports
// it once as the failed shutdown step. A successful flush is recorded as
// audit.flush.completed.
//
// Only a backend implementing errorReporter can say that it failed: the
// upstream audit.Backend interface returns nothing from Shutdown, and the
// bundled log and buffered webhook backends log a delivery failure through the
// Kubernetes error handler instead of returning it. For those the flush is
// recorded as completed and the failure, if any, is a bridged component=k8s
// record.
func (a *Audit) Shutdown() error {
	backend := a.serverConfig.AuditBackend
	if backend == nil {
		return nil
	}

	ctx := context.Background()
	start := time.Now()
	backend.Shutdown()
	elapsed := time.Since(start)

	if reporter, ok := backend.(errorReporter); ok {
		if err := reporter.ShutdownErr(); err != nil {
			a.metrics.AuditBackendFailure(metrics.AuditShutdown)
			return fmt.Errorf("audit backend failed to flush: %w", err)
		}
	}

	logging.Emit(ctx, a.logger, logging.EventAuditFlushCompleted,
		slog.Int64("duration_ms", elapsed.Milliseconds()))
	return nil
}

// WithRequestInfo resolves the request into the verb, resource and namespace
// the rest of the proxy reasons about, and puts it on the request context.
//
// The audit filters do this for themselves, but they are the innermost wrap:
// everything ahead of them -- the lifecycle filter deciding whether a request
// is long running, and the error handler recording a denial -- would otherwise
// see a request that has not been resolved at all. Applied high in the chain it
// resolves once for all of them; the inner filters re-resolve the same value,
// which is wasted work rather than a disagreement.
func (a *Audit) WithRequestInfo(handler http.Handler) http.Handler {
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
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
// handler. WithAuditInit mirrors WithRequest above: without it there is no
// AuditContext on the request, the failed-authentication filter finds
// auditing disabled, and a 401 leaves no audit event at all
// (TremoloSecurity/kube-oidc-proxy#92).
func (a *Audit) WithUnauthorized(handler http.Handler) http.Handler {
	handler = genericapifilters.WithFailedAuthenticationAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator)
	handler = genericapifilters.WithAuditInit(handler)
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}
