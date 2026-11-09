// Copyright Jetstack Ltd. See LICENSE for details.

// Package audit wires the Kubernetes apiserver audit backend into the proxy,
// emitting audit events for proxied requests.
//
// It also owns the two request classifications the audit backend depends on,
// and the rest of the proxy chain reuses them rather than keeping its own:
// RequestInfo resolution (WithRequestInfo, which the proxy runs once, high in
// its chain) and the kube-apiserver long-running rule (IsLongRunning). Both
// live here because the audit event's verb, objectRef and stages are decided
// by them; a lifecycle record or metric that classified a request differently
// would disagree with the audit log about the same request.
package audit

import (
	"context"
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
// above, using the same rule the audit backend applies.
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

	// metrics receives backend start failures.
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

	// Metrics receives backend start failures. Optional; see package metrics.
	Metrics *metrics.Recorder
}

// New creates the auditor for proxied requests: mostly a wrapper that combines
// the apiserver's audit handlers with the proxy.
//
// logger is the audit-component logger. The error reports audit options that
// cannot be applied.
func New(cfg Config, logger *slog.Logger) (*Audit, error) {
	logging.RequireLogger(logger, "audit")

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
		return nil, fmt.Errorf("audit: applying audit options: %w", err)
	}

	serverConfig.EffectiveVersion = compatibility.NewEffectiveVersionFromString(version.Get().String(), version.Get().String(), version.Get().String())

	completed := serverConfig.Complete(nil)

	return &Audit{
		logger:       logger,
		metrics:      cfg.Metrics,
		serverConfig: &completed,
	}, nil
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
		return fmt.Errorf("audit: running the backend: %w", err)
	}

	// The upstream backends describe themselves by type ("log",
	// "buffered<...>"), which is what an operator needs to correlate the
	// record with the audit flags.
	logging.Emit(ctx, a.logger, logging.EventAuditBackendStarted,
		slog.String("backend_kind", logging.Bound(a.serverConfig.AuditBackend.String(), logging.MaxIdentity)))
	return nil
}

// Shutdown flushes the audit backend, if one is configured, and records how
// long the flush took as audit.flush.completed.
//
// It cannot report a failed flush, and does not pretend to: the upstream
// audit.Backend interface returns nothing from Shutdown, and none of the
// bundled backends (log, buffered webhook, truncate, union) has another way to
// say it dropped events. The buffered backend reports a delivery failure
// through the Kubernetes error handler, which surfaces as a bridged
// component=k8s ERROR record ahead of this one.
func (a *Audit) Shutdown() {
	backend := a.serverConfig.AuditBackend
	if backend == nil {
		return
	}

	start := time.Now()
	backend.Shutdown()

	logging.Emit(context.Background(), a.logger, logging.EventAuditFlushCompleted,
		slog.Int64("duration_ms", time.Since(start).Milliseconds()))
}

// WithRequestInfo resolves the request into the verb, resource and namespace
// the rest of the proxy reasons about, and puts it on the request context.
//
// It runs high in the chain, ahead of everything that needs the answer: the
// lifecycle filter deciding whether a request is long running, the refusal
// path recording a denial, and both audit chains. The request is resolved once
// for all of them; WithRequest and WithFailedAuthentication do not resolve it
// again.
func (a *Audit) WithRequestInfo(handler http.Handler) http.Handler {
	return genericapifilters.WithRequestInfo(handler, a.serverConfig.RequestInfoResolver)
}

// WithRequest wraps handler in the ordinary request audit chain. It audits
// every request that authenticated: the admitted ones on their way to the
// reverse proxy, and the ones the proxy then refuses itself, whatever status
// the refusal carries. The event names the identity the caller placed on the
// request context with genericapirequest.WithUser.
//
// The request's RequestInfo must already be on the context: WithRequestInfo
// resolves it once, high in the chain, for every filter that needs it. With a
// backend configured and no RequestInfo, the apiserver filter cannot build the
// event and answers 500 in place of handler.
func (a *Audit) WithRequest(handler http.Handler) http.Handler {
	handler = genericapifilters.WithAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator, a.serverConfig.LongRunningFunc)
	return genericapifilters.WithAuditInit(handler)
}

// WithFailedAuthentication wraps handler in the failed-authentication audit
// chain, for a request that did not authenticate: the event is recorded as an
// authentication failure against the anonymous user. A request that
// authenticated and was then refused goes through WithRequest instead, which
// keeps its identity; this chain would evaluate the audit policy against an
// empty user.
//
// WithAuditInit mirrors WithRequest: without it there is no AuditContext on
// the request, the failed-authentication filter finds auditing disabled, and a
// 401 leaves no audit event at all (TremoloSecurity/kube-oidc-proxy#92). Like
// WithRequest it requires WithRequestInfo to have run, and answers 500 in
// place of handler when it has not.
func (a *Audit) WithFailedAuthentication(handler http.Handler) http.Handler {
	handler = genericapifilters.WithFailedAuthenticationAudit(handler, a.serverConfig.AuditBackend, a.serverConfig.AuditPolicyRuleEvaluator)
	return genericapifilters.WithAuditInit(handler)
}
