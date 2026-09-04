// Copyright Jetstack Ltd. See LICENSE for details.

// Package audit wires the Kubernetes apiserver audit backend into the proxy,
// emitting audit events for proxied requests.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"k8s.io/apimachinery/pkg/util/sets"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
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
	// lifecycle through. Never nil: New substitutes a discarding logger.
	logger *slog.Logger

	opts         *options.AuditOptions
	serverConfig *server.CompletedConfig
}

// New creates a new Audit struct to handle auditing for proxy requests. This
// is mostly a wrapper for the apiserver auditing handlers to combine them with
// the proxy.
//
// logger is the audit-component logger; a nil logger yields one that discards
// every record, so a partially wired caller cannot panic on the request path.
func New(opts *options.AuditOptions, externalAddress string, secureServingInfo *server.SecureServingInfo, logger *slog.Logger) (*Audit, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

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
		// the verb or subresource it matches on, so exec, attach, portforward,
		// log and proxy are never treated as long running however the set above
		// is written — nor is a core group watch, which the generic default
		// already covered. All of them live under /api.
		LegacyAPIGroupPrefixes: sets.NewString(server.DefaultLegacyAPIPrefix),
	}

	// We do not support dynamic auditing, so leave nil
	if err := opts.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	serverConfig.EffectiveVersion = compatibility.NewEffectiveVersionFromString(version.Get().String(), version.Get().String(), version.Get().String())

	completed := serverConfig.Complete(nil)

	return &Audit{
		logger:       logger,
		opts:         opts,
		serverConfig: &completed,
	}, nil
}

// errorReporter is implemented by an audit backend that can say whether its
// Shutdown flushed successfully. The upstream audit.Backend interface declares
// Shutdown with no return value, so a backend that knows it dropped events has
// no way to report that through the interface; one that implements this is
// asked, and the answer decides between audit.flush.completed and
// audit.flush.failed.
type errorReporter interface {
	ShutdownErr() error
}

// Run will run the audit backend if configured. A backend that fails to start
// is an error the process cannot serve correctly through: without it, proxied
// requests leave no audit trail.
func (a *Audit) Run(stopCh <-chan struct{}) error {
	if a.serverConfig.AuditBackend == nil {
		return nil
	}

	ctx := context.Background()
	if err := a.serverConfig.AuditBackend.Run(stopCh); err != nil {
		logging.Emit(ctx, a.logger, logging.EventAuditBackendFailed, logging.ErrAttr(err))
		return fmt.Errorf("failed to run the audit backend: %s", err)
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

// Shutdown flushes the audit backend if configured and reports the outcome,
// both as a record and to the caller. A failed flush means audit events for
// requests this process already served were dropped, so it must not be
// swallowed.
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
			logging.Emit(ctx, a.logger, logging.EventAuditFlushFailed, logging.ErrAttr(err))
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
