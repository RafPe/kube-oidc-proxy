// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// Namespace is the prefix of every metric this binary exports. It is part of
// the published contract and never changes.
const Namespace = "kube_oidc_proxy"

// other is the value every projection collapses an undocumented input onto.
// A label must never carry a client-controlled string: kube-apiserver can
// label by resource because its labels come from its route table, but this
// proxy would take them from the request path, and a client could then mint
// one series per request until the process ran out of memory. Every label
// value therefore passes through one of the projections below.
const other = "other"

// Verb is the Kubernetes verb a request resolved to, projected onto a closed
// lowercase set. Resource requests carry the resolver's verb (create, get,
// list, watch, update, patch, delete, deletecollection, proxy), except that a
// request to one of the streaming subresources (exec, attach, portforward,
// log, proxy) is VerbConnect whatever method carried it, the same
// normalisation kube-apiserver applies in its request metrics. A
// non-resource request carries the raw HTTP method as its verb, so only GET
// maps to a value (VerbGet); everything else is VerbOther. Anything outside
// the set is VerbOther.
type Verb string

const (
	VerbGet              Verb = "get"
	VerbList             Verb = "list"
	VerbWatch            Verb = "watch"
	VerbCreate           Verb = "create"
	VerbUpdate           Verb = "update"
	VerbPatch            Verb = "patch"
	VerbDelete           Verb = "delete"
	VerbDeleteCollection Verb = "deletecollection"
	VerbProxy            Verb = "proxy"
	VerbConnect          Verb = "connect"
	VerbOther            Verb = other
)

var knownVerbs = map[Verb]struct{}{
	VerbGet: {}, VerbList: {}, VerbWatch: {}, VerbCreate: {}, VerbUpdate: {}, VerbPatch: {},
	VerbDelete: {}, VerbDeleteCollection: {}, VerbProxy: {}, VerbConnect: {},
}

// connectSubresources are the streaming subresources kube-apiserver reports
// as CONNECT in its own metrics, whichever HTTP method reached them.
var connectSubresources = map[string]struct{}{
	"exec": {}, "attach": {}, "portforward": {}, "log": {}, "proxy": {},
}

// VerbFor projects the resolved RequestInfo onto the verb label. See Verb for
// the rules; a request without RequestInfo is VerbOther.
func VerbFor(info *genericapirequest.RequestInfo) Verb {
	if info == nil {
		return VerbOther
	}
	if !info.IsResourceRequest {
		if info.Verb == string(VerbGet) {
			return VerbGet
		}
		return VerbOther
	}
	if _, ok := connectSubresources[info.Subresource]; ok {
		return VerbConnect
	}
	return Verb(projectVerb(Verb(info.Verb)))
}

func projectVerb(v Verb) string {
	if _, ok := knownVerbs[v]; ok {
		return string(v)
	}
	return string(VerbOther)
}

// Scope is how much of the API a request addressed, mirroring kube-apiserver's
// CleanScope. ScopeNone is the explicit rendering of a non-resource request:
// in Prometheus an empty label value is indistinguishable from an absent
// label, so the empty scope kube-apiserver uses is never emitted.
type Scope string

const (
	ScopeCluster   Scope = "cluster"
	ScopeNamespace Scope = "namespace"
	ScopeResource  Scope = "resource"
	ScopeNone      Scope = "none"
)

var knownScopes = map[Scope]struct{}{ScopeCluster: {}, ScopeNamespace: {}, ScopeResource: {}, ScopeNone: {}}

// ScopeFor projects the resolved RequestInfo onto the scope label.
func ScopeFor(info *genericapirequest.RequestInfo) Scope {
	if info == nil || !info.IsResourceRequest {
		return ScopeNone
	}
	if info.Name != "" || info.Verb == string(VerbCreate) {
		return ScopeResource
	}
	if info.Namespace != "" {
		return ScopeNamespace
	}
	return ScopeCluster
}

func projectScope(s Scope) string {
	if _, ok := knownScopes[s]; ok {
		return string(s)
	}
	return string(ScopeNone)
}

// CodeFor renders an HTTP status for the code label. The domain is the IANA
// registry as Go knows it, so a status the proxy or the API server never
// sends cannot create a series; a request that ended without a status (a
// hijacked connection, a dropped one) is "none".
func CodeFor(status int) string {
	if status == 0 {
		return "none"
	}
	if http.StatusText(status) == "" {
		return other
	}
	return strconv.Itoa(status)
}

// The termination vocabulary of pkg/proxy/lifecycle.go, repeated here rather
// than imported so this package has no dependency on the proxy.
var knownTerminations = map[string]struct{}{
	"normal": {}, "hijacked": {}, "client_cancel": {}, "panic": {},
	"upstream_timeout": {}, "upstream_reset": {}, "proxy_error": {},
}

func projectTermination(v string) string {
	if _, ok := knownTerminations[v]; ok {
		return v
	}
	return other
}

// The auth_method vocabulary of pkg/proxy/handlers.go.
var knownAuthMethods = map[string]struct{}{"oidc": {}, "tokenreview": {}, "none": {}}

func projectAuthMethod(v string) string {
	if _, ok := knownAuthMethods[v]; ok {
		return v
	}
	return other
}

// The access-record reason vocabulary of pkg/proxy/handlers.go. The empty
// reason is the reason of an allow and passes through.
var knownReasons = map[string]struct{}{
	"": {}, "unauthorized": {}, "reserved_identity": {}, "no_username_claim": {},
	"impersonation_denied": {}, "too_many_impersonation_values": {}, "client_canceled": {},
	"internal_error": {}, "upstream_error": {}, "authentication_dependency_error": {},
}

func projectReason(v string) string {
	if _, ok := knownReasons[v]; ok {
		return v
	}
	return other
}

// AuthOutcome is how one authentication attempt ended, before the identity
// and authorization checks that follow it.
type AuthOutcome string

const (
	AuthAccepted AuthOutcome = "accepted"
	AuthRejected AuthOutcome = "rejected"
	AuthError    AuthOutcome = "error"
)

func projectAuthOutcome(o AuthOutcome) string {
	switch o {
	case AuthAccepted, AuthRejected, AuthError:
		return string(o)
	}
	return other
}

// Review names one of the two review APIs the proxy calls.
type Review string

const (
	ReviewTokenReview Review = "tokenreview"
	ReviewSAR         Review = "sar"
)

func projectReview(r Review) string {
	switch r {
	case ReviewTokenReview, ReviewSAR:
		return string(r)
	}
	return other
}

// ReviewOutcome is how one review API call ended, classified from the actual
// client completion rather than from any caller-level decision.
type ReviewOutcome string

const (
	ReviewAllow    ReviewOutcome = "allow"
	ReviewDeny     ReviewOutcome = "deny"
	ReviewTimeout  ReviewOutcome = "timeout"
	ReviewCanceled ReviewOutcome = "canceled"
	ReviewError    ReviewOutcome = "error"
)

// ReviewOutcomeFor classifies a review call. allowed is only consulted when
// err is nil: for a TokenReview it means authenticated, for a
// SubjectAccessReview it means the impersonation was permitted.
func ReviewOutcomeFor(err error, allowed bool) ReviewOutcome {
	if err == nil {
		if allowed {
			return ReviewAllow
		}
		return ReviewDeny
	}
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ReviewTimeout
	case errors.As(err, &netErr) && netErr.Timeout():
		return ReviewTimeout
	case apierrors.IsTimeout(err):
		// The API server answered with a Timeout status rather than the
		// transport timing out.
		return ReviewTimeout
	case errors.Is(err, context.Canceled):
		return ReviewCanceled
	}
	return ReviewError
}

func projectReviewOutcome(o ReviewOutcome) string {
	switch o {
	case ReviewAllow, ReviewDeny, ReviewTimeout, ReviewCanceled, ReviewError:
		return string(o)
	}
	return other
}

// CacheResult is the outcome of one review-cache consultation.
type CacheResult string

const (
	CacheHit    CacheResult = "hit"
	CacheMiss   CacheResult = "miss"
	CacheBypass CacheResult = "bypass"
)

func projectCacheResult(r CacheResult) string {
	switch r {
	case CacheHit, CacheMiss, CacheBypass:
		return string(r)
	}
	return other
}

// AuditOperation names the audit backend operation a failure was observed in.
type AuditOperation string

const (
	AuditRun      AuditOperation = "run"
	AuditShutdown AuditOperation = "shutdown"
)

func projectAuditOperation(o AuditOperation) string {
	switch o {
	case AuditRun, AuditShutdown:
		return string(o)
	}
	return other
}
