// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
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

// isConnectSubresource reports the streaming subresources kube-apiserver
// reports as CONNECT in its own metrics, whichever HTTP method reached them.
func isConnectSubresource(sub string) bool {
	switch sub {
	case "exec", "attach", "portforward", "log", "proxy":
		return true
	}
	return false
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
	if isConnectSubresource(info.Subresource) {
		return VerbConnect
	}
	return Verb(projectVerb(Verb(info.Verb)))
}

// verbs is the documented verb set, in catalogue order. VerbOther is the
// catch-all and is listed last.
var verbs = []Verb{
	VerbGet, VerbList, VerbWatch, VerbCreate, VerbUpdate, VerbPatch,
	VerbDelete, VerbDeleteCollection, VerbProxy, VerbConnect, VerbOther,
}

func projectVerb(v Verb) string {
	return project(verbs, v, VerbOther)
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

// scopes is the documented scope set. ScopeNone doubles as the catch-all.
var scopes = []Scope{ScopeCluster, ScopeNamespace, ScopeResource, ScopeNone}

func projectScope(s Scope) string {
	return project(scopes, s, ScopeNone)
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

// Termination is how a request ended, as the terminal record's termination
// and the requests counter's label report it. The lifecycle filter decides the
// first four; the error handler classifies the upstream three.
type Termination string

const (
	TerminationNormal       Termination = "normal"
	TerminationHijacked     Termination = "hijacked"
	TerminationClientCancel Termination = "client_cancel"
	TerminationPanic        Termination = "panic"

	TerminationUpstreamTimeout Termination = "upstream_timeout"
	TerminationUpstreamReset   Termination = "upstream_reset"
	TerminationProxyError      Termination = "proxy_error"
)

// terminations is the documented set, in catalogue order.
var terminations = []Termination{
	TerminationNormal, TerminationHijacked, TerminationClientCancel, TerminationPanic,
	TerminationUpstreamTimeout, TerminationUpstreamReset, TerminationProxyError,
}

func projectTermination(t Termination) string {
	return project(terminations, t, other)
}

// AuthMethod is how a request authenticated, as the access record's
// auth_method and the authentication and decision counters report it.
type AuthMethod string

const (
	AuthMethodOIDC        AuthMethod = "oidc"
	AuthMethodTokenReview AuthMethod = "tokenreview"

	// AuthMethodNone is a request refused before any authenticator accepted
	// its credential.
	AuthMethodNone AuthMethod = "none"
)

// authMethods is the documented set, in catalogue order.
var authMethods = []AuthMethod{AuthMethodOIDC, AuthMethodTokenReview, AuthMethodNone}

func projectAuthMethod(m AuthMethod) string {
	return project(authMethods, m, other)
}

// Decision is the outcome of a request's single access decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// DecisionFor renders an allowed/denied outcome as the decision value every
// record and label uses.
func DecisionFor(allowed bool) Decision {
	if allowed {
		return DecisionAllow
	}
	return DecisionDeny
}

// Reason is why a request was refused, as the access record's reason and the
// decision counter's label report it. An allow has no reason: ReasonNone.
type Reason string

const (
	ReasonNone                       Reason = ""
	ReasonUnauthorized               Reason = "unauthorized"
	ReasonReservedIdentity           Reason = "reserved_identity"
	ReasonNoUsernameClaim            Reason = "no_username_claim"
	ReasonImpersonationDenied        Reason = "impersonation_denied"
	ReasonTooManyImpersonationValues Reason = "too_many_impersonation_values"
	ReasonClientCanceled             Reason = "client_canceled"
	ReasonInternalError              Reason = "internal_error"

	// ReasonUpstreamError classifies a failure of the hop to the API server
	// itself, as opposed to anything the proxy decided about the request. It
	// is carried by the upstream record and by the terminal record, never by
	// an access decision: the request was already admitted.
	ReasonUpstreamError Reason = "upstream_error"

	// ReasonAuthenticationDependencyError classifies a TokenReview that could
	// not be answered at all: the API server was unreachable or returned a
	// status error. It is not a verdict on the credential.
	ReasonAuthenticationDependencyError Reason = "authentication_dependency_error"

	// ReasonAuthorizationDependencyError classifies a SubjectAccessReview
	// that could not be answered, the authorization counterpart of
	// ReasonAuthenticationDependencyError.
	ReasonAuthorizationDependencyError Reason = "authorization_dependency_error"

	// ReasonMalformedImpersonation classifies a request whose Impersonate-*
	// headers have a shape the proxy refuses before asking anyone: a kind it
	// does not know, or groups, uid or extras with no user to refine.
	ReasonMalformedImpersonation Reason = "malformed_impersonation"
)

// reasons is the documented set, in catalogue order. ReasonNone is the
// reason of an allow and passes through.
var reasons = []Reason{
	ReasonNone, ReasonUnauthorized, ReasonReservedIdentity, ReasonNoUsernameClaim,
	ReasonImpersonationDenied, ReasonTooManyImpersonationValues, ReasonClientCanceled,
	ReasonInternalError, ReasonUpstreamError, ReasonAuthenticationDependencyError,
	ReasonAuthorizationDependencyError, ReasonMalformedImpersonation,
}

func projectReason(r Reason) string {
	return project(reasons, r, other)
}

// AuthOutcome is how one authentication attempt ended, before the identity
// and authorization checks that follow it.
type AuthOutcome string

const (
	AuthAccepted AuthOutcome = "accepted"
	AuthRejected AuthOutcome = "rejected"
	AuthError    AuthOutcome = "error"
)

var authOutcomes = []AuthOutcome{AuthAccepted, AuthRejected, AuthError}

func projectAuthOutcome(o AuthOutcome) string {
	return project(authOutcomes, o, other)
}

// Review names one of the two review APIs the proxy calls.
type Review string

const (
	ReviewTokenReview Review = "tokenreview"
	ReviewSAR         Review = "sar"
)

var reviews = []Review{ReviewTokenReview, ReviewSAR}

func projectReview(r Review) string {
	return project(reviews, r, other)
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

var reviewOutcomes = []ReviewOutcome{ReviewAllow, ReviewDeny, ReviewTimeout, ReviewCanceled, ReviewError}

func projectReviewOutcome(o ReviewOutcome) string {
	return project(reviewOutcomes, o, other)
}

// CacheResult is the outcome of one review-cache consultation.
type CacheResult string

const (
	CacheHit    CacheResult = "hit"
	CacheMiss   CacheResult = "miss"
	CacheBypass CacheResult = "bypass"
)

var cacheResults = []CacheResult{CacheHit, CacheMiss, CacheBypass}

func projectCacheResult(r CacheResult) string {
	return project(cacheResults, r, other)
}

// AuditOperation names the audit backend operation a failure was observed in.
type AuditOperation string

const (
	AuditRun      AuditOperation = "run"
	AuditShutdown AuditOperation = "shutdown"
)

var auditOperations = []AuditOperation{AuditRun, AuditShutdown}

func projectAuditOperation(o AuditOperation) string {
	return project(auditOperations, o, other)
}

// project is the one projection every label goes through: a documented value
// passes unchanged, anything else collapses onto catchAll. The same slice
// feeds the catalogue's allowed values, so the two cannot disagree.
func project[T ~string, C ~string](documented []T, v T, catchAll C) string {
	if slices.Contains(documented, v) {
		return string(v)
	}
	return string(catchAll)
}
