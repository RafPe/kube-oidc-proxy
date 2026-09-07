// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

func TestVerbForProjectsOntoTheClosedSet(t *testing.T) {
	tests := map[string]struct {
		info *genericapirequest.RequestInfo
		want Verb
	}{
		"nil info":                          {nil, VerbOther},
		"list":                              {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "list"}, VerbList},
		"watch":                             {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "watch"}, VerbWatch},
		"deletecollection":                  {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "deletecollection"}, VerbDeleteCollection},
		"POST exec is connect":              {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "create", Resource: "pods", Subresource: "exec"}, VerbConnect},
		"GET logs is connect":               {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods", Subresource: "log"}, VerbConnect},
		"GET status stays get":              {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", Resource: "pods", Subresource: "status"}, VerbGet},
		"unknown method on a resource":      {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: ""}, VerbOther},
		"non-resource GET is get":           {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "get"}, VerbGet},
		"non-resource POST":                 {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "post"}, VerbOther},
		"non-resource DELETE is not a verb": {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "delete"}, VerbOther},
		"client-invented method":            {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "propfind"}, VerbOther},
		"attacker-controlled verb":          {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "x\"y{z}"}, VerbOther},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := VerbFor(tc.info); got != tc.want {
				t.Fatalf("VerbFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestVerbForThroughTheRealResolver resolves real URLs through the same
// RequestInfoFactory the audit filter uses, so the projection is tested
// against what the proxy will actually see: POST .../exec resolves to verb
// "create" with subresource "exec", and only the projection turns that into
// connect.
func TestVerbForThroughTheRealResolver(t *testing.T) {
	factory := &genericapirequest.RequestInfoFactory{
		APIPrefixes:          sets.NewString("api", "apis"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}
	tests := map[string]struct {
		method, path string
		want         Verb
	}{
		"POST exec":        {http.MethodPost, "/api/v1/namespaces/a/pods/p/exec", VerbConnect},
		"GET exec":         {http.MethodGet, "/api/v1/namespaces/a/pods/p/exec", VerbConnect},
		"GET logs":         {http.MethodGet, "/api/v1/namespaces/a/pods/p/log", VerbConnect},
		"GET pod proxy":    {http.MethodGet, "/api/v1/namespaces/a/pods/p/proxy/", VerbConnect},
		"POST portforward": {http.MethodPost, "/api/v1/namespaces/a/pods/p/portforward", VerbConnect},
		"list pods":        {http.MethodGet, "/api/v1/namespaces/a/pods", VerbList},
		"watch pods":       {http.MethodGet, "/api/v1/namespaces/a/pods?watch=true", VerbWatch},
		"create deploy":    {http.MethodPost, "/apis/apps/v1/namespaces/a/deployments", VerbCreate},
		"non-resource":     {http.MethodGet, "/healthz", VerbGet},
		"odd method":       {"PROPFIND", "/apis/x/v1/y", VerbOther},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			info, err := factory.NewRequestInfo(httptest.NewRequest(tc.method, tc.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := VerbFor(info); got != tc.want {
				t.Fatalf("VerbFor(%s %s) = %q, want %q (resolver verb %q, subresource %q)", tc.method, tc.path, got, tc.want, info.Verb, info.Subresource)
			}
		})
	}
}

func TestScopeForProjectsOntoTheClosedSet(t *testing.T) {
	tests := map[string]struct {
		info *genericapirequest.RequestInfo
		want Scope
	}{
		"nil info":                    {nil, ScopeNone},
		"non-resource":                {&genericapirequest.RequestInfo{IsResourceRequest: false, Verb: "get"}, ScopeNone},
		"cluster list":                {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "list", Resource: "nodes"}, ScopeCluster},
		"namespaced list":             {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "list", Namespace: "a"}, ScopeNamespace},
		"named object":                {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", Namespace: "a", Name: "p"}, ScopeResource},
		"create is resource scoped":   {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "create", Namespace: "a"}, ScopeResource},
		"cluster-scoped named object": {&genericapirequest.RequestInfo{IsResourceRequest: true, Verb: "get", Name: "n"}, ScopeResource},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ScopeFor(tc.info); got != tc.want {
				t.Fatalf("ScopeFor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCodeForIsBoundedByTheIANARegistry(t *testing.T) {
	tests := map[int]string{200: "200", 401: "401", 431: "431", 502: "502", 0: "none", 299: "other", 999: "other", -1: "other"}
	for status, want := range tests {
		if got := CodeFor(status); got != want {
			t.Errorf("CodeFor(%d) = %q, want %q", status, got, want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestReviewOutcomeFor(t *testing.T) {
	var netErr net.Error = timeoutErr{}
	tests := map[string]struct {
		err     error
		allowed bool
		want    ReviewOutcome
	}{
		"allowed":            {nil, true, ReviewAllow},
		"denied":             {nil, false, ReviewDeny},
		"deadline":           {context.DeadlineExceeded, false, ReviewTimeout},
		"wrapped deadline":   {errors.Join(errors.New("sar"), context.DeadlineExceeded), false, ReviewTimeout},
		"canceled":           {context.Canceled, false, ReviewCanceled},
		"net timeout":        {netErr, false, ReviewTimeout},
		"apiserver timeout":  {apierrors.NewTimeoutError("review", 0), false, ReviewTimeout},
		"anything else":      {errors.New("boom"), false, ReviewError},
		"allowed with error": {errors.New("boom"), true, ReviewError},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ReviewOutcomeFor(tc.err, tc.allowed); got != tc.want {
				t.Fatalf("ReviewOutcomeFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProjectionsNeverPassAnUnknownValue is the property every label relies on:
// whatever string reaches a projection, only a documented value leaves it.
func TestProjectionsNeverPassAnUnknownValue(t *testing.T) {
	hostile := []string{"", "x", "GET", "system:masters", "a\"b", "../../etc", "很长"}
	for _, v := range hostile {
		if got := projectTermination(v); got != "other" {
			t.Errorf("projectTermination(%q) = %q", v, got)
		}
		if got := projectAuthMethod(v); got != "other" {
			t.Errorf("projectAuthMethod(%q) = %q", v, got)
		}
		if v != "" { // the empty reason is the reason of an allow and passes through
			if got := projectReason(v); got != "other" {
				t.Errorf("projectReason(%q) = %q", v, got)
			}
		}
		if got := projectVerb(Verb(v)); got != string(VerbOther) {
			t.Errorf("projectVerb(%q) = %q", v, got)
		}
		if got := projectScope(Scope(v)); got != string(ScopeNone) {
			t.Errorf("projectScope(%q) = %q", v, got)
		}
	}
	// The documented values pass through unchanged.
	for _, v := range []string{"normal", "hijacked", "client_cancel", "panic", "upstream_timeout", "upstream_reset", "proxy_error"} {
		if projectTermination(v) != v {
			t.Errorf("projectTermination(%q) altered a documented value", v)
		}
	}
	for _, v := range []string{"unauthorized", "reserved_identity", "no_username_claim", "impersonation_denied",
		"too_many_impersonation_values", "client_canceled", "internal_error", "upstream_error", "authentication_dependency_error"} {
		if projectReason(v) != v {
			t.Errorf("projectReason(%q) altered a documented value", v)
		}
	}
	if projectReason("") != "" {
		t.Errorf("projectReason must keep the empty reason of an allow")
	}
	// The five typed projections the review, cache, auth and audit collectors
	// use hold the same property against a value outside their own type set.
	for _, v := range hostile {
		if got := projectAuthOutcome(AuthOutcome(v)); got != "other" {
			t.Errorf("projectAuthOutcome(%q) = %q", v, got)
		}
		if got := projectReview(Review(v)); got != "other" {
			t.Errorf("projectReview(%q) = %q", v, got)
		}
		if got := projectReviewOutcome(ReviewOutcome(v)); got != "other" {
			t.Errorf("projectReviewOutcome(%q) = %q", v, got)
		}
		if got := projectCacheResult(CacheResult(v)); got != "other" {
			t.Errorf("projectCacheResult(%q) = %q", v, got)
		}
		if got := projectAuditOperation(AuditOperation(v)); got != "other" {
			t.Errorf("projectAuditOperation(%q) = %q", v, got)
		}
	}
	// Their documented values pass through unchanged.
	for _, v := range []AuthOutcome{AuthAccepted, AuthRejected, AuthError} {
		if projectAuthOutcome(v) != string(v) {
			t.Errorf("projectAuthOutcome(%q) altered a documented value", v)
		}
	}
	for _, v := range []Review{ReviewTokenReview, ReviewSAR} {
		if projectReview(v) != string(v) {
			t.Errorf("projectReview(%q) altered a documented value", v)
		}
	}
	for _, v := range []ReviewOutcome{ReviewAllow, ReviewDeny, ReviewTimeout, ReviewCanceled, ReviewError} {
		if projectReviewOutcome(v) != string(v) {
			t.Errorf("projectReviewOutcome(%q) altered a documented value", v)
		}
	}
	for _, v := range []CacheResult{CacheHit, CacheMiss, CacheBypass} {
		if projectCacheResult(v) != string(v) {
			t.Errorf("projectCacheResult(%q) altered a documented value", v)
		}
	}
	for _, v := range []AuditOperation{AuditRun, AuditShutdown} {
		if projectAuditOperation(v) != string(v) {
			t.Errorf("projectAuditOperation(%q) altered a documented value", v)
		}
	}
}
