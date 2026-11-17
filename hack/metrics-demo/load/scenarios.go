// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// result is one HTTP exchange: what it was, what came back, and what was
// expected. A scenario reports one per constituent call rather than one for
// itself, so --once asserts every call it makes and the log carries a record
// per call instead of per scenario: a scenario whose first eight calls failed
// and whose ninth succeeded used to report success.
//
// want is the status the proxy or the API server must answer with; statusNone
// means the exchange finishes without one, because the connection was upgraded
// or the body was streamed.
type result struct {
	kind     string
	want     int
	status   int
	duration time.Duration
	err      error
}

func (r result) ok() bool { return r.err == nil && r.status == r.want }

// scenario is one kind of traffic, made of one or more calls.
type scenario struct {
	name string
	run  func(context.Context) []result
}

// observe runs one call and times it. The error is carried in the result
// rather than returned, so a scenario reports every call it made even when an
// early one failed.
func (g *generator) observe(ctx context.Context, kind string, want int, run func(context.Context) (int, error)) result {
	start := time.Now()
	status, err := run(ctx)

	return result{kind: kind, want: want, status: status, duration: time.Since(start), err: err}
}

// one builds a scenario that is a single call.
func (g *generator) one(name string, want int, run func(context.Context) (int, error)) scenario {
	return scenario{name: name, run: func(ctx context.Context) []result {
		return []result{g.observe(ctx, name, want, run)}
	}}
}

// failed builds the single result that stands for a scenario whose setup — a
// token to mint, a pod to find — did not get as far as a call.
func failed(kind string, err error) []result {
	return []result{{kind: kind, err: err}}
}

func (g *generator) scenarios() []scenario {
	pods := fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace)

	return []scenario{
		// requests_total{list,namespace,200}, the duration histogram,
		// authentication_attempts_total{oidc,accepted}, decisions{allow}.
		g.one("allowed_list", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods, nil)
		}),
		// The same, at resource scope rather than namespace scope.
		g.one("allowed_get", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod, nil)
		}),
		// The proxy allows the request; the API server refuses the
		// impersonated identity. A 403 that is not a proxy denial.
		g.one("forbidden_by_rbac", http.StatusForbidden, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, "/api/v1/nodes", nil)
		}),
		// A 5xx from the upstream, provoked without any fault injection: a
		// list at a resource version the API server will never observe is
		// answered "Too large resource version" with 504 after it gives up
		// waiting. It is the API server's own answer, so the proxy's exchange
		// completed normally - this is what puts a 5xx band on "Responses by
		// code class", not what puts a line on "Upstream failures/s", which
		// counts requests the hop to the API server never completed at all.
		g.one("upstream_5xx", http.StatusGatewayTimeout, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet,
				pods+"?resourceVersion=99999999999&timeoutSeconds=2", nil)
		}),
		// Not a JWT at all: rejected by OIDC, then by the TokenReview
		// fallback. decisions{deny,unauthorized}.
		g.one("invalid_token", http.StatusUnauthorized, func(ctx context.Context) (int, error) {
			return g.do(ctx, http.MethodGet, pods, "not-a-token-"+time.Now().Format(time.RFC3339Nano), nil)
		}),
		// Correctly signed, but past its exp: the same outcome by a
		// different route through the authenticator.
		g.one("expired_token", http.StatusUnauthorized, func(ctx context.Context) (int, error) {
			token, err := g.token(demoUser, []string{"demo"}, time.Now().Add(-time.Hour))
			if err != nil {
				return 0, err
			}

			return g.do(ctx, http.MethodGet, pods, token, nil)
		}),
		// review_requests_total{sar,allow}, cache_lookups_total (a miss,
		// then hits on every later run), decisions{allow}.
		{name: "impersonation_allowed", run: func(ctx context.Context) []result {
			// Three times, back to back: the first call to each replica is a
			// cache miss and issues a real SubjectAccessReview, and with two
			// replicas a third call is guaranteed to land on one that is
			// already warm. One call on its own would only ever produce
			// misses, because the rotation comes round again long after the
			// cache entry has expired.
			headers := http.Header{"Impersonate-User": []string{impersonated}}

			return g.repeat(ctx, "impersonation_allowed", cacheWarmCalls, http.StatusOK,
				func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
				})
		}},
		// The flight group: identical impersonation calls that arrive at one
		// replica while its cache is cold share a single SubjectAccessReview.
		{name: "impersonation_coalesced", run: g.coalescedImpersonation},
		// review_requests_total{sar,deny},
		// decisions{deny,impersonation_denied}.
		g.one("impersonation_denied", http.StatusForbidden, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods,
				http.Header{"Impersonate-User": []string{notImpersonated}})
		}),
		// decisions{deny,too_many_impersonation_values}: refused on the
		// header count before any review is issued.
		g.one("too_many_impersonation_values", http.StatusRequestHeaderFieldsTooLarge, func(ctx context.Context) (int, error) {
			headers := http.Header{"Impersonate-User": []string{impersonated}}
			for i := 0; i < 100; i++ {
				headers.Add("Impersonate-Group", fmt.Sprintf("group-%d", i))
			}

			return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
		}),
		// decisions{deny,reserved_identity}: a token claiming a group the
		// proxy will never impersonate.
		g.one("reserved_identity", http.StatusForbidden, func(ctx context.Context) (int, error) {
			token, err := g.token(demoUser, []string{"system:masters"}, time.Now().Add(10*time.Minute))
			if err != nil {
				return 0, err
			}

			return g.do(ctx, http.MethodGet, pods, token, nil)
		}),
		// decisions{deny,no_username_claim}: a token the issuer vouches for
		// that names nobody.
		{name: "no_username_claim", run: g.noUsernameClaim},
		// authentication_attempts_total{oidc,rejected} then
		// {tokenreview,accepted}, review_requests_total{tokenreview,allow}.
		{name: "passthrough_allowed", run: func(ctx context.Context) []result {
			token, err := g.serviceAccountToken(ctx)
			if err != nil {
				return failed("passthrough_allowed", err)
			}

			// The same token repeatedly, so the TokenReview result is cached
			// and reused rather than reviewed again on every call. A freshly
			// minted token on each call would only ever miss.
			return g.repeat(ctx, "passthrough_allowed", cacheWarmCalls, http.StatusOK,
				func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, token, nil)
				})
		}},
		// A token the API server cannot authenticate either. It answers
		// authenticated=false *and* status.error "invalid bearer token", so
		// the proxy records
		// authentication_attempts_total{tokenreview,error} - not
		// {tokenreview,rejected}, which nothing here produces. See
		// unknownServiceAccountToken.
		{name: "passthrough_denied", run: func(ctx context.Context) []result {
			// Repeated with the same token, so a later lookup is served from
			// the TokenReview failure cache rather than reviewed again; that
			// is what shields the API server from a client retrying a bad
			// token in a loop.
			return g.repeat(ctx, "passthrough_denied", cacheWarmCalls, http.StatusUnauthorized,
				func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, unknownServiceAccountToken(), nil)
				})
		}},
		// long_running_requests{watch}, released when the client goes away:
		// termination client_cancel.
		g.one("watch", statusNone, g.watch),
		// The hijack path: long_running_requests{connect}, termination
		// hijacked, code none.
		g.one("exec", statusNone, g.exec),
		// A streamed response that is long-running but not hijacked.
		g.one("logs", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod+"/log", nil)
		}),
		// scope none, verb get: paths with no RequestInfo resource. Both are
		// asserted; the /version status used to be discarded because only the
		// last call of a scenario was checked.
		{name: "non_resource", run: func(ctx context.Context) []result {
			return []result{
				g.observe(ctx, "non_resource[/version]", http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, "/version", nil)
				}),
				g.observe(ctx, "non_resource[/healthz]", http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, "/healthz", nil)
				}),
			}
		}},
		// Verbs that are not HTTP methods and not Kubernetes verbs: every one
		// must land on k8s_verb="other", scope="none", and never create a new
		// series.
		{name: "hostile_methods", run: g.hostileMethods},
	}
}

// noUsernameClaim sends a token the issuer signed that carries no username in
// the claim the proxy maps identities from, and asserts that the replica it
// went to counted the denial under that reason rather than under a generic
// one. Without the counter check the scenario would only prove that some
// denial happened.
func (g *generator) noUsernameClaim(ctx context.Context) []result {
	token, err := g.tokenWithoutUsername(time.Now().Add(10 * time.Minute))
	if err != nil {
		return failed("no_username_claim", err)
	}

	before, err := g.scrape(ctx)
	if err != nil {
		return failed("no_username_claim", err)
	}

	r := g.observe(ctx, "no_username_claim", noUsernameClaimStatus, func(ctx context.Context) (int, error) {
		return g.doAt(ctx, g.pinned.proxy.URL(), http.MethodGet,
			fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace), token, nil)
	})
	if r.err != nil {
		return []result{r}
	}

	after, err := g.scrape(ctx)
	if err != nil {
		r.err = err

		return []result{r}
	}

	labels := map[string]string{"decision": "deny", "reason": "no_username_claim"}
	grew := seriesSum(after, metricDecisions, labels) - seriesSum(before, metricDecisions, labels)
	if grew < 1 {
		r.err = fmt.Errorf("%s recorded no decisions{reason=no_username_claim} for the call (delta %.0f)",
			g.pinned.name, grew)
	}

	return []result{r}
}

// watch holds a list-watch open, so the long-running gauge rises and then
// falls when the client cancels.
func (g *generator) watch(ctx context.Context) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	client, err := kubernetes.NewForConfig(g.restConfig(token))
	if err != nil {
		return 0, err
	}

	watchCtx, cancel := context.WithTimeout(ctx, watchHold)
	defer cancel()

	w, err := client.CoreV1().Pods(g.namespace).Watch(watchCtx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to open a watch: %w", err)
	}
	defer w.Stop()

	// Drain until the hold elapses; the point is the open connection, not
	// the events.
	for {
		select {
		case <-watchCtx.Done():
			return statusNone, nil
		case _, ok := <-w.ResultChan():
			if !ok {
				return statusNone, nil
			}
		}
	}
}

// exec runs a trivial command in the demo pod. The reverse proxy hijacks the
// connection before writing the 101, which is the case the recorder's onHijack
// hook exists for.
func (g *generator) exec(ctx context.Context) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	cfg := g.restConfig(token)
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return 0, err
	}

	req := client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(g.namespace).Name(demoPod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "shell",
			Command:   []string{"true"},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, http.MethodPost, req.URL())
	if err != nil {
		return 0, fmt.Errorf("failed to build an exec executor: %w", err)
	}

	execCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	if err := executor.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdout: io.Discard,
		Stderr: io.Discard,
	}); err != nil {
		return 0, fmt.Errorf("exec into %s/%s failed: %w", g.namespace, demoPod, err)
	}

	return statusNone, nil
}

// hostileMethods sends verbs no Kubernetes client uses. They must all be
// projected onto k8s_verb="other" rather than creating a series each. Each
// method is asserted and logged on its own: the scenario used to discard all
// nine statuses and report statusNone, so any of them could have been anything
// at all.
func (g *generator) hostileMethods(ctx context.Context) []result {
	token, err := g.validToken()
	if err != nil {
		return failed("hostile_methods", err)
	}

	out := make([]result, 0, hostileMethodCount)
	for i := 1; i <= hostileMethodCount; i++ {
		method := fmt.Sprintf("M%d", i)
		out = append(out, g.observe(ctx, "hostile_methods["+method+"]", hostileMethodStatus,
			func(ctx context.Context) (int, error) {
				return g.do(ctx, method, "/apis/x/v1/y", token, nil)
			}))
	}

	return out
}

// repeat runs the same call n times so a scenario can warm a cache and then
// hit it, and returns one result per call. It stops at the first call whose
// status diverged from want and names it: returning only the last status let a
// warm-up call fail unnoticed as long as the final one answered correctly.
func (g *generator) repeat(ctx context.Context, kind string, n, want int, call func(context.Context) (int, error)) []result {
	out := make([]result, 0, n)
	for i := 0; i < n; i++ {
		r := g.observe(ctx, fmt.Sprintf("%s[%d/%d]", kind, i+1, n), want, call)
		if r.err == nil && r.status != want {
			r.err = fmt.Errorf("call %d of %d answered %d, want %d", i+1, n, r.status, want)
		}
		out = append(out, r)
		if r.err != nil {
			return out
		}
	}

	return out
}
