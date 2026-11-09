// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/rafpe/kube-oidc-proxy/pkg/authz/subjectaccessreview/fake"
)

// countingFakeReviewer counts submitted reviews while delegating the decision
// itself to the shared fake, so the cap tests can prove that a refused request
// never submits a SubjectAccessReview at all.
type countingFakeReviewer struct {
	*fake.FakeReviewer

	calls atomic.Int32
}

func (c *countingFakeReviewer) Create(ctx context.Context, req *v1.SubjectAccessReview, co metav1.CreateOptions) (*v1.SubjectAccessReview, error) {
	c.calls.Add(1)
	return c.FakeReviewer.Create(ctx, req, co)
}

// blockingReviewer is a local test double implementing
// clientazv1.SubjectAccessReviewInterface. Only Create is exercised: it counts
// calls, signals entry once, then blocks until its context is done and returns
// the context error. This lets the cancellation tests prove that request
// cancellation and deadlines short-circuit the SAR sequence.
type blockingReviewer struct {
	// entered is buffered(1) and signaled with a non-blocking send so a second,
	// unexpected Create can neither block nor panic.
	entered chan struct{}
	calls   atomic.Int32
}

var _ clientazv1.SubjectAccessReviewInterface = (*blockingReviewer)(nil)

func (b *blockingReviewer) Create(ctx context.Context, _ *v1.SubjectAccessReview, _ metav1.CreateOptions) (*v1.SubjectAccessReview, error) {
	b.calls.Add(1)
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// sarResult carries the return of ResolveImpersonation back from the
// worker goroutine over a channel, keeping the tests race-clean.
type sarResult struct {
	target user.Info
	err    error
}

// TestCheckAuthorizedForImpersonationCanceled verifies that cancelling the
// inbound request context while a SAR check is in flight promptly aborts the
// sequence with context.Canceled and does not run further checks.
func TestCheckAuthorizedForImpersonationCanceled(t *testing.T) {
	reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
	sar := New(reviewer, Config{Timeout: DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(testRequestContext())
	defer cancel()

	req := (&http.Request{Header: impersonationHeaders()}).WithContext(ctx)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.ResolveImpersonation(req, requester)
		done <- sarResult{target: target, err: err}
	}()

	// Wait for the first (and only) SAR Create to be in flight and blocking.
	select {
	case <-reviewer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("SAR Create was never entered")
	}

	cancel()

	select {
	case res := <-done:
		if !errors.Is(res.err, context.Canceled) {
			t.Errorf("error = %v, want errors.Is(context.Canceled)", res.err)
		}
		if res.target != nil {
			t.Errorf("target = %+v, want nil", res.target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no return after cancellation")
	}

	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times, want exactly 1 (later checks must be skipped)", got)
	}
}

// TestCheckAuthorizedForImpersonationDeadlineExceeded verifies that a short
// inbound request deadline aborts the SAR sequence with
// context.DeadlineExceeded and runs at most the first check.
func TestCheckAuthorizedForImpersonationDeadlineExceeded(t *testing.T) {
	reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
	sar := New(reviewer, Config{Timeout: DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithTimeout(testRequestContext(), 50*time.Millisecond)
	defer cancel()

	req := (&http.Request{Header: impersonationHeaders()}).WithContext(ctx)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.ResolveImpersonation(req, requester)
		done <- sarResult{target: target, err: err}
	}()

	select {
	case res := <-done:
		if !errors.Is(res.err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want errors.Is(context.DeadlineExceeded)", res.err)
		}
		if res.target != nil {
			t.Errorf("target = %+v, want nil", res.target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no return after deadline")
	}

	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times, want exactly 1 (later checks must be skipped)", got)
	}
}

// TestCheckAuthorizedForImpersonationConfiguredTimeout verifies that the
// configured SAR timeout is honored even when the inbound request carries no
// deadline of its own: a short timeout passed to New bounds a stalled SAR
// sequence with context.DeadlineExceeded. The 2s guard keeps a short (50ms)
// budget distinguishable from a longer one that would only expire much later.
func TestCheckAuthorizedForImpersonationConfiguredTimeout(t *testing.T) {
	reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
	sar := New(reviewer, Config{Timeout: 50 * time.Millisecond, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))

	// context.Background() has no deadline, so only the configured timeout can
	// abort the blocked SAR call.
	req := (&http.Request{Header: impersonationHeaders()}).WithContext(testRequestContext())
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.ResolveImpersonation(req, requester)
		done <- sarResult{target: target, err: err}
	}()

	select {
	case res := <-done:
		if !errors.Is(res.err, context.DeadlineExceeded) {
			t.Errorf("error = %v, want errors.Is(context.DeadlineExceeded)", res.err)
		}
		if !errors.Is(res.err, ErrCreateSubjectAccessReview) {
			t.Errorf("error = %v, want errors.Is(ErrCreateSubjectAccessReview)", res.err)
		}
		if res.target != nil {
			t.Errorf("target = %+v, want nil", res.target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no return after configured timeout; the New() timeout was not honored")
	}

	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times, want exactly 1 (later checks must be skipped)", got)
	}
}

// gateReviewer holds every Create open until release is closed, so a second
// caller has time to join the in-flight singleflight call before it answers.
type gateReviewer struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

var _ clientazv1.SubjectAccessReviewInterface = (*gateReviewer)(nil)

func (r *gateReviewer) Create(_ context.Context, req *v1.SubjectAccessReview, _ metav1.CreateOptions) (*v1.SubjectAccessReview, error) {
	r.calls.Add(1)
	select {
	case r.entered <- struct{}{}:
	default:
	}
	<-r.release
	req.Status = v1.SubjectAccessReviewStatus{Allowed: true}
	return req, nil
}
