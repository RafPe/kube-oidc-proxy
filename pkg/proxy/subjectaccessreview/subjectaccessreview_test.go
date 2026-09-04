// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// testRequestContext returns a context carrying a request id, exactly as the
// proxy's request filter installs one in production. Every record this package
// emits requires request_id, so a bare context trips the logcheck build.
func testRequestContext() context.Context {
	return logging.WithRequestID(context.Background(), "test-request")
}

// errReview is the sentinel injected into the fake reviewer so that error-path
// tests can assert with errors.Is after the production code wraps the Create
// error with %w.
var errReview = errors.New("error authorizing the request")

// stores the context for each test case
type testT struct {
	// the already authenticated user
	requester user.Info

	// the expected target information from the request
	expTarget user.Info

	// the expected authorization decision
	expAz bool

	// the expected error
	expErr error

	// expected error from rbacCheck
	expErrorRbac error

	// should the impersonation headers be found?
	expImpersonationHeaders bool

	// should include extra impersonation header?
	extraImpersonationHeader bool
}

func TestSubjectAccessReview(t *testing.T) {
	tests := map[string]testT{
		"if all reviews pass, user is authorized to impersonate": {
			requester: &user.DefaultInfo{
				Name:   "mmosley",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    true,
			expErr:                   nil,
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"user not authorized to impersonate target username": {
			requester: &user.DefaultInfo{
				Name:   "mmosley",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson-x",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: "user", Target: "'jjackson-x'"},
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"user not authorized to impersonate target group": {
			requester: &user.DefaultInfo{
				Name:   "mmosley",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group4"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: "group", Target: "'group4'"},
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"user not authorized to impersonate target extraInfo": {
			requester: &user.DefaultInfo{
				Name:   "mmosley",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.5"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: "extra info", Target: "'remoteaddr'='1.2.3.5'"},
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"user is not authorized to impersonate the uid": {
			requester: &user.DefaultInfo{
				Name:   "mmosley",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-5",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: "uid", Target: "'1-2-3-5'"},
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"error on the call returns false": {
			requester: &user.DefaultInfo{
				Name:   "mmosley-x",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   errReview,
			expErrorRbac:             errReview,
			extraImpersonationHeader: false,
		},

		"no impersonation headers found, should set flag as such": {
			requester: &user.DefaultInfo{
				Name:   "mmosley-x",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{},

			expImpersonationHeaders:  false,
			expAz:                    false,
			expErr:                   nil,
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},

		"unknown impersonation header, error": {
			requester: &user.DefaultInfo{
				Name:   "mmosley-x",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "jjackson",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   errors.New("unknown impersonation header 'Impersonate-doesnotexist'"),
			expErrorRbac:             nil,
			extraImpersonationHeader: true,
		},

		"missing impersonation-user": {
			requester: &user.DefaultInfo{
				Name:   "mmosley-x",
				Groups: []string{"group1", "group2"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
			},

			expTarget: &user.DefaultInfo{
				Name:   "",
				Groups: []string{"group3"},
				Extra: map[string][]string{
					"remoteaddr": {"1.2.3.4"},
				},
				UID: "1-2-3-4",
			},

			expImpersonationHeaders:  true,
			expAz:                    false,
			expErr:                   errors.New("no Impersonation-User header found for request"),
			expErrorRbac:             nil,
			extraImpersonationHeader: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			runTest(t, name, test)
		})
	}
}

func runTest(t *testing.T, name string, test testT) {

	extras := map[string]v1.ExtraValue{}

	for key, value := range test.requester.GetExtra() {
		extras[key] = value
	}

	testReviewer, _ := New(fake.New(test.expErrorRbac), DefaultTimeout, 0, 0, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))

	headers := map[string][]string{}

	if test.expImpersonationHeaders {
		if test.expTarget.GetName() != "" {
			headers["Impersonate-User"] = []string{test.expTarget.GetName()}
		}

		headers["Impersonate-Group"] = test.expTarget.GetGroups()
		headers["Impersonate-Uid"] = []string{test.expTarget.GetUID()}

		for key, value := range test.expTarget.GetExtra() {
			headers["Impersonate-Extra-"+strings.ToUpper(key)] = value
		}

		if test.extraImpersonationHeader {
			headers["Impersonate-doesnotexist"] = []string{"doesnotmatter"}
		}
	}

	target, err := testReviewer.CheckAuthorizedForImpersonation(
		(&http.Request{
			Header: headers,
		}).WithContext(testRequestContext()), test.requester)

	// check if the errors match. The backend-error case wraps both the
	// production sentinel and the underlying injected error with the multi-%w
	// verb, so assert errors.Is against both there; the other cases build fresh
	// message-only errors that are only comparable by value.
	if test.expErrorRbac != nil {
		if !errors.Is(err, ErrCreateSubjectAccessReview) {
			t.Errorf("CheckAuthorizedForImpersonation() error = %v, want errors.Is(%v)", err, ErrCreateSubjectAccessReview)
		}
		if !errors.Is(err, errReview) {
			t.Errorf("CheckAuthorizedForImpersonation() error = %v, want errors.Is(%v) (underlying error must survive multi-%%w wrap)", err, errReview)
		}
	} else if !reflect.DeepEqual(test.expErr, err) {
		t.Errorf("unexpected error, exp=%t got %t", test.expErr, err)
	}

	//check if impersonation was found when expected

	headersFound := err != nil || target != nil

	if test.expImpersonationHeaders != headersFound {
		t.Errorf("unexpected result when checking if impersonation headers were present, exp=%t got=%t", test.expImpersonationHeaders, (err == nil && target == nil))
	}

	azSuccess := target != nil && err == nil
	// check if authorization matchs
	if azSuccess != test.expAz {
		t.Errorf("authorization decision doesn't match, exp=%t got=%t", azSuccess, test.expAz)
	}

	// check that the final impersonated user lines up with the expected test case
	if azSuccess {
		if !reflect.DeepEqual(test.expTarget, target) {
			t.Errorf(" target doesn't match, exp=%+v got %+v", test.expTarget, target)
		}
	} else {

		if target != nil {
			t.Errorf("expected empty target, got=%+v", target)
		}
	}

	// everything checks out!

}

// TestImpersonationAuthErrorClassification pins the typed-error contract for
// issue #51: every denial classifies as ErrImpersonationNotAllowed via
// errors.Is (and errors.As), unrelated errors do not, and the client-facing
// message is preserved verbatim.
func TestImpersonationAuthErrorClassification(t *testing.T) {
	tests := map[string]struct {
		err    *ImpersonationAuthError
		expMsg string
	}{
		"user": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: "user", Target: "'a-user'"},
			expMsg: "mmosley is not allowed to impersonate user 'a-user'",
		},
		"group": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: "group", Target: "'a-group'"},
			expMsg: "mmosley is not allowed to impersonate group 'a-group'",
		},
		"uid": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: "uid", Target: "'bar'"},
			expMsg: "mmosley is not allowed to impersonate uid 'bar'",
		},
		"extra info": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: "extra info", Target: "'foo'='bar'"},
			expMsg: "mmosley is not allowed to impersonate extra info 'foo'='bar'",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Message is stable and client-facing.
			if got := tc.err.Error(); got != tc.expMsg {
				t.Errorf("Error() = %q, want %q", got, tc.expMsg)
			}

			// Classifies as the sentinel through a wrap, without message matching.
			wrapped := fmt.Errorf("handling request: %w", tc.err)
			if !errors.Is(wrapped, ErrImpersonationNotAllowed) {
				t.Errorf("errors.Is(wrapped, ErrImpersonationNotAllowed) = false, want true")
			}

			var asErr *ImpersonationAuthError
			if !errors.As(wrapped, &asErr) {
				t.Errorf("errors.As did not recover *ImpersonationAuthError from %v", wrapped)
			}
		})
	}

	// Unrelated errors must not be misclassified as a denial.
	if errors.Is(ErrorNoImpersonationUserFound, ErrImpersonationNotAllowed) {
		t.Error("ErrorNoImpersonationUserFound must not classify as ErrImpersonationNotAllowed")
	}
	if errors.Is(errors.New("boom"), ErrImpersonationNotAllowed) {
		t.Error("arbitrary error must not classify as ErrImpersonationNotAllowed")
	}
}

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

// TestCheckAuthorizedForImpersonationHeaderValueCap pins the SAR fan-out cap:
// impersonation header values are counted exactly as the consumption loop
// matches them (case-insensitive Impersonate- prefix, every value of every
// key), and an over-cap request is refused with
// ErrTooManyImpersonationHeaderValues before any SubjectAccessReview is sent.
func TestCheckAuthorizedForImpersonationHeaderValueCap(t *testing.T) {
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	fullHeaders := http.Header{
		"Impersonate-User":             {"jjackson"},
		"Impersonate-Group":            {"group3"},
		"Impersonate-Uid":              {"1-2-3-4"},
		"Impersonate-Extra-Remoteaddr": {"1.2.3.4"},
	}

	tests := map[string]struct {
		max      int
		headers  http.Header
		expOver  bool
		expCalls int32
	}{
		"at the cap the full sequence still runs": {
			max:      4,
			headers:  fullHeaders,
			expOver:  false,
			expCalls: 4,
		},

		"one value over the cap is refused before any review": {
			max:      3,
			headers:  fullHeaders,
			expOver:  true,
			expCalls: 0,
		},

		"every value of a repeated header counts": {
			max: 3,
			headers: http.Header{
				"Impersonate-User":  {"jjackson"},
				"Impersonate-Group": {"group3", "group3", "group3"},
			},
			expOver:  true,
			expCalls: 0,
		},

		"case-variant duplicate keys cannot smuggle values past the cap": {
			max: 2,
			headers: http.Header{
				"Impersonate-User":  {"jjackson"},
				"Impersonate-Group": {"group3"},
				// Non-canonical duplicate of Impersonate-Group: the consumption
				// loop would consume it, so the count must include it too.
				"impersonate-group": {"group3"},
			},
			expOver:  true,
			expCalls: 0,
		},

		"unknown impersonation headers count toward the cap": {
			max: 2,
			headers: http.Header{
				"Impersonate-User":         {"jjackson"},
				"Impersonate-Doesnotexist": {"a", "b"},
			},
			expOver:  true,
			expCalls: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			reviewer := &countingFakeReviewer{FakeReviewer: fake.New(nil)}
			sar, err := New(reviewer, DefaultTimeout, 0, 0, tc.max, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			target, err := sar.CheckAuthorizedForImpersonation(
				(&http.Request{Header: tc.headers}).WithContext(testRequestContext()), requester)

			if tc.expOver {
				if !errors.Is(err, ErrTooManyImpersonationHeaderValues) {
					t.Errorf("error = %v, want errors.Is(ErrTooManyImpersonationHeaderValues)", err)
				}
				// A cap refusal is a request-shape rejection, not an
				// authorization denial or a backend failure: it must not select
				// the 403 or 500 handler paths.
				if errors.Is(err, ErrImpersonationNotAllowed) {
					t.Errorf("cap refusal must not classify as ErrImpersonationNotAllowed: %v", err)
				}
				if errors.Is(err, ErrCreateSubjectAccessReview) {
					t.Errorf("cap refusal must not classify as ErrCreateSubjectAccessReview: %v", err)
				}
				if target != nil {
					t.Errorf("target = %+v, want nil", target)
				}
			} else {
				if err != nil {
					t.Fatalf("CheckAuthorizedForImpersonation() error = %v, want nil", err)
				}
				if target == nil {
					t.Fatal("target = nil, want the impersonated user")
				}
			}

			if got := reviewer.calls.Load(); got != tc.expCalls {
				t.Errorf("SAR Create ran %d times, want %d", got, tc.expCalls)
			}
		})
	}
}

// TestNewRejectsNonPositiveMaxHeaderValues pins that the cap cannot be
// disabled by construction: every SAR costs a round trip, so an unbounded
// reviewer must not be constructible.
func TestNewRejectsNonPositiveMaxHeaderValues(t *testing.T) {
	for _, max := range []int{0, -1} {
		if _, err := New(fake.New(nil), DefaultTimeout, 0, 0, max, slog.New(slog.DiscardHandler)); err == nil {
			t.Errorf("New(maxHeaderValues=%d) error = nil, want error", max)
		}
	}
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

// impersonationHeaders returns a request header set with every impersonation
// kind (user, group, uid, extra) so that short-circuiting after the first
// blocked SAR check is observable.
func impersonationHeaders() http.Header {
	return http.Header{
		"Impersonate-User":             {"jjackson"},
		"Impersonate-Group":            {"group3"},
		"Impersonate-Uid":              {"1-2-3-4"},
		"Impersonate-Extra-Remoteaddr": {"1.2.3.4"},
	}
}

// sarResult carries the return of CheckAuthorizedForImpersonation back from the
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
	sar, err := New(reviewer, DefaultTimeout, 0, 0, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(testRequestContext())
	defer cancel()

	req := (&http.Request{Header: impersonationHeaders()}).WithContext(ctx)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.CheckAuthorizedForImpersonation(req, requester)
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
	sar, err := New(reviewer, DefaultTimeout, 0, 0, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(testRequestContext(), 50*time.Millisecond)
	defer cancel()

	req := (&http.Request{Header: impersonationHeaders()}).WithContext(ctx)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.CheckAuthorizedForImpersonation(req, requester)
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
	sar, err := New(reviewer, 50*time.Millisecond, 0, 0, DefaultMaxHeaderValues, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// context.Background() has no deadline, so only the configured timeout can
	// abort the blocked SAR call.
	req := (&http.Request{Header: impersonationHeaders()}).WithContext(testRequestContext())
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}

	done := make(chan sarResult, 1)
	go func() {
		target, err := sar.CheckAuthorizedForImpersonation(req, requester)
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

// newSARWithFakeReviewer builds a reviewer that logs through root as the sar
// component and answers every review with decide. Both cache TTLs are
// non-zero so the decision cache is live and hit/miss lookups are observable.
func newSARWithFakeReviewer(t *testing.T, root *slog.Logger, decide func(*v1.SubjectAccessReview) (*v1.SubjectAccessReview, error)) *SubjectAccessReview {
	t.Helper()

	s, err := New(&fnReviewer{fn: decide}, DefaultTimeout,
		DefaultAllowCacheTTL, DefaultDenyCacheTTL, DefaultMaxHeaderValues,
		logging.ForComponent(root, logging.ComponentSAR))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

// TestCacheHitAndLiveCheckEvents pins the records one authorization check
// emits: a cache lookup every time, a completed live review only when the
// cache did not answer, and never any cache key material.
func TestCacheHitAndLiveCheckEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	s := newSARWithFakeReviewer(t, root, allowAll)
	requester := &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
	ctx := logging.WithRequestID(logging.NewContext(context.Background(), root), "r1")

	if _, err := s.checkRbacImpersonationAuthorization(ctx, "users", "bob", requester); err != nil {
		t.Fatal(err)
	}
	miss := cap.ByEvent(logging.EventCacheSARLookup)
	if len(miss) != 1 || miss[0].String("cache_result") != "miss" {
		t.Fatalf("%v", miss)
	}
	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("decision") != "allow" || live.String("request_id") != "r1" || live["request_coalesced"] != false {
		t.Fatalf("%v", live)
	}
	if _, ok := live.Int("duration_ms"); !ok {
		t.Fatal("duration_ms missing")
	}

	if _, err := s.checkRbacImpersonationAuthorization(ctx, "users", "bob", requester); err != nil {
		t.Fatal(err)
	}
	hits := cap.ByEvent(logging.EventCacheSARLookup)
	if len(hits) != 2 || hits[1].String("cache_result") != "hit" || hits[1].String("decision") != "allow" {
		t.Fatalf("%v", hits)
	}
	if strings.Contains(cap.Raw(), `"spec"`) || strings.Contains(cap.Raw(), "SubjectAccessReviewSpec") {
		t.Fatal("cache key material logged")
	}
}
