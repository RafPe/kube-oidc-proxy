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
	"sync"
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

// newLoggingSAR builds a reviewer that logs through root as the sar component,
// so the records a check emits are observable with the given cache TTLs.
func newLoggingSAR(t *testing.T, root *slog.Logger, r clientazv1.SubjectAccessReviewInterface, sarTimeout, allowTTL, denyTTL time.Duration) *SubjectAccessReview {
	t.Helper()

	s, err := New(r, sarTimeout, allowTTL, denyTTL, DefaultMaxHeaderValues,
		logging.ForComponent(root, logging.ComponentSAR))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

// newSARWithFakeReviewer builds a logging reviewer that answers every review
// with decide. Both cache TTLs are non-zero so the decision cache is live and
// hit/miss lookups are observable.
func newSARWithFakeReviewer(t *testing.T, root *slog.Logger, decide func(*v1.SubjectAccessReview) (*v1.SubjectAccessReview, error)) *SubjectAccessReview {
	t.Helper()

	return newLoggingSAR(t, root, &fnReviewer{fn: decide}, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
}

// loggingTestRequester is the authenticated identity the logging tests ask
// their authorization questions on behalf of.
func loggingTestRequester() *user.DefaultInfo {
	return &user.DefaultInfo{Name: "mmosley", Groups: []string{"group1"}}
}

// TestCacheHitAndLiveCheckEvents pins the records one authorization check
// emits: a cache lookup every time, a completed live review only when the
// cache did not answer, and never any cache key material.
func TestCacheHitAndLiveCheckEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
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

// TestCacheBypassEvents covers the two ways a decision is never cacheable: the
// cache is switched off entirely, and the serialized spec is over the key-size
// cap. Both report cache_result=bypass and still complete a live review.
func TestCacheBypassEvents(t *testing.T) {
	tests := map[string]struct {
		allowTTL, denyTTL time.Duration
		name              string
	}{
		"a disabled cache bypasses every lookup": {
			allowTTL: 0,
			denyTTL:  0,
			name:     "bob",
		},
		"a spec over the key-size cap bypasses the cache": {
			allowTTL: DefaultAllowCacheTTL,
			denyTTL:  DefaultDenyCacheTTL,
			name:     strings.Repeat("a", maxCacheKeySize+1),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root, cap := logtest.New(t, 2)
			defer logtest.AssertRegistered(t, cap)
			s := newLoggingSAR(t, root, &fnReviewer{fn: allowAll}, DefaultTimeout, tc.allowTTL, tc.denyTTL)
			ctx := logging.WithRequestID(context.Background(), "r1")

			for i := range 2 {
				if _, err := s.checkRbacImpersonationAuthorization(ctx, "users", tc.name, loggingTestRequester()); err != nil {
					t.Fatalf("check %d: %v", i, err)
				}
			}

			lookups := cap.ByEvent(logging.EventCacheSARLookup)
			if len(lookups) != 2 {
				t.Fatalf("want 2 cache lookups, got %d: %v", len(lookups), lookups)
			}
			for i, rec := range lookups {
				if rec.String("cache_result") != "bypass" {
					t.Errorf("lookup %d: cache_result = %q, want bypass", i, rec.String("cache_result"))
				}
				if rec.String("decision") != "" {
					t.Errorf("lookup %d: bypass must not carry a decision, got %q", i, rec.String("decision"))
				}
			}

			// Nothing was cached, so both checks reached the API server.
			live := cap.ByEvent(logging.EventAuthzSARCompleted)
			if len(live) != 2 {
				t.Fatalf("want 2 completed reviews, got %d: %v", len(live), live)
			}
		})
	}
}

// TestCachedDenyDecisionEvents pins that a denial is cached and served like an
// allow: the second lookup is a hit carrying decision=deny, and no second
// review is run.
func TestCachedDenyDecisionEvents(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	reviewer := &fnReviewer{fn: denyAll}
	s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
	ctx := logging.WithRequestID(context.Background(), "r1")

	for i := range 2 {
		allowed, err := s.checkRbacImpersonationAuthorization(ctx, "groups", "group3", loggingTestRequester())
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		if allowed {
			t.Fatalf("check %d: want the review denied", i)
		}
	}

	lookups := cap.ByEvent(logging.EventCacheSARLookup)
	if len(lookups) != 2 || lookups[0].String("cache_result") != "miss" {
		t.Fatalf("want a miss then a hit, got %v", lookups)
	}
	if lookups[1].String("cache_result") != "hit" || lookups[1].String("decision") != "deny" {
		t.Fatalf("want hit with decision=deny, got %v", lookups[1])
	}

	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("decision") != "deny" || live.String("target_kind") != "group" {
		t.Fatalf("%v", live)
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Errorf("SAR Create ran %d times, want 1 (the deny must be cached)", got)
	}
}

// TestLiveCheckFailureEvents pins how a failed review is classified: an API
// server that answers with an error is an ERROR dependency failure, while the
// requester abandoning its own request is a DEBUG per-request condition a
// client must not be able to drive to ERROR at will.
func TestLiveCheckFailureEvents(t *testing.T) {
	t.Run("an apiserver error is an ERROR dependency failure", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		s := newLoggingSAR(t, root, &fnReviewer{fn: failWith(errReview)}, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
		ctx := logging.WithRequestID(context.Background(), "r1")

		if _, err := s.checkRbacImpersonationAuthorization(ctx, "users", "bob", loggingTestRequester()); !errors.Is(err, ErrCreateSubjectAccessReview) {
			t.Fatalf("error = %v, want errors.Is(ErrCreateSubjectAccessReview)", err)
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "ERROR" {
			t.Errorf("level = %q, want ERROR", rec.String("level"))
		}
		if rec.String("reason") != "authorization_dependency_error" {
			t.Errorf("reason = %q, want authorization_dependency_error", rec.String("reason"))
		}
		if !strings.Contains(rec.String("error_message"), errReview.Error()) {
			t.Errorf("error_message = %q, want it to carry the underlying error", rec.String("error_message"))
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
		// A failure is not an authorization answer.
		if got := cap.ByEvent(logging.EventAuthzSARCompleted); len(got) != 0 {
			t.Errorf("a failed review must not emit a completion record, got %v", got)
		}
	})

	t.Run("caller cancellation is a DEBUG client condition", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		ctx, cancel := context.WithCancel(logging.WithRequestID(context.Background(), "r1"))
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := s.checkRbacImpersonationAuthorization(ctx, "users", "bob", loggingTestRequester())
			done <- err
		}()

		select {
		case <-reviewer.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("SAR Create was never entered")
		}
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want errors.Is(context.Canceled)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after cancellation")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "DEBUG" {
			t.Errorf("level = %q, want DEBUG: a client disconnect must not raise an ERROR", rec.String("level"))
		}
		if rec.String("reason") != "client_canceled" {
			t.Errorf("reason = %q, want client_canceled", rec.String("reason"))
		}
		if rec.String("error_message") == "" {
			t.Error("error_message must still carry the bounded cause")
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
	})

	t.Run("the proxy's own authorization budget expiring is an ERROR dependency failure", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		s := newLoggingSAR(t, root, reviewer, 50*time.Millisecond, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		h := http.Header{}
		h.Set("Impersonate-User", "bob")
		// The requester never goes away: the only deadline that can expire is
		// the proxy's own SAR budget, which means the API server did not answer
		// in time. That is a dependency failure, not a client condition.
		req := (&http.Request{Header: h}).WithContext(logging.WithRequestID(context.Background(), "r1"))

		done := make(chan error, 1)
		go func() {
			_, err := s.CheckAuthorizedForImpersonation(req, loggingTestRequester())
			done <- err
		}()

		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v, want errors.Is(context.DeadlineExceeded)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after the authorization budget expired")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "ERROR" {
			t.Errorf("level = %q, want ERROR: a slow API server is a dependency failure", rec.String("level"))
		}
		if rec.String("reason") != "authorization_dependency_error" {
			t.Errorf("reason = %q, want authorization_dependency_error", rec.String("reason"))
		}
		if !strings.Contains(rec.String("error_message"), "timed out") {
			t.Errorf("error_message = %q, want it to say the subject access review timed out", rec.String("error_message"))
		}
		if rec.String("request_id") != "r1" {
			t.Errorf("request_id = %q, want r1", rec.String("request_id"))
		}
	})

	t.Run("a client disconnect on the request path stays a DEBUG client condition", func(t *testing.T) {
		root, cap := logtest.New(t, 2)
		defer logtest.AssertRegistered(t, cap)
		reviewer := &blockingReviewer{entered: make(chan struct{}, 1)}
		// A generous authorization budget, so the only deadline that can fire is
		// the requester's own. This is the production path, where the derived
		// context carries the parent to classify against; the direct-call subtest
		// above exercises the fallback for a check with no recorded parent.
		s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)

		reqCtx, cancel := context.WithCancel(logging.WithRequestID(context.Background(), "r1"))
		defer cancel()

		h := http.Header{}
		h.Set("Impersonate-User", "bob")
		req := (&http.Request{Header: h}).WithContext(reqCtx)

		done := make(chan error, 1)
		go func() {
			_, err := s.CheckAuthorizedForImpersonation(req, loggingTestRequester())
			done <- err
		}()

		select {
		case <-reviewer.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("SAR Create was never entered")
		}
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want errors.Is(context.Canceled)", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the check never returned after the client disconnected")
		}

		rec := cap.Only(t, logging.EventAuthzSARFailed)
		if rec.String("level") != "DEBUG" {
			t.Errorf("level = %q, want DEBUG: a client disconnect must not raise an ERROR", rec.String("level"))
		}
		if rec.String("reason") != "client_canceled" {
			t.Errorf("reason = %q, want client_canceled", rec.String("reason"))
		}
		if strings.Contains(rec.String("error_message"), "timed out") {
			t.Errorf("error_message = %q, must not blame the API server for a client disconnect", rec.String("error_message"))
		}
	})
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

// TestCoalescedLiveCheckEvent pins request_coalesced=true: two callers asking
// the identical authorization question share one SubjectAccessReview, and each
// reports its own completion record so the sharing is queryable per request.
func TestCoalescedLiveCheckEvent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	reviewer := &gateReviewer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := newLoggingSAR(t, root, reviewer, DefaultTimeout, DefaultAllowCacheTTL, DefaultDenyCacheTTL)
	ctx := logging.WithRequestID(context.Background(), "r1")

	check := func(wg *sync.WaitGroup, err *error) {
		defer wg.Done()
		_, e := s.checkRbacImpersonationAuthorization(ctx, "users", "bob", loggingTestRequester())
		*err = e
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)

	wg.Add(1)
	go check(&wg, &errs[0])

	select {
	case <-reviewer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("SAR Create was never entered")
	}

	wg.Add(1)
	go check(&wg, &errs[1])

	// Give the second caller time to join the in-flight call before it answers.
	time.Sleep(300 * time.Millisecond)
	close(reviewer.release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := reviewer.calls.Load(); got != 1 {
		t.Fatalf("SAR Create ran %d times, want 1 (the two callers must share one review)", got)
	}

	live := cap.ByEvent(logging.EventAuthzSARCompleted)
	if len(live) != 2 {
		t.Fatalf("want one completion record per caller, got %d: %v", len(live), live)
	}
	for i, rec := range live {
		if rec["request_coalesced"] != true {
			t.Errorf("record %d: request_coalesced = %v, want true", i, rec["request_coalesced"])
		}
		if rec.String("decision") != "allow" || rec.String("target_kind") != "user" {
			t.Errorf("record %d: %v", i, rec)
		}
	}
}

// TestImpersonationResolvedEvent pins the record closing a whole allowed
// impersonation sequence: the user target it resolved to, and nothing else.
func TestImpersonationResolvedEvent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	defer logtest.AssertRegistered(t, cap)
	s := newSARWithFakeReviewer(t, root, allowAll)

	h := http.Header{}
	h.Set("Impersonate-User", "bob")
	req := (&http.Request{Header: h}).WithContext(logging.WithRequestID(context.Background(), "r1"))

	target, err := s.CheckAuthorizedForImpersonation(req, loggingTestRequester())
	if err != nil {
		t.Fatalf("CheckAuthorizedForImpersonation() error = %v", err)
	}
	if target == nil || target.GetName() != "bob" {
		t.Fatalf("target = %v, want the impersonated user bob", target)
	}

	rec := cap.Only(t, logging.EventAuthzImpersonationResolved)
	if rec.String("target_kind") != "user" {
		t.Errorf("target_kind = %q, want user", rec.String("target_kind"))
	}
	if rec.String("target_name") != "bob" {
		t.Errorf("target_name = %q, want bob", rec.String("target_name"))
	}
	if rec.String("request_id") != "r1" {
		t.Errorf("request_id = %q, want r1", rec.String("request_id"))
	}

	live := cap.Only(t, logging.EventAuthzSARCompleted)
	if live.String("target_kind") != "user" {
		t.Errorf("completed target_kind = %q, want user", live.String("target_kind"))
	}
}

// TestTargetKind pins the closed target_kind value set at its source. The four
// caller forms are internal constants today, so nothing user-controlled reaches
// this function -- but the mapping is what keeps target_kind a closed set, and
// a resource nobody anticipated must report that it was not recognised rather
// than borrow the label of the extras it is not.
func TestTargetKind(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"users":             "user",
		"groups":            "group",
		"uids":              "uid",
		"userextras/scopes": "extra",
		"userextras/":       "extra",
		"pods":              "unknown",
		"":                  "unknown",
		"userextra/scopes":  "unknown",
		"serviceaccounts":   "unknown",
		"USERS":             "unknown",
	}

	for resource, want := range tests {
		resource, want := resource, want
		t.Run(resource, func(t *testing.T) {
			t.Parallel()
			if got := targetKind(resource); got != want {
				t.Errorf("targetKind(%q) = %q, want %q", resource, got, want)
			}
		})
	}
}
