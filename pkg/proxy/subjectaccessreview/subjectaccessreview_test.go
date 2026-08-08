// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	clientazv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

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

	testReviewer, _ := New(fake.New(test.expErrorRbac), DefaultTimeout)

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
		&http.Request{
			Header: headers,
		}, test.requester)

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
	sar, err := New(reviewer, DefaultTimeout)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
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
	sar, err := New(reviewer, DefaultTimeout)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
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
	sar, err := New(reviewer, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// context.Background() has no deadline, so only the configured timeout can
	// abort the blocked SAR call.
	req := (&http.Request{Header: impersonationHeaders()}).WithContext(context.Background())
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
