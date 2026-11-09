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
	"testing"
	"time"

	v1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
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
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: TargetUser, Target: "jjackson-x"},
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
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: TargetGroup, Target: "group4"},
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
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: TargetExtra, ExtraKey: "remoteaddr", Target: "1.2.3.5"},
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
			expErr:                   &ImpersonationAuthError{Requester: "mmosley", Kind: TargetUID, Target: "1-2-3-5"},
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
			expErr:                   fmt.Errorf("%w: %q", ErrUnknownImpersonationHeader, "Impersonate-doesnotexist"),
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

	testReviewer, _ := New(fake.New(test.expErrorRbac), Config{Timeout: DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))

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
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: TargetUser, Target: "a-user"},
			expMsg: "mmosley is not allowed to impersonate user 'a-user'",
		},
		"group": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: TargetGroup, Target: "a-group"},
			expMsg: "mmosley is not allowed to impersonate group 'a-group'",
		},
		"uid": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: TargetUID, Target: "bar"},
			expMsg: "mmosley is not allowed to impersonate uid 'bar'",
		},
		"extra info": {
			err:    &ImpersonationAuthError{Requester: "mmosley", Kind: TargetExtra, ExtraKey: "foo", Target: "bar"},
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
	if errors.Is(ErrNoImpersonationUser, ErrImpersonationNotAllowed) {
		t.Error("ErrNoImpersonationUser must not classify as ErrImpersonationNotAllowed")
	}
	if errors.Is(errors.New("boom"), ErrImpersonationNotAllowed) {
		t.Error("arbitrary error must not classify as ErrImpersonationNotAllowed")
	}
}

// TestNewSettlesTheTimeout pins that a zero or negative budget means
// DefaultTimeout. Passed through as is, it would give every review an already
// expired context and deny every impersonating request.
func TestNewSettlesTheTimeout(t *testing.T) {
	for name, test := range map[string]struct {
		timeout, exp time.Duration
	}{
		"zero means the default":     {0, DefaultTimeout},
		"negative means the default": {-time.Second, DefaultTimeout},
		"a positive value is kept":   {2 * time.Second, 2 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New(fake.New(nil), Config{Timeout: test.timeout, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if s.sarTimeout != test.exp {
				t.Errorf("sarTimeout = %s, want %s", s.sarTimeout, test.exp)
			}
		})
	}
}

// TestNewRequiresLogger pins that the logger is a required collaborator, as it
// is for every constructor in the module: a nil one fails at construction.
func TestNewRequiresLogger(t *testing.T) {
	if _, err := New(fake.New(nil), Config{MaxHeaderValues: DefaultMaxHeaderValues}, nil); err == nil {
		t.Fatal("New(nil logger) error = nil, want an error")
	}
}
