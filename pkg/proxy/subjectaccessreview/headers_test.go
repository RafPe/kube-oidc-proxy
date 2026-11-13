// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview/fake"
)

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
			sar, err := New(reviewer, Config{Timeout: DefaultTimeout, AllowCacheTTL: 0, DenyCacheTTL: 0, MaxHeaderValues: tc.max}, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			target, err := sar.ResolveImpersonation(
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
					t.Fatalf("ResolveImpersonation() error = %v, want nil", err)
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

// TestNewSettlesTheMaxHeaderValues pins that a zero or negative cap means
// DefaultMaxHeaderValues, the same rule Timeout follows: the cap cannot be
// disabled by construction, because every SAR costs a round trip.
func TestNewSettlesTheMaxHeaderValues(t *testing.T) {
	for name, test := range map[string]struct {
		max, exp int
	}{
		"zero means the default":     {0, DefaultMaxHeaderValues},
		"negative means the default": {-1, DefaultMaxHeaderValues},
		"a positive value is kept":   {3, 3},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New(fake.New(nil), Config{MaxHeaderValues: test.max}, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if s.maxHeaderValues != test.exp {
				t.Errorf("maxHeaderValues = %d, want %d", s.maxHeaderValues, test.exp)
			}
		})
	}
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

// TestHasImpersonationHeaders pins the predicate that decides whether a
// request is authorized through ResolveImpersonation at all: any
// Impersonate- prefixed key, however the client spelled it, counts, including
// kinds this proxy does not know, so nothing impersonation-shaped is ever
// forwarded unexamined.
func TestHasImpersonationHeaders(t *testing.T) {
	noImpersonation := []http.Header{
		{},
		{"foo": {"bar", "foo"}},
		{"impersonation": {"bar"}, "impersonate": {"bar"}},
		{"Impersonate": {"bar", "foo"}},
		{"-impersonate-Extra-": {"bar", "foo"}},
		{"a": {"Impersonate-User"}, "b": {"Impersonate-Group"}, "c": {"Impersonate-Extra-"}},
	}
	hasImpersonation := []http.Header{
		{"Impersonate-User": {"bar", "foo"}},
		{"impersonate-user": {"bar", "foo"}},
		{"impersonate-user": nil},
		{"impersonate-group": nil},
		{"impersonate-Group": {"bar", "foo"}},
		{"impersonate-Extra-foobar___foo": {"bar", "foo"}},
		{"impersonate-Extra-": {"bar", "foo"}},
		{"impersonate-Extra-": {"bar", "foo"}, "impersonate-Group": {"bar", "foo"}, "impersonate-User": {"bar"}},
		{"impersonate-Extra-": {"bar", "foo"}, "foo": {"bar", "foo"}, "bar": {"bar"}},
		// A kind this proxy does not know is still an impersonation attempt.
		{"impersonate-Extra": {"bar", "foo"}},
	}

	for _, h := range noImpersonation {
		if HasImpersonationHeaders(h) {
			t.Errorf("HasImpersonationHeaders(%v) = true, want false", h)
		}
	}
	for _, h := range hasImpersonation {
		if !HasImpersonationHeaders(h) {
			t.Errorf("HasImpersonationHeaders(%v) = false, want true", h)
		}
	}
}

// TestStripImpersonationHeaders pins that the forwarded request keeps every
// other header and loses every impersonation header, and that the caller's
// map is left alone.
func TestStripImpersonationHeaders(t *testing.T) {
	in := http.Header{
		"Impersonate-User":      {"bob"},
		"impersonate-group":     {"a", "b"},
		"Impersonate-Extra-Foo": {"bar"},
		"Authorization":         {"Bearer x"},
		"Accept":                {"application/json", "*/*"},
	}

	out := StripImpersonationHeaders(in)

	want := http.Header{
		"Authorization": {"Bearer x"},
		"Accept":        {"application/json", "*/*"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("StripImpersonationHeaders = %v, want %v", out, want)
	}
	if len(in) != 5 {
		t.Errorf("caller's headers were modified: %v", in)
	}
	out["Accept"][0] = "changed"
	if in["Accept"][0] != "application/json" {
		t.Error("stripped headers share value slices with the caller")
	}
}

// TestUnknownImpersonationHeaderIsRefusedBeforeAnyReview pins that an unknown
// Impersonate- kind is refused with its sentinel before a single
// SubjectAccessReview is sent, whatever else the request asks for and whatever
// order the header map iterates in.
func TestUnknownImpersonationHeaderIsRefusedBeforeAnyReview(t *testing.T) {
	for i := 0; i < 20; i++ {
		reviewer := &countingFakeReviewer{FakeReviewer: fake.New(nil)}
		sar, err := New(reviewer, Config{Timeout: DefaultTimeout, MaxHeaderValues: DefaultMaxHeaderValues}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		req := (&http.Request{Header: http.Header{
			"Impersonate-User":  {"bob"},
			"Impersonate-Group": {"a", "b"},
			"Impersonate-Foo":   {"x"},
		}}).WithContext(testRequestContext())

		_, err = sar.ResolveImpersonation(req, &user.DefaultInfo{Name: "alice"})
		if !errors.Is(err, ErrUnknownImpersonationHeader) {
			t.Fatalf("error = %v, want ErrUnknownImpersonationHeader", err)
		}
		if got := reviewer.calls.Load(); got != 0 {
			t.Fatalf("%d SubjectAccessReviews sent for a request refused on its shape", got)
		}
	}
}
