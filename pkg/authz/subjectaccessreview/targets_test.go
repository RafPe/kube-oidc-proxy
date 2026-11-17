// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"testing"

	azv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"
)

// attributeRecorder answers every review with decide and records the
// resource attributes of each, in the order they were asked.
type attributeRecorder struct {
	mu    sync.Mutex
	asked []azv1.ResourceAttributes
}

func (r *attributeRecorder) reviewer(decide func(azv1.ResourceAttributes) bool) *fnReviewer {
	return &fnReviewer{fn: func(req *azv1.SubjectAccessReview) (*azv1.SubjectAccessReview, error) {
		attrs := *req.Spec.ResourceAttributes
		r.mu.Lock()
		r.asked = append(r.asked, attrs)
		r.mu.Unlock()
		req.Status = azv1.SubjectAccessReviewStatus{Allowed: decide(attrs)}
		return req, nil
	}}
}

func allowAllAttributes(azv1.ResourceAttributes) bool { return true }

// newUncachedAuthorizer returns an Authorizer that sends every review to
// client, so each test sees every question it causes.
func newUncachedAuthorizer(client *fnReviewer) *Authorizer {
	return New(client, Config{}, slog.New(slog.DiscardHandler))
}

func impersonationRequest(headers http.Header) *http.Request {
	return (&http.Request{Header: headers}).WithContext(testRequestContext())
}

// TestServiceAccountTargetReview pins that an Impersonate-User naming a
// service account is reviewed the way kube-apiserver reviews it: as
// serviceaccounts/<name> in <namespace> when serviceaccount.SplitUsername
// accepts it, and as users/<name> otherwise.
func TestServiceAccountTargetReview(t *testing.T) {
	tests := map[string]struct {
		name string
		want azv1.ResourceAttributes
	}{
		"a service account is reviewed in its namespace": {
			name: "system:serviceaccount:team-a:deployer",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "serviceaccounts", Namespace: "team-a", Name: "deployer"},
		},
		"a plain user is reviewed as a user": {
			name: "jane",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "jane"},
		},
		"a name with no account part is a user": {
			name: "system:serviceaccount:team-a",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount:team-a"},
		},
		"a name with too many parts is a user": {
			name: "system:serviceaccount:team-a:deployer:extra",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount:team-a:deployer:extra"},
		},
		"an invalid namespace is a user": {
			name: "system:serviceaccount:Team_A:deployer",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount:Team_A:deployer"},
		},
		"an empty namespace is a user": {
			name: "system:serviceaccount::deployer",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount::deployer"},
		},
		"an invalid account name is a user": {
			name: "system:serviceaccount:team-a:Deployer!",
			want: azv1.ResourceAttributes{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount:team-a:Deployer!"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &attributeRecorder{}
			a := newUncachedAuthorizer(rec.reviewer(allowAllAttributes))

			_, target, err := a.ConsumeImpersonation(impersonationRequest(http.Header{"Impersonate-User": {tc.name}}), cacheTestRequester())
			if err != nil {
				t.Fatalf("ConsumeImpersonation() error = %v", err)
			}
			if target.GetName() != tc.name {
				t.Errorf("resolved name = %q, want %q", target.GetName(), tc.name)
			}
			if want := []azv1.ResourceAttributes{tc.want}; !reflect.DeepEqual(rec.asked, want) {
				t.Errorf("reviews asked = %+v, want %+v", rec.asked, want)
			}
		})
	}
}

// TestUsersGrantDoesNotAuthorizeServiceAccount pins the authorization
// consequence: a requester allowed to impersonate users but not service
// accounts is refused a service account, and a namespaced service-account
// grant is honoured.
func TestUsersGrantDoesNotAuthorizeServiceAccount(t *testing.T) {
	const sa = "system:serviceaccount:team-a:deployer"
	req := func() *http.Request { return impersonationRequest(http.Header{"Impersonate-User": {sa}}) }

	usersOnly := newUncachedAuthorizer((&attributeRecorder{}).reviewer(func(attrs azv1.ResourceAttributes) bool {
		return attrs.Resource == "users"
	}))
	_, _, err := usersOnly.ConsumeImpersonation(req(), cacheTestRequester())
	want := &ImpersonationAuthError{Requester: "mmosley", Kind: TargetUser, Target: sa}
	if !reflect.DeepEqual(err, want) {
		t.Fatalf("users-only grant: error = %v, want %v", err, want)
	}

	saInNamespace := newUncachedAuthorizer((&attributeRecorder{}).reviewer(func(attrs azv1.ResourceAttributes) bool {
		return attrs.Resource == "serviceaccounts" && attrs.Namespace == "team-a" && attrs.Name == "deployer"
	}))
	_, target, err := saInNamespace.ConsumeImpersonation(req(), cacheTestRequester())
	if err != nil || target.GetName() != sa {
		t.Fatalf("service-account grant: target = %v, error = %v, want %q allowed", target, err, sa)
	}
}

// TestExtraKeyDecoding pins that an Impersonate-Extra- key is lower-cased and
// then percent-unescaped exactly as kube-apiserver decodes it, and that the
// review and the resolved identity both use the decoded key.
func TestExtraKeyDecoding(t *testing.T) {
	tests := map[string]struct {
		header string
		want   string
	}{
		"a plain key is lower-cased":           {header: "Impersonate-Extra-Scopes", want: "scopes"},
		"an escaped slash is decoded":          {header: "Impersonate-Extra-Example.com%2fscope", want: "example.com/scope"},
		"an upper-case escape is decoded":      {header: "Impersonate-Extra-Example.com%2Fscope", want: "example.com/scope"},
		"an escaped percent is decoded":        {header: "Impersonate-Extra-A%25b", want: "a%b"},
		"a malformed escape keeps the raw key": {header: "Impersonate-Extra-Foo%zz", want: "foo%zz"},
		"an escaped control byte is decoded":   {header: "Impersonate-Extra-A%0ab", want: "a\nb"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &attributeRecorder{}
			a := newUncachedAuthorizer(rec.reviewer(allowAllAttributes))

			_, target, err := a.ConsumeImpersonation(impersonationRequest(http.Header{
				"Impersonate-User": {"jane"},
				tc.header:          {"v"},
			}), cacheTestRequester())
			if err != nil {
				t.Fatalf("ConsumeImpersonation() error = %v", err)
			}
			if want := map[string][]string{tc.want: {"v"}}; !reflect.DeepEqual(target.GetExtra(), want) {
				t.Errorf("resolved extra = %v, want %v", target.GetExtra(), want)
			}
			wantReview := azv1.ResourceAttributes{Verb: "impersonate", Group: "authentication.k8s.io",
				Resource: "userextras", Subresource: tc.want, Name: "v"}
			if len(rec.asked) != 2 || rec.asked[1] != wantReview {
				t.Errorf("reviews asked = %+v, want the user then %+v", rec.asked, wantReview)
			}
		})
	}
}

// TestDecodedExtraKeySurvivesForwarding pins the round trip: client-go's
// impersonating round tripper encodes the resolved key again, and the API
// server's decoding (extraKeyFromHeader mirrors it) yields the same key.
func TestDecodedExtraKeySurvivesForwarding(t *testing.T) {
	for _, key := range []string{"example.com/scope", "a%b", "scopes"} {
		var sent http.Header
		rt := transport.NewImpersonatingRoundTripper(transport.ImpersonationConfig{
			UserName: "jane",
			Extra:    map[string][]string{key: {"v"}},
		}, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			sent = req.Header
			return &http.Response{StatusCode: http.StatusOK}, nil
		}))
		req, err := http.NewRequest(http.MethodGet, "https://apiserver.example", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}

		var got []string
		for header := range sent {
			if hasPrefixFold(header, transport.ImpersonateUserExtraHeaderPrefix) {
				got = append(got, extraKeyFromHeader(header))
			}
		}
		if want := []string{key}; !reflect.DeepEqual(got, want) {
			t.Errorf("key %q forwarded and decoded as %q, want %q", key, got, want)
		}
	}
}

// TestReviewOrderIsFixed pins that targets are reviewed in one order whatever
// order the header map iterates in -- the user, the groups in header order,
// the extras by key, then the uid -- so a request refused on several targets
// is always refused on the same one. The request is resolved repeatedly
// because a map-order dependence would only show on some iterations.
func TestReviewOrderIsFixed(t *testing.T) {
	headers := func() http.Header {
		return http.Header{
			"Impersonate-User":        {"jane"},
			"Impersonate-Uid":         {"1234"},
			"Impersonate-Group":       {"g2", "g1"},
			"Impersonate-Extra-Zeta":  {"z"},
			"Impersonate-Extra-Alpha": {"a2", "a1"},
			"Impersonate-Extra-Mid":   {"m"},
		}
	}
	wantOrder := []azv1.ResourceAttributes{
		{Verb: "impersonate", Resource: "users", Name: "jane"},
		{Verb: "impersonate", Resource: "groups", Name: "g2"},
		{Verb: "impersonate", Resource: "groups", Name: "g1"},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "userextras", Subresource: "alpha", Name: "a2"},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "userextras", Subresource: "alpha", Name: "a1"},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "userextras", Subresource: "mid", Name: "m"},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "userextras", Subresource: "zeta", Name: "z"},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "uids", Name: "1234"},
	}

	for i := range 20 {
		rec := &attributeRecorder{}
		a := newUncachedAuthorizer(rec.reviewer(allowAllAttributes))
		if _, _, err := a.ConsumeImpersonation(impersonationRequest(headers()), cacheTestRequester()); err != nil {
			t.Fatalf("iteration %d: ConsumeImpersonation() error = %v", i, err)
		}
		if !reflect.DeepEqual(rec.asked, wantOrder) {
			t.Fatalf("iteration %d: reviews asked = %+v, want %+v", i, rec.asked, wantOrder)
		}

		// Only the user is allowed: every other target is refused, and the
		// refusal always names the first group.
		denyAll := newUncachedAuthorizer((&attributeRecorder{}).reviewer(func(attrs azv1.ResourceAttributes) bool {
			return attrs.Resource == "users"
		}))
		_, _, err := denyAll.ConsumeImpersonation(impersonationRequest(headers()), cacheTestRequester())
		var denial *ImpersonationAuthError
		if !errors.As(err, &denial) || denial.Kind != TargetGroup || denial.Target != "g2" {
			t.Fatalf("iteration %d: error = %v, want the denial of group g2", i, err)
		}
	}
}

// TestResolvedIdentityKeepsHeaderOrder pins that the resolved identity lists
// groups and extra values in the order the request sent them.
func TestResolvedIdentityKeepsHeaderOrder(t *testing.T) {
	a := newUncachedAuthorizer((&attributeRecorder{}).reviewer(allowAllAttributes))
	_, target, err := a.ConsumeImpersonation(impersonationRequest(http.Header{
		"Impersonate-User":       {"jane"},
		"Impersonate-Group":      {"g2", "g1"},
		"Impersonate-Extra-Keys": {"b", "a"},
	}), cacheTestRequester())
	if err != nil {
		t.Fatalf("ConsumeImpersonation() error = %v", err)
	}
	want := &user.DefaultInfo{Name: "jane", Groups: []string{"g2", "g1"}, Extra: map[string][]string{"keys": {"b", "a"}}}
	if !reflect.DeepEqual(target, want) {
		t.Errorf("resolved identity = %+v, want %+v", target, want)
	}
}

// TestServiceAccountTargetGroups pins the groups a service-account target
// resolves to, as kube-apiserver's impersonation filter builds them: with no
// Impersonate-Group, the account's fixed groups, unreviewed; with groups
// named, exactly the reviewed groups and nothing else. A user target never
// gets groups it did not ask for.
func TestServiceAccountTargetGroups(t *testing.T) {
	tests := map[string]struct {
		headers    http.Header
		wantGroups []string
		wantAsked  []azv1.ResourceAttributes
	}{
		"a service account without groups gets its fixed groups": {
			headers:    http.Header{"Impersonate-User": {"system:serviceaccount:team-a:deployer"}},
			wantGroups: []string{"system:serviceaccounts", "system:serviceaccounts:team-a"},
			wantAsked: []azv1.ResourceAttributes{
				{Verb: "impersonate", Resource: "serviceaccounts", Namespace: "team-a", Name: "deployer"},
			},
		},
		"a service account with groups gets only the reviewed groups": {
			headers: http.Header{
				"Impersonate-User":  {"system:serviceaccount:team-a:deployer"},
				"Impersonate-Group": {"ops"},
			},
			wantGroups: []string{"ops"},
			wantAsked: []azv1.ResourceAttributes{
				{Verb: "impersonate", Resource: "serviceaccounts", Namespace: "team-a", Name: "deployer"},
				{Verb: "impersonate", Resource: "groups", Name: "ops"},
			},
		},
		"a malformed service-account name is a user and gets no groups": {
			headers:    http.Header{"Impersonate-User": {"system:serviceaccount:team-a"}},
			wantGroups: []string{},
			wantAsked: []azv1.ResourceAttributes{
				{Verb: "impersonate", Resource: "users", Name: "system:serviceaccount:team-a"},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &attributeRecorder{}
			a := newUncachedAuthorizer(rec.reviewer(allowAllAttributes))

			_, target, err := a.ConsumeImpersonation(impersonationRequest(tc.headers), cacheTestRequester())
			if err != nil {
				t.Fatalf("ConsumeImpersonation() error = %v", err)
			}
			if !reflect.DeepEqual(target.GetGroups(), tc.wantGroups) {
				t.Errorf("resolved groups = %q, want %q", target.GetGroups(), tc.wantGroups)
			}
			if !reflect.DeepEqual(rec.asked, tc.wantAsked) {
				t.Errorf("reviews asked = %+v, want %+v", rec.asked, tc.wantAsked)
			}
		})
	}
}

// TestForwardedExtraKey pins the round trip the proxy checks every decoded
// extra key against: what the API server receives once client-go has encoded
// the key into a header name and the API server has decoded it again.
func TestForwardedExtraKey(t *testing.T) {
	tests := map[string]struct {
		key  string
		want string
	}{
		"a plain lower-case key":         {key: "scopes", want: "scopes"},
		"a key with a slash":             {key: "example.com/scope", want: "example.com/scope"},
		"a key with a percent":           {key: "a%b", want: "a%b"},
		"a key with a control byte":      {key: "a\nb", want: "a\nb"},
		"a key with a non-ASCII rune":    {key: "zürich", want: "zürich"},
		"upper case arrives lower-cased": {key: "Abc", want: "abc"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := forwardedExtraKey(tc.key); got != tc.want {
				t.Errorf("forwardedExtraKey(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// TestUnforwardableExtraKeyIsRefusedBeforeAnyReview pins that an extra key
// which would reach the API server under another name is refused on the
// request's shape, before any SubjectAccessReview, while keys that round-trip
// are reviewed as usual.
func TestUnforwardableExtraKeyIsRefusedBeforeAnyReview(t *testing.T) {
	tests := map[string]struct {
		header  string
		refused bool
	}{
		"a plain key passes":                  {header: "Impersonate-Extra-Scopes"},
		"an escaped slash passes":             {header: "Impersonate-Extra-Example.com%2Fscope"},
		"a malformed escape kept raw passes":  {header: "Impersonate-Extra-Foo%zz"},
		"an escape decoding to upper case":    {header: "Impersonate-Extra-%41bc", refused: true},
		"an escaped upper case after a slash": {header: "Impersonate-Extra-Example.com%2F%53cope", refused: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := (&attributeRecorder{}).reviewer(allowAllAttributes)
			a := newUncachedAuthorizer(client)

			_, _, err := a.ConsumeImpersonation(impersonationRequest(http.Header{
				"Impersonate-User": {"jane"},
				tc.header:          {"v"},
			}), cacheTestRequester())

			if !tc.refused {
				if err != nil {
					t.Fatalf("ConsumeImpersonation() error = %v, want the key accepted", err)
				}
				return
			}
			if !errors.Is(err, ErrUnforwardableExtraKey) {
				t.Fatalf("ConsumeImpersonation() error = %v, want ErrUnforwardableExtraKey", err)
			}
			if errors.Is(err, ErrImpersonationNotAllowed) {
				t.Errorf("a shape refusal must not classify as an authorization denial: %v", err)
			}
			if got := client.calls.Load(); got != 0 {
				t.Errorf("%d SubjectAccessReviews sent for a request refused on its shape", got)
			}
		})
	}
}
