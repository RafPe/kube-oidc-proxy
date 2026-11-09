// Copyright Jetstack Ltd. See LICENSE for details.
package subjectaccessreview

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"
)

// The resource attributes a SubjectAccessReview asks about for impersonation,
// exactly as kube-apiserver's impersonation filter builds them. Users,
// service accounts and groups are core-group resources; uids and user extras
// live in authentication.k8s.io, so a review without that group checks a
// resource no RBAC rule grants.
const (
	impersonateVerb   = "impersonate"
	authenticationAPI = "authentication.k8s.io"

	resourceUsers           = "users"
	resourceServiceAccounts = "serviceaccounts"
	resourceGroups          = "groups"
	resourceUIDs            = "uids"
	resourceUserExtras      = "userextras"
)

// impersonationTarget is one identity attribute a request asks to impersonate:
// the resource attributes of the SubjectAccessReview that authorizes it, the
// kind the record reports it under, and the value being asked for.
type impersonationTarget struct {
	kind        TargetKind
	group       string
	resource    string
	subresource string
	namespace   string

	// name is the resource name the review asks about. It is the requested
	// value itself, except for a service account, where it is the account's
	// name within namespace.
	name string

	// value is the identity value as the request asked for it: the user name,
	// group, uid or extra value.
	value string

	// extraKey is the extra's key when kind is TargetExtra.
	extraKey string

	// serviceAccount is set for a TargetUser whose name is a valid
	// service-account username; namespace is then the account's namespace.
	serviceAccount bool
}

// userImpersonation asks about an Impersonate-User value. A name of the form
// system:serviceaccount:<namespace>:<name>, valid as serviceaccount.SplitUsername
// judges it, is a service account and is reviewed as serviceaccounts/<name>
// in <namespace>, the way kube-apiserver reviews it (and parseImpersonation
// gives it the service-account groups when the request names none); every
// other name,
// including a malformed service-account name, is reviewed as users/<name>.
func userImpersonation(name string) impersonationTarget {
	if namespace, account, err := serviceaccount.SplitUsername(name); err == nil {
		return impersonationTarget{kind: TargetUser, resource: resourceServiceAccounts,
			namespace: namespace, name: account, value: name, serviceAccount: true}
	}
	return impersonationTarget{kind: TargetUser, resource: resourceUsers, name: name, value: name}
}

func groupImpersonation(name string) impersonationTarget {
	return impersonationTarget{kind: TargetGroup, resource: resourceGroups, name: name, value: name}
}

func uidImpersonation(uid string) impersonationTarget {
	return impersonationTarget{kind: TargetUID, group: authenticationAPI, resource: resourceUIDs, name: uid, value: uid}
}

// extraImpersonation asks about one value of a user extra. key is the extra's
// key as extraKeyFromHeader decodes it.
func extraImpersonation(key, value string) impersonationTarget {
	return impersonationTarget{kind: TargetExtra, group: authenticationAPI, resource: resourceUserExtras,
		subresource: key, name: value, value: value, extraKey: key}
}

// denial is the typed error a refused target is reported through.
func (t impersonationTarget) denial(requester user.Info) error {
	return &ImpersonationAuthError{
		Requester: requester.GetName(),
		Kind:      t.kind,
		Target:    t.value,
		ExtraKey:  t.extraKey,
	}
}

// parseImpersonation reads the impersonation headers into the identity they
// ask for and the targets that must each be authorized before it is used, in
// review order. It refuses a request whose headers ask for nothing to
// impersonate a user with, or that carries an impersonation header of a kind
// this proxy does not know.
//
// Header keys are visited in sorted order, so the targets, and the order
// values of one kind accumulate in, never depend on map iteration.
func parseImpersonation(headers http.Header) (*user.DefaultInfo, []impersonationTarget, error) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		if !isImpersonationHeader(key) {
			continue
		}
		if !isKnownImpersonationHeader(key) {
			return nil, nil, fmt.Errorf("%w: %q", ErrUnknownImpersonationHeader, key)
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)

	// Groups, uids and extras refine a user; without one there is nothing to
	// impersonate.
	if headers.Get(transport.ImpersonateUserHeader) == "" {
		return nil, nil, ErrNoImpersonationUser
	}

	targetUser := &user.DefaultInfo{
		Groups: make([]string, 0),
		Extra:  map[string][]string{},
	}
	var userTarget, uidTarget impersonationTarget
	var groupTargets, extraTargets []impersonationTarget
	for _, key := range keys {
		values := headers[key]
		switch {
		case strings.EqualFold(key, transport.ImpersonateUserHeader):
			if targetUser.Name == "" && len(values) > 0 {
				userTarget = userImpersonation(values[0])
				targetUser.Name = userTarget.value
			}

		case strings.EqualFold(key, transport.ImpersonateUIDHeader):
			if targetUser.UID == "" && len(values) > 0 {
				uidTarget = uidImpersonation(values[0])
				targetUser.UID = uidTarget.value
			}

		case strings.EqualFold(key, transport.ImpersonateGroupHeader):
			for _, group := range values {
				groupTargets = append(groupTargets, groupImpersonation(group))
				targetUser.Groups = append(targetUser.Groups, group)
			}

		default:
			// An Impersonate-Extra- header: every other kind was refused above.
			extraKey := extraKeyFromHeader(key)
			if forwarded := forwardedExtraKey(extraKey); forwarded != extraKey {
				return nil, nil, fmt.Errorf("%w: %q decodes to the key %q, which the API server would receive as %q",
					ErrUnforwardableExtraKey, key, extraKey, forwarded)
			}
			for _, value := range values {
				extraTargets = append(extraTargets, extraImpersonation(extraKey, value))
				targetUser.Extra[extraKey] = append(targetUser.Extra[extraKey], value)
			}
		}
	}

	// A service account's groups are a fixed mapping from its namespace, so
	// when the request names none, the identity gets them unreviewed, exactly
	// as kube-apiserver's impersonation filter does with
	// serviceaccount.MakeGroupNames. Groups the request does name are the
	// authority, and only those are reviewed and kept.
	if userTarget.serviceAccount && len(groupTargets) == 0 {
		targetUser.Groups = serviceaccount.MakeGroupNames(userTarget.namespace)
	}

	targets := append([]impersonationTarget{userTarget}, groupTargets...)
	targets = append(targets, extraTargets...)
	if targetUser.UID != "" {
		targets = append(targets, uidTarget)
	}
	return targetUser, targets, nil
}

// extraKeyFromHeader returns the user-extra key an Impersonate-Extra- header
// names, decoded exactly as kube-apiserver decodes it: the suffix is
// lower-cased, then percent-unescaped with url.PathUnescape, since client-go
// percent-encodes every byte that is not legal in a header name (a '/', for
// instance) and '%' itself. A suffix that does not unescape is kept as the
// lower-cased suffix, as the API server keeps it. The review and the resolved
// identity both use this key, and client-go encodes it again when the
// identity is forwarded.
//
// The decoded key can carry upper case (a client sent %41, say). The API
// server keeps that too, but such a key cannot be forwarded unchanged, so
// parseImpersonation refuses it (ErrUnforwardableExtraKey).
func extraKeyFromHeader(key string) string {
	encoded := strings.ToLower(key[len(transport.ImpersonateUserExtraHeaderPrefix):])
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		return encoded
	}
	return decoded
}

// forwardedExtraKey returns the extra key the API server receives when the
// proxy forwards key: client-go's impersonating round tripper writes it into
// an Impersonate-Extra- header name, percent-encoding the bytes a header name
// cannot carry, the header name is canonicalized on the wire, and the API
// server decodes it with extraKeyFromHeader's rule. It runs client-go's own
// round tripper rather than restating its encoding, so the check cannot drift
// from what is actually sent.
func forwardedExtraKey(key string) string {
	var sent http.Header
	rt := transport.NewImpersonatingRoundTripper(transport.ImpersonationConfig{
		UserName: "forwarded-extra-key",
		Extra:    map[string][]string{key: {""}},
	}, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		sent = req.Header
		return &http.Response{Body: http.NoBody}, nil
	}))
	if resp, err := rt.RoundTrip(&http.Request{Header: http.Header{}}); err == nil {
		_ = resp.Body.Close()
	}

	for name := range sent {
		if hasPrefixFold(name, transport.ImpersonateUserExtraHeaderPrefix) {
			return extraKeyFromHeader(http.CanonicalHeaderKey(name))
		}
	}
	return ""
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
